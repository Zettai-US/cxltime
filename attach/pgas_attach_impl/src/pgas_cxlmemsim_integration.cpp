// SPDX-License-Identifier: MIT
// Implementation of PGAS CXLMemSim integration

#include "pgas_cxlmemsim_integration.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <sstream>
#include <cstring>
#include <dlfcn.h>

namespace bpftime {
namespace attach {

// ============================================================================
// cxlmemsim_connection_manager implementation
// ============================================================================

int cxlmemsim_connection_manager::init(
    const std::vector<pgas_node_info>& nodes,
    uint16_t local_node_id) {

    std::lock_guard<std::mutex> lock(mutex_);
    local_node_id_ = local_node_id;

    for (const auto& node : nodes) {
        if (node.node_id == local_node_id) {
            SPDLOG_INFO("Node {} is local, skipping CXLMemSim connection",
                        node.node_id);
            continue;
        }

        auto ctx = std::make_unique<cxlmemsim_ctx_t>();
        if (cxlmemsim_init(ctx.get(), node.hostname.c_str(), node.port) != 0) {
            SPDLOG_ERROR("Failed to init CXLMemSim client for node {}",
                         node.node_id);
            continue;
        }

        if (cxlmemsim_connect(ctx.get()) != 0) {
            SPDLOG_ERROR("Failed to connect to CXLMemSim server at {}:{}",
                         node.hostname, node.port);
            cxlmemsim_finalize(ctx.get());
            continue;
        }

        SPDLOG_INFO("Connected to CXLMemSim server for node {} at {}:{}",
                    node.node_id, node.hostname, node.port);
        connections_[node.node_id] = std::move(ctx);
    }

    return connections_.empty() ? -1 : 0;
}

cxlmemsim_ctx_t* cxlmemsim_connection_manager::get_connection(uint16_t node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(node_id);
    return (it != connections_.end()) ? it->second.get() : nullptr;
}

void cxlmemsim_connection_manager::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, ctx] : connections_) {
        cxlmemsim_finalize(ctx.get());
    }
    connections_.clear();
}

cxlmemsim_connection_manager::stats
cxlmemsim_connection_manager::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void cxlmemsim_connection_manager::reset_stats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = {};
}

// ============================================================================
// pgas_cxlmemsim_hooker implementation
// ============================================================================

int pgas_cxlmemsim_hooker::init(const config& cfg) {
    config_ = cfg;

    // Initialize CXLMemSim connections
    auto& conn_mgr = cxlmemsim_connection_manager::instance();
    if (conn_mgr.init(cfg.nodes, cfg.local_node_id) != 0) {
        SPDLOG_WARN("No CXLMemSim connections established, "
                    "remote access will fail");
    }

    // Create attach implementation
    attach_impl_ = std::make_unique<pgas_attach_impl>();

    // Set PGAS region
    attach_impl_->set_pgas_region(cfg.pgas_base_addr, cfg.pgas_region_size);

    initialized_ = true;
    SPDLOG_INFO("PGAS CXLMemSim hooker initialized: "
                "local_node={} num_nodes={} pgas_base=0x{:x} pgas_size={}",
                cfg.local_node_id, cfg.num_nodes,
                cfg.pgas_base_addr, cfg.pgas_region_size);

    return 0;
}

int pgas_cxlmemsim_hooker::install_hooks() {
    if (!initialized_) {
        SPDLOG_ERROR("Hooker not initialized");
        return -1;
    }

    if (hooks_installed_) {
        SPDLOG_WARN("Hooks already installed");
        return 0;
    }

    // Hook memcpy
    if (config_.hook_memcpy) {
        void* memcpy_addr = dlsym(RTLD_DEFAULT, "memcpy");
        if (memcpy_addr) {
            attach_impl_->create_memcpy_hook(memcpy_addr,
                                              config_.local_node_id,
                                              config_.num_nodes);
            SPDLOG_INFO("Hooked memcpy at {}", memcpy_addr);
        }
    }

    // Hook memmove
    if (config_.hook_memmove) {
        void* memmove_addr = dlsym(RTLD_DEFAULT, "memmove");
        if (memmove_addr) {
            pgas_attach_private_data priv;
            priv.target_address = memmove_addr;
            priv.op_type = pgas_op_type::MEMMOVE;
            priv.local_node_id = config_.local_node_id;
            priv.num_nodes = config_.num_nodes;
            attach_impl_->create_pgas_hook(priv, nullptr);
            SPDLOG_INFO("Hooked memmove at {}", memmove_addr);
        }
    }

    // Hook memset
    if (config_.hook_memset) {
        void* memset_addr = dlsym(RTLD_DEFAULT, "memset");
        if (memset_addr) {
            pgas_attach_private_data priv;
            priv.target_address = memset_addr;
            priv.op_type = pgas_op_type::MEMSET;
            priv.local_node_id = config_.local_node_id;
            priv.num_nodes = config_.num_nodes;
            attach_impl_->create_pgas_hook(priv, nullptr);
            SPDLOG_INFO("Hooked memset at {}", memset_addr);
        }
    }

    hooks_installed_ = true;
    return 0;
}

void pgas_cxlmemsim_hooker::remove_hooks() {
    if (!hooks_installed_) return;

    attach_impl_.reset();
    hooks_installed_ = false;
    SPDLOG_INFO("PGAS hooks removed");
}

int pgas_cxlmemsim_hooker::remote_read(uint16_t node_id, uint64_t addr,
                                        void* dest, size_t size) {
    auto& conn_mgr = cxlmemsim_connection_manager::instance();

    if (conn_mgr.is_local(node_id)) {
        // Local read - direct memory access
        memcpy(dest, (void*)addr, size);
        return 0;
    }

    // Remote read via CXLMemSim
    auto* ctx = conn_mgr.get_connection(node_id);
    if (!ctx) {
        SPDLOG_ERROR("No connection for node {}", node_id);
        return -1;
    }

    return cxlmemsim_remote_load(ctx, addr, dest, size);
}

int pgas_cxlmemsim_hooker::remote_write(uint16_t node_id, uint64_t addr,
                                         const void* src, size_t size) {
    auto& conn_mgr = cxlmemsim_connection_manager::instance();

    if (conn_mgr.is_local(node_id)) {
        // Local write - direct memory access
        memcpy((void*)addr, src, size);
        return 0;
    }

    // Remote write via CXLMemSim
    auto* ctx = conn_mgr.get_connection(node_id);
    if (!ctx) {
        SPDLOG_ERROR("No connection for node {}", node_id);
        return -1;
    }

    return cxlmemsim_remote_store(ctx, addr, src, size);
}

uint16_t pgas_cxlmemsim_hooker::addr_to_node(uint64_t addr) const {
    if (!is_pgas_addr(addr)) {
        return config_.local_node_id;  // Non-PGAS address is local
    }

    // Simple partitioning: each node owns a contiguous region
    uint64_t offset = addr - config_.pgas_base_addr;
    uint64_t region_size = config_.pgas_region_size / config_.num_nodes;
    return static_cast<uint16_t>(offset / region_size) % config_.num_nodes;
}

uint64_t pgas_cxlmemsim_hooker::translate_addr(uint64_t local_addr,
                                                uint16_t target_node) const {
    // In this simple model, addresses are the same across nodes
    // For more complex setups, this would do actual translation
    return local_addr;
}

void pgas_cxlmemsim_hooker::print_stats() const {
    auto stats = cxlmemsim_connection_manager::instance().get_stats();

    printf("\n=== PGAS CXLMemSim Hook Statistics ===\n");
    printf("Local reads:  %lu\n", stats.local_reads);
    printf("Local writes: %lu\n", stats.local_writes);
    printf("Remote reads:  %lu\n", stats.remote_reads);
    printf("Remote writes: %lu\n", stats.remote_writes);
    printf("Total remote latency: %lu ns\n", stats.total_remote_latency_ns);

    uint64_t total_remote = stats.remote_reads + stats.remote_writes;
    if (total_remote > 0) {
        printf("Avg remote latency: %lu ns\n",
               stats.total_remote_latency_ns / total_remote);
    }
    printf("======================================\n\n");
}

// ============================================================================
// Remote operation handlers (called from Frida hooks)
// ============================================================================

int pgas_remote_memcpy_handler(void* dest, const void* src, size_t n,
                                uint16_t target_node, bool dest_is_remote) {
    auto& hooker = pgas_cxlmemsim_hooker::instance();

    if (dest_is_remote) {
        // Writing to remote node
        return hooker.remote_write(target_node, (uint64_t)dest, src, n);
    } else {
        // Reading from remote node
        return hooker.remote_read(target_node, (uint64_t)src, dest, n);
    }
}

int pgas_remote_memset_handler(void* s, int c, size_t n, uint16_t target_node) {
    // For remote memset, we need to create a local buffer and send it
    auto& hooker = pgas_cxlmemsim_hooker::instance();

    // For small sizes, use stack buffer
    if (n <= 4096) {
        char buf[4096];
        memset(buf, c, n);
        return hooker.remote_write(target_node, (uint64_t)s, buf, n);
    }

    // For larger sizes, allocate
    void* buf = malloc(n);
    if (!buf) return -1;

    memset(buf, c, n);
    int ret = hooker.remote_write(target_node, (uint64_t)s, buf, n);
    free(buf);

    return ret;
}

// ============================================================================
// hooks namespace - simplified interface
// ============================================================================

namespace hooks {

static bool g_active = false;

int init_from_config(const std::string& config_file) {
    pgas_cxlmemsim_hooker::config cfg;

    std::ifstream file(config_file);
    if (!file.is_open()) {
        SPDLOG_ERROR("Failed to open config file: {}", config_file);
        return -1;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value)) {
            if (key == "local_node_id") {
                cfg.local_node_id = std::stoi(value);
            } else if (key == "num_nodes") {
                cfg.num_nodes = std::stoi(value);
            } else if (key == "pgas_base") {
                cfg.pgas_base_addr = std::stoull(value, nullptr, 0);
            } else if (key == "pgas_size") {
                cfg.pgas_region_size = std::stoull(value, nullptr, 0);
            } else if (key.substr(0, 9) == "cxlmemsim") {
                // Parse cxlmemsimN=host:port:node_id
                pgas_node_info node;
                std::istringstream vss(value);
                std::string host, port_str, node_id_str;
                if (std::getline(vss, host, ':') &&
                    std::getline(vss, port_str, ':') &&
                    std::getline(vss, node_id_str)) {
                    node.hostname = host;
                    node.port = std::stoi(port_str);
                    node.node_id = std::stoi(node_id_str);
                    cfg.nodes.push_back(node);
                }
            }
        }
    }

    return pgas_cxlmemsim_hooker::instance().init(cfg);
}

int init(uint16_t local_node_id, uint16_t num_nodes,
         const std::vector<std::pair<std::string, int>>& server_addresses,
         uint64_t pgas_base_addr, uint64_t pgas_size) {

    pgas_cxlmemsim_hooker::config cfg;
    cfg.local_node_id = local_node_id;
    cfg.num_nodes = num_nodes;
    cfg.pgas_base_addr = pgas_base_addr;
    cfg.pgas_region_size = pgas_size;

    for (size_t i = 0; i < server_addresses.size(); i++) {
        pgas_node_info node;
        node.node_id = static_cast<uint16_t>(i);
        node.hostname = server_addresses[i].first;
        node.port = server_addresses[i].second;
        cfg.nodes.push_back(node);
    }

    return pgas_cxlmemsim_hooker::instance().init(cfg);
}

int start() {
    int ret = pgas_cxlmemsim_hooker::instance().install_hooks();
    if (ret == 0) {
        g_active = true;
    }
    return ret;
}

void stop() {
    pgas_cxlmemsim_hooker::instance().remove_hooks();
    g_active = false;
}

bool is_active() {
    return g_active;
}

cxlmemsim_connection_manager::stats get_stats() {
    return cxlmemsim_connection_manager::instance().get_stats();
}

void finalize() {
    stop();
    cxlmemsim_connection_manager::instance().shutdown();
}

} // namespace hooks

} // namespace attach
} // namespace bpftime

// ============================================================================
// C interface implementation
// ============================================================================

extern "C" {

int pgas_hook_init(const char* config_file) {
    return bpftime::attach::hooks::init_from_config(config_file);
}

int pgas_hook_start(void) {
    return bpftime::attach::hooks::start();
}

void pgas_hook_stop(void) {
    bpftime::attach::hooks::stop();
}

int pgas_hook_remote_read(uint16_t node_id, uint64_t addr,
                           void* dest, size_t size) {
    return bpftime::attach::pgas_cxlmemsim_hooker::instance().remote_read(
        node_id, addr, dest, size);
}

int pgas_hook_remote_write(uint16_t node_id, uint64_t addr,
                            const void* src, size_t size) {
    return bpftime::attach::pgas_cxlmemsim_hooker::instance().remote_write(
        node_id, addr, src, size);
}

void pgas_hook_finalize(void) {
    bpftime::attach::hooks::finalize();
}

void pgas_hook_print_stats(void) {
    bpftime::attach::pgas_cxlmemsim_hooker::instance().print_stats();
}

} // extern "C"
