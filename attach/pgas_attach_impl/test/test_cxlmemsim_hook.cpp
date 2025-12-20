// SPDX-License-Identifier: MIT
// Test for transparent ld/st hooking via CXLMemSim

#include "pgas_cxlmemsim_integration.hpp"
#include <iostream>
#include <cstring>
#include <chrono>
#include <vector>
#include <thread>

using namespace bpftime::attach;

// Test buffer size
constexpr size_t BUFFER_SIZE = 4096;
constexpr int NUM_ITERATIONS = 1000;

// Simulated PGAS memory region (will be intercepted by hooks)
alignas(64) static char g_pgas_region[BUFFER_SIZE * 16];

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " <mode> [args]\n\n"
              << "Modes:\n"
              << "  manual <host> <port>       - Test manual remote access\n"
              << "  hook <config_file>         - Test transparent hooking\n"
              << "  benchmark <host> <port>    - Benchmark hook overhead\n"
              << std::endl;
}

// Test manual remote access without hooks
int test_manual(const char* host, int port) {
    std::cout << "\n=== Test: Manual Remote Access ===\n" << std::endl;

    // Initialize connection manager
    std::vector<pgas_node_info> nodes;
    pgas_node_info node;
    node.node_id = 1;  // Remote node
    node.hostname = host;
    node.port = port;
    nodes.push_back(node);

    auto& conn_mgr = cxlmemsim_connection_manager::instance();
    if (conn_mgr.init(nodes, 0) != 0) {
        std::cerr << "Failed to initialize connection manager" << std::endl;
        return -1;
    }

    // Test write
    char write_data[64];
    for (int i = 0; i < 64; i++) write_data[i] = i;

    std::cout << "Writing 64 bytes to remote address 0x1000..." << std::endl;
    auto* ctx = conn_mgr.get_connection(1);
    if (!ctx) {
        std::cerr << "No connection to node 1" << std::endl;
        return -1;
    }

    if (cxlmemsim_write(ctx, 0x1000, write_data, 64, nullptr) == 0) {
        std::cout << "Write successful" << std::endl;
    } else {
        std::cerr << "Write failed" << std::endl;
        return -1;
    }

    // Test read
    char read_data[64] = {0};
    std::cout << "Reading 64 bytes from remote address 0x1000..." << std::endl;

    if (cxlmemsim_read(ctx, 0x1000, read_data, 64, nullptr) == 0) {
        std::cout << "Read successful" << std::endl;

        // Verify
        if (memcmp(write_data, read_data, 64) == 0) {
            std::cout << "Data verification: PASSED" << std::endl;
        } else {
            std::cout << "Data verification: FAILED" << std::endl;
        }
    } else {
        std::cerr << "Read failed" << std::endl;
        return -1;
    }

    conn_mgr.shutdown();
    return 0;
}

// Test transparent hooking
int test_hook(const char* config_file) {
    std::cout << "\n=== Test: Transparent Hooking ===\n" << std::endl;

    // Initialize from config
    if (hooks::init_from_config(config_file) != 0) {
        std::cerr << "Failed to initialize hooks from config" << std::endl;
        return -1;
    }

    std::cout << "Installing memory operation hooks..." << std::endl;
    if (hooks::start() != 0) {
        std::cerr << "Failed to start hooks" << std::endl;
        return -1;
    }

    std::cout << "Hooks installed. Testing memcpy..." << std::endl;

    // Prepare test data
    char src[256];
    char dest[256] = {0};
    for (int i = 0; i < 256; i++) src[i] = i;

    // This memcpy will be intercepted by our hook
    memcpy(dest, src, 256);

    // Verify
    if (memcmp(src, dest, 256) == 0) {
        std::cout << "memcpy verification: PASSED" << std::endl;
    } else {
        std::cout << "memcpy verification: FAILED" << std::endl;
    }

    // Test with PGAS region address
    auto& hooker = pgas_cxlmemsim_hooker::instance();
    const auto& cfg = hooker.get_config();

    std::cout << "\nPGAS region: base=0x" << std::hex << cfg.pgas_base_addr
              << " size=" << std::dec << cfg.pgas_region_size << std::endl;

    // Test memset on PGAS region
    memset(g_pgas_region, 0xAA, 1024);
    std::cout << "memset on PGAS region completed" << std::endl;

    // Print statistics
    hooker.print_stats();

    // Cleanup
    hooks::finalize();
    return 0;
}

// Benchmark hook overhead
int test_benchmark(const char* host, int port) {
    std::cout << "\n=== Benchmark: Hook Overhead ===\n" << std::endl;

    // Initialize with manual config
    std::vector<std::pair<std::string, int>> servers = {
        {"127.0.0.1", 9000},  // Node 0 (local, won't be used)
        {host, port}         // Node 1 (remote)
    };

    if (hooks::init(0, 2, servers,
                    (uint64_t)g_pgas_region,
                    sizeof(g_pgas_region)) != 0) {
        std::cerr << "Failed to initialize" << std::endl;
        return -1;
    }

    // Benchmark WITHOUT hooks
    char src[BUFFER_SIZE];
    char dest[BUFFER_SIZE];
    for (size_t i = 0; i < BUFFER_SIZE; i++) src[i] = i & 0xFF;

    std::cout << "Benchmarking memcpy WITHOUT hooks..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        memcpy(dest, src, BUFFER_SIZE);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto no_hook_time = std::chrono::duration_cast<std::chrono::microseconds>(
        end - start).count();

    std::cout << "  " << NUM_ITERATIONS << " iterations in "
              << no_hook_time << " us" << std::endl;
    std::cout << "  " << (double)no_hook_time / NUM_ITERATIONS
              << " us per operation" << std::endl;

    // Install hooks
    std::cout << "\nInstalling hooks..." << std::endl;
    hooks::start();

    // Benchmark WITH hooks (local access - no remote)
    std::cout << "Benchmarking memcpy WITH hooks (local access)..." << std::endl;
    start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        memcpy(dest, src, BUFFER_SIZE);
    }

    end = std::chrono::high_resolution_clock::now();
    auto with_hook_time = std::chrono::duration_cast<std::chrono::microseconds>(
        end - start).count();

    std::cout << "  " << NUM_ITERATIONS << " iterations in "
              << with_hook_time << " us" << std::endl;
    std::cout << "  " << (double)with_hook_time / NUM_ITERATIONS
              << " us per operation" << std::endl;

    // Calculate overhead
    double overhead = ((double)with_hook_time / no_hook_time - 1.0) * 100.0;
    std::cout << "\nHook overhead: " << overhead << "%" << std::endl;

    // Benchmark remote access
    std::cout << "\nBenchmarking remote access via hooks..." << std::endl;
    auto& hooker = pgas_cxlmemsim_hooker::instance();

    start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 100; i++) {  // Fewer iterations for remote
        hooker.remote_write(1, 0x10000 + i * 64, src, 64);
    }

    end = std::chrono::high_resolution_clock::now();
    auto remote_time = std::chrono::duration_cast<std::chrono::microseconds>(
        end - start).count();

    std::cout << "  100 remote writes in " << remote_time << " us" << std::endl;
    std::cout << "  " << (double)remote_time / 100 << " us per operation"
              << std::endl;

    // Print final stats
    hooker.print_stats();

    hooks::finalize();
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "manual") {
        if (argc < 4) {
            std::cerr << "manual mode requires <host> <port>" << std::endl;
            return 1;
        }
        return test_manual(argv[2], std::atoi(argv[3]));
    }
    else if (mode == "hook") {
        if (argc < 3) {
            std::cerr << "hook mode requires <config_file>" << std::endl;
            return 1;
        }
        return test_hook(argv[2]);
    }
    else if (mode == "benchmark") {
        if (argc < 4) {
            std::cerr << "benchmark mode requires <host> <port>" << std::endl;
            return 1;
        }
        return test_benchmark(argv[2], std::atoi(argv[3]));
    }
    else {
        std::cerr << "Unknown mode: " << mode << std::endl;
        print_usage(argv[0]);
        return 1;
    }
}
