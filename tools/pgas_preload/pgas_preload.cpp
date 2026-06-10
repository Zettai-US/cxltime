// SPDX-License-Identifier: MIT
// PGAS LD_PRELOAD library for CXLMemSim
// Usage: PGAS_CONFIG=config.conf LD_PRELOAD=libpgas_preload.so ./your_app

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <unistd.h>
#include <atomic>
#include <mutex>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <alloca.h>

// CXLMemSim client for remote memory access (from libpgas)
extern "C" {
#include "pgas/cxlmemsim_client.h"
#include "pgas/pgas.h"  // For pgas_region_info_t
}

// Global state
static std::mutex g_mutex;
static bool g_initialized = false;

// Configuration
static uint16_t g_local_node_id = 0;
static uint16_t g_num_nodes = 1;
static uint64_t g_pgas_base = 0;
static uint64_t g_pgas_size = 1ULL << 30;  // 1GB default
static bool g_verbose = false;
static bool g_enable_stats = true;

// =============================================================================
// Dynamic PGAS region registration (populated by libpgas at runtime)
// =============================================================================
#define MAX_PGAS_REGIONS 16
static std::mutex g_region_mutex;
static pgas_region_info_t g_registered_regions[MAX_PGAS_REGIONS];
static int g_num_registered_regions = 0;
static bool g_regions_initialized = false;  // True once libpgas registers regions

// CXLMemSim configuration
static char g_cxlmemsim_host[256] = "localhost";
static int g_cxlmemsim_port = 9999;
static cxlmemsim_ctx_t* g_cxlmemsim_ctx = nullptr;  // Connection to server
static bool g_cxlmemsim_connected = false;

// Statistics
static std::atomic<uint64_t> g_total_memcpy{0};
static std::atomic<uint64_t> g_total_memmove{0};
static std::atomic<uint64_t> g_total_memset{0};
static std::atomic<uint64_t> g_total_malloc{0};
static std::atomic<uint64_t> g_total_free{0};
static std::atomic<uint64_t> g_bytes_copied{0};
static std::atomic<uint64_t> g_local_accesses{0};
static std::atomic<uint64_t> g_remote_accesses{0};

// Hook IDs
static int g_memcpy_hook_id = -1;
static int g_memmove_hook_id = -1;
static int g_memset_hook_id = -1;

// Original function pointers (for fallback)
typedef void* (*memcpy_fn)(void*, const void*, size_t);
typedef void* (*memmove_fn)(void*, const void*, size_t);
typedef void* (*memset_fn)(void*, int, size_t);
typedef void* (*malloc_fn)(size_t);
typedef void (*free_fn)(void*);

// Export these so the attach impl can use them (avoid re-entrancy)
extern "C" {
    memcpy_fn pgas_orig_memcpy = nullptr;
    memmove_fn pgas_orig_memmove = nullptr;
    memset_fn pgas_orig_memset = nullptr;
}

static malloc_fn orig_malloc = nullptr;
static free_fn orig_free = nullptr;

// Aliases for backward compatibility
#define orig_memcpy pgas_orig_memcpy
#define orig_memmove pgas_orig_memmove
#define orig_memset pgas_orig_memset

// =============================================================================
// PGAS Region Registration API (called by libpgas)
// These override the weak symbols in libpgas
// =============================================================================

extern "C" {

void pgas_register_region(const pgas_region_info_t* region) {
    if (!region) return;

    std::lock_guard<std::mutex> lock(g_region_mutex);

    // Check if region already exists (update it)
    for (int i = 0; i < g_num_registered_regions; i++) {
        if (g_registered_regions[i].node_id == region->node_id) {
            g_registered_regions[i] = *region;
            if (g_verbose) {
                fprintf(stderr, "[PGAS] Updated region for node %d: base=0x%lx size=%lu local=%d\n",
                        region->node_id, region->base_addr, region->size, region->is_local);
            }
            // Update local node info if this is our node
            if (region->is_local) {
                g_local_node_id = region->node_id;
            }
            g_regions_initialized = true;
            return;
        }
    }

    // Add new region
    if (g_num_registered_regions < MAX_PGAS_REGIONS) {
        g_registered_regions[g_num_registered_regions++] = *region;
        if (region->is_local) {
            g_local_node_id = region->node_id;
        }
        g_num_nodes = g_num_registered_regions;
        g_regions_initialized = true;

        if (g_verbose) {
            fprintf(stderr, "[PGAS] Registered region for node %d: base=0x%lx size=%lu local=%d\n",
                    region->node_id, region->base_addr, region->size, region->is_local);
        }
    } else {
        fprintf(stderr, "[PGAS] Warning: Max regions (%d) reached, cannot register node %d\n",
                MAX_PGAS_REGIONS, region->node_id);
    }
}

void pgas_unregister_region(uint16_t node_id) {
    std::lock_guard<std::mutex> lock(g_region_mutex);

    for (int i = 0; i < g_num_registered_regions; i++) {
        if (g_registered_regions[i].node_id == node_id) {
            // Shift remaining regions down
            for (int j = i; j < g_num_registered_regions - 1; j++) {
                g_registered_regions[j] = g_registered_regions[j + 1];
            }
            g_num_registered_regions--;
            g_num_nodes = g_num_registered_regions;

            if (g_verbose) {
                fprintf(stderr, "[PGAS] Unregistered region for node %d\n", node_id);
            }

            if (g_num_registered_regions == 0) {
                g_regions_initialized = false;
            }
            return;
        }
    }
}

int pgas_get_registered_regions(pgas_region_info_t* regions, int max_regions) {
    std::lock_guard<std::mutex> lock(g_region_mutex);

    int count = (g_num_registered_regions < max_regions) ? g_num_registered_regions : max_regions;
    for (int i = 0; i < count; i++) {
        regions[i] = g_registered_regions[i];
    }
    return count;
}

}  // extern "C"

// Load configuration from file then environment (env overrides file)
static void load_config() {
    // Config file first (optional) - environment variables will override
    const char *config_file = getenv("PGAS_CONFIG");
    if (config_file) {
        std::ifstream ifs(config_file);
        if (ifs.is_open()) {
            std::string line;
            while (std::getline(ifs, line)) {
                if (line.empty() || line[0] == '#') continue;

                std::istringstream iss(line);
                std::string key, value;
                if (std::getline(iss, key, '=') && std::getline(iss, value)) {
                    if (key == "node_id" || key == "local_node_id") g_local_node_id = atoi(value.c_str());
                    else if (key == "num_nodes") g_num_nodes = atoi(value.c_str());
                    else if (key == "base_addr" || key == "pgas_base") g_pgas_base = strtoull(value.c_str(), nullptr, 0);
                    else if (key == "size" || key == "pgas_size") g_pgas_size = strtoull(value.c_str(), nullptr, 0);
                    else if (key == "verbose") g_verbose = (value == "1" || value == "true");
                    // CXLMemSim config file options
                    else if (key == "cxlmemsim_host") strncpy(g_cxlmemsim_host, value.c_str(), sizeof(g_cxlmemsim_host) - 1);
                    else if (key == "cxlmemsim_port") g_cxlmemsim_port = atoi(value.c_str());
                }
            }
        }
    }

    // Environment variables override config file
    const char *env_node = getenv("PGAS_NODE_ID");
    if (!env_node) env_node = getenv("PGAS_LOCAL_NODE");
    if (env_node) {
        g_local_node_id = atoi(env_node);
    }

    const char *env_nodes = getenv("PGAS_NUM_NODES");
    if (env_nodes) {
        g_num_nodes = atoi(env_nodes);
    }

    const char *env_base = getenv("PGAS_BASE_ADDR");
    if (!env_base) env_base = getenv("PGAS_BASE");
    if (env_base) {
        g_pgas_base = strtoull(env_base, nullptr, 0);
    }

    const char *env_size = getenv("PGAS_SIZE");
    if (env_size) {
        g_pgas_size = strtoull(env_size, nullptr, 0);
    }

    const char *env_verbose = getenv("PGAS_VERBOSE");
    if (env_verbose && strcmp(env_verbose, "1") == 0) {
        g_verbose = true;
    }

    const char *env_stats = getenv("PGAS_STATS");
    if (env_stats && strcmp(env_stats, "0") == 0) {
        g_enable_stats = false;
    }

    // CXLMemSim environment variables override config file
    const char *env_cxl_host = getenv("CXL_MEMSIM_HOST");
    if (env_cxl_host) {
        strncpy(g_cxlmemsim_host, env_cxl_host, sizeof(g_cxlmemsim_host) - 1);
    }

    const char *env_cxl_port = getenv("CXL_MEMSIM_PORT");
    if (env_cxl_port) {
        g_cxlmemsim_port = atoi(env_cxl_port);
    }
}

// Print statistics
static void print_stats() {
    if (!g_enable_stats) return;

    fprintf(stderr, "\n=== PGAS Statistics ===\n");
    fprintf(stderr, "Node ID: %d / %d\n", g_local_node_id, g_num_nodes);
    fprintf(stderr, "memcpy calls: %lu\n", g_total_memcpy.load());
    fprintf(stderr, "memmove calls: %lu\n", g_total_memmove.load());
    fprintf(stderr, "memset calls: %lu\n", g_total_memset.load());
    fprintf(stderr, "Total bytes copied: %lu\n", g_bytes_copied.load());
    fprintf(stderr, "Local accesses: %lu\n", g_local_accesses.load());
    fprintf(stderr, "Remote accesses: %lu\n", g_remote_accesses.load());

    if (g_local_accesses + g_remote_accesses > 0) {
        double remote_pct = 100.0 * g_remote_accesses /
                           (g_local_accesses + g_remote_accesses);
        fprintf(stderr, "Remote access ratio: %.2f%%\n", remote_pct);
    }
    fprintf(stderr, "========================\n\n");
}

// Initialize PGAS hooks
static void init_pgas() {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_initialized) return;

    // Load configuration
    load_config();

    fprintf(stderr, "[PGAS] Initializing PGAS preload library\n");
    fprintf(stderr, "[PGAS] Node: %d/%d, Base: 0x%lx, Size: %lu MB\n",
            g_local_node_id, g_num_nodes, g_pgas_base, g_pgas_size / (1024*1024));

    // Get original function pointers
    orig_memcpy = (memcpy_fn)dlsym(RTLD_NEXT, "memcpy");
    orig_memmove = (memmove_fn)dlsym(RTLD_NEXT, "memmove");
    orig_memset = (memset_fn)dlsym(RTLD_NEXT, "memset");
    orig_malloc = (malloc_fn)dlsym(RTLD_NEXT, "malloc");
    orig_free = (free_fn)dlsym(RTLD_NEXT, "free");

    // Using direct LD_PRELOAD interposition instead of Frida hooks
    // The memcpy/memmove/memset functions defined at the bottom of this file
    // will be called automatically via LD_PRELOAD symbol interposition
    fprintf(stderr, "[PGAS] Using direct LD_PRELOAD interposition\n");

    // Connect to CXLMemSim server for remote memory access
    if (g_cxlmemsim_port > 0) {
        g_cxlmemsim_ctx = (cxlmemsim_ctx_t*)malloc(sizeof(cxlmemsim_ctx_t));
        if (g_cxlmemsim_ctx) {
            if (cxlmemsim_init(g_cxlmemsim_ctx, g_cxlmemsim_host, g_cxlmemsim_port) == 0) {
                if (cxlmemsim_connect(g_cxlmemsim_ctx) == 0) {
                    g_cxlmemsim_connected = true;
                    fprintf(stderr, "[PGAS] Connected to CXLMemSim server at %s:%d\n",
                            g_cxlmemsim_host, g_cxlmemsim_port);
                } else {
                    fprintf(stderr, "[PGAS] Warning: Failed to connect to CXLMemSim at %s:%d, "
                            "remote accesses will use local memory only\n",
                            g_cxlmemsim_host, g_cxlmemsim_port);
                }
            } else {
                fprintf(stderr, "[PGAS] Warning: Failed to initialize CXLMemSim client\n");
            }
        }
    } else {
        fprintf(stderr, "[PGAS] CXLMemSim disabled (port=0), using local memory only\n");
    }

    g_initialized = true;
    fprintf(stderr, "[PGAS] Initialization complete\n");
}

// Cleanup PGAS
static void cleanup_pgas() {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (!g_initialized) return;

    fprintf(stderr, "[PGAS] Shutting down...\n");

    // Print CXLMemSim statistics if connected
    if (g_cxlmemsim_connected && g_cxlmemsim_ctx) {
        cxlmemsim_stats_t cxl_stats;
        cxlmemsim_get_stats(g_cxlmemsim_ctx, &cxl_stats);
        fprintf(stderr, "\n=== CXLMemSim Statistics ===\n");
        fprintf(stderr, "Total reads: %lu\n", cxl_stats.total_reads);
        fprintf(stderr, "Total writes: %lu\n", cxl_stats.total_writes);
        fprintf(stderr, "Total bytes read: %lu\n", cxl_stats.total_bytes_read);
        fprintf(stderr, "Total bytes written: %lu\n", cxl_stats.total_bytes_written);
        fprintf(stderr, "Total latency: %lu ns\n", cxl_stats.total_latency_ns);
        fprintf(stderr, "============================\n");
    }

    // Disconnect from CXLMemSim server
    if (g_cxlmemsim_ctx) {
        if (g_cxlmemsim_connected) {
            cxlmemsim_disconnect(g_cxlmemsim_ctx);
            g_cxlmemsim_connected = false;
        }
        cxlmemsim_finalize(g_cxlmemsim_ctx);
        free(g_cxlmemsim_ctx);
        g_cxlmemsim_ctx = nullptr;
    }

    // Print statistics
    print_stats();

    g_initialized = false;
    fprintf(stderr, "[PGAS] Shutdown complete\n");
}

// Library constructor - called when library is loaded
__attribute__((constructor))
static void pgas_preload_init() {
    init_pgas();
}

// Library destructor - called when library is unloaded
__attribute__((destructor))
static void pgas_preload_fini() {
    cleanup_pgas();
}

// Signal handler for graceful shutdown
extern "C" void pgas_signal_handler(int sig) {
    fprintf(stderr, "[PGAS] Received signal %d\n", sig);
    print_stats();
}

// API for runtime control
extern "C" {

// Get current statistics (renamed to avoid conflict with pgas.h)
void pgas_preload_get_stats(uint64_t *memcpy_calls, uint64_t *memmove_calls,
                            uint64_t *memset_calls, uint64_t *bytes_copied,
                            uint64_t *local_accesses, uint64_t *remote_accesses) {
    if (memcpy_calls) *memcpy_calls = g_total_memcpy.load();
    if (memmove_calls) *memmove_calls = g_total_memmove.load();
    if (memset_calls) *memset_calls = g_total_memset.load();
    if (bytes_copied) *bytes_copied = g_bytes_copied.load();
    if (local_accesses) *local_accesses = g_local_accesses.load();
    if (remote_accesses) *remote_accesses = g_remote_accesses.load();
}

// Reset statistics (renamed to avoid conflict with pgas.h)
void pgas_preload_reset_stats() {
    g_total_memcpy = 0;
    g_total_memmove = 0;
    g_total_memset = 0;
    g_bytes_copied = 0;
    g_local_accesses = 0;
    g_remote_accesses = 0;
}

// Print statistics to stderr
void pgas_print_stats() {
    print_stats();
}

// Check if PGAS is initialized
int pgas_is_initialized() {
    return g_initialized ? 1 : 0;
}

// Get node configuration
void pgas_get_config(uint16_t *node_id, uint16_t *num_nodes,
                     uint64_t *base_addr, uint64_t *size) {
    if (node_id) *node_id = g_local_node_id;
    if (num_nodes) *num_nodes = g_num_nodes;
    if (base_addr) *base_addr = g_pgas_base;
    if (size) *size = g_pgas_size;
}

} // extern "C"

// =============================================================================
// Direct LD_PRELOAD interposition (no Frida hooks needed)
// These override libc's memcpy/memmove/memset directly
// =============================================================================

// Helper to check if address is in any PGAS region
// Uses dynamically registered regions from libpgas if available,
// otherwise falls back to static configuration
static inline bool is_pgas_addr(const void *addr) {
    uintptr_t a = (uintptr_t)addr;

    // If libpgas has registered regions, use those (dynamic mode)
    if (g_regions_initialized) {
        for (int i = 0; i < g_num_registered_regions; i++) {
            uint64_t base = g_registered_regions[i].base_addr;
            uint64_t size = g_registered_regions[i].size;
            if (a >= base && a < base + size) {
                return true;
            }
        }
        return false;
    }

    // Fallback to static configuration (for standalone use without libpgas)
    return a >= g_pgas_base && a < g_pgas_base + g_pgas_size;
}

// Helper to route address to node
// Uses dynamically registered regions from libpgas if available
static inline uint16_t route_to_node(uintptr_t addr) {
    if (g_num_nodes <= 1) return g_local_node_id;
    if (!is_pgas_addr((void*)addr)) return g_local_node_id;

    // If libpgas has registered regions, find which node owns this address
    if (g_regions_initialized) {
        for (int i = 0; i < g_num_registered_regions; i++) {
            uint64_t base = g_registered_regions[i].base_addr;
            uint64_t size = g_registered_regions[i].size;
            if (addr >= base && addr < base + size) {
                return g_registered_regions[i].node_id;
            }
        }
        // Address not in any registered region
        return g_local_node_id;
    }

    // Fallback to static configuration (divide PGAS space evenly)
    uint64_t offset = addr - g_pgas_base;
    uint64_t region_size = g_pgas_size / g_num_nodes;
    return (uint16_t)(offset / region_size) % g_num_nodes;
}

extern "C" void *memcpy(void *dest, const void *src, size_t n) {
    // Ensure we have the original function
    if (!pgas_orig_memcpy) {
        pgas_orig_memcpy = (memcpy_fn)dlsym(RTLD_NEXT, "memcpy");
    }

    if (g_initialized) {
        g_total_memcpy++;
        g_bytes_copied += n;

        bool dest_pgas = is_pgas_addr(dest);
        bool src_pgas = is_pgas_addr(src);

        if (dest_pgas || src_pgas) {
            uint16_t dest_node = dest_pgas ? route_to_node((uintptr_t)dest) : g_local_node_id;
            uint16_t src_node = src_pgas ? route_to_node((uintptr_t)src) : g_local_node_id;

            bool dest_remote = (dest_node != g_local_node_id);
            bool src_remote = (src_node != g_local_node_id);

            if (dest_remote || src_remote) {
                g_remote_accesses++;
            } else {
                g_local_accesses++;
            }

            if (g_verbose) {
                fprintf(stderr, "[PGAS] CXL memcpy: %p <- %p (%zu bytes) dest_node=%d src_node=%d\n",
                        dest, src, n, dest_node, src_node);
            }

            // Route ALL CXL memory accesses through CXLMemSim if connected
            // This tracks both local and remote CXL accesses for latency simulation
            if (g_cxlmemsim_connected && g_cxlmemsim_ctx) {
                if (src_pgas && dest_pgas) {
                    // Both in CXL memory: read from src, write to dest via CXLMemSim
                    char *temp_buf = (char*)alloca(n < 4096 ? n : 4096);

                    size_t remaining = n;
                    size_t offset = 0;
                    while (remaining > 0) {
                        size_t chunk = remaining > 4096 ? 4096 : remaining;
                        cxlmemsim_remote_load(g_cxlmemsim_ctx, (uint64_t)src + offset, temp_buf, chunk);
                        cxlmemsim_remote_store(g_cxlmemsim_ctx, (uint64_t)dest + offset, temp_buf, chunk);
                        offset += chunk;
                        remaining -= chunk;
                    }
                    // Also do actual memcpy for data integrity
                    pgas_orig_memcpy(dest, src, n);
                    return dest;
                } else if (src_pgas) {
                    // Source is in CXL memory: track the read via CXLMemSim
                    cxlmemsim_remote_load(g_cxlmemsim_ctx, (uint64_t)src, dest, n);
                    // Also do actual memcpy for data integrity
                    pgas_orig_memcpy(dest, src, n);
                    return dest;
                } else if (dest_pgas) {
                    // Dest is in CXL memory: track the write via CXLMemSim
                    cxlmemsim_remote_store(g_cxlmemsim_ctx, (uint64_t)dest, src, n);
                    // Also do actual memcpy for data integrity
                    pgas_orig_memcpy(dest, src, n);
                    return dest;
                }
            }
        } else {
            g_local_accesses++;
        }
    }

    return pgas_orig_memcpy(dest, src, n);
}

extern "C" void *memmove(void *dest, const void *src, size_t n) {
    if (!pgas_orig_memmove) {
        pgas_orig_memmove = (memmove_fn)dlsym(RTLD_NEXT, "memmove");
    }

    if (g_initialized) {
        g_total_memmove++;
        g_bytes_copied += n;

        bool dest_pgas = is_pgas_addr(dest);
        bool src_pgas = is_pgas_addr(src);

        if (dest_pgas || src_pgas) {
            uint16_t dest_node = dest_pgas ? route_to_node((uintptr_t)dest) : g_local_node_id;
            uint16_t src_node = src_pgas ? route_to_node((uintptr_t)src) : g_local_node_id;

            bool dest_remote = (dest_node != g_local_node_id);
            bool src_remote = (src_node != g_local_node_id);

            if (dest_remote || src_remote) {
                g_remote_accesses++;
            } else {
                g_local_accesses++;
            }

            if (g_verbose) {
                fprintf(stderr, "[PGAS] CXL memmove: %p <- %p (%zu bytes) dest_node=%d src_node=%d\n",
                        dest, src, n, dest_node, src_node);
            }

            // Route ALL CXL memory accesses through CXLMemSim if connected
            if (g_cxlmemsim_connected && g_cxlmemsim_ctx) {
                if (src_pgas && dest_pgas) {
                    // Both in CXL memory: read from src, write to dest via CXLMemSim
                    char *temp_buf = (char*)alloca(n < 4096 ? n : 4096);

                    size_t remaining = n;
                    size_t offset = 0;
                    while (remaining > 0) {
                        size_t chunk = remaining > 4096 ? 4096 : remaining;
                        cxlmemsim_remote_load(g_cxlmemsim_ctx, (uint64_t)src + offset, temp_buf, chunk);
                        cxlmemsim_remote_store(g_cxlmemsim_ctx, (uint64_t)dest + offset, temp_buf, chunk);
                        offset += chunk;
                        remaining -= chunk;
                    }
                    pgas_orig_memmove(dest, src, n);
                    return dest;
                } else if (src_pgas) {
                    // Source is in CXL memory: track the read via CXLMemSim
                    cxlmemsim_remote_load(g_cxlmemsim_ctx, (uint64_t)src, dest, n);
                    pgas_orig_memmove(dest, src, n);
                    return dest;
                } else if (dest_pgas) {
                    // Dest is in CXL memory: track the write via CXLMemSim
                    cxlmemsim_remote_store(g_cxlmemsim_ctx, (uint64_t)dest, src, n);
                    pgas_orig_memmove(dest, src, n);
                    return dest;
                }
            }
        } else {
            g_local_accesses++;
        }
    }

    return pgas_orig_memmove(dest, src, n);
}

extern "C" void *memset(void *s, int c, size_t n) {
    if (!pgas_orig_memset) {
        pgas_orig_memset = (memset_fn)dlsym(RTLD_NEXT, "memset");
    }

    if (g_initialized) {
        g_total_memset++;

        if (is_pgas_addr(s)) {
            uint16_t target = route_to_node((uintptr_t)s);
            if (target != g_local_node_id) {
                g_remote_accesses++;
            } else {
                g_local_accesses++;
            }

            if (g_verbose) {
                fprintf(stderr, "[PGAS] CXL memset: %p (%zu bytes) -> node %d\n",
                        s, n, target);
            }

            // Route ALL CXL memory writes through CXLMemSim if connected
            if (g_cxlmemsim_connected && g_cxlmemsim_ctx) {
                // Create a buffer filled with the byte value and send to CXLMemSim
                size_t chunk_size = 4096;
                char *temp_buf = (char*)alloca(chunk_size);
                pgas_orig_memset(temp_buf, c, chunk_size);

                size_t remaining = n;
                size_t offset = 0;
                while (remaining > 0) {
                    size_t chunk = remaining > chunk_size ? chunk_size : remaining;
                    cxlmemsim_remote_store(g_cxlmemsim_ctx, (uint64_t)s + offset, temp_buf, chunk);
                    offset += chunk;
                    remaining -= chunk;
                }
                // Also do actual memset for data integrity
                pgas_orig_memset(s, c, n);
                return s;
            }
        } else {
            g_local_accesses++;
        }
    }

    return pgas_orig_memset(s, c, n);
}
