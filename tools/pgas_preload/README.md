# PGAS LD_PRELOAD Library

This library provides PGAS (Partitioned Global Address Space) memory operation hooks using LD_PRELOAD. It also exposes an optional PGAS-aware remote pthread negotiation path for FAISS and other registered worker functions.

## Building

```bash
cmake -S lib/cxltime/tools/pgas_preload -B /tmp/pgas-preload-build
cmake --build /tmp/pgas-preload-build --target cxltime_pgas_preload
```

The library will be built at: `/tmp/pgas-preload-build/libpgas_preload.so`

## Usage

### Basic Usage

```bash
# Start memcached with PGAS hooks
LD_PRELOAD=/path/to/libpgas_preload.so memcached -m 1024 -p 11211
```

### With Configuration

```bash
# Configure via environment variables
export PGAS_NODE_ID=0          # This node's ID (0-based)
export PGAS_NUM_NODES=4        # Total number of nodes
export PGAS_BASE_ADDR=0x0      # Base address of PGAS region
export PGAS_SIZE=1073741824    # Size in bytes (1GB)
export PGAS_VERBOSE=1          # Enable verbose logging
export PGAS_STATS=1            # Enable statistics (default)

LD_PRELOAD=/path/to/libpgas_preload.so memcached -m 1024 -p 11211
```

### With Configuration File

Create a config file (e.g., `pgas.conf`):

```ini
node_id=0
num_nodes=4
base_addr=0x0
size=1073741824
verbose=true
```

Then use:

```bash
PGAS_CONFIG=/path/to/pgas.conf LD_PRELOAD=/path/to/libpgas_preload.so memcached -m 1024
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PGAS_NODE_ID` | Local node identifier | 0 |
| `PGAS_NUM_NODES` | Total number of nodes | 1 |
| `PGAS_BASE_ADDR` | Base address of PGAS memory region | 0 |
| `PGAS_SIZE` | Size of PGAS region in bytes | 1GB |
| `PGAS_VERBOSE` | Enable verbose output (1/0) | 0 |
| `PGAS_STATS` | Enable statistics output (1/0) | 1 |
| `PGAS_CONFIG` | Path to configuration file | (none) |

### Remote pthread / FAISS variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PGAS_REMOTE_THREADS` | Enable remote thread negotiation: `registered`, `auto`, or `faiss` | off |
| `PGAS_FAISS_PRELOAD` | Enable FAISS C API wrappers and FAISS symbol allowlist | off |
| `PGAS_REMOTE_THREAD_TARGET_NODE` | Node selected for remotable pthreads | next node |
| `PGAS_REMOTE_THREAD_HOSTS` | Comma-separated `node=host:port` entries | `127.0.0.1:49000+node` |
| `PGAS_REMOTE_THREAD_PORT_BASE` | Base listener port | 49000 |
| `PGAS_REMOTE_THREAD_PORT` | Explicit local listener port | base + local node |
| `PGAS_REMOTE_THREAD_STRICT` | Return failure instead of local fallback when remote create fails | 0 |
| `PGAS_REMOTE_THREAD_ALLOWLIST` | Comma-separated symbol substrings for auto registration | FAISS symbols when FAISS mode is on |

Remote thread creation is intentionally conservative. A thread is only remoted when its start routine is registered or matches the enabled allowlist, and its argument must point into the PGAS region unless the function was registered with `PGAS_REMOTE_THREAD_F_ALLOW_NONPGAS_ARG`.

```c
#include "pgas/pgas_remote_thread.h"

static void *faiss_worker(void *arg) {
    /* arg should describe PGAS-resident FAISS query/index/result buffers */
    return NULL;
}

pgas_faiss_register_thread("faiss_worker", faiss_worker,
                           PGAS_REMOTE_THREAD_ABI_VERSION, 0);
```

FAISS C API calls are wrapped without a compile-time libfaiss dependency:

```c
faiss_Index_search(...)
faiss_Index_add(...)
faiss_Index_train(...)
```

The wrappers forward to the real `RTLD_NEXT` symbols and increment remote-thread preload statistics.

### Two-host FAISS PGAS application

The repository includes an end-to-end two-process FAISS PGAS application test:

```bash
script/test_faiss_pgas_two_host.sh
```

The test starts a node-1 server process with the preload listener, starts a node-0 client, creates a remote FAISS shard-search pthread on node 1, joins the proxy thread on node 0, merges both shard top-k results, and validates them against an exact global search. If `libfaiss-dev` is installed, the app builds against `faiss::IndexFlatL2`; otherwise it uses an internal exact L2 fallback with the same shard-search ABI.

Important knobs:

| Variable | Description | Default |
|----------|-------------|---------|
| `PGAS_FAISS_TWO_HOST_BIN` | Output path for the compiled app | `/tmp/faiss_pgas_two_host_app` |
| `PGAS_FAISS_REGION_SIZE` | PGAS test region size | 64MB |
| `PGAS_FAISS_SHM_NAME` | Local two-process shared-memory backing name | `/pgas_faiss_two_host` |
| `PGAS_FAISS_LIBS` | Linker flags for real FAISS detection/build | `-lfaiss` |

## How It Works

1. **Library Loading**: When the library is loaded via LD_PRELOAD, the constructor function `pgas_preload_init()` is called automatically.

2. **Hook Installation**: The library interposes `memcpy`, `memmove`, `memset`, and optionally `pthread_create`, `pthread_join`, and `pthread_detach`.

3. **Address Routing**: Each memory operation is analyzed to determine which node owns the target address based on a simple hash-based partitioning scheme.

4. **Statistics Collection**: The library tracks:
   - Number of each operation type
   - Total bytes copied
   - Local vs remote access counts

5. **Cleanup**: When memcached exits, the destructor prints statistics and cleans up hooks.

## Statistics Output

When memcached exits (or on signal), you'll see output like:

```
=== PGAS Statistics ===
Node ID: 0 / 4
memcpy calls: 125000
memmove calls: 50
memset calls: 10000
Total bytes copied: 50000000
Local accesses: 31250
Remote accesses: 93750
Remote access ratio: 75.00%
========================
```

## Multi-Node Setup

For a 4-node memcached cluster:

**Node 0:**
```bash
PGAS_NODE_ID=0 PGAS_NUM_NODES=4 LD_PRELOAD=libpgas_preload.so memcached -p 11211
```

**Node 1:**
```bash
PGAS_NODE_ID=1 PGAS_NUM_NODES=4 LD_PRELOAD=libpgas_preload.so memcached -p 11212
```

**Node 2:**
```bash
PGAS_NODE_ID=2 PGAS_NUM_NODES=4 LD_PRELOAD=libpgas_preload.so memcached -p 11213
```

**Node 3:**
```bash
PGAS_NODE_ID=3 PGAS_NUM_NODES=4 LD_PRELOAD=libpgas_preload.so memcached -p 11214
```

## Programmatic API

The library exports C functions that can be called at runtime:

```c
// Get current statistics
void pgas_get_stats(uint64_t *memcpy_calls, uint64_t *memmove_calls,
                    uint64_t *memset_calls, uint64_t *bytes_copied,
                    uint64_t *local_accesses, uint64_t *remote_accesses);

// Reset statistics
void pgas_reset_stats();

// Print statistics to stderr
void pgas_print_stats();

// Check if PGAS is initialized
int pgas_is_initialized();

// Get node configuration
void pgas_get_config(uint16_t *node_id, uint16_t *num_nodes,
                     uint64_t *base_addr, uint64_t *size);
```

## Extending for Real CXL/RDMA

The current implementation routes addresses to nodes but performs local memory operations. To implement actual distributed memory:

1. Modify the override handlers in `pgas_attach_impl.cpp`:
   - `pgas_memcpy_override_handler()`
   - `pgas_memmove_override_handler()`
   - `pgas_memset_override_handler()`

2. Add network transport code when `ctx->is_remote` is true:
   - For CXL: Use CXL.mem load/store semantics
   - For RDMA: Use ibverbs for remote memory access

## Cross-Process OCEAN Regression

`regression/pgas_preload_cross_process_test.c` verifies that a reader gets
the bytes returned by CXLMemSim rather than its own anonymous PGAS shadow.
`regression/cxlmemsim_direct_pattern_verify.c` reads the same pattern through
the direct client API. On an allocated FX700 Slurm job, run:

```bash
PGAS_JOB_ID=<jobid> PGAS_CONFIG_OUT=<run-dir> \
PGAS_PRELOAD=<path-to-libpgas_preload.so> \
scripts/slurm_preload_cross_process_test.sh

PGAS_JOB_ID=<jobid> PGAS_CONFIG_OUT=<run-dir> \
scripts/slurm_direct_pattern_verify.sh
```

The first script requires `REMOTE_READ_VERIFY_PASS`; the second confirms the
OCEAN-side pattern with `DIRECT_REMOTE_VERIFY_PASS`.

## Troubleshooting

### Library not loading
```bash
# Check library dependencies
ldd /path/to/libpgas_preload.so

# Verify it loads
LD_DEBUG=libs LD_PRELOAD=/path/to/libpgas_preload.so /bin/true
```

### No hooks installed
- Ensure memcpy/memmove/memset symbols are found
- Check verbose output for errors

### Performance issues
- Disable verbose mode: `PGAS_VERBOSE=0`
- Disable statistics if not needed: `PGAS_STATS=0`
