# SlugAllocator

SlugAllocator is a compiler instrumentation route for CXLMemSim. It uses an
LLVM pass to mark every basic-block entry and to report each IR memory
operation (`load`, `store`, atomics, `memcpy`, `memmove`, and `memset`) to a
small runtime library.

This is intentionally different from the existing `pgas_preload` and
Frida/Stalker code:

- `pgas_preload` sees library calls such as `memcpy`.
- Frida/Stalker sees decoded machine instructions at runtime.
- SlugAllocator sees compiler IR, so it is portable to macOS and does not need
  PEBS, LBR, or privileged PMU sampling.

## Build

```sh
cmake -S . -B build-slug \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DLLVM_DIR="$(brew --prefix llvm@21)/lib/cmake/llvm" \
  -DBPFTIME_BUILD_WITH_LIBBPF=OFF \
  -DBPFTIME_BUILD_KERNEL_BPF=OFF \
  -DBUILD_BPFTIME_DAEMON=OFF \
  -DBPFTIME_LLVM_JIT=OFF
cmake --build build-slug --target SlugAllocatorPass slug_allocator_runtime
```

## Use With Clang

```sh
LLVM_ROOT="$(brew --prefix llvm@21)"
PASS="$PWD/build-slug/tools/slug_allocator/SlugAllocatorPass.dylib"
RT_DIR="$PWD/build-slug/tools/slug_allocator"

"$LLVM_ROOT/bin/clang" -O1 -g \
  -fpass-plugin="$PASS" \
  app.c \
  -L"$RT_DIR" -lslug_allocator_runtime \
  -Wl,-rpath,"$RT_DIR" \
  -o app.slug

SLUG_TRACE=/tmp/slug.csv SLUG_VERBOSE=1 ./app.slug
```

The pass can also be used with `opt`:

```sh
"$LLVM_ROOT/bin/opt" -load-pass-plugin "$PASS" -passes=slug-allocator \
  input.ll -S -o output.ll
```

## Runtime Environment

| Variable | Meaning |
| --- | --- |
| `SLUG_TRACE=/path/file.csv` | Write CSV memory-access events. |
| `SLUG_VERBOSE=1` | Print startup information. |
| `SLUG_STATS=0` | Disable process-exit statistics. |
| `SLUG_REGION_BASE=0x...` | Start of the instrumented CXL/PGAS region. Falls back to `PGAS_BASE_ADDR`. |
| `SLUG_REGION_SIZE=...` | Size of the instrumented region. Falls back to `PGAS_SIZE`. |
| `SLUG_TRACE_ALL=0` | Only trace addresses inside the configured region. |
| `SLUG_CXL_HOST=127.0.0.1` | CXLMemSim TCP server host. |
| `SLUG_CXL_PORT=9999` | Enable direct CXLMemSim TCP reporting. Falls back to `CXL_MEMSIM_PORT`. |
| `SLUG_CXL_ADDR_BASE=0` | Translate instrumented addresses to CXLMemSim addresses by adding this base after subtracting `SLUG_REGION_BASE`. |
| `SLUG_CXL_SEND_WRITES=0` | Disable copying write bytes into CXLMemSim write requests. On by default. |

Without `SLUG_CXL_PORT`, SlugAllocator only records trace and statistics. With
`SLUG_CXL_PORT`, the runtime sends cacheline-split read/write notifications to
the CXLMemSim TCP server protocol used by `cxlmemsim_server`.

## Notes

LLVM IR does not preserve every machine `mov`. SlugAllocator tracks memory
traffic that survives into IR: loads, stores, atomics, and memory intrinsics.
Register-to-register moves are intentionally ignored.
