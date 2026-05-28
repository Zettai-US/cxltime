#
# Project settings
#

option(BPFTIME_BUILD_EXECUTABLE "Build the project as an executable, rather than a library." OFF)

#
# library options
#
option(BPFTIME_LLVM_JIT "Use LLVM as jit backend." ON)
option(BPFTIME_UBPF_JIT "Use uBPF as jit backend." ON)

#
# Compiler options
#

option(BPFTIME_WARNINGS_AS_ERRORS "Treat compiler warnings as errors." OFF)

#
#
# CUDA options
#

option(BPFTIME_CUDA_ROOT "Root for CUDA installation" "")
option(BPFTIME_ENABLE_CUDA_ATTACH "Whether to enable CUDA attach" OFF)

#
# Unit testing
#
# Currently supporting: GoogleTest, Catch2.

option(BPFTIME_ENABLE_UNIT_TESTING "Enable unit tests for the projects (from the `test` subfolder)." OFF)

option(BPFTIME_USE_CATCH2 "Use the Catch2 project for creating unit tests." OFF)

#
# Miscelanious options
#

# Generate compile_commands.json for clang based tools
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BPFTIME_VERBOSE_OUTPUT "Enable verbose output, allowing for a better understanding of each step taken." ON)

# Export all symbols when building a shared library
if(BUILD_SHARED_LIBS)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)
  set(CMAKE_CXX_VISIBILITY_PRESET hidden)
  set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
endif()

option(BPFTIME_ENABLE_LTO "Enable Interprocedural Optimization, aka Link Time Optimization (LTO)." OFF)
if(BPFTIME_ENABLE_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT result OUTPUT output)
  if(result)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
  else()
    message(SEND_ERROR "IPO is not supported: ${output}.")
  endif()
endif()

option(BPFTIME_ENABLE_CCACHE "Enable the usage of Ccache, in order to speed up rebuild times." OFF)
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif()

option(BPFTIME_ENABLE_ASAN "Enable Address Sanitize to detect memory error." OFF)
if(BPFTIME_ENABLE_ASAN)
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

option(BPFTIME_ENABLE_MPK "Enable Memory Protection Keys for the share memory." OFF)
if(BPFTIME_ENABLE_MPK)
    add_definitions(-DBPFTIME_ENABLE_MPK)
endif()

option(BPFTIME_ENABLE_IOURING_EXT "Enable iouring helpers extensions." OFF)
if(BPFTIME_ENABLE_IOURING_EXT)
    add_definitions(-DBPFTIME_ENABLE_IOURING_EXT)
endif()

# whether to enable eBPF verifier in userspace
option(ENABLE_EBPF_VERIFIER "Whether to enable ebpf verifier" OFF)

# whether to build with bpftime daemon
option(BUILD_BPFTIME_DAEMON "Whether to build the bpftime daemon" ON)

# whether to build with shared bpf_map
option(BPFTIME_BUILD_KERNEL_BPF "Whether to build with bpf share maps" ON)

# whether to build single static library
option(BPFTIME_BUILD_STATIC_LIB "Whether to build a single static library for different archive files" OFF)

# whether to build bpftime with libbpf and other linux headers
option(BPFTIME_BUILD_WITH_LIBBPF "Whether to build with libbpf and other linux headers" ON)

if(APPLE)
  set(BPFTIME_DEFAULT_BUILD_RUNTIME OFF)
  set(BPFTIME_DEFAULT_BUILD_ATTACH OFF)
else()
  set(BPFTIME_DEFAULT_BUILD_RUNTIME ON)
  set(BPFTIME_DEFAULT_BUILD_ATTACH ON)
endif()

# whether to build the bpftime runtime/agent libraries. The runtime currently
# contains Linux BPF headers and pthread spin locks, so keep it opt-in on macOS.
option(BPFTIME_BUILD_RUNTIME "Whether to build the bpftime runtime and agents" ${BPFTIME_DEFAULT_BUILD_RUNTIME})

# whether to build attach implementations.
option(BPFTIME_BUILD_ATTACH "Whether to build bpftime attach implementations" ${BPFTIME_DEFAULT_BUILD_ATTACH})

# whether to build bpftime CLI tools that depend on the runtime.
option(BPFTIME_BUILD_BPFTIME_TOOLS "Whether to build bpftime CLI/runtime tools" ${BPFTIME_DEFAULT_BUILD_RUNTIME})

# whether to build SlugAllocator LLVM basic-block instrumentation
option(BPFTIME_BUILD_SLUG_ALLOCATOR "Whether to build SlugAllocator LLVM instrumentation" ON)

# whether to build the legacy PGAS LD_PRELOAD helper
option(BPFTIME_BUILD_PGAS_PRELOAD "Whether to build the PGAS LD_PRELOAD helper" ON)

# whether to build the legacy PGAS Frida attach implementation.
option(BPFTIME_BUILD_PGAS_ATTACH "Whether to build the PGAS attach implementation" ON)

# whether to enable probe read check
option(ENABLE_PROBE_READ_CHECK "Whether to enable probe read check" ON)
# whether to enable probe write check
option(ENABLE_PROBE_WRITE_CHECK "Whether to enable probe write check" ON)
