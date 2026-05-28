cmake_minimum_required(VERSION 3.16)

include(GNUInstallDirs)

find_package(LLVM CONFIG QUIET)

if(NOT LLVM_FOUND)
    message(WARNING "LLVM package not found; skipping SlugAllocator LLVM pass")
    return()
endif()

message(STATUS "Building SlugAllocator with LLVM ${LLVM_PACKAGE_VERSION}")

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})

add_llvm_pass_plugin(SlugAllocatorPass
    SlugAllocatorPass.cpp
    PARTIAL_SOURCES_INTENDED
)

target_include_directories(SlugAllocatorPass PRIVATE
    ${LLVM_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(SlugAllocatorPass PRIVATE ${LLVM_DEFINITIONS_LIST})
target_compile_features(SlugAllocatorPass PRIVATE cxx_std_17)

if(NOT LLVM_ENABLE_RTTI)
    target_compile_options(SlugAllocatorPass PRIVATE -fno-rtti)
endif()

add_library(slug_allocator_runtime SHARED
    slug_runtime.cpp
)

target_include_directories(slug_allocator_runtime PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(slug_allocator_runtime PUBLIC cxx_std_17)
target_compile_options(slug_allocator_runtime PRIVATE -Wall -Wextra)

if(UNIX)
    target_link_libraries(slug_allocator_runtime PRIVATE pthread)
endif()

set_target_properties(slug_allocator_runtime PROPERTIES
    OUTPUT_NAME slug_allocator_runtime
    VERSION 0.1.0
    SOVERSION 0
)

install(TARGETS SlugAllocatorPass slug_allocator_runtime
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES include/slug_allocator.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
