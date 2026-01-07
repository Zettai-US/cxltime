cmake_minimum_required(VERSION 3.15)

# PGAS LD_PRELOAD library for memcached
# Include CXLMemSim client source directly
# Handle both standalone and subdirectory builds
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/libpgas/src/cxlmemsim_client.c")
    set(CXLMEMSIM_CLIENT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/libpgas/src/cxlmemsim_client.c)
else()
    set(CXLMEMSIM_CLIENT_SRC ${CMAKE_SOURCE_DIR}/src/libpgas/src/cxlmemsim_client.c)
endif()

add_library(pgas_preload SHARED
    pgas_preload.cpp
    ${CXLMEMSIM_CLIENT_SRC}
)

# Include directories
# Determine libpgas include path
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/libpgas/include")
    set(LIBPGAS_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/libpgas/include)
else()
    set(LIBPGAS_INCLUDE ${CMAKE_SOURCE_DIR}/src/libpgas/include)
endif()

target_include_directories(pgas_preload PRIVATE
    ${CMAKE_SOURCE_DIR}/attach/pgas_attach_impl/include
    ${CMAKE_SOURCE_DIR}/attach/base_attach_impl
    ${CMAKE_SOURCE_DIR}/attach/frida_uprobe_attach_impl/include
    ${SPDLOG_INCLUDE}
    ${FRIDA_GUM_INSTALL_DIR}
    # CXLMemSim client from libpgas
    ${LIBPGAS_INCLUDE}
)

# Link dependencies
target_link_libraries(pgas_preload
    bpftime_pgas_attach_impl
    ${FRIDA_GUM_INSTALL_DIR}/libfrida-gum.a
    spdlog
    pthread
    dl
    resolv
)

# Platform-specific settings
if(UNIX AND NOT APPLE)
    target_link_libraries(pgas_preload rt)
endif()

# Compiler flags
target_compile_options(pgas_preload PRIVATE
    -fPIC
    -Wall -Wextra
)

# Set library properties
set_target_properties(pgas_preload PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME pgas_preload
)

# Installation
install(TARGETS pgas_preload
    LIBRARY DESTINATION lib
)

message(STATUS "PGAS preload library configured")
