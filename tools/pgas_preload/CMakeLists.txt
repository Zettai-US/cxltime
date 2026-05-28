cmake_minimum_required(VERSION 3.15)
cmake_minimum_required(VERSION 3.15)

# PGAS LD_PRELOAD library for memcached
# Include CXLMemSim client source directly
# Handle both standalone and subdirectory builds
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/libpgas/src/cxlmemsim_client.c")
    set(CXLMEMSIM_CLIENT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/libpgas/src/cxlmemsim_client.c)
else()
    set(CXLMEMSIM_CLIENT_SRC ${CMAKE_SOURCE_DIR}/src/libpgas/src/cxlmemsim_client.c)
endif()

# Include directories
# Determine libpgas include path
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/libpgas/include")
    set(LIBPGAS_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/libpgas/include)
else()
    set(LIBPGAS_INCLUDE ${CMAKE_SOURCE_DIR}/src/libpgas/include)
endif()

