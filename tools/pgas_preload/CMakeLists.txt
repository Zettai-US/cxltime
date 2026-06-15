cmake_minimum_required(VERSION 3.15)
project(cxltime_pgas_preload LANGUAGES C CXX)

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

add_library(cxltime_pgas_preload SHARED
    pgas_preload.cpp
    ${CXLMEMSIM_CLIENT_SRC}
)

target_include_directories(cxltime_pgas_preload PRIVATE
    ${LIBPGAS_INCLUDE}
)

target_link_libraries(cxltime_pgas_preload
    pthread
    dl
)

target_compile_options(cxltime_pgas_preload PRIVATE -fPIC)
set_target_properties(cxltime_pgas_preload PROPERTIES
    OUTPUT_NAME pgas_preload
    VERSION 1.0.0
    SOVERSION 1
)
