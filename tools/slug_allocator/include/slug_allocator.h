#ifndef SLUG_ALLOCATOR_H
#define SLUG_ALLOCATOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum slug_access_kind {
    SLUG_ACCESS_LOAD = 0,
    SLUG_ACCESS_STORE = 1,
    SLUG_ACCESS_ATOMIC = 2,
    SLUG_ACCESS_MEMCPY_READ = 3,
    SLUG_ACCESS_MEMCPY_WRITE = 4,
    SLUG_ACCESS_MEMSET = 5,
};

void __slug_bb_enter(uint32_t function_id, uint32_t basic_block_id,
                     uint32_t load_count, uint32_t store_count,
                     const char *function_name);

void __slug_mem_access(const void *addr, uint64_t size, uint32_t kind,
                       uint32_t function_id, uint32_t basic_block_id);

void __slug_flush(void);

#ifdef __cplusplus
}
#endif

#endif
