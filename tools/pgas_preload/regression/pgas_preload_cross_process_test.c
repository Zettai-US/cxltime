#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

typedef void *(*memcpy_fn)(void *, const void *, size_t);

enum {
    TEST_BLOCK_SIZE = 4096,
    TEST_REMOTE_OFFSET = 0x4000,
};

static unsigned char expected_byte(size_t index)
{
    return (unsigned char)((index * 29U + 0x41U) & 0xffU);
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "write") != 0 &&
                      strcmp(argv[1], "read") != 0)) {
        fprintf(stderr, "Usage: %s <write|read>\n", argv[0]);
        return 2;
    }

    const char *base_env = getenv("PGAS_BASE_ADDR");
    const char *size_env = getenv("PGAS_SIZE");
    if (!base_env || !size_env) {
        fprintf(stderr, "PGAS_BASE_ADDR or PGAS_SIZE is missing\n");
        return 3;
    }

    uintptr_t base_addr = strtoull(base_env, NULL, 0);
    size_t region_size = strtoull(size_env, NULL, 0);
    if (region_size < TEST_REMOTE_OFFSET + TEST_BLOCK_SIZE) {
        fprintf(stderr, "PGAS_SIZE is too small: %zu\n", region_size);
        return 4;
    }

    unsigned char *region = mmap((void *)base_addr, region_size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS |
                                     MAP_FIXED_NOREPLACE,
                                 -1, 0);
    if (region == MAP_FAILED) {
        fprintf(stderr, "mmap(%p, %zu) failed: %s\n",
                (void *)base_addr, region_size, strerror(errno));
        return 5;
    }

    unsigned char *remote_shadow = region + TEST_REMOTE_OFFSET;
    unsigned char *expected = malloc(TEST_BLOCK_SIZE);
    unsigned char *actual = malloc(TEST_BLOCK_SIZE);
    if (!expected || !actual) {
        fprintf(stderr, "malloc failed\n");
        return 6;
    }

    for (size_t i = 0; i < TEST_BLOCK_SIZE; ++i) {
        expected[i] = expected_byte(i);
        actual[i] = 0;
    }

    volatile memcpy_fn call_memcpy = memcpy;

    if (strcmp(argv[1], "write") == 0) {
        call_memcpy(remote_shadow, expected, TEST_BLOCK_SIZE);
        printf("REMOTE_WRITE_DONE addr=%p size=%d first=0x%02x last=0x%02x\n",
               remote_shadow, TEST_BLOCK_SIZE,
               expected[0], expected[TEST_BLOCK_SIZE - 1]);
    } else {
        /* Poison only this process's anonymous local shadow.  Volatile scalar
         * stores avoid calling the preload memset hook and do not update OCEAN. */
        volatile unsigned char *poison = remote_shadow;
        for (size_t i = 0; i < TEST_BLOCK_SIZE; ++i) {
            poison[i] = 0xa5;
        }

        call_memcpy(actual, remote_shadow, TEST_BLOCK_SIZE);

        size_t first_bad = TEST_BLOCK_SIZE;
        for (size_t i = 0; i < TEST_BLOCK_SIZE; ++i) {
            if (actual[i] != expected[i]) {
                first_bad = i;
                break;
            }
        }

        if (first_bad != TEST_BLOCK_SIZE) {
            fprintf(stderr,
                    "REMOTE_READ_VERIFY_FAIL addr=%p index=%zu expected=0x%02x actual=0x%02x\n",
                    remote_shadow, first_bad,
                    expected[first_bad], actual[first_bad]);
            return 10;
        }

        printf("REMOTE_READ_VERIFY_PASS addr=%p size=%d first=0x%02x last=0x%02x\n",
               remote_shadow, TEST_BLOCK_SIZE,
               actual[0], actual[TEST_BLOCK_SIZE - 1]);
    }

    munmap(region, region_size);
    free(expected);
    free(actual);
    return 0;
}
