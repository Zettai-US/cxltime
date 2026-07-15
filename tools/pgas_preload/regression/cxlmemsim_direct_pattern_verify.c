#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "pgas/cxlmemsim_client.h"

enum { TEST_BLOCK_SIZE = 4096 };

static unsigned char expected_byte(size_t index)
{
    return (unsigned char)((index * 29U + 0x41U) & 0xffU);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <host> <port> <address>\n", argv[0]);
        return 2;
    }

    const char *host = argv[1];
    int port = atoi(argv[2]);
    errno = 0;
    uint64_t addr = strtoull(argv[3], NULL, 0);
    if (errno != 0 || port <= 0) {
        perror("invalid port or address");
        return 3;
    }

    unsigned char *actual = calloc(1, TEST_BLOCK_SIZE);
    if (!actual) {
        perror("calloc");
        return 4;
    }

    cxlmemsim_ctx_t ctx;
    if (cxlmemsim_init(&ctx, host, port) != 0) {
        fprintf(stderr, "DIRECT_VERIFY_INIT_FAIL host=%s port=%d\n", host, port);
        return 5;
    }
    if (cxlmemsim_connect(&ctx) != 0) {
        fprintf(stderr, "DIRECT_VERIFY_CONNECT_FAIL host=%s port=%d\n", host, port);
        cxlmemsim_finalize(&ctx);
        return 6;
    }

    int load_rc = cxlmemsim_remote_load(&ctx, addr, actual, TEST_BLOCK_SIZE);
    if (load_rc != 0) {
        fprintf(stderr,
                "DIRECT_VERIFY_LOAD_FAIL host=%s port=%d addr=0x%" PRIx64 " rc=%d\n",
                host, port, addr, load_rc);
        cxlmemsim_finalize(&ctx);
        return 7;
    }

    size_t first_bad = TEST_BLOCK_SIZE;
    for (size_t i = 0; i < TEST_BLOCK_SIZE; ++i) {
        if (actual[i] != expected_byte(i)) {
            first_bad = i;
            break;
        }
    }

    cxlmemsim_stats_t stats;
    cxlmemsim_get_stats(&ctx, &stats);
    printf("DIRECT_VERIFY_STATS reads=%" PRIu64 " bytes_read=%" PRIu64
           " writes=%" PRIu64 " bytes_written=%" PRIu64 "\n",
           stats.total_reads, stats.total_bytes_read,
           stats.total_writes, stats.total_bytes_written);

    if (first_bad != TEST_BLOCK_SIZE) {
        fprintf(stderr,
                "DIRECT_REMOTE_VERIFY_FAIL addr=0x%" PRIx64
                " index=%zu expected=0x%02x actual=0x%02x\n",
                addr, first_bad, expected_byte(first_bad), actual[first_bad]);
        cxlmemsim_finalize(&ctx);
        free(actual);
        return 10;
    }

    printf("DIRECT_REMOTE_VERIFY_PASS addr=0x%" PRIx64
           " size=%d first=0x%02x last=0x%02x\n",
           addr, TEST_BLOCK_SIZE, actual[0], actual[TEST_BLOCK_SIZE - 1]);

    cxlmemsim_finalize(&ctx);
    free(actual);
    return 0;
}
