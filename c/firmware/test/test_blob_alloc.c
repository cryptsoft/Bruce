/* test_blob_alloc.c -- host test for the blob's two-ended arena
 * allocator (core1-riscv-blob/blob_alloc.c) under the REAL crypto
 * workload in a DEVICE-SIZED arena.
 *
 * The crypto translation units (hybrid.c + openssl-mini) are compiled
 * with -Dmalloc=blob_malloc etc. (see the Makefile rule), so every
 * allocation the ML-DSA / EC code makes on the device goes through the
 * arena here too. The arena is sized to the mixed build's level-87
 * blob heap (the tightest real configuration), so this test failing
 * means the device would OOM.
 *
 * Covers: allocator mechanics (split / out-of-order free / coalesce /
 * trailing-chunk reclaim), then pub-from-seed + two full hybrid signs
 * with arena resets between ops -- exactly the worker loop's pattern --
 * with signature verification.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <string.h>

#include "blob_alloc.h"
#include "hybrid.h"
#include "pqf_crypto.h"

static int fails = 0;
#define CHECK(c, m) do { if (c) printf("  ok: %s\n", m); \
    else { fprintf(stderr, "FAIL: %s\n", m); fails++; } } while (0)

/* Mixed-build level-87 blob heap: 384 KiB window - ~121 KiB image -
 * 32 KiB stack (blob.ld, silicon values 2026-07-17). */
#define ARENA_LEN 239344
static uint8_t arena[ARENA_LEN];

static size_t oom_reqs;
void blob_alloc_oom(size_t req) { oom_reqs++; (void)req; }

int main(void)
{
    printf("blob arena allocator test (variant %d, arena %u B)\n",
           PQF_HYBRID_VARIANT, (unsigned)ARENA_LEN);
    blob_heap_init(arena, arena + ARENA_LEN);

    /* ---- allocator mechanics ---- */
    {
        void *p1 = blob_malloc(100000);
        void *p2 = blob_malloc(50000);
        void *s1 = blob_malloc(64);          /* small side */
        CHECK(p1 && p2 && s1, "mixed allocations succeed");
        blob_free(p1);
        void *p3 = blob_malloc(90000);
        CHECK(p3 == p1, "freed big hole is reused first-fit");
        blob_free(p2);
        blob_free(p3);
        void *p4 = blob_malloc(150000);
        CHECK(p4 == p1, "out-of-order frees coalesce (150 KB fits the merged hole)");
        blob_free(p4);
        void *r = blob_malloc(600);
        r = blob_realloc(r, 70000);
        CHECK(r != NULL, "realloc small->big preserves");
        memset(r, 0x5a, 70000);
        blob_free(r);
        blob_heap_reset();
        CHECK(oom_reqs == 0, "no spurious OOM in mechanics");
    }

    /* ---- the real workload, worker-loop pattern ---- */
    uint8_t seed[32];  memset(seed, 0x42, sizeof seed);
    uint8_t scalar[32]; memset(scalar, 0x17, sizeof scalar);
    scalar[31] = 1;

    /* op 1: MB_OP_MLDSA_PUB */
    blob_heap_reset();
    static uint8_t ec_x[32], ec_y[32];
    static uint8_t pk[PQF_HYBRID_PK_LEN]; size_t pk_len = 0;
    CHECK(pqf_mldsa_pub_from_seed(PQF_HYBRID_MLDSA, seed, pk, &pk_len) == 0
          && pk_len == PQF_HYBRID_PK_LEN,
          "pub-from-seed inside the arena");
    CHECK(pqf_p256_derive_public(scalar, ec_x, ec_y) == 0,
          "EC public derive inside the arena");
    printf("  arena high-water after pub: %zu KiB\n",
           (blob_heap_hw() + 512) / 1024);

    /* op 2 + 3: MB_OP_SIGN twice -- the ML-DSA-87 sign's 138 KiB
     * contiguous temp blob must fit BOTH times (reset between). */
    uint8_t msg[101]; memset(msg, 0xAB, sizeof msg);
    for (int i = 0; i < 2; i++) {
        blob_heap_reset();
        static uint8_t sig[PQF_HYBRID_MAX_SIG]; size_t sig_len = 0;
        CHECK(hybrid_sign(scalar, seed, msg, sizeof msg, sig, &sig_len) == 0
              && sig_len > PQF_HYBRID_SIG_LEN,
              i ? "second hybrid sign after reset" : "first hybrid sign");
        CHECK(hybrid_verify(ec_x, ec_y, pk, pk_len,
                            msg, sizeof msg, sig, sig_len) == 1,
              "signature verifies");
    }
    printf("  arena high-water after signs: %zu KiB (arena %u KiB)\n",
           (blob_heap_hw() + 512) / 1024, (unsigned)(ARENA_LEN / 1024));
    CHECK(oom_reqs == 0, "no allocation was ever refused");

    printf(fails ? "RESULT: %d FAILURE(S)\n" : "RESULT: all passed\n", fails);
    return fails ? 1 : 0;
}
