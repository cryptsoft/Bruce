/* blob_alloc.h -- the core-1 blob's two-ended arena allocator.
 *
 * Replaces newlib malloc on the blob. Motivation (silicon, 2026-07-17):
 * ML-DSA-87's sign then made a SINGLE contiguous 138,240-byte
 * allocation (ml_dsa_sign.c's "one blob for the temporary vectors":
 * 134 polys + w1) after the seed->key derivation had already churned the
 * heap. The derivation's transient polynomial blobs free back, but small
 * long-lived chunks allocated between them (EVP/SHAKE contexts, the
 * key struct) pin the holes, so newlib-over-_sbrk found no contiguous
 * region: the sign failed at a 116,464-byte high-water in BOTH a
 * 186 KiB and a 233 KiB heap window. Fragmentation, not capacity.
 *
 * Scheme: one arena, two ends.
 *   - big chunks (>= 512 B: polynomial blobs, key encodings) grow
 *     bottom-up with an address-sorted free list and immediate
 *     coalescing -- transient poly blobs merge back into one hole;
 *   - small chunks (< 512 B: BN limbs, EVP/SHAKE contexts) bump
 *     top-down and are never reused within an op, pinning nothing on
 *     the big side;
 *   - OOM only when the two ends would cross;
 *   - the embedder resets the arena between self-contained ops.
 *
 * Costs, re-measured 2026-08-04 after the low-memory ML-DSA rewrite
 * (openssl-mini/ML-DSA-LOWMEM.md), through this allocator on the host:
 * an instrumented copy with the arena AND the counters reset
 * immediately before each hybrid call, 15,000 ops per level, one
 * distinct ML-DSA seed each, in a 239,344-byte arena. Bytes include the
 * per-chunk headers, at host sizes (caveat below). "big" and "small"
 * are each end's OWN high-water extent over the op; "peak" is the
 * largest SIMULTANEOUS total, which is what an OOM trips over, so
 * peak <= big + small. A row's peak is NOT its big column:
 *
 *   level  op                big     small      peak   largest request
 *      44  hybrid_public  25,648    10,272    35,824    12,288
 *      44  hybrid_sign    30,880    25,528    56,408    28,416
 *      65  hybrid_public  35,888    10,272    46,064    17,408
 *      65  hybrid_sign    49,760    29,176    78,936    45,824
 *      87  hybrid_public  48,176    10,272    58,352    23,552
 *      87  hybrid_sign    25,280    32,424    57,704    20,480
 *
 * (hybrid_verify, which only the host test runs, peaks at 31,448 /
 * 36,288 / 41,368.) Message length moves nothing: hybrid.c stages
 * LABEL || msg [|| der] in .bss, so a 3,000-byte MakeCredential message
 * measures the same as a 101-byte assertion. The 87 sign row postdates
 * keygen_sign_only() (ml_dsa_key.c) bit-packing s1/s2/t0 as it samples
 * them, which dropped that row from 48,176 big / 23,552 largest.
 *
 * The big side is entirely ML-DSA and deterministic -- 5 allocations for
 * a derivation, 4 for a sign, 3 for a verify, its extent at high-water
 * equal to its live bytes at every level, i.e. no holes -- and the whole
 * column reconstructs from the source, in polys of 1,024 B plus one
 * header per allocation. Key derivation holds t1 (k), the s1/s2/t0
 * vector blob (l + 2k) and its own transient (k + l + 1): 4k + 2l + 1
 * polys and three headers, 25,648 / 35,888 / 48,176 -- the hybrid_public
 * rows' BIG column, not their peak column of 35,824 / 46,064 / 58,352.
 * A sign holds different things: the packed private key (sk_len - 128 =
 * 2,432 / 3,904 / 4,768) and ml_dsa_sign.c's temp blob,
 * w1 + (3 + k + l + polys_A) polys = 28,416 / 45,824 / 20,480, where
 * polys_A is 1 once that file streams A (k*l >= 32, so level 87 only,
 * which is why 87 asks for LESS than 65). Those two and their headers
 * are the sign rows' big column, 30,880 / 49,760 / 25,280 -- so at 87 it
 * is registration, not signing, that sets the big side.
 *
 * (Host vs device: the above carries the host's 16-byte big_hdr_t,
 * 8 bytes on the 32-bit target, so the device's big extent is 8 B per
 * live chunk lower. The small side does not transfer 1:1 either --
 * openssl-mini/include/crypto/bn_conf.h picks a 64-bit BN_ULONG on an
 * LP64 host and a 32-bit one on the target, so limb arrays round to
 * 4-byte instead of 8-byte words at equal bit length, sizeof(BIGNUM)
 * goes 24 -> 20 and the 16-BIGNUM BN_CTX pool block 400 -> 328. All of
 * it moves one way: the device lands at or below these figures, never
 * above. None of this has been measured on the target.)
 *
 * The ECDSA half never touches the big side: its largest request is
 * 400 B, that pool block. All the variance is on the small side, in two
 * terms, both per CALL:
 *   - the ECDSA nonce k comes from RAND_bytes (arc4random on the host,
 *     the RP2350 TRNG on the device), redrawn every signature: 3,000
 *     signs with the scalar AND the hash held fixed still spread
 *     14,688..15,176 B, a 488 B range, and that is the ECDSA half's
 *     whole contribution;
 *   - the ML-DSA rejection-iteration count, deterministic in (seed,
 *     message) -- 3,000 signs of one message under one seed measured an
 *     identical 2,504 / 2,936 / 4,280 B -- but the ML-DSA half signs
 *     LABEL || msg || ecdsaDER, and that DER carries the per-call
 *     nonce, so the count is redrawn per call here too: 3,000 hybrid
 *     signs with scalar, seed and message ALL fixed spread
 *     16,952..24,656 (44), 17,336..27,904 (65), 17,816..28,232 (87).
 * The rejection count dominates by ~20x and leaves no per-seed-only
 * term: varying the seed too widened level 87 from a 10,416 to a
 * 13,664 B spread. Its shape is the iteration count's geometric tail --
 * at 87, 17,816 min / 18,784 median / 23,600 p99 / 31,480 worst of
 * 3,000 seeded signs, 32,424 worst of 15,000 -- so read the small and
 * peak columns as sample maxima, not bounds: a second 15,000-op run
 * reproduced every big and largest-request cell exactly, but put level
 * 65's sign peak at 79,240.
 *
 * BLOB_SMALL_MAX = 512 has slack both ways: the largest small-side
 * request measures 432 B and the smallest big-side one 1,312 B
 * (ML-DSA-44's encoded public key), so any threshold in 440..1,312
 * classifies the whole workload identically.
 *
 * The arena earns its place on SHAPE, not size. The 138,240-byte
 * request is gone (worst is now 45,824, at level 65), but the pattern
 * that failed is unchanged: the key blob and the encoded pk/sk stay
 * live while transient poly blobs come and go, small chunks allocated
 * between them. Two ends make that unrepresentable rather than merely
 * unlikely, and reset-per-op keeps teardown O(1). Against the table the
 * sizes are generous, the small side's tail being what the headroom is
 * for: blob.ld's floor (ASSERT >= 0x2B000 = 176,128 B) is 2.2x level
 * 65's 78,936 B, the arena the blob actually links
 * (__heap_end - __heap_start = 240,288 B in this tree) 3.0x it, and
 * core1_arena.c's PQF_SIGN_ARENA_BYTES = 245,760 B is 4.3x the 57,704 B
 * at level 87.
 *
 * Exercised on the host by test/test_blob_alloc.c against the real
 * openssl-mini workload in a device-sized arena, whose ARENA_LEN of
 * 239,344 is not linker-derived but a 2026-07-17 snapshot of one mixed
 * build's 384 KiB window less a ~121 KiB image and a 32 KiB stack. Its
 * mechanics phase also sets a ~147 KiB high-water before any crypto
 * runs, and blob_heap_hw() is cumulative since init, so the figure that
 * test prints is NOT a per-op peak -- the table above needed a harness
 * resetting both the arena and its counters before each call.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQF_BLOB_ALLOC_H
#define PQF_BLOB_ALLOC_H

#include <stddef.h>

/* Set the arena bounds and reset. Call once before first use. */
void blob_heap_init(void *lo, void *hi);

/* Reset the arena (frees everything at once). The embedder calls this
 * between ops; every allocation made before the reset is dead. */
void blob_heap_reset(void);

/* High-water mark (bytes, both ends combined) since init -- cumulative,
 * NOT per-op: only blob_heap_init resets it. */
size_t blob_heap_hw(void);

/* malloc family. The blob maps newlib's malloc/free/calloc/realloc
 * onto these; the host test calls them directly. */
void *blob_malloc(size_t n);
void  blob_free(void *p);
void *blob_calloc(size_t nmemb, size_t size);
void *blob_realloc(void *p, size_t n);

/* Provided BY THE EMBEDDER: called on allocation failure with the
 * rejected request size (diagnostics; return normally). */
extern void blob_alloc_oom(size_t req);

#endif /* PQF_BLOB_ALLOC_H */
