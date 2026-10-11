/* core1_arena.c -- dedicated two-ended arena for the core-1 hybrid sign
 * (single-ISA builds at ML-DSA level 87 only; CMake gates this file
 * behind PQF_SIGN_ARENA).
 *
 * Why (silicon, 2026-07-20): the full hybrid sign at level 87 peaks at
 * ~216 KiB of heap (host-measured: ~199 KiB big-side live + ~17 KiB
 * small), including one ~138 KiB contiguous allocation (ml_dsa_sign.c's
 * "one blob for the temp vectors"). The copy_to_ram image left ~210 KiB
 * of newlib heap -- the sign could not fit, malloc returned NULL, and
 * pico_malloc's default PICO_MALLOC_PANIC turned that into
 * panic("Out of memory") on core 1: a bkpt-with-no-debugger wedge on
 * the Arm build, and an ebreak into the trap handler (clean CTAP error
 * via core1_dead_loop's poisoned ST_ERROR reply) on the RISC-V build.
 * Two symptoms, one OOM.
 *
 * Fix, mirroring the mixed build's proven blob_alloc arena
 * (core1-riscv-blob/blob_alloc.{c,h}, silicon-validated 2026-07-17):
 *   - the 87 image runs from XIP (CMake defaults PQF_COPY_TO_RAM=OFF),
 *     freeing the ~204 KiB of SRAM the image used to occupy;
 *   - the sign gets this dedicated arena, so the 138 KiB contiguous
 *     allocation is fragmentation-proof (big allocs coalesce bottom-up,
 *     small ones bump top-down, reset before every sign);
 *   - the openssl-mini TUs are compiled with
 *     -Dmalloc=pqf_sign_malloc (etc.), and the dispatch below routes
 *     core 1 -> arena, core 0 -> newlib. The two cores no longer share
 *     an allocator, which also removes the core-0/core-1 malloc race
 *     (newlib here has no __malloc_lock wiring; only pico_malloc's
 *     wrap-layer mutex guarded it, and only for wrapped callers).
 *
 * Budget (Arm/87, XIP): SRAM 520 KiB - ~88 KiB .bss/.data - 16 KiB
 * core-1 stack - 240 KiB arena leaves ~170 KiB of newlib heap for
 * core 0 -- comfortably above the ML-DSA-87 keygen peak at registration.
 *
 * SIZING, measured. The original 240 KiB was chosen for a ~216 KiB peak
 * that the ML-DSA low-memory rework has since cut by a factor of five.
 * Measured on silicon 2026-08-17 on a Feitian RP2350, real ML-DSA-87
 * hybrid operations with -DPQF_XIP_STATS=ON reporting pqf_sign_arena_hw:
 *
 *     public-key derivation (MakeCredential)   13,536 B
 *     full hybrid sign      (GetAssertion)     42,712 B peak over 4 signs
 *
 * 96 KiB is 2.3x that peak. Validated end to end at level 87: four
 * consecutive register+authenticate round trips, 4,697-byte signatures,
 * zero OOM events, and a high-water that did not creep across repeats.
 * It frees 147,456 bytes of SRAM against the old reservation (.bss
 * 334,852 -> 187,396).
 *
 * If you change it, re-run the same check: build with -DPQF_XIP_STATS=ON,
 * do several level-87 GetAssertions, and watch pqf_sign_arena_hw against
 * the reservation. An undersized arena does NOT brick anything --
 * PICO_MALLOC_PANIC=0 is set for this build, so the allocation returns
 * NULL, the signature fails with a clean CTAP error, and
 * blob_alloc_oom() records the size that was wanted in
 * pqf_arena_oom_req / pqf_arena_oom_hw. That is the intended way to size
 * this: try it and read the forensics.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include "hardware/structs/sio.h"   /* cpuid -- which core is calling  */

#include "blob_alloc.h"
#include "core1_arena.h"

#ifndef PQF_SIGN_ARENA_BYTES
#define PQF_SIGN_ARENA_BYTES (96u * 1024u)
#endif

static uint8_t s_arena[PQF_SIGN_ARENA_BYTES] __attribute__((aligned(8)));

volatile uint32_t pqf_arena_oom_req;
volatile uint32_t pqf_arena_oom_hw;
volatile uint32_t pqf_heap_oom_req;
volatile uint32_t pqf_sign_arena_hw;

void core1_arena_init(void)
{
    blob_heap_init(s_arena, s_arena + sizeof s_arena);
}

void core1_arena_reset(void)
{
    blob_heap_reset();
}

void core1_arena_note_hw(void)
{
    if ((uint32_t)blob_heap_hw() > pqf_sign_arena_hw)
        pqf_sign_arena_hw = (uint32_t)blob_heap_hw();
}

/* blob_alloc.h embedder hook: first-OOM forensics. hw is stamped before
 * req so main.c (which polls req) never reads a torn pair. */
void blob_alloc_oom(size_t req)
{
    if (pqf_arena_oom_req != 0)
        return;
    pqf_arena_oom_hw  = (uint32_t)blob_heap_hw();
    pqf_arena_oom_req = (uint32_t)(req ? req : 1);
}

volatile int pqf_sign_arena_force;

/* Route to the arena when running on core 1, or when the single-core
 * signer says an op is in flight on core 0 (pqf_sign_arena_force). */
static inline int on_core1(void)
{
    return (sio_hw->cpuid & 1u) != 0 || pqf_sign_arena_force != 0;
}

static inline int arena_owns(const void *p)
{
    return (const uint8_t *)p >= s_arena
        && (const uint8_t *)p <  s_arena + sizeof s_arena;
}

/* Allocation routes by CORE (only core 1 runs inside a sign; core 0's
 * crypto -- ML-DSA keygen at registration, PIN-protocol ECDH -- runs on
 * newlib as before, and the two never overlap: core 0 blocks in
 * core1_hybrid_sign() while core 1 signs). free/realloc route by
 * POINTER, which is correct regardless of the calling core. */
void *pqf_sign_malloc(size_t n)
{
    if (on_core1())
        return blob_malloc(n);
    void *p = malloc(n);
    if (p == NULL && pqf_heap_oom_req == 0)
        pqf_heap_oom_req = (uint32_t)(n ? n : 1);
    return p;
}

void pqf_sign_free(void *p)
{
    if (p == NULL)
        return;
    if (arena_owns(p)) {
        blob_free(p);
        return;
    }
    free(p);
}

void *pqf_sign_calloc(size_t nmemb, size_t size)
{
    if (on_core1())
        return blob_calloc(nmemb, size);
    void *p = calloc(nmemb, size);
    if (p == NULL && pqf_heap_oom_req == 0 && nmemb != 0 && size != 0)
        pqf_heap_oom_req = (uint32_t)(nmemb * size);
    return p;
}

void *pqf_sign_realloc(void *p, size_t n)
{
    if (p == NULL)
        return pqf_sign_malloc(n);
    if (arena_owns(p))
        return blob_realloc(p, n);
    void *q = realloc(p, n);
    if (q == NULL && n != 0 && pqf_heap_oom_req == 0)
        pqf_heap_oom_req = (uint32_t)n;
    return q;
}
