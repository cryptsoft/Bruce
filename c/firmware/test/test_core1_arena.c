/* test_core1_arena.c -- host test of the core-1 sign arena dispatcher.
 *
 * core1_arena.c is small and does one thing: route malloc/free/calloc/
 * realloc to one of two allocators. Core 1 (inside a hybrid sign) gets
 * the dedicated arena; core 0 gets newlib. It exists because the two
 * cores sharing an allocator produced both an out-of-memory wedge at
 * ML-DSA-87 and a core-0/core-1 malloc race, and it has a history of
 * biting.
 *
 * The rule that makes it safe is subtle enough to be worth a test:
 * *allocation* routes by CORE, but *free and realloc route by POINTER*,
 * because a block can be allocated on one core and released on the
 * other. Getting that backwards hands an arena pointer to newlib's free
 * or a newlib pointer to the arena's -- heap corruption either way, on
 * whichever core happens to lose.
 *
 * blob_alloc.c itself is covered by test_blob_alloc.c; this is the
 * dispatcher above it.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "hardware/structs/sio.h"
#include "blob_alloc.h"
#include "core1_arena.h"

pqf_host_sio_t pqf_host_sio;

/* Forensics counters the arena stamps; declared in the firmware. */
extern volatile uint32_t pqf_arena_oom_req;
extern volatile uint32_t pqf_arena_oom_hw;
extern volatile uint32_t pqf_sign_arena_hw;
extern volatile uint32_t pqf_heap_oom_req;

static int failures, checks;
#define CHECK(cond, ...) do {                                       \
        checks++;                                                   \
        if (!(cond)) {                                              \
            failures++;                                             \
            printf("  [FAIL] " __VA_ARGS__);                        \
            printf("\n         at %s:%d\n", __FILE__, __LINE__);    \
        }                                                           \
    } while (0)

static void as_core0(void) { pqf_host_sio.cpuid = 0; }
static void as_core1(void) { pqf_host_sio.cpuid = 1; }

static void fresh(void)
{
    as_core0();
    core1_arena_init();
    core1_arena_reset();
    pqf_arena_oom_req = 0;
    pqf_arena_oom_hw = 0;
    pqf_sign_arena_hw = 0;
    pqf_heap_oom_req = 0;
}

/* Is this pointer inside the arena? Inferred from the allocator rather
 * than from the firmware's private range check, so the two are not the
 * same code agreeing with itself: anything blob_alloc hands out on
 * core 1 is by definition arena memory. */
static const uint8_t *arena_lo, *arena_hi;
static void learn_arena_bounds(void)
{
    as_core1();
    core1_arena_reset();
    uint8_t *a = pqf_sign_malloc(16);
    uint8_t *b = pqf_sign_malloc(32 * 1024);
    arena_lo = a < b ? a : b;
    arena_hi = (a < b ? b : a) + 32 * 1024;
    core1_arena_reset();
    as_core0();
}
static int looks_like_arena(const void *p)
{
    return (const uint8_t *)p >= arena_lo - 65536
        && (const uint8_t *)p <= arena_hi + 65536;
}

/* ---- allocation routes by core ---------------------------------- */

static void t_routing(void)
{
    printf("--- allocation routes by core ---\n");
    fresh();

    as_core1();
    void *from_core1 = pqf_sign_malloc(256);
    CHECK(from_core1 != NULL, "core 1 got nothing back");
    CHECK(looks_like_arena(from_core1),
          "core 1's allocation did not come from the arena");

    as_core0();
    void *from_core0 = pqf_sign_malloc(256);
    CHECK(from_core0 != NULL, "core 0 got nothing back");
    CHECK(!looks_like_arena(from_core0),
          "core 0's allocation came from the arena -- the two cores are "
          "sharing again, which is the race this file exists to remove");

    free(from_core0);
    as_core1();
    core1_arena_reset();
}

static void t_calloc_zeroes(void)
{
    printf("--- calloc, both sides ---\n");
    fresh();

    /* Both allocators must zero. ML-DSA's temp vectors are calloc'd and
     * a non-zero block would be signed over. */
    as_core1();
    unsigned char *a = pqf_sign_calloc(300, 1);
    CHECK(a != NULL, "core 1 calloc returned nothing");
    int nonzero = 0;
    for (size_t i = 0; a && i < 300; i++) if (a[i]) nonzero = 1;
    CHECK(!nonzero, "core 1 calloc returned memory that was not zeroed");

    as_core0();
    unsigned char *b = pqf_sign_calloc(300, 1);
    CHECK(b != NULL, "core 0 calloc returned nothing");
    nonzero = 0;
    for (size_t i = 0; b && i < 300; i++) if (b[i]) nonzero = 1;
    CHECK(!nonzero, "core 0 calloc returned memory that was not zeroed");
    free(b);

    as_core1();
    core1_arena_reset();
}

/* ---- free and realloc route by pointer --------------------------- */

static void t_free_routes_by_pointer(void)
{
    printf("--- free routes by pointer, not by core ---\n");
    fresh();

    /* The case the comment in core1_arena.c is about. Allocate on core
     * 1, release from core 0. If free routed by the *calling* core this
     * would hand an arena pointer to newlib's free -- corruption, and
     * the kind that surfaces somewhere else entirely. */
    as_core1();
    void *p = pqf_sign_malloc(1024);
    CHECK(p != NULL, "setup: core 1 allocation");
    as_core0();
    pqf_sign_free(p);           /* must not reach newlib's free */
    CHECK(1, "freeing an arena pointer from core 0 did not crash");

    /* And the mirror: a newlib pointer released while core 1 is the
     * caller must go back to newlib, not the arena. */
    as_core0();
    void *q = pqf_sign_malloc(1024);
    CHECK(q != NULL, "setup: core 0 allocation");
    as_core1();
    pqf_sign_free(q);
    CHECK(1, "freeing a newlib pointer from core 1 did not crash");

    core1_arena_reset();
    as_core0();
}

static void t_free_null_is_safe(void)
{
    printf("--- free(NULL) ---\n");
    fresh();
    as_core1();
    pqf_sign_free(NULL);
    as_core0();
    pqf_sign_free(NULL);
    CHECK(1, "free(NULL) is a no-op on both cores");
    core1_arena_reset();
}

static void t_realloc_routes_by_pointer(void)
{
    printf("--- realloc routes by pointer ---\n");
    fresh();

    as_core1();
    unsigned char *p = pqf_sign_malloc(64);
    CHECK(p != NULL, "setup: core 1 allocation");
    for (int i = 0; i < 64; i++) p[i] = (unsigned char)(i + 1);

    /* Grow it from core 0. The block is the arena's, so realloc must
     * stay in the arena and the contents must survive. */
    as_core0();
    unsigned char *g = pqf_sign_realloc(p, 512);
    CHECK(g != NULL, "growing an arena block from core 0 failed");
    if (g) {
        int intact = 1;
        for (int i = 0; i < 64; i++) if (g[i] != (unsigned char)(i + 1)) intact = 0;
        CHECK(intact, "growing an arena block lost its contents");
        CHECK(looks_like_arena(g), "an arena block was reallocated off the arena");
    }

    /* A newlib block grown while core 1 is the caller stays on newlib. */
    as_core0();
    unsigned char *h = pqf_sign_malloc(64);
    for (int i = 0; i < 64; i++) h[i] = (unsigned char)(0xF0 - i);
    as_core1();
    unsigned char *h2 = pqf_sign_realloc(h, 512);
    CHECK(h2 != NULL, "growing a newlib block from core 1 failed");
    if (h2) {
        int intact = 1;
        for (int i = 0; i < 64; i++) if (h2[i] != (unsigned char)(0xF0 - i)) intact = 0;
        CHECK(intact, "growing a newlib block lost its contents");
        CHECK(!looks_like_arena(h2), "a newlib block was reallocated into the arena");
        free(h2);
    }

    as_core1();
    core1_arena_reset();
    as_core0();
}

static void t_realloc_null_is_malloc(void)
{
    printf("--- realloc(NULL, n) ---\n");
    fresh();
    as_core1();
    void *p = pqf_sign_realloc(NULL, 128);
    CHECK(p != NULL, "realloc(NULL) on core 1 returned nothing");
    CHECK(looks_like_arena(p), "realloc(NULL) on core 1 did not use the arena");
    core1_arena_reset();

    as_core0();
    void *q = pqf_sign_realloc(NULL, 128);
    CHECK(q != NULL, "realloc(NULL) on core 0 returned nothing");
    CHECK(!looks_like_arena(q), "realloc(NULL) on core 0 used the arena");
    free(q);
}

/* ---- capacity, reset and forensics -------------------------------- */

static void t_reset_reclaims(void)
{
    printf("--- reset reclaims the whole arena ---\n");
    fresh();
    as_core1();

    /* The arena is reset before every sign rather than freed
     * incrementally, so a reset that did not reclaim everything would
     * make the second signature of a session fail while the first
     * worked -- an intermittent that would be miserable to chase. */
    size_t got_first = 0;
    for (;;) {
        void *p = pqf_sign_malloc(4096);
        if (p == NULL) break;
        got_first += 4096;
        if (got_first > 4u * 1024 * 1024) break;   /* safety net */
    }
    CHECK(got_first > 0, "the arena handed out nothing at all");

    core1_arena_reset();
    size_t got_second = 0;
    for (;;) {
        void *p = pqf_sign_malloc(4096);
        if (p == NULL) break;
        got_second += 4096;
        if (got_second > 4u * 1024 * 1024) break;
    }
    CHECK(got_second == got_first,
          "after a reset the arena handed out %zu bytes, not the %zu it did "
          "when empty", got_second, got_first);
    core1_arena_reset();
    as_core0();
}

static void t_oom_is_reported_not_fatal(void)
{
    printf("--- exhaustion ---\n");
    fresh();
    as_core1();

    /* One allocation larger than the arena. It must fail cleanly and be
     * recorded: on silicon this is the difference between a CTAP error
     * and panic("Out of memory") on a core with no debugger attached. */
    void *huge = pqf_sign_malloc(64u * 1024 * 1024);
    CHECK(huge == NULL, "the arena satisfied a 64 MiB request");
    CHECK(pqf_arena_oom_req != 0,
          "an arena OOM was not recorded -- the forensics counter is how "
          "this gets sized on silicon");

    core1_arena_reset();
    CHECK(pqf_sign_malloc(1024) != NULL,
          "the arena did not recover from a failed oversized request");
    core1_arena_reset();
    as_core0();
}

static void t_high_water(void)
{
    printf("--- high-water tracking ---\n");
    fresh();
    as_core1();

    core1_arena_note_hw();
    uint32_t idle = pqf_sign_arena_hw;

    void *p = pqf_sign_malloc(8192);
    CHECK(p != NULL, "setup: an 8 KiB allocation");
    core1_arena_note_hw();
    CHECK(pqf_sign_arena_hw >= idle + 8192,
          "the high-water mark did not follow an 8 KiB allocation "
          "(%u after %u) -- this is the number the arena is sized from",
          pqf_sign_arena_hw, idle);

    /* It is a high-water mark, so it must not fall back. */
    uint32_t peak = pqf_sign_arena_hw;
    core1_arena_reset();
    core1_arena_note_hw();
    CHECK(pqf_sign_arena_hw == peak,
          "the high-water mark dropped to %u after a reset, from %u",
          pqf_sign_arena_hw, peak);
    as_core0();
}

static void t_zero_sized(void)
{
    printf("--- zero-sized requests ---\n");
    fresh();
    for (int core = 0; core < 2; core++) {
        if (core) as_core1(); else as_core0();
        void *p = pqf_sign_malloc(0);
        void *q = pqf_sign_calloc(0, 16);
        void *r = pqf_sign_calloc(16, 0);
        /* Whatever they return, releasing it must be safe and nothing
         * may be recorded as an out-of-memory event. */
        pqf_sign_free(p);
        pqf_sign_free(q);
        pqf_sign_free(r);
        CHECK(1, "zero-sized requests on core %d survived", core);
    }
    CHECK(pqf_arena_oom_req == 0,
          "a zero-sized request was recorded as an arena OOM");
    as_core1();
    core1_arena_reset();
    as_core0();
}

int main(void)
{
    printf("core-1 sign arena host test\n");
    core1_arena_init();
    learn_arena_bounds();
    t_routing();
    t_calloc_zeroes();
    t_free_routes_by_pointer();
    t_free_null_is_safe();
    t_realloc_routes_by_pointer();
    t_realloc_null_is_malloc();
    t_reset_reclaims();
    t_oom_is_reported_not_fatal();
    t_high_water();
    t_zero_sized();
    printf("%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
