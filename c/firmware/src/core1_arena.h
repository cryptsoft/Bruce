/* core1_arena.h -- dedicated sign-heap for single-ISA ML-DSA-87 builds.
 *
 * Compiled (with core1_arena.c) only when CMake sets PQF_SIGN_ARENA=1,
 * i.e. a single-ISA build at PQF_HYBRID_VARIANT=87. See core1_arena.c
 * for the sizing/budget rationale.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQF_CORE1_ARENA_H
#define PQF_CORE1_ARENA_H

#include <stdint.h>
#include <stddef.h>

/* Set the arena bounds. Call once at boot (before core 1 launches). */
void core1_arena_init(void);

/* Reset the arena -- core 1 calls this at the top of every sign; each
 * request is self-contained (keys re-derived from seed/scalar, EVP_MD
 * fetch returns statics, the EC group is built per call -- same
 * verification as the mixed build's blob), so nothing allocated in a
 * previous op is live. */
void core1_arena_reset(void);

/* Record the arena high-water into pqf_sign_arena_hw (core 1 calls
 * this after each sign, before publishing the DONE flag). */
void core1_arena_note_hw(void);

/* Single-core build (core0_signer.c): there is no core 1 to route by,
 * so the signer raises this for the duration of each op and the
 * allocations below go to the arena exactly as they would on core 1.
 * Zero in the dual-core builds. */
extern volatile int pqf_sign_arena_force;

/* The malloc family the openssl-mini translation units are compiled
 * against (-Dmalloc=pqf_sign_malloc ...): core 1 -> the arena, core 0 ->
 * newlib. free/realloc route by pointer, so ownership is exact even if
 * a pointer ever crossed cores. */
void *pqf_sign_malloc(size_t n);
void  pqf_sign_free(void *p);
void *pqf_sign_calloc(size_t nmemb, size_t size);
void *pqf_sign_realloc(void *p, size_t n);

/* Diagnostics (main.c prints these over CDC):
 *   pqf_arena_oom_req  -- request size of the first arena OOM (0 = none)
 *   pqf_arena_oom_hw   -- arena bytes-in-use high-water at that OOM
 *   pqf_heap_oom_req   -- request size of the first core-0 newlib OOM
 *   pqf_sign_arena_hw  -- arena high-water across all signs so far */
extern volatile uint32_t pqf_arena_oom_req;
extern volatile uint32_t pqf_arena_oom_hw;
extern volatile uint32_t pqf_heap_oom_req;
extern volatile uint32_t pqf_sign_arena_hw;

#endif /* PQF_CORE1_ARENA_H */
