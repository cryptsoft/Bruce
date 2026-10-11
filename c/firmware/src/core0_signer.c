/* core0_signer.c -- the signer inline on core 0 (PQF_SINGLE_CORE).
 *
 * Drop-in replacement for core1_signer.c behind the same core1_signer.h
 * API, for a build that leaves core 1 asleep. The hybrid sign, the
 * P-256 ops and the ML-DSA public-key derivation all run on the core
 * that also talks to the host.
 *
 * The one thing core 1 was for. The dual-core design exists because a
 * hybrid signature takes on the order of a second and the CTAPHID
 * client expects a KEEPALIVE every ~100 ms while a command is in
 * flight -- Chrome drops the transaction otherwise. There, core 0 pumps
 * USB + KEEPALIVE in a wait loop while core 1 signs. Here the pump runs
 * from INSIDE the crypto instead: the vendored ML-DSA and EC code calls
 * pqf_yield() (pqf_yield.h) from its heavy loops -- per sampled matrix
 * element, per NTT, per rejection iteration, per ladder step, each a
 * few microseconds apart -- and this file's pqf_yield() runs the same
 * long-op tick the dual-core wait loop uses, rate-limited to once per
 * PQF_YIELD_US. Between ticks the hook costs one timer read.
 *
 * What this build gives back: the core-1 stack, the flash-op park
 * handshake (there is nobody to park; a flash write runs its callback
 * directly), the ARCHSEL games, and one more thing that can hang.
 *
 * Level 87 keeps its sign arena (PQF_SIGN_ARENA): the dual-core build
 * routes allocations to it by core id, this one by a flag raised for
 * the duration of each op (core1_arena.c, pqf_sign_arena_force), so the
 * heap behaviour is the same as on core 1.
 *
 * Instrumentation for the banner: how many ops ran, how often the hook
 * was called and how often it fired, and two durations that must be
 * kept apart. The GAP is the longest stretch of an op between two yield
 * calls with the tick's own time taken out: the crypto's blind spot,
 * where no keepalive can be sent. The TICK is the longest time one tick
 * took -- USB service plus one KEEPALIVE frame, which blocks until the
 * host has fetched the previous IN report -- so a long tick is the host
 * being slow to poll, not the crypto being silent. Measured on the token
 * so a claim about Chrome's watchdog does not rest on a comment.
 *
 * Host-testable: -DPQF_YIELD_HOST makes the clock a function the test
 * supplies (test/test_yield.c), everything else is the shipping code.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core1_signer.h"
#include "hybrid.h"
#include "pqf_crypto.h"
#include "pqf_yield.h"

#if defined(PQF_SIGN_ARENA)
#include "core1_arena.h"
#endif

#if defined(PQF_YIELD_HOST)
uint64_t pqf_yield_test_now(void);           /* the test's clock */
#define NOW_US() pqf_yield_test_now()
#else
#include "pico/time.h"
#define NOW_US() time_us_64()
#endif

/* How often the hook services USB and emits a KEEPALIVE. 25 ms sits
 * well inside the ~100 ms the CTAPHID client expects and costs the sign
 * ~2%: a KEEPALIVE frame waits for the 1 ms HID IN slot, so 40 of them
 * per second is ~40 ms of a 1 s sign. */
#ifndef PQF_YIELD_US
#define PQF_YIELD_US 25000u
#endif

void (*core1_long_op_tick)(void) = NULL;

struct pqf_single_core_stats pqf_1core;

static bool     s_in_op;
static uint64_t s_last_call_us;   /* the previous pqf_yield() call */
static uint64_t s_next_tick_us;   /* when the hook next fires the tick */

/* Called from inside the crypto (see pqf_yield.h). Overrides the weak
 * no-op the vendored code carries. */
void pqf_yield(void)
{
    uint64_t now = NOW_US();

    if (s_in_op) {
        uint32_t gap = (uint32_t)(now - s_last_call_us);
        if (gap > pqf_1core.op_gap_us) {
            pqf_1core.op_gap_us = gap;
            pqf_1core.op_gap_at = pqf_1core.op_yields;
        }
        pqf_1core.op_yields++;
    }
    s_last_call_us = now;
    pqf_1core.yields++;

    if (now < s_next_tick_us)
        return;
    pqf_1core.ticks++;
    pqf_1core.op_ticks++;
    if (core1_long_op_tick != NULL)
        core1_long_op_tick();
    /* The tick's own duration is the host's, not the crypto's: take it
     * out of the next gap and account for it separately. */
    {
        uint64_t after = NOW_US();
        uint32_t dur = (uint32_t)(after - now);
        if (dur > pqf_1core.op_tick_us)
            pqf_1core.op_tick_us = dur;
        s_last_call_us = after;
        s_next_tick_us = after + PQF_YIELD_US;
    }
}

static void op_begin(uint32_t kind)
{
    uint64_t now = NOW_US();

    pqf_1core.ops++;
    pqf_1core.op_kind = kind;
    pqf_1core.op_gap_us = 0;
    pqf_1core.op_gap_at = 0;
    pqf_1core.op_yields = 0;
    pqf_1core.op_tick_us = 0;
    pqf_1core.op_ticks = 0;
    s_last_call_us = now;
    s_next_tick_us = now + PQF_YIELD_US;
    s_in_op = true;
#if defined(PQF_SIGN_ARENA)
    core1_arena_reset();                    /* fresh arena per op */
    pqf_sign_arena_force = 1;
#endif
}

static void op_end(void)
{
    /* The stretch after the last yield (packing, DER encoding) counts
     * against the gap too: a keepalive cannot fire there either. */
    uint32_t tail = (uint32_t)(NOW_US() - s_last_call_us);
    if (tail > pqf_1core.op_gap_us) {
        pqf_1core.op_gap_us = tail;
        pqf_1core.op_gap_at = pqf_1core.op_yields;
    }
    if (pqf_1core.op_gap_us > pqf_1core.max_gap_us)
        pqf_1core.max_gap_us = pqf_1core.op_gap_us;
    if (pqf_1core.op_kind < 4
        && pqf_1core.op_gap_us > pqf_1core.kind_gap_us[pqf_1core.op_kind])
        pqf_1core.kind_gap_us[pqf_1core.op_kind] = pqf_1core.op_gap_us;
    if (pqf_1core.op_tick_us > pqf_1core.max_tick_us)
        pqf_1core.max_tick_us = pqf_1core.op_tick_us;
    s_in_op = false;
#if defined(PQF_SIGN_ARENA)
    pqf_sign_arena_force = 0;
    core1_arena_note_hw();
#endif
}

void core1_signer_init(void)
{
#if defined(PQF_SIGN_ARENA)
    core1_arena_init();
#endif
    /* No second core to launch. */
}

int core1_hybrid_sign(const uint8_t ecdsa_scalar[32],
                      const uint8_t mldsa_seed[32],
                      const uint8_t *msg, size_t msg_len,
                      uint8_t *sig, size_t *sig_len)
{
    int rc;

    op_begin(0);
    rc = hybrid_sign(ecdsa_scalar, mldsa_seed, msg, msg_len, sig, sig_len);
    op_end();
    return rc;
}

int core1_p256_keygen(uint8_t priv[32], uint8_t pub_x[32], uint8_t pub_y[32])
{
    int rc;

    op_begin(1);
    rc = pqf_p256_keygen(priv, pub_x, pub_y);
    op_end();
    return rc;
}

int core1_p256_sign(const uint8_t scalar[32], const uint8_t prehash[32],
                    uint8_t *sig, size_t *sig_len)
{
    int rc;

    op_begin(2);
    rc = pqf_ecdsa_p256_sign(scalar, prehash, sig, sig_len);
    op_end();
    return rc;
}

int core1_mldsa_pub(const uint8_t seed[32], uint8_t *pub, size_t *pub_len)
{
    int rc;

    op_begin(3);
    rc = pqf_mldsa_pub_from_seed(PQF_HYBRID_MLDSA, seed, pub, pub_len);
    op_end();
    return rc;
}

/* Nothing to park: no other core fetches from XIP while the flash op
 * disables it. The callback is RAM-resident (flash_store.c) as before. */
void core1_run_flash_op(void (*cb)(void *), void *arg)
{
    cb(arg);
}
