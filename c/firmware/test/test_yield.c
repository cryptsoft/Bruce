/* test_yield.c -- the single-core signer and the yield hook the crypto
 * calls, on the host.
 *
 * The claim under test is the one the single-core build rests on: while
 * a hybrid signature is being computed, the vendored ML-DSA and EC code
 * calls pqf_yield() often enough, and core0_signer.c turns those calls
 * into a rate-limited tick, so a KEEPALIVE goes out on schedule with no
 * second core involved. The clock is the test's (-DPQF_YIELD_HOST):
 * every yield call advances it by exactly 1 ms, so the expected tick
 * count and the expected worst gap are known numbers, not guesses.
 *
 * What is linked is the REAL src/core0_signer.c, the REAL hybrid.c and
 * the REAL openssl-mini; the only stand-ins are the clock and the tick.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "core1_signer.h"
#include "hybrid.h"
#include "pqf_crypto.h"
#include "pqf_yield.h"

static int checks, failures;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); } } while (0)

/* The clock: 1 ms per yield call. */
static uint64_t now_us;
uint64_t pqf_yield_test_now(void) { now_us += 1000; return now_us; }

/* The tick core0_signer.c fires: count it, and note the clock. */
static uint32_t ticks;
static uint64_t last_tick_us, max_tick_gap_us;
static void tick(void)
{
    if (ticks > 0 && now_us - last_tick_us > max_tick_gap_us)
        max_tick_gap_us = now_us - last_tick_us;
    last_tick_us = now_us;
    ticks++;
}

static const uint8_t SCALAR[32] = {
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x27 };
/* The flash-op callback: sets the int it is handed. */
static void set_flag(void *a) { *(int *)a = 1; }

static const uint8_t SEED[32] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                  17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };

int main(void)
{
    uint8_t sig[PQF_HYBRID_MAX_SIG];
    size_t  sig_len = 0;
    uint8_t msg[200];
    uint8_t ec_x[32], ec_y[32];
    uint8_t pk[PQF_HYBRID_PK_LEN];
    size_t  pk_len = 0;

    for (size_t i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 7);

    core1_long_op_tick = tick;
    core1_signer_init();

    printf("--- a hybrid sign yields, ticks on schedule, and verifies ---\n");
    uint32_t yields0 = pqf_1core.yields;
    CHECK(core1_hybrid_sign(SCALAR, SEED, msg, sizeof msg, sig, &sig_len) == 0,
          "hybrid sign failed");
    uint32_t y = pqf_1core.yields - yields0;
    printf("      yields=%u ticks=%u op_gap=%u us\n", y, ticks, pqf_1core.op_gap_us);
    CHECK(pqf_1core.ops == 1, "ops not counted");
    CHECK(y > 200, "the crypto yielded fewer than 200 times during a hybrid sign");
    CHECK(ticks > 0, "the tick never fired");
    CHECK(ticks == pqf_1core.ticks && ticks == pqf_1core.op_ticks,
          "tick counters disagree with the callback count");
    /* 1 ms per clock read: each yield is one read, a tick costs one
     * more (its duration), so a 25 ms period is ~24 yields + 1 tick. */
    CHECK(ticks >= y / 25 - 1 && ticks <= y / 24 + 2,
          "tick count is not one per ~25 ms of yields");
    CHECK(max_tick_gap_us <= 27000, "two ticks were more than 27 ms apart");
    CHECK(pqf_1core.op_gap_us <= 1000,
          "a stretch of the op went longer than one clock step without a yield");
    CHECK(pqf_1core.op_tick_us == 1000, "a tick should measure exactly one clock step here");
    CHECK(pqf_1core.max_gap_us == pqf_1core.op_gap_us, "max gap not carried over");
    CHECK(pqf_1core.max_tick_us == pqf_1core.op_tick_us, "max tick not carried over");
    CHECK(pqf_1core.op_kind == 0 && pqf_1core.kind_gap_us[0] == pqf_1core.op_gap_us,
          "the hybrid sign was not filed under kind 0");
    CHECK(pqf_1core.op_yields == y, "per-op yield count disagrees with the delta");
    /* and it is a real signature */
    CHECK(hybrid_public(SCALAR, SEED, ec_x, ec_y, pk, &pk_len) == 0, "hybrid_public failed");
    CHECK(hybrid_verify(ec_x, ec_y, pk, pk_len, msg, sizeof msg, sig, sig_len) == 1,
          "the inline signature does not verify");

    printf("--- P-256 keygen yields per ladder step ---\n");
    uint8_t priv[32], px[32], py[32];
    yields0 = pqf_1core.yields;
    CHECK(core1_p256_keygen(priv, px, py) == 0, "p256 keygen failed");
    printf("      yields=%u\n", pqf_1core.yields - yields0);
    CHECK(pqf_1core.yields - yields0 >= 200, "a scalar multiplication yielded fewer than 200 times");
    CHECK(pqf_1core.ops == 2, "ops not counted for keygen");
    CHECK(pqf_1core.op_kind == 1 && pqf_1core.kind_gap_us[1] == 1000,
          "the keygen was not filed under kind 1 with a one-step worst gap");

    printf("--- ML-DSA public key derivation yields ---\n");
    yields0 = pqf_1core.yields;
    pk_len = 0;
    CHECK(core1_mldsa_pub(SEED, pk, &pk_len) == 0, "mldsa pub failed");
    printf("      yields=%u\n", pqf_1core.yields - yields0);
    CHECK(pqf_1core.yields - yields0 >= 50, "keygen yielded fewer than 50 times");
    CHECK(pk_len == PQF_HYBRID_PK_LEN, "unexpected public key length");

    printf("--- P-256 sign yields ---\n");
    uint8_t der[PQF_P256_MAX_SIG_DER]; size_t der_len = 0; uint8_t h[32];
    pqf_sha256(msg, sizeof msg, h);
    yields0 = pqf_1core.yields;
    CHECK(core1_p256_sign(SCALAR, h, der, &der_len) == 0, "p256 sign failed");
    CHECK(pqf_1core.yields - yields0 >= 200, "ECDSA sign yielded fewer than 200 times");

    printf("--- the flash-op guard runs its callback and parks nobody ---\n");
    {
        int ran = 0;
        core1_run_flash_op(set_flag, &ran);
        CHECK(ran == 1, "flash-op callback did not run");
    }

    printf("--- no tick installed: the hook must not crash ---\n");
    core1_long_op_tick = NULL;
    CHECK(core1_p256_keygen(priv, px, py) == 0, "keygen without a tick failed");

    printf("test_yield: %d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
