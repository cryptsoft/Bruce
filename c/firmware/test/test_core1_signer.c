/* test_core1_signer.c -- the cross-core mailbox.
 *
 * Core 0 publishes a request, raises a flag, and spins pumping USB
 * keepalives until core 1 answers. Core 1 wakes, does several seconds of
 * ML-DSA work, and publishes a result. Nothing about that has ever been
 * checked off-silicon, and it is the path every signature takes.
 *
 * Core 1 is a thread here. That is not the real thing -- no separate
 * instruction stream, no XIP, no lockout -- but it makes the mailbox a
 * genuine two-party protocol, which a single-threaded stub cannot. What
 * is under test is the handshake and the state machine, not parallelism.
 *
 * The crypto is real: this links the same openssl-mini stack the other
 * host tests do, so a round trip really does produce a signature.
 *
 * BUILT TWICE, and the difference matters. Without PQF_SIGN_ARENA,
 * core1_p256_keygen and core1_p256_sign run LOCALLY on core 0 and never
 * reach the mailbox -- the #if in core1_signer.c sends them straight to
 * pqf_p256_keygen. A first run of this file missed that and reported
 * sixty-odd passing checks, two of which were measuring a code path that
 * was not running. Both configurations ship, so both are built.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>

#include "core1_signer.h"

/* The shims the translation unit needs, defined once here. */
#include "hardware/structs/sio.h"
pqf_host_sio_t pqf_host_sio;      /* cpuid, read by the arena dispatcher */

volatile bool     pqf_host_irqs_masked;
volatile uint32_t pqf_host_sevs;
volatile uint32_t pqf_host_wfes;

static pthread_t core1_thread;
static void (*core1_entry)(void);
static bool core1_started;

static void *core1_trampoline(void *arg)
{
    (void)arg;
    core1_entry();          /* never returns: it is the worker loop */
    return NULL;
}

void multicore_launch_core1_with_stack(void (*entry)(void),
                                       uint32_t *stack, size_t stack_size)
{
    (void)stack; (void)stack_size;
    core1_entry = entry;
    core1_started = true;
    pthread_create(&core1_thread, NULL, core1_trampoline, NULL);
}
void multicore_launch_core1(void (*entry)(void))
{
    multicore_launch_core1_with_stack(entry, NULL, 0);
}
void multicore_lockout_victim_init(void) {}
void multicore_lockout_start_blocking(void) {}
void multicore_lockout_end_blocking(void) {}
void multicore_reset_core1(void) {}

static int failures, checks;
#define CHECK(cond, ...) do {                                       \
        checks++;                                                   \
        if (!(cond)) {                                              \
            failures++;                                             \
            printf("  [FAIL] " __VA_ARGS__);                        \
            printf("\n         at %s:%d\n", __FILE__, __LINE__);    \
        }                                                           \
    } while (0)

/* ---- the mailbox round trip ---------------------------------------- */

static void t_keygen_round_trip(void)
{
    printf("--- P-256 keygen through the mailbox ---\n");
    uint8_t priv[32] = {0}, x[32] = {0}, y[32] = {0};
    int rc = core1_p256_keygen(priv, x, y);
    CHECK(rc == 0, "keygen returned %d", rc);

    /* A result that never came back would leave these zeroed, which is
     * how a mailbox that reports success without publishing looks. */
    int nz_priv = 0, nz_x = 0, nz_y = 0;
    for (int i = 0; i < 32; i++) {
        nz_priv |= priv[i]; nz_x |= x[i]; nz_y |= y[i];
    }
    CHECK(nz_priv, "the private scalar came back all zero");
    CHECK(nz_x, "the public X came back all zero");
    CHECK(nz_y, "the public Y came back all zero");
}

static void t_keygen_is_not_constant(void)
{
    printf("--- successive keygens differ ---\n");
    /* A mailbox that returned a stale result would look like success and
     * give every credential the same key. */
    uint8_t p1[32], x1[32], y1[32], p2[32], x2[32], y2[32];
    CHECK(core1_p256_keygen(p1, x1, y1) == 0, "first keygen");
    CHECK(core1_p256_keygen(p2, x2, y2) == 0, "second keygen");
    CHECK(memcmp(p1, p2, 32) != 0, "two keygens returned the same private key");
    CHECK(memcmp(x1, x2, 32) != 0, "two keygens returned the same public X");
}

static void t_sign_round_trip(void)
{
    printf("--- P-256 sign through the mailbox ---\n");
    uint8_t priv[32], x[32], y[32];
    CHECK(core1_p256_keygen(priv, x, y) == 0, "setup: keygen");

    uint8_t prehash[32];
    for (int i = 0; i < 32; i++) prehash[i] = (uint8_t)(i * 3 + 1);
    uint8_t sig[80];
    size_t sig_len = 0;
    int rc = core1_p256_sign(priv, prehash, sig, &sig_len);
    CHECK(rc == 0, "sign returned %d", rc);
    CHECK(sig_len >= 8 && sig_len <= sizeof sig,
          "signature length %zu is implausible", sig_len);
    CHECK(sig_len == 0 || sig[0] == 0x30,
          "the signature is not a DER SEQUENCE (first byte %#04x)", sig[0]);
}

static void t_many_requests_in_a_row(void)
{
    printf("--- back-to-back requests ---\n");
    /* The state machine returns to ST_IDLE after each request. If it did
     * not, the second request would either hang or be answered with the
     * first one's result -- and on the token that is one signature
     * serving two ceremonies. */
    uint8_t priv[32], x[32], y[32];
    uint8_t prev[32];
    memset(prev, 0, sizeof prev);
    for (int i = 0; i < 6; i++) {
        int rc = core1_p256_keygen(priv, x, y);
        CHECK(rc == 0, "request %d returned %d", i, rc);
        if (i > 0)
            CHECK(memcmp(prev, priv, 32) != 0,
                  "request %d returned the previous request's result", i);
        memcpy(prev, priv, 32);
    }
}

/* ---- signalling ------------------------------------------------------ */

static void t_requests_signal_the_other_core(void)
{
    printf("--- every request wakes core 1 ---\n");
#if !defined(PQF_SIGN_ARENA)
    /* Without the arena, core1_p256_keygen runs LOCALLY on core 0 and
     * never touches the mailbox at all -- so there is nothing to signal.
     * That is a real configuration, and worth stating rather than
     * silently passing: this whole file only exercises the cross-core
     * protocol when built with -DPQF_SIGN_ARENA. */
    printf("  (skipped: no arena, so keygen runs on core 0)\n");
    return;
#endif
    /* Core 1 waits in `wfe`. A request that does not `sev` leaves it
     * asleep and core 0 spinning until the host gives up -- which on
     * silicon is a token that stops signing after an idle period. */
    uint32_t before = pqf_host_sevs;
    uint8_t priv[32], x[32], y[32];
    CHECK(core1_p256_keygen(priv, x, y) == 0, "setup: a request");
    CHECK(pqf_host_sevs > before,
          "the request did not signal core 1 (sev count unchanged at %u)",
          pqf_host_sevs);
}

/* ---- the long-operation tick ----------------------------------------- */

static int ticks;
static void count_tick(void) { ticks++; }

static void t_long_operations_pump_the_host(void)
{
    printf("--- core 0 pumps USB while it waits ---\n");
#if !defined(PQF_SIGN_ARENA)
    printf("  (skipped: no arena, so there is no wait to pump through)\n");
    return;
#endif
    /* Core 0 blocks for the whole signature -- seconds, at ML-DSA-87.
     * If it stopped servicing USB the host would time the transaction
     * out and the browser would report a dead key. The tick hook is what
     * keeps CTAPHID keepalives flowing. */
    ticks = 0;
    core1_long_op_tick = count_tick;
    uint8_t priv[32], x[32], y[32];
    CHECK(core1_p256_keygen(priv, x, y) == 0, "setup: a request");
    core1_long_op_tick = NULL;
    CHECK(ticks > 0,
          "the wait never pumped the host -- a multi-second signature "
          "would time the USB transaction out");
}

/* ---- the flash-op park ----------------------------------------------- */

static int flash_cb_runs;
static void flash_cb(void *arg) { (void)arg; flash_cb_runs++; }

static void t_flash_op_parks_and_releases(void)
{
    printf("--- core1_run_flash_op ---\n");
    /* A flash erase makes XIP unreadable. Core 1 has to be in its
     * RAM-resident spin loop for the duration or its next instruction
     * fetch is undefined. */
    flash_cb_runs = 0;
    core1_run_flash_op(flash_cb, NULL);
    CHECK(flash_cb_runs == 1, "the flash callback ran %d times, want 1",
          flash_cb_runs);

    /* And the signer still works afterwards: core 1 must have come back
     * out of the spin loop. */
    uint8_t priv[32], x[32], y[32];
    CHECK(core1_p256_keygen(priv, x, y) == 0,
          "the signer stopped answering after a flash op -- core 1 was left "
          "parked");
}

static void t_repeated_flash_ops(void)
{
    printf("--- repeated flash ops ---\n");
    /* Every signature is preceded by a counter write, so this pairing
     * happens on every ceremony. A handshake that leaked state would
     * fail on the second or third, not the first. */
    for (int i = 0; i < 8; i++) {
        flash_cb_runs = 0;
        core1_run_flash_op(flash_cb, NULL);
        CHECK(flash_cb_runs == 1, "flash op %d did not run its callback", i);
    }
    uint8_t priv[32], x[32], y[32];
    CHECK(core1_p256_keygen(priv, x, y) == 0,
          "the signer stopped answering after eight flash ops");
}

static void t_flash_op_and_sign_interleave(void)
{
    printf("--- flash ops interleaved with signing ---\n");
    /* The real sequence on every GetAssertion: bump the counter (flash),
     * then sign. Ten times, because a mailbox that half-releases would
     * pass once. */
    uint8_t priv[32], x[32], y[32], prehash[32], sig[80];
    size_t sig_len;
    for (int i = 0; i < 10; i++) {
        core1_run_flash_op(flash_cb, NULL);
        CHECK(core1_p256_keygen(priv, x, y) == 0, "keygen after flash op %d", i);
        memset(prehash, (uint8_t)i, sizeof prehash);
        sig_len = 0;
        CHECK(core1_p256_sign(priv, prehash, sig, &sig_len) == 0,
              "sign after flash op %d", i);
        CHECK(sig_len > 0, "sign %d produced no signature", i);
    }
}

int main(void)
{
    printf("core-1 mailbox host test\n");
    core1_signer_init();
    /* Give the worker thread a moment to reach its wait loop. */
    usleep(50000);

    t_keygen_round_trip();
    t_keygen_is_not_constant();
    t_sign_round_trip();
    t_many_requests_in_a_row();
    t_requests_signal_the_other_core();
    t_long_operations_pump_the_host();
    t_flash_op_parks_and_releases();
    t_repeated_flash_ops();
    t_flash_op_and_sign_interleave();

    printf("%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
