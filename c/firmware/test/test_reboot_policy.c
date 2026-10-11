/* test_reboot_policy.c -- host test of the CTAPHID_CMD_REBOOT presence
 * policy, per board (src/board.h PQF_REBOOT_NEEDS_UP, src/ctaphid.c).
 *
 * Whether CMD_REBOOT waits for a touch is decided at compile time from
 * the board macro, so one binary can only ever see one answer. The
 * Makefile therefore builds this file once per configuration that
 * matters, and each binary checks the answer its own build should get:
 *
 *   -DPQF_BOARD_FEITIAN_RP2350          gated: a button to press and a
 *                                       power-on BOOTSEL to fall back on
 *   ... plus -DPQF_REBOOT_NO_UP=1       not gated: the flash-station
 *                                       override still works there
 *   -DPQF_BOARD_FEITIAN_RP2350_USBC     not gated, BY DESIGN
 *
 * The last one is the reason this file exists. The sealed USB-C token's
 * power-on BOOTSEL sensing does not work, so CMD_REBOOT is its only way
 * back into the bootloader; an image that gated it on a touch the token
 * cannot deliver could never be reflashed. A gate here is not a bug
 * report, it is a token in a drawer. So the ungated builds install a
 * presence hook that would DECLINE and require that it is never asked.
 *
 * The expectations below are spelled out per board, not read back from
 * PQF_REBOOT_NEEDS_UP -- a test that restated the macro would pass
 * whatever it said. The Rust port's equivalent is
 * crates/firmware-hosttest/tests/reboot_policy.rs. The malformed-request
 * cases, which do not depend on the board, stay in test_ctaphid.c
 * (built with no board macro, so its gate is compiled out).
 *
 * Platform seams as test_ctaphid.c: PQF_CTAPHID_HOST supplies the clock,
 * pqf_board_reboot is recorded rather than performed, and
 * pqf_board_bootsel_available is settable.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "ctaphid.h"
#include "ctap2.h"
#include "board.h"

/* What this build must do, by board -- independent of board.h. */
#if defined(PQF_BOARD_FEITIAN_RP2350_USBC)
#define VARIANT               "feitian_rp2350_usbc"
#define WANT_GATED            0   /* CMD_REBOOT is its only way back */
#define WANT_USER_BUTTON      1   /* FIDO presence is still a touch */
#define WANT_POWER_ON_BOOTSEL 0
#elif defined(PQF_BOARD_FEITIAN_RP2350) && defined(PQF_REBOOT_NO_UP)
#define VARIANT               "feitian_rp2350, PQF_REBOOT_NO_UP"
#define WANT_GATED            0   /* the flash-station override */
#define WANT_USER_BUTTON      1
#define WANT_POWER_ON_BOOTSEL 1
#elif defined(PQF_BOARD_FEITIAN_RP2350)
#define VARIANT               "feitian_rp2350"
#define WANT_GATED            1
#define WANT_USER_BUTTON      1
#define WANT_POWER_ON_BOOTSEL 1
#else
#error "build with -DPQF_BOARD_FEITIAN_RP2350[_USBC] (see the Makefile)"
#endif

static int failures;
static int checks;
#define CHECK(cond, ...) do {                                       \
        checks++;                                                   \
        if (!(cond)) {                                              \
            failures++;                                             \
            printf("  [FAIL] " __VA_ARGS__);                        \
            printf("\n         at %s:%d\n", __FILE__, __LINE__);    \
        }                                                           \
    } while (0)

/* ---- the seams ------------------------------------------------- */

static uint64_t host_clock_us;
uint64_t pqf_ctaphid_host_now_us(void) { return host_clock_us; }

static int reboot_calls;
static enum pqf_reboot_mode reboot_mode;
void pqf_board_reboot(enum pqf_reboot_mode mode)
{
    reboot_calls++;
    reboot_mode = mode;
}

static bool bootsel_available = true;
bool pqf_board_bootsel_available(void) { return bootsel_available; }

/* The presence hook, as fido_hid.c installs wait_for_up on the token.
 * It records every call, sends KEEPALIVE(UPNEEDED) the way the real
 * wait does (so the test can see the channel was armed for it), and
 * answers whatever the test chose. */
static int      up_calls;
static uint32_t up_timeout_us;
static bool     up_answer;
static bool presence_hook(uint32_t timeout_us)
{
    up_calls++;
    up_timeout_us = timeout_us;
    ctaphid_send_keepalive(CTAPHID_STATUS_UPNEEDED);
    return up_answer;
}

/* ---- captured output ------------------------------------------- */

#define MAX_FRAMES 16
static uint8_t sent[MAX_FRAMES][CTAPHID_FRAME_SIZE];
static size_t  sent_n;

static void capture(const uint8_t *frame)
{
    if (sent_n < MAX_FRAMES) memcpy(sent[sent_n], frame, CTAPHID_FRAME_SIZE);
    sent_n++;
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | p[3];
}

static uint8_t  resp_cmd(size_t i) { return sent[i][4] & 0x7fu; }
static uint32_t resp_cid(size_t i) { return be32(sent[i]); }
static uint8_t  resp_b0(size_t i)  { return sent[i][7]; }  /* first payload byte */

/* A single-frame message: CID | 0x80|cmd | BE16 length | data. Every
 * request here fits in one init frame. */
static void feed(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len)
{
    uint8_t f[CTAPHID_FRAME_SIZE];
    memset(f, 0, sizeof f);
    f[0] = (uint8_t)(cid >> 24); f[1] = (uint8_t)(cid >> 16);
    f[2] = (uint8_t)(cid >> 8);  f[3] = (uint8_t)cid;
    f[4] = (uint8_t)(cmd | CTAPHID_INIT_BIT);
    f[5] = (uint8_t)(len >> 8);
    f[6] = (uint8_t)len;
    if (len) memcpy(f + 7, data, len);
    ctaphid_recv_frame(f, capture);
}

/* Fresh transport, the hook installed, and an allocated channel. */
static uint32_t fresh_channel(bool answer)
{
    ctaphid_init();
    ctap2_user_presence_hook = presence_hook;
    up_answer = answer;
    bootsel_available = true;
    host_clock_us = 0;

    uint8_t nonce[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    sent_n = 0;
    feed(CTAPHID_BROADCAST_CID, CTAPHID_CMD_INIT, nonce, sizeof nonce);
    uint32_t cid = sent_n ? be32(sent[0] + 7 + 8) : 0;

    sent_n = 0;
    up_calls = 0;
    up_timeout_us = 0;
    reboot_calls = 0;
    return cid;
}

static const char *mode_name(uint8_t mode)
{
    return mode == CTAPHID_REBOOT_BOOTSEL ? "BOOTSEL" : "warm";
}

static enum pqf_reboot_mode board_mode(uint8_t mode)
{
    return mode == CTAPHID_REBOOT_BOOTSEL ? PQF_REBOOT_BOOTSEL : PQF_REBOOT_WARM;
}

static const uint8_t MODES[2] = { CTAPHID_REBOOT_WARM, CTAPHID_REBOOT_BOOTSEL };

/* ---- the board facts ------------------------------------------- */

static void t_board_facts(void)
{
    printf("--- board.h resolves as this board should ---\n");
    CHECK(PQF_BOARD_HAS_USER_BUTTON == WANT_USER_BUTTON,
          "PQF_BOARD_HAS_USER_BUTTON is %d, want %d",
          PQF_BOARD_HAS_USER_BUTTON, WANT_USER_BUTTON);
    CHECK(PQF_BOARD_HAS_POWER_ON_BOOTSEL == WANT_POWER_ON_BOOTSEL,
          "PQF_BOARD_HAS_POWER_ON_BOOTSEL is %d, want %d",
          PQF_BOARD_HAS_POWER_ON_BOOTSEL, WANT_POWER_ON_BOOTSEL);
    CHECK(!!(PQF_REBOOT_NEEDS_UP) == WANT_GATED,
          "PQF_REBOOT_NEEDS_UP is %d, want %d -- %s",
          !!(PQF_REBOOT_NEEDS_UP), WANT_GATED,
          WANT_GATED ? "this board has a power-on BOOTSEL; the gate belongs"
                     : "CMD_REBOOT would wait for a touch");
}

/* ---- gated: a touch decides ------------------------------------ */

#if WANT_GATED
static void t_gate_declined(void)
{
    printf("--- gated: no touch, no reboot ---\n");
    for (size_t i = 0; i < sizeof MODES; i++) {
        uint8_t m[1] = { MODES[i] };
        uint32_t cid = fresh_channel(false);
        feed(cid, CTAPHID_CMD_REBOOT, m, 1);

        CHECK(up_calls == 1, "%s REBOOT asked for presence %d times, want 1",
              mode_name(MODES[i]), up_calls);
        CHECK(up_timeout_us == CTAPHID_REBOOT_UP_TIMEOUT_US,
              "%s REBOOT waited %u us for presence, want %u",
              mode_name(MODES[i]), (unsigned)up_timeout_us,
              (unsigned)CTAPHID_REBOOT_UP_TIMEOUT_US);
        CHECK(reboot_calls == 0,
              "%s REBOOT with presence declined rebooted anyway",
              mode_name(MODES[i]));

        /* KEEPALIVE(UPNEEDED) from inside the wait, then ERR_OTHER --
         * both on the requesting channel. The first is what makes the
         * host show "touch your key"; the second is the documented
         * answer to a declined or timed-out gate. */
        CHECK(sent_n == 2, "%s REBOOT declined: %zu frames, want 2",
              mode_name(MODES[i]), sent_n);
        if (sent_n == 2) {
            CHECK(resp_cmd(0) == CTAPHID_CMD_KEEPALIVE && resp_cid(0) == cid
                  && resp_b0(0) == CTAPHID_STATUS_UPNEEDED,
                  "%s REBOOT: the presence wait had no KEEPALIVE channel",
                  mode_name(MODES[i]));
            CHECK(resp_cmd(1) == CTAPHID_CMD_ERROR && resp_cid(1) == cid
                  && resp_b0(1) == CTAPHID_ERR_OTHER,
                  "%s REBOOT declined: answered cmd %#04x err %#04x, want "
                  "ERROR / ERR_OTHER", mode_name(MODES[i]),
                  resp_cmd(1), resp_b0(1));
        }

        /* ...and the channel is disarmed again afterwards. */
        sent_n = 0;
        ctaphid_send_keepalive(CTAPHID_STATUS_UPNEEDED);
        CHECK(sent_n == 0, "%s REBOOT left the KEEPALIVE channel armed",
              mode_name(MODES[i]));
    }
}

static void t_gate_confirmed(void)
{
    printf("--- gated: a touch reboots ---\n");
    for (size_t i = 0; i < sizeof MODES; i++) {
        uint8_t m[1] = { MODES[i] };
        uint32_t cid = fresh_channel(true);
        feed(cid, CTAPHID_CMD_REBOOT, m, 1);

        CHECK(up_calls == 1, "%s REBOOT asked for presence %d times, want 1",
              mode_name(MODES[i]), up_calls);
        CHECK(reboot_calls == 1,
              "%s REBOOT with presence confirmed did not reboot",
              mode_name(MODES[i]));
        if (reboot_calls == 1)
            CHECK(reboot_mode == board_mode(MODES[i]),
                  "%s REBOOT asked the board for mode %d",
                  mode_name(MODES[i]), (int)reboot_mode);
        for (size_t f = 0; f < sent_n && f < MAX_FRAMES; f++)
            CHECK(resp_cmd(f) != CTAPHID_CMD_ERROR,
                  "%s REBOOT confirmed but answered an error frame",
                  mode_name(MODES[i]));
    }
}
#endif /* WANT_GATED */

/* ---- ungated: the hook is never consulted ---------------------- */

#if !WANT_GATED
static void t_ungated(void)
{
    printf("--- not gated: reboots without asking for a touch ---\n");
    for (size_t i = 0; i < sizeof MODES; i++) {
        uint8_t m[1] = { MODES[i] };
        /* A hook that would DECLINE: were it consulted, the reboot
         * would not happen, and the checks below would say so. */
        uint32_t cid = fresh_channel(false);
        feed(cid, CTAPHID_CMD_REBOOT, m, 1);

        CHECK(up_calls == 0,
              "%s REBOOT asked for presence on a board where it must not "
              "(" VARIANT ")", mode_name(MODES[i]));
        CHECK(reboot_calls == 1, "%s REBOOT did not reboot (" VARIANT ")",
              mode_name(MODES[i]));
        if (reboot_calls == 1)
            CHECK(reboot_mode == board_mode(MODES[i]),
                  "%s REBOOT asked the board for mode %d",
                  mode_name(MODES[i]), (int)reboot_mode);
        CHECK(sent_n == 0,
              "%s REBOOT sent %zu frame(s); the device re-enumerates away "
              "and answers nothing", mode_name(MODES[i]), sent_n);
    }
}
#endif

/* ---- what the policy leaves alone ------------------------------ */

/* The fused-off BOOTSEL refusal comes BEFORE the gate: no touch is
 * asked for a request that would be refused anyway, gated or not. */
static void t_fused_off(void)
{
    printf("--- BOOTSEL fused off: refused before any gate ---\n");
    uint8_t boot[1] = { CTAPHID_REBOOT_BOOTSEL };
    uint32_t cid = fresh_channel(true);
    bootsel_available = false;
    feed(cid, CTAPHID_CMD_REBOOT, boot, 1);
    CHECK(reboot_calls == 0, "BOOTSEL fused off: the reboot happened anyway");
    CHECK(up_calls == 0, "BOOTSEL fused off: asked for a touch first");
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR
          && resp_cid(0) == cid && resp_b0(0) == CTAPHID_ERR_INVALID_PAR,
          "BOOTSEL fused off: the host got no ERR_INVALID_PAR");
    bootsel_available = true;
}

/* FIDO user presence is not part of the reboot policy. authenticator-
 * Selection (0x0B) is the simplest command that takes a test of user
 * presence, so it stands in for MakeCredential / GetAssertion: in every
 * build here, the ungated USB-C token included, it must ask the hook
 * and honour a refusal. */
static void t_fido_presence_untouched(void)
{
    printf("--- FIDO presence is still asked for ---\n");
    uint8_t selection[1] = { CTAP2_CMD_SELECTION };
    uint32_t cid = fresh_channel(false);
    feed(cid, CTAPHID_CMD_CBOR, selection, 1);
    CHECK(up_calls == 1,
          "authenticatorSelection asked for presence %d times, want 1",
          up_calls);
    size_t last = sent_n ? sent_n - 1 : 0;
    CHECK(sent_n >= 1 && resp_cmd(last) == CTAPHID_CMD_CBOR
          && resp_cid(last) == cid
          && resp_b0(last) == CTAP2_ERR_OPERATION_DENIED,
          "authenticatorSelection with presence declined was not denied");
}

int main(void)
{
    printf("CMD_REBOOT presence policy host test (" VARIANT ")\n");
    t_board_facts();
#if WANT_GATED
    t_gate_declined();
    t_gate_confirmed();
#else
    t_ungated();
#endif
    t_fused_off();
    t_fido_presence_untouched();
    printf("%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
