/* test_fido_hid.c -- the user-presence gate.
 *
 * This is the security boundary of the whole device. Every registration
 * and every assertion passes through `wait_for_up`, and its job is to
 * be certain a human touched the token *for this operation*. Nothing has
 * ever tested it: on hardware it is exercised by a finger, which cannot
 * check the cases that matter.
 *
 * Three properties, and the first is the one worth having:
 *
 *   - one continuous hold must not satisfy two operations. The loop
 *     tracks `saw_release` precisely so a finger left on the pad cannot
 *     authorise a second ceremony the user never agreed to;
 *   - a press must be HELD for PQF_UP_HOLD_US, so a contact bounce or a
 *     brush is not consent;
 *   - the wait must end. A gate with no deadline is a token that hangs
 *     until unplugged.
 *
 * The clock and the button are both under the test's control
 * (test/pico/time.h, and the stubs below), so a timeout takes
 * microseconds rather than ten seconds and the debounce boundary can be
 * probed exactly.
 *
 * `wait_for_up` is static; it is reached the way the firmware reaches
 * it, through the ctap2_user_presence_hook that fido_hid_install_tick
 * installs.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "pico/time.h"
#include "fido_hid.h"
#include "ctap2.h"
#include <stddef.h>

/* ---- the world the gate sees ------------------------------------- */

uint64_t pqf_host_now_us;          /* the clock, driven by each test */

static bool button_state;
static bool led_state;
static int  led_transitions;
static int  keepalives;
static int  usb_tasks;

/* The button can be scripted to change at a given time, which is how a
 * press "arrives" partway through the wait. */
static uint64_t press_at_us  = UINT64_MAX;
static uint64_t release_at_us = UINT64_MAX;

/* Each poll of the button advances the clock a little, the way a real
 * loop iteration takes time. Without this the deadline could never be
 * reached and a timeout test would spin forever. */
#define TICK_US 100u

bool pqf_board_user_present(void)
{
    pqf_host_now_us += TICK_US;
    /* One-shot: a scheduled transition fires once and is consumed.
     * Leaving them armed made whichever was tested last win forever,
     * which is a bug in the harness rather than the firmware -- it made
     * a legitimate release-then-press look like a refusal. */
    if (pqf_host_now_us >= release_at_us) {
        button_state = false;
        release_at_us = UINT64_MAX;
    }
    if (pqf_host_now_us >= press_at_us) {
        button_state = true;
        press_at_us = UINT64_MAX;
    }
    return button_state;
}

void pqf_board_led_set(bool on)
{
    if (on != led_state) led_transitions++;
    led_state = on;
}

/* pqf_usb_task is defined by fido_hid.c itself; it calls tud_int_handler
 * and tud_task, both stubbed below. The counter is incremented there. */
void pqf_gdb_poll(void) {}
void ctaphid_send_keepalive(uint8_t status) { (void)status; keepalives++; }

/* Referenced by the translation unit but not by the presence gate. */
void ctaphid_recv_frame(const uint8_t *f, void (*s)(const uint8_t *)) { (void)f; (void)s; }
void ctaphid_poll_timeout(void (*s)(const uint8_t *)) { (void)s; }
void ctaphid_keepalive_pump(void) {}
void (*core1_long_op_tick)(void);
bool (*ctap2_user_presence_hook)(uint32_t timeout_us);

/* TinyUSB device API, stubbed: the gate pumps tud_task but sends
 * nothing. `ready` is false so the frame path is never entered. */
void tud_task_ext(uint32_t ms, bool in_isr) { (void)ms; (void)in_isr; usb_tasks++; }
void tud_int_handler(uint8_t rhport) { (void)rhport; }
bool tud_hid_n_ready(uint8_t i) { (void)i; return false; }
bool tud_hid_n_report(uint8_t i, uint8_t id, const void *r, uint16_t len)
{ (void)i; (void)id; (void)r; (void)len; return false; }
const uint8_t pqf_hid_report_desc[] = { 0x06, 0xd0, 0xf1, 0x09, 0x01 };
const size_t pqf_hid_report_desc_len = sizeof(pqf_hid_report_desc);

static int failures, checks;
#define CHECK(cond, ...) do {                                       \
        checks++;                                                   \
        if (!(cond)) {                                              \
            failures++;                                             \
            printf("  [FAIL] " __VA_ARGS__);                        \
            printf("\n         at %s:%d\n", __FILE__, __LINE__);    \
        }                                                           \
    } while (0)

/* The hold the firmware requires, mirrored. If these diverge the tests
 * below stop probing the boundary they claim to. */
#ifndef PQF_UP_HOLD_US
#define PQF_UP_HOLD_US 20000u
#endif

static bool (*gate)(uint32_t);

static void reset(void)
{
    pqf_host_now_us = 1000;
    button_state = false;
    led_state = false;
    led_transitions = 0;
    keepalives = 0;
    usb_tasks = 0;
    press_at_us = UINT64_MAX;
    release_at_us = UINT64_MAX;
}

/* ---- the hold ------------------------------------------------------ */

static void t_timeout(void)
{
    printf("--- an untouched token times out ---\n");
    reset();
    /* Nobody touches it. The gate must give up rather than wait
     * forever: a token that hangs until unplugged is worse than one
     * that refuses. */
    bool r = gate(1000000);           /* 1 s */
    CHECK(!r, "the gate confirmed presence with nothing touching it");
    CHECK(pqf_host_now_us >= 1000000,
          "the gate returned before its deadline (%llu us elapsed)",
          (unsigned long long)pqf_host_now_us);
    CHECK(keepalives > 0,
          "no KEEPALIVE was sent while waiting -- the browser would show "
          "nothing and time out on its own");
    CHECK(usb_tasks > 0, "USB was not pumped during the wait");
}

static void t_held_press_confirms(void)
{
    printf("--- a held press confirms ---\n");
    reset();
    press_at_us = pqf_host_now_us + 5000;
    bool r = gate(1000000);
    CHECK(r, "a held press did not confirm presence");
}

static void t_brief_touch_is_not_consent(void)
{
    printf("--- a brush is not consent ---\n");
    reset();
    /* Pressed and released well inside the debounce window. A contact
     * bounce, or a finger brushing the pad on the way past, must not
     * authorise a credential. */
    press_at_us   = pqf_host_now_us + 5000;
    release_at_us = press_at_us + (PQF_UP_HOLD_US / 4);
    bool r = gate(500000);
    CHECK(!r, "a touch shorter than the hold time was accepted as consent");
}

static void t_hold_boundary(void)
{
    printf("--- the hold boundary ---\n");
    /* Just under the required hold: refused. Just over: accepted. The
     * two together show the threshold is actually applied rather than
     * the press merely being noticed. */
    reset();
    press_at_us   = pqf_host_now_us + 2000;
    release_at_us = press_at_us + (PQF_UP_HOLD_US - 2 * TICK_US);
    CHECK(!gate(500000), "a press just under the hold time was accepted");

    reset();
    press_at_us = pqf_host_now_us + 2000;
    CHECK(gate(500000), "a press just over the hold time was refused");
}

/* ---- the property that matters most -------------------------------- */

static void t_one_hold_does_not_authorise_twice(void)
{
    printf("--- one hold, one operation ---\n");
    reset();
    /* First ceremony: the user presses and holds. */
    press_at_us = pqf_host_now_us + 2000;
    CHECK(gate(500000), "setup: the first press should confirm");

    /* The finger never leaves the pad. A second ceremony arrives -- a
     * hostile page issuing back-to-back requests, or simply a slow
     * user. It must NOT be satisfied by the same continuous contact:
     * consent is per-operation. */
    bool second = gate(200000);
    CHECK(!second,
          "a single continuous hold authorised a second operation -- "
          "consent is per-ceremony, and this is how a page gets a "
          "signature the user never agreed to");
}

static void t_release_then_press_authorises_again(void)
{
    printf("--- release, then press again ---\n");
    reset();
    press_at_us = pqf_host_now_us + 2000;
    CHECK(gate(500000), "setup: first press");

    /* Let go, then press again. That is a genuine second consent and
     * must be accepted, or the token would need a replug between
     * operations. */
    release_at_us = pqf_host_now_us + 1000;
    press_at_us   = pqf_host_now_us + 20000;
    CHECK(gate(1000000), "a genuine second press was refused");
}

/* ---- the light ------------------------------------------------------ */

static void t_led_blinks_while_waiting(void)
{
    printf("--- the LED asks for the press ---\n");
    reset();
    gate(500000);
    /* Rapid blink is the only blinking pattern in the LED model -- idle
     * and busy are both solid -- so it is the entire user-facing signal
     * that the token wants a touch. No transitions means a user staring
     * at a static light with no idea anything is required. */
    CHECK(led_transitions > 4,
          "the LED changed %d times while waiting -- the user is given no "
          "indication a press is needed", led_transitions);
}

static void t_led_ends_solid_on_confirm(void)
{
    printf("--- the LED after a confirm ---\n");
    reset();
    press_at_us = pqf_host_now_us + 2000;
    CHECK(gate(500000), "setup: press confirms");
    CHECK(led_state,
          "the LED was left off after a confirmed press -- the multi-second "
          "signature that follows would look like a dead token");
}

static void t_led_ends_off_on_timeout(void)
{
    printf("--- the LED after a timeout ---\n");
    reset();
    gate(200000);
    CHECK(!led_state, "the LED was left blinking after the gate timed out");
}

/* ---- keepalives ----------------------------------------------------- */

static void t_keepalives_are_paced(void)
{
    printf("--- KEEPALIVE pacing ---\n");
    reset();
    gate(1000000);           /* 1 s */
    /* CTAPHID KEEPALIVE keeps the host's transaction alive and is what
     * makes a browser show "touch your key". Too few and the host times
     * out; one per loop iteration would flood the endpoint. */
    CHECK(keepalives >= 5,
          "only %d keepalives in a 1 s wait -- a host would time out",
          keepalives);
    CHECK(keepalives <= 200,
          "%d keepalives in a 1 s wait -- that is one per loop iteration, "
          "not a paced heartbeat", keepalives);
    printf("  (%d keepalives in 1 s)\n", keepalives);
}

int main(void)
{
    printf("FIDO HID presence-gate host test\n");
    fido_hid_install_tick();
    gate = ctap2_user_presence_hook;
    if (gate == NULL) {
        printf("  [FAIL] no presence hook was installed\n");
        return 1;
    }
    t_timeout();
    t_held_press_confirms();
    t_brief_touch_is_not_consent();
    t_hold_boundary();
    t_one_hold_does_not_authorise_twice();
    t_release_then_press_authorises_again();
    t_led_blinks_while_waiting();
    t_led_ends_solid_on_confirm();
    t_led_ends_off_on_timeout();
    t_keepalives_are_paced();
    printf("%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
