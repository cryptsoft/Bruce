/* fido_hid.c -- TinyUSB FIDO HID class glue.
 *
 * Owns three callbacks TinyUSB calls into:
 *
 *   tud_hid_descriptor_report_cb : returns the FIDO HID report
 *                                  descriptor (defined in
 *                                  usb_descriptors.c).
 *   tud_hid_get_report_cb        : host-side GET_REPORT -- FIDO
 *                                  doesn't use it, so we report
 *                                  zero bytes.
 *   tud_hid_set_report_cb        : host wrote a 64-byte report to
 *                                  our HID OUT endpoint. We hand
 *                                  it straight to the CTAPHID
 *                                  dispatcher.
 *
 * Plus one outward-bound helper, fido_hid_send_frame(), used by
 * the dispatcher to push response frames back via TinyUSB's HID
 * IN endpoint.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pico/time.h"
#include "tusb.h"
#include "class/hid/hid_device.h"

#include "fido_hid.h"
#include "usb_descriptors.h"
#include "ctaphid.h"
#include "ctap2.h"
#include "core1_signer.h"
#include "board.h"
#include "gdbstub.h"

/* Service the USB stack -- the single pump every wait loop in this
 * firmware calls.
 *
 * Arm: the USBCTRL IRQ is live; controller events were already
 * handled at interrupt time, so this is just TinyUSB's deferred task.
 *
 * RISC-V (Hazard3): the USBCTRL IRQ is deliberately DISABLED (main.c)
 * and the controller handler is POLLED here instead, so the firmware
 * runs with zero enabled interrupts -- the same concurrency model as
 * the silicon-validated Rust RISC-V port. Motivation: the pure
 * RISC-V build froze non-deterministically at runtime flash commits
 * (the park handshake / XIP-off window), and interrupt delivery was
 * the one systemic difference from the Rust port on identical
 * silicon -- the freeze always brackets the points where a masked,
 * pended IRQ burst would be delivered (the ack-wait spin and the
 * restore_interrupts() after the boot-ROM erase/program). The
 * vendored crypto itself was exonerated by a QEMU differential test
 * (bit-identical to a host reference across keygen/ECDH/ECDSA/ML-DSA
 * with the same GCC + flags). Polling tud_int_handler() from thread
 * context is TinyUSB-supported (single caller, no reentrancy) and at
 * main-loop rates far outpaces the 1 ms full-speed frame cadence. */
void pqf_usb_task(void)
{
#if defined(__riscv)
    tud_int_handler(0);         /* poll the controller: no USBCTRL IRQ */
#endif
    tud_task();
}

/* Long-op tick: while core 1 computes a hybrid PQC signature, core 0
 * sits in core1_hybrid_sign()'s poll loop calling this. It services
 * the USB stack (so the device stays responsive + drains the HID IN
 * endpoint) and emits a CTAPHID KEEPALIVE on the in-flight channel.
 * Registered into core1_long_op_tick at boot (fido_hid_install_tick). */
static void long_op_tick(void)
{
    pqf_usb_task();
    /* GDB stub: keep the GDB channel serviced while core 0 sits in a
     * multi-second sign wait -- this is exactly the moment a developer
     * wants Ctrl-C to work. Thread-level and outside tud_task(), so
     * it's a safe halt site. No-op in non-debug builds. */
    pqf_gdb_poll();
    ctaphid_keepalive_pump();
}

/* Real user-presence wait -- the C analog of the Rust port's
 * host(HostOp::WaitForUp) loop in main.rs, installed as
 * ctap2_user_presence_hook. Runs INSIDE the CTAPHID CBOR dispatch (so
 * the in-flight channel is armed for KEEPALIVE), pumping tud_task() the
 * same way the long-op sign tick and fido_hid_send_frame() already do.
 *
 * While waiting it blinks the status LED and emits KEEPALIVE(UPNEEDED)
 * every 50 ms so the browser shows "touch your key", and polls the
 * board button for a FRESH release->press gesture (a button still held
 * from a previous op does NOT count), requiring the press to hold ~20 ms
 * (debounce). Returns true on a confirmed press, false after
 * timeout_us. On buttonless boards it auto-confirms immediately,
 * mirroring the Rust `if !HAS_USER_BUTTON { return true }`. */
/* How long the pad must read PRESSED, continuously, to count as a press.
 *
 * 20 ms is a plain debounce and is what this build ships with: a normal
 * press, not a deliberate hold.
 *
 * Be aware this is NOT sufficient to reject the spurious presses measured
 * on this board -- roughly 180 ms episodic bursts on the
 * BOOTSEL-through-QSPI read, which at 20 ms let five untouched
 * MakeCredentials out of five through. Raising it narrows the window
 * (250 ms leaked 1 of 9; 750 ms was built but never measured) at the cost
 * of requiring a longer hold. Override without editing:
 *
 *     cmake -DPQF_UP_HOLD_US=750000 ...
 *
 * The real fix is to stop the false presses, not to outwait them. See
 * docs/notes/UP-GATE-RETRACTED.md. */
#ifndef PQF_UP_HOLD_US
#define PQF_UP_HOLD_US 20000u
#endif

static bool wait_for_up(uint32_t timeout_us)
{
#if !PQF_BOARD_HAS_USER_BUTTON
    (void)timeout_us;
    return true;                       /* no readable button: auto-confirm */
#else
    absolute_time_t deadline   = make_timeout_time_us(timeout_us);
    absolute_time_t next_blink = get_absolute_time();
    absolute_time_t next_pump  = get_absolute_time();
    bool led = false;

    /* Presence wait = a CLEAN rapid blink: drop the solid "processing"
     * light (set around the CBOR dispatch in tud_hid_set_report_cb) so
     * on single-LED boards the rapid blink is actually visible instead
     * of being held on by the busy indicator. Solid = busy; rapid
     * blink = "press the button". Mirrors the Rust port's WaitForUp. */
    pqf_board_led_set(false);

    /* Only accept a press once the pad has been seen released, so one
     * continuous hold can't satisfy back-to-back operations (matches
     * the Rust loop's `saw_release`). */
    bool saw_release = !pqf_board_user_present();
    bool press_timing = false;
    absolute_time_t pressed_since = get_absolute_time();

    for (;;) {
        pqf_usb_task();                /* keep USB alive + catch CANCEL */
        pqf_gdb_poll();                /* GDB stub: Ctrl-C works during the UP wait */

        bool touched = pqf_board_user_present();
        if (!touched) {
            saw_release = true;
            press_timing = false;
        } else if (saw_release) {
            if (!press_timing) {
                press_timing = true;
                pressed_since = get_absolute_time();
            } else if (absolute_time_diff_us(pressed_since,
                                             get_absolute_time()) >= PQF_UP_HOLD_US) {
                /* Confirmed -> back to the solid "processing" light for
                 * the (multi-second, core-1) sign that follows. */
                pqf_board_led_set(true);
                return true;
            }
        }

        if (time_reached(deadline)) {
            pqf_board_led_set(false);
            return false;
        }
        if (time_reached(next_blink)) {
            /* Rapid 50 ms toggle (10 Hz) -- the ONLY blinking pattern
             * in the LED model (idle and busy are both solid), so
             * "press the button" is unmistakable. */
            led = !led;
            pqf_board_led_set(led);
            next_blink = make_timeout_time_ms(50);
        }
        if (time_reached(next_pump)) {
            ctaphid_send_keepalive(CTAPHID_STATUS_UPNEEDED);
            next_pump = make_timeout_time_ms(50);
        }
    }
#endif
}

void fido_hid_install_tick(void)
{
    core1_long_op_tick = long_op_tick;
    ctap2_user_presence_hook = wait_for_up;
}

/* ---- Outbound helper exported to ctaphid.c --------------------- */

int fido_hid_send_frame(const uint8_t *frame64)
{
    /* TinyUSB's HID IN FIFO is one report deep. When we ship a
     * multi-frame CTAP response (INIT response + multi-frame CBOR
     * response, all in the same dispatch), we'd otherwise enqueue
     * back-to-back faster than the host can drain -- the 2nd and
     * 3rd calls would silently fail and the host would only see
     * the first frame.
     *
     * Block until the IN endpoint can accept another report,
     * pumping tud_task() while we wait so endpoint-complete IRQs
     * actually fire. Safe vs reentrancy because the CTAPHID
     * dispatcher snapshots and clears its active-transaction state
     * BEFORE calling into the response builder (see
     * dispatch_complete() in ctaphid.c), so a nested OUT report
     * processed by tud_task() can't corrupt our outer send.
     */
    while (!tud_hid_n_ready(FIDO_HID_INSTANCE)) {
        pqf_usb_task();
    }
    /* report_id = 0 -> TinyUSB does NOT prepend a report-ID byte.
     * Matches what FIDO hosts expect on the wire. */
    return tud_hid_n_report(FIDO_HID_INSTANCE, 0, frame64, 64) ? 1 : 0;
}

/* The ctaphid_send_fn signature is void; wrap accordingly. */
static void ctaphid_send_via_hid(const uint8_t *frame64)
{
    (void)fido_hid_send_frame(frame64);
}

/* Main-loop sweep for the CTAPHID reassembly inactivity timeout (L16).
 * The on-frame sweep in ctaphid_recv_frame only fires when a frame
 * arrives; a host that sends an INIT with a large BCNT and then goes
 * silent would otherwise wedge the single reassembly slot forever. The
 * main loop calls this every iteration so a stalled partial message is
 * aborted with ERR_MSG_TIMEOUT after ~500 ms regardless of traffic. */
void fido_hid_poll_timeout(void)
{
    ctaphid_poll_timeout(ctaphid_send_via_hid);
}

/* ---- TinyUSB descriptor / report callbacks --------------------- */

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance)
{
    (void)instance;
    return pqf_hid_report_desc;
}

uint16_t tud_hid_get_report_cb(uint8_t instance,
                                uint8_t report_id,
                                hid_report_type_t report_type,
                                uint8_t *buffer, uint16_t reqlen)
{
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)reqlen;
    /* FIDO devices never service host-initiated GET_REPORT -- all
     * device-to-host traffic comes through the interrupt IN
     * endpoint. Returning 0 stalls the request, which is the
     * spec-conformant answer. */
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance,
                            uint8_t report_id,
                            hid_report_type_t report_type,
                            const uint8_t *buffer,
                            uint16_t bufsize)
{
    (void)instance;
    (void)report_id;

    /* Distinguish a true OUT-endpoint report from a control-pipe
     * SET_REPORT. FIDO hosts always use the interrupt OUT
     * endpoint; we accept either but require exactly 64 bytes. */
    if (report_type != HID_REPORT_TYPE_INVALID
        && report_type != HID_REPORT_TYPE_OUTPUT) {
        return;
    }
    if (bufsize != 64) {
        return;
    }

    /* Busy light: solid while a dispatch runs (a hybrid PQC sign on
     * core 1 takes seconds -- without this the LED sits dark and the
     * device looks hung; the Rust port shows the same solid
     * "processing" light). wait_for_up repaints the LED during its
     * gate; the idle heartbeat (led_task in main.c) resumes after we
     * return. Depth-tracked because a nested tud_task() inside the
     * keepalive pump / send wait can re-enter this callback (answered
     * with CHANNEL_BUSY by the dispatcher) -- the nested exit must not
     * kill the outer dispatch's busy light. */
    static uint8_t busy_depth;
    if (busy_depth++ == 0)
        pqf_board_led_set(true);
    ctaphid_recv_frame(buffer, ctaphid_send_via_hid);
    if (--busy_depth == 0)
        pqf_board_led_set(false);
}
