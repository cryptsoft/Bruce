/* fido_hid.h -- TinyUSB HID glue for the FIDO interface.
 *
 * Exposes one entry point -- fido_hid_send_frame() -- used by the
 * CTAPHID dispatcher to push a 64-byte HID IN report up to the
 * host. The matching receive direction is handled inside
 * fido_hid.c via TinyUSB's `tud_hid_set_report_cb` callback.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_FIDO_HID_H
#define PQF_FIDO_HID_H

#include <stdint.h>

/* Send one 64-byte CTAP HID report to the host. Returns non-zero on
 * a successful enqueue, zero if the IN endpoint was still busy
 * with the previous report (caller may retry / drop). */
int fido_hid_send_frame(const uint8_t *frame64);

/* Service the USB stack. On Arm this is just tud_task() (the USBCTRL
 * IRQ delivers controller events as usual). On RISC-V (Hazard3) the
 * USBCTRL IRQ is left DISABLED (see main.c) and this polls the
 * TinyUSB controller handler inline first -- the whole firmware then
 * runs interrupt-free, matching the silicon-validated Rust port's
 * concurrency model. Every place that used to pump tud_task() must
 * call this instead. */
void pqf_usb_task(void);

/* Install the long-op tick (USB service + CTAPHID KEEPALIVE) into
 * core1_long_op_tick. Call once at boot, after core1_signer_init. */
void fido_hid_install_tick(void);

/* Sweep the CTAPHID reassembly inactivity timeout (L16). Call once per
 * main-loop iteration; aborts a stalled partial message with
 * ERR_MSG_TIMEOUT even when no further frames arrive. */
void fido_hid_poll_timeout(void);

#endif /* PQF_FIDO_HID_H */
