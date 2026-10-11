/* usb_descriptors.h -- interface numbering for the composite USB
 * device. Shared between the descriptor table (`usb_descriptors.c`)
 * and the TinyUSB callback wiring (`fido_hid.c`).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_USB_DESCRIPTORS_H
#define PQF_USB_DESCRIPTORS_H

#include <stdint.h>
#include <stddef.h>

/* Interface numbers in the configuration descriptor.
 *
 * CDC ACM takes two interfaces: one for the control class (CDC
 * Control), one for the data class (CDC Data). They MUST be
 * adjacent -- the host treats them as an Interface Association.
 */
#define ITF_NUM_CDC             0   /* CDC Control                  */
#define ITF_NUM_CDC_DATA        1   /* CDC Data                     */
#define ITF_NUM_HID             2   /* FIDO HID                     */
/* Two optional interfaces may follow, and they are numbered
 * sequentially so that either, both, or neither can be enabled:
 *
 *   PQF_GDB_STUB     a second CDC pair (2 interfaces) for the on-token
 *                    GDB remote-serial-protocol stub (gdbstub.c);
 *   PQF_DFU_RUNTIME  a DFU *runtime* interface (1 interface, control
 *                    endpoint only) so `dfu-util -D` can DETACH the
 *                    running token into the DFU bootloader.
 *
 * Both were originally written as the single "extra" interface and
 * both claimed interface 3 and string index 6. Chaining them off
 * PQF_ITF_AFTER_GDB / PQF_STRID_AFTER_GDB keeps the production
 * numbering (CDC 0/1, HID 2) fixed in every combination. */
#if defined(PQF_GDB_STUB)
#define ITF_NUM_GDB             3   /* GDB CDC Control              */
#define ITF_NUM_GDB_DATA        4   /* GDB CDC Data                 */
#define PQF_ITF_AFTER_GDB       5
#define PQF_STRID_GDB           6
#define PQF_STRID_AFTER_GDB     7
/* TinyUSB CDC instance index of the GDB channel (instance order
 * follows descriptor order: 0 = banner port, 1 = GDB). */
#define PQF_GDB_CDC_ITF         1
#else
#define PQF_ITF_AFTER_GDB       3
#define PQF_STRID_AFTER_GDB     6
#endif

#if defined(PQF_DFU_RUNTIME)
#define ITF_NUM_DFU_RT          PQF_ITF_AFTER_GDB
#define PQF_STRID_DFU_RT        PQF_STRID_AFTER_GDB
#define ITF_NUM_TOTAL           (PQF_ITF_AFTER_GDB + 1)
#else
#define ITF_NUM_TOTAL           PQF_ITF_AFTER_GDB
#endif

/* TinyUSB HID instance index (we have only one HID interface). */
#define FIDO_HID_INSTANCE       0

/* The FIDO HID report descriptor. Declared here so the
 * `tud_hid_descriptor_report_cb` implementation in `fido_hid.c` can
 * return its address. The bytes themselves live in
 * `usb_descriptors.c`. */
extern const uint8_t pqf_hid_report_desc[];
extern const size_t  pqf_hid_report_desc_len;

/* Randomize the USB serial-number string for this boot (macOS
 * HID-cache workaround -- see the comment in usb_descriptors.c). Must
 * be called BEFORE tud_init() so the first descriptor read already
 * sees the fresh serial. */
void pqf_usb_serial_randomize(void);

#endif /* PQF_USB_DESCRIPTORS_H */
