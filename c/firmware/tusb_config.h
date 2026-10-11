/* tusb_config.h -- TinyUSB configuration for Bruce (C port).
 *
 * pico-sdk's TinyUSB integration looks for this file at the project
 * include root. We compose **one** USB device with two classes:
 *
 *   - CDC ACM (interface 0 + 1): a virtual serial port for banner /
 *     debug output, replacing what `pico_enable_stdio_usb(1)` used
 *     to provide in Phase C-1. The host opens it as a regular tty
 *     (e.g. `/dev/cu.usbmodem...` on macOS, `/dev/ttyACM0` on
 *     Linux) and can `screen` it.
 *
 *   - HID (interface 2): the FIDO/CTAPHID transport -- 64-byte raw
 *     interrupt IN and OUT reports on the FIDO usage page 0xF1D0.
 *     This is the interface `fido2-token -L`, libfido2, and
 *     `python-fido2` enumerate.
 *
 * Both share the same single USB device address; the host's CDC
 * client and FIDO client coexist without conflict.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_TUSB_CONFIG_H
#define PQF_TUSB_CONFIG_H

/* MCU + OS hooks. RP2350 reuses TinyUSB's RP2040 port driver -- the
 * USB controller is the same IP block. */
#define CFG_TUSB_MCU                OPT_MCU_RP2040
#define CFG_TUSB_OS                 OPT_OS_PICO

/* Single-port device mode. */
#define CFG_TUSB_RHPORT0_MODE       (OPT_MODE_DEVICE | OPT_MODE_DEFAULT_SPEED)
#define CFG_TUD_ENABLED             1
#define CFG_TUD_ENDPOINT0_SIZE      64

/* Interface counts. We use CDC + HID; no MSC / MIDI / vendor.
 * Debug builds (-DPQF_GDB_STUB=ON) add a second CDC instance carrying
 * the on-token GDB stub (gdbstub.c) -- instance 0 stays the banner /
 * BOOTSEL-magic port, instance 1 is the `target remote` channel. */
#if defined(PQF_GDB_STUB)
#define CFG_TUD_CDC                 2
#else
#define CFG_TUD_CDC                 1
#endif
#define CFG_TUD_HID                 1
#define CFG_TUD_MSC                 0
#define CFG_TUD_MIDI                0
#define CFG_TUD_VENDOR              0

/* CDC ring-buffer sizes. The values mirror TinyUSB's example for a
 * mostly-write-from-device, light-read-from-host workload (banners
 * out, no real input). GDB-stub builds take a deeper RX ring: GDB
 * front-loads multi-hundred-byte command packets (G writes, fat M
 * writes) and a 64-byte ring costs a NAK-retry round-trip per frame. */
#if defined(PQF_GDB_STUB)
#define CFG_TUD_CDC_RX_BUFSIZE      256
#else
#define CFG_TUD_CDC_RX_BUFSIZE      64
#endif
#define CFG_TUD_CDC_TX_BUFSIZE      256

/* FIDO HID frame size. The CTAP HID spec mandates 64-byte reports
 * (FIDO CTAP sec. 8.1.4) so this is non-negotiable. */
#define CFG_TUD_HID_EP_BUFSIZE      64

/* DFU *runtime* interface (PQF_BOOTLOADER builds only): lets
 * `dfu-util` send DFU_DETACH to the running token, which reboots into
 * the DFU bootloader for a firmware update. Control-endpoint only --
 * no extra endpoints, no buffers. The DFU-mode class stays off; that
 * lives in the bootloader (c/bootloader/). */
#if defined(PQF_DFU_RUNTIME)
#define CFG_TUD_DFU_RUNTIME         1
#endif

#endif /* PQF_TUSB_CONFIG_H */
