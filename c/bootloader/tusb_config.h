/* tusb_config.h -- TinyUSB configuration for the DFU bootloader.
 *
 * One device, one class: USB DFU 1.1 (DFU mode). No CDC, no HID --
 * the bootloader's whole USB surface is what `dfu-util` needs.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_BOOT_TUSB_CONFIG_H
#define PQF_BOOT_TUSB_CONFIG_H

#define CFG_TUSB_MCU                OPT_MCU_RP2040
#define CFG_TUSB_OS                 OPT_OS_PICO

#define CFG_TUSB_RHPORT0_MODE       (OPT_MODE_DEVICE | OPT_MODE_DEFAULT_SPEED)
#define CFG_TUD_ENABLED             1
#define CFG_TUD_ENDPOINT0_SIZE      64

#define CFG_TUD_DFU                 1
/* 4 KiB = wTransferSize = one RP2350 flash sector per DNLOAD block,
 * so every block is exactly one erase+program. */
#define CFG_TUD_DFU_XFER_BUFSIZE    4096

#define CFG_TUD_CDC                 0
#define CFG_TUD_HID                 0
#define CFG_TUD_MSC                 0
#define CFG_TUD_MIDI                0
#define CFG_TUD_VENDOR              0

#endif /* PQF_BOOT_TUSB_CONFIG_H */
