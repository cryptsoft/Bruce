/* usb_descriptors.c -- USB descriptors for the DFU-mode bootloader.
 *
 * A single-interface DFU 1.1 device (class 0xFE/1, protocol 2) with
 * one alternate setting ("firmware" = the app slot). Deliberately the
 * SAME VID:PID as the application: dfu-util distinguishes runtime vs
 * DFU mode by bInterfaceProtocol, so a plain
 *
 *     dfu-util -D bruce_c.dfu
 *
 * detaches the running app, waits for this device to enumerate, and
 * downloads -- one command, no -d gymnastics.
 *
 * Descriptor scaffolding adapted from TinyUSB examples/device/dfu
 * (MIT License, Copyright (c) 2019 Ha Thach) -- see THIRD_PARTY.md.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdio.h>

#include "tusb.h"
#include "usb_descriptors.h"

#define USB_VID     0xcafe
#define USB_PID     0xf1d0

/* ---- Device descriptor ------------------------------------------- */

static const tusb_desc_device_t desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = 0x00,             /* per-interface           */
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = USB_VID,
    .idProduct          = USB_PID,
    .bcdDevice          = 0x0200,           /* 2.x = bootloader        */
    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,
    .bNumConfigurations = 0x01,
};

uint8_t const *tud_descriptor_device_cb(void)
{
    return (const uint8_t *)&desc_device;
}

/* ---- Configuration descriptor ------------------------------------ */

#define CONFIG_TOTAL_LEN    (TUD_CONFIG_DESC_LEN + TUD_DFU_DESC_LEN(1))

/* No upload: firmware never leaves a security token. Manifestation-
 * tolerant: after a successful manifest the device answers dfuIDLE
 * (dfu-util prints "Done!") and reboots itself moments later.
 *
 * NOTE (hardware-observed, Tiny 2350 2026-07-20): with the tolerant
 * bit set, a manifest-time errVERIFY IS reported by the device
 * (dfu-util prints "dfuERROR, status(7) = ...") and the image is
 * NOT installed -- the rejection is correct -- but dfu-util 0.11 still
 * exits 0. Clearing DFU_ATTR_MANIFESTATION_TOLERANT would leave the
 * device parked in dfuERROR so the host errors out too, at the cost
 * of a mandatory USB reset on every (including successful) update.
 * Left tolerant for now; the device-side rejection is the security
 * boundary, the host exit code is cosmetic. Revisit if CI needs a
 * nonzero dfu-util exit on rejection. */
#define DFU_FUNC_ATTRS  (DFU_ATTR_CAN_DOWNLOAD | DFU_ATTR_MANIFESTATION_TOLERANT)

static const uint8_t desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, CONFIG_TOTAL_LEN, 0x00, 100),
    /* itf 0, 1 alt setting, alt-name string index 4, 1000 ms detach
     * timeout, 4 KiB transfers (= one flash sector per block). */
    TUD_DFU_DESCRIPTOR(0, 1, 4, DFU_FUNC_ATTRS, 1000,
                       CFG_TUD_DFU_XFER_BUFSIZE),
};

uint8_t const *tud_descriptor_configuration_cb(uint8_t index)
{
    (void)index;
    return desc_configuration;
}

/* ---- String descriptors ------------------------------------------ */

static const char *const desc_string_table[] = {
    (const char *)"\x09\x04",       /* 0: English (0x0409)            */
    "Bruce",                     /* 1: manufacturer                */
    "Bruce DFU bootloader",      /* 2: product                     */
    "PQF-DFU",                      /* 3: serial -- see serial_string() */
    "firmware",                     /* 4: alt 0 = the app slot        */
};

static uint16_t string_buffer[32];

/* The serial string doubles as the crash channel. main.c arms a
 * watchdog across every flash op and leaves the stage it reached in
 * the watchdog scratch registers; if a run was killed mid-op we report
 * it here as "PQF-DFU-Ennn-Ssss" (E = stage code, S = sector index).
 * `dfu-util -l` prints it, so the step that hung is visible with no
 * debugger, no UART and nobody touching the board. A clean boot keeps
 * the plain "PQF-DFU". */
extern uint32_t pqf_dfu_trace_last;
extern uint32_t pqf_dfu_trace_sector;

static char serial_buf[24];

static const char *serial_string(void)
{
    if (pqf_dfu_trace_last == 0)
        return "PQF-DFU";
    snprintf(serial_buf, sizeof serial_buf, "PQF-DFU-E%02u-S%04u",
             (unsigned)(pqf_dfu_trace_last & 0xFFu),
             (unsigned)(pqf_dfu_trace_sector & 0xFFFFu));
    return serial_buf;
}

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
    (void)langid;
    size_t chr_count = 0;

    if (index == 0) {
        memcpy(&string_buffer[1], desc_string_table[0], 2);
        chr_count = 1;
    } else if (index < (sizeof(desc_string_table)
                        / sizeof(desc_string_table[0]))) {
        const char *str = (index == 3) ? serial_string()
                                       : desc_string_table[index];
        chr_count = strlen(str);
        if (chr_count > 31) chr_count = 31;
        for (size_t i = 0; i < chr_count; i++)
            string_buffer[1 + i] = (uint16_t)str[i];
    } else {
        return NULL;
    }

    string_buffer[0] = (uint16_t)((TUSB_DESC_STRING << 8)
                                  | (2 * chr_count + 2));
    return string_buffer;
}
