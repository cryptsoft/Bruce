/* usb_descriptors.c -- composite USB device descriptors + TinyUSB
 * descriptor callbacks.
 *
 * Layout:
 *
 *   Device:            single composite device, VID/PID below.
 *   Configuration:     one config bundling CDC + HID.
 *   CDC (itf 0+1):     virtual serial port for banner / debug
 *                      output. Endpoint addresses 0x81 (notif),
 *                      0x02 / 0x82 (bulk).
 *   HID (itf 2):       FIDO HID with 64-byte interrupt IN / OUT
 *                      reports. Endpoint addresses 0x03 / 0x83.
 *
 * The HID report descriptor follows FIDO CTAP sec. 8.1.8.2 verbatim:
 * usage page 0xF1D0 (FIDO Alliance), usage 0x01 (CTAPHID), in a
 * single Application collection with one 64-byte Input report and
 * one 64-byte Output report.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "pqf_rand.h"
#include "tusb.h"
#include "usb_descriptors.h"

/* ---- Device descriptor ----------------------------------------- */

/* Vendor / product IDs. We use TinyUSB's demo-VID + a project-local
 * PID for now. A real release would register a vendor ID with the
 * USB-IF or use a sub-allocated PID from a vendor that has one. */
#define USB_VID         0xcafe
#define USB_PID         0xf1d0   /* visually matches the FIDO usage page */

static const tusb_desc_device_t desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,

    /* Interface Association Descriptor class triplet -- required
     * for any composite device whose interfaces span more than one
     * class (CDC + HID here). */
    .bDeviceClass       = TUSB_CLASS_MISC,
    .bDeviceSubClass    = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol    = MISC_PROTOCOL_IAD,

    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = USB_VID,
    .idProduct          = USB_PID,
    .bcdDevice          = 0x0100,

    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,

    .bNumConfigurations = 0x01,
};

uint8_t const *tud_descriptor_device_cb(void)
{
    return (const uint8_t *)&desc_device;
}

/* ---- HID report descriptor (FIDO CTAP sec. 8.1.8.2) ---------------- */

const uint8_t pqf_hid_report_desc[] = {
    0x06, 0xD0, 0xF1,       /* Usage Page (FIDO Alliance, 0xF1D0)   */
    0x09, 0x01,             /* Usage (CTAPHID)                      */
    0xA1, 0x01,             /* Collection (Application)             */
    0x09, 0x20,             /*   Usage (Input Report Data)          */
    0x15, 0x00,             /*   Logical Min (0)                    */
    0x26, 0xFF, 0x00,       /*   Logical Max (255)                  */
    0x75, 0x08,             /*   Report Size (8)                    */
    0x95, 0x40,             /*   Report Count (64)                  */
    0x81, 0x02,             /*   Input (Data, Variable, Absolute)   */
    0x09, 0x21,             /*   Usage (Output Report Data)         */
    0x15, 0x00,             /*   Logical Min (0)                    */
    0x26, 0xFF, 0x00,       /*   Logical Max (255)                  */
    0x75, 0x08,             /*   Report Size (8)                    */
    0x95, 0x40,             /*   Report Count (64)                  */
    0x91, 0x02,             /*   Output (Data, Variable, Absolute)  */
    0xC0,                   /* End Collection                       */
};
const size_t pqf_hid_report_desc_len = sizeof(pqf_hid_report_desc);

/* ---- Configuration descriptor ---------------------------------- */

/* Endpoint addresses. The high bit (0x80) marks IN endpoints. */
#define EPNUM_CDC_NOTIF     0x81
#define EPNUM_CDC_OUT       0x02
#define EPNUM_CDC_IN        0x82
#define EPNUM_HID_OUT       0x03
#define EPNUM_HID_IN        0x83
#if defined(PQF_GDB_STUB)
/* Second CDC pair: the GDB stub channel (debug builds only). */
#define EPNUM_GDB_NOTIF     0x84
#define EPNUM_GDB_OUT       0x05
#define EPNUM_GDB_IN        0x85
#endif

#if defined(PQF_GDB_STUB)
#define PQF_GDB_DESC_LEN        TUD_CDC_DESC_LEN
#else
#define PQF_GDB_DESC_LEN        0
#endif
#if defined(PQF_DFU_RUNTIME)
#define PQF_DFU_RT_DESC_LEN     TUD_DFU_RT_DESC_LEN
#else
#define PQF_DFU_RT_DESC_LEN     0
#endif
#define CONFIG_TOTAL_LEN    (TUD_CONFIG_DESC_LEN \
                             + TUD_CDC_DESC_LEN \
                             + TUD_HID_INOUT_DESC_LEN \
                             + PQF_GDB_DESC_LEN \
                             + PQF_DFU_RT_DESC_LEN)

/* Polling interval for the HID interrupt endpoints, in ms. The
 * CTAP HID spec does not require a particular value; 5 ms matches
 * what most production FIDO tokens advertise. */
#define HID_POLL_INTERVAL_MS    5

static const uint8_t desc_configuration[] = {
    /* Single config, 3 interfaces, no remote wakeup, 100 mA bus. */
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN,
                          0x00, 100),

    /* CDC ACM: control on iManufacturer string index 4, data
     * endpoints below. */
    TUD_CDC_DESCRIPTOR(ITF_NUM_CDC, 4, EPNUM_CDC_NOTIF, 8,
                       EPNUM_CDC_OUT, EPNUM_CDC_IN, 64),

    /* HID INOUT: FIDO report descriptor above; 64-byte IN + OUT. */
    TUD_HID_INOUT_DESCRIPTOR(ITF_NUM_HID, 5,
                             HID_ITF_PROTOCOL_NONE,
                             sizeof(pqf_hid_report_desc),
                             EPNUM_HID_OUT, EPNUM_HID_IN,
                             CFG_TUD_HID_EP_BUFSIZE,
                             HID_POLL_INTERVAL_MS),

#if defined(PQF_GDB_STUB)
    /* GDB stub CDC (debug builds): a second virtual serial port that
     * speaks the GDB remote serial protocol -- `target remote <tty>`.
     * Appended last so the banner CDC and FIDO HID keep their
     * interface numbers. See gdbstub.c / docs/GDB_DEBUG.md. */
    TUD_CDC_DESCRIPTOR(ITF_NUM_GDB, PQF_STRID_GDB, EPNUM_GDB_NOTIF, 8,
                       EPNUM_GDB_OUT, EPNUM_GDB_IN, 64),
#endif

#if defined(PQF_DFU_RUNTIME)
    /* DFU runtime (control endpoint only, no data endpoints): lets
     * `dfu-util -D` DETACH the running token into the DFU bootloader
     * (see the reboot hook in main.c). bmAttributes advertise the
     * DFU-mode device's capabilities: can download, will self-detach.
     * 1000 ms detach window, 4 KiB transfers -- must mirror the
     * bootloader's DFU-mode descriptor (c/bootloader/). */
    TUD_DFU_RT_DESCRIPTOR(ITF_NUM_DFU_RT, PQF_STRID_DFU_RT,
                          DFU_ATTR_CAN_DOWNLOAD | DFU_ATTR_WILL_DETACH,
                          1000, 4096),
#endif
};

uint8_t const *tud_descriptor_configuration_cb(uint8_t index)
{
    (void)index;
    return desc_configuration;
}

/* ---- String descriptors --------------------------------------- */

/* Per-boot randomized serial number -- the same macOS HID-cache
 * workaround the Rust port carries (see main.rs): with a fixed
 * serial, macOS treats every re-enumeration of the VID/PID/serial
 * triple as the SAME device and serves stale IOHIDDevice state
 * (capability bits, e.g. "no CBOR") cached from whatever firmware
 * was flashed before, until a physical replug. A fresh serial every
 * boot makes each enumeration look like a new device, forcing the
 * host to re-query INIT/getInfo from scratch. Filled by
 * pqf_usb_serial_randomize() before tud_init(); the placeholder
 * survives only if that call is somehow skipped.
 *
 * The bytes come from the entropy picker (pqf_rand.h), not from a raw
 * source: the serial is not secret, but every random need in this
 * firmware goes through the same queue, so the QRNG feeds it too when
 * one is attached. main() runs pqf_rand_init() before this. */
static char serial_string[9] = "PQF-C-XX";

void pqf_usb_serial_randomize(void)
{
    static const char hex[] = "0123456789ABCDEF";
    uint8_t r[4];
    pqf_rand_bytes(r, sizeof r);
    for (size_t i = 0; i < 8; i++)
        serial_string[i] = hex[(r[i / 2] >> ((i & 1) * 4)) & 0xF];
    serial_string[8] = '\0';
}

/* Strings indexed by the iManufacturer / iProduct / iSerialNumber
 * / iInterface fields in the descriptors above. Index 0 is the
 * supported-languages list (English-US). */
static const char *const desc_string_table[] = {
    (const char *)"\x09\x04",      /* 0: lang = English (0x0409) */
    "Bruce",                     /* 1: manufacturer            */
    "Bruce (C port)",            /* 2: product                 */
    serial_string,                  /* 3: serial number (per-boot random) */
    "Bruce debug serial",        /* 4: CDC interface           */
    "Bruce FIDO HID",            /* 5: HID interface           */
#if defined(PQF_GDB_STUB)
    "Bruce GDB stub",            /* 6: GDB CDC interface       */
#endif
#if defined(PQF_DFU_RUNTIME)
    "Bruce DFU runtime",         /* DFU runtime interface      */
#endif
};

/* TinyUSB hands us a scratch buffer to populate with the
 * UTF-16-encoded string. Up to 32 code units after the length /
 * descriptor-type header. */
static uint16_t string_buffer[32];

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
    (void)langid;
    size_t chr_count = 0;

    if (index == 0) {
        memcpy(&string_buffer[1], desc_string_table[0], 2);
        chr_count = 1;
    } else if (index < (sizeof(desc_string_table)
                        / sizeof(desc_string_table[0]))) {
        const char *str = desc_string_table[index];
        chr_count = strlen(str);
        if (chr_count > 31) chr_count = 31;
        for (size_t i = 0; i < chr_count; i++) {
            string_buffer[1 + i] = (uint16_t)str[i];
        }
    } else {
        return NULL;
    }

    /* USB string descriptor header: length (in bytes) + type. */
    string_buffer[0] = (uint16_t)((TUSB_DESC_STRING << 8)
                                  | (2 * chr_count + 2));
    return string_buffer;
}
