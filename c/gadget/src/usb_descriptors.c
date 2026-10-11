/* SPDX-License-Identifier: Apache-2.0
 *
 * USB descriptors for the pqf-gadget network device.
 *
 * Composite layout (docs/NETWORK-GADGET.md sec. 3.1):
 *   configuration 1:  CDC-NCM (2 interfaces, IAD)          -- always
 *                     CDC-ACM debug console (2 interfaces) -- unless the
 *                     NCM-only iOS-validation image (PQF_GADGET_CONSOLE=0)
 *
 * iOS is intolerant of malformed composite descriptors, so the interface
 * association descriptors come straight from TinyUSB's canonical macros and
 * the ECM fallback is deferred to a SECOND configuration once NCM is proven
 * (not interleaved into this one).
 *
 * Identity is stable across reconnects (plan sec. 3.1): both the MAC and the
 * serial string derive from the RP2350 flash unique ID -- a handset must see
 * the same interface every plug-in, or it renegotiates DHCP/mDNS state.
 * (Deliberately unlike the CTAP token's per-boot random serial, which works
 * around macOS's HID cache; a *network* interface wants the opposite.)
 */

#include <string.h>

#include "pico/unique_id.h"
#include "tusb.h"

#include "usb_descriptors.h"

#define USB_VID 0xcafe
#define USB_PID 0xf1d1 /* Bruce token is 0xf1d0; the gadget sits beside it */

/* Host-visible MAC of the device end of the link. Referenced by TinyUSB's
 * NCM driver and returned (hex-encoded) via the iMACAddress string. First
 * byte 0x02 = locally administered, unicast. */
uint8_t tud_network_mac_address[6];

static char serial_string[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];

void pqf_gadget_identity_init(void)
{
    pico_unique_board_id_t uid;
    pico_get_unique_board_id(&uid);

    tud_network_mac_address[0] = 0x02;
    memcpy(&tud_network_mac_address[1], &uid.id[3], 5);
    /* Keep the LSbit clear: net_glue gives lwIP this MAC with the LSbit
     * toggled, so both ends stay distinct and deterministic. */
    tud_network_mac_address[5] &= 0xFE;

    static const char hex[] = "0123456789ABCDEF";
    for (unsigned i = 0; i < PICO_UNIQUE_BOARD_ID_SIZE_BYTES; i++) {
        serial_string[2 * i]     = hex[uid.id[i] >> 4];
        serial_string[2 * i + 1] = hex[uid.id[i] & 0xF];
    }
    serial_string[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES] = '\0';
}

/* ---- Device descriptor ---- */

static const tusb_desc_device_t desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    /* Composite with IADs -- the shape iOS expects for multi-function. */
    .bDeviceClass       = TUSB_CLASS_MISC,
    .bDeviceSubClass    = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol    = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = USB_VID,
    .idProduct          = USB_PID,
    .bcdDevice          = 0x0001,
    .iManufacturer      = 1,
    .iProduct           = 2,
    .iSerialNumber      = 3,
    .bNumConfigurations = 1,
};

const uint8_t *tud_descriptor_device_cb(void)
{
    return (const uint8_t *) &desc_device;
}

/* ---- Configuration descriptor ---- */

enum {
    ITF_NUM_NCM = 0,
    ITF_NUM_NCM_DATA,
#if PQF_GADGET_CONSOLE
    ITF_NUM_CDC,
    ITF_NUM_CDC_DATA,
#endif
    ITF_NUM_TOTAL,
};

enum {
    STRID_LANGID = 0,
    STRID_MANUFACTURER,
    STRID_PRODUCT,
    STRID_SERIAL,
    STRID_NCM,
    STRID_MAC,
#if PQF_GADGET_CONSOLE
    STRID_CDC,
#endif
};

#define EPNUM_NCM_NOTIF 0x81
#define EPNUM_NCM_OUT   0x02
#define EPNUM_NCM_IN    0x82
#define EPNUM_CDC_NOTIF 0x83
#define EPNUM_CDC_OUT   0x04
#define EPNUM_CDC_IN    0x84

#if PQF_GADGET_CONSOLE
#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_CDC_NCM_DESC_LEN + TUD_CDC_DESC_LEN)
#else
#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_CDC_NCM_DESC_LEN)
#endif

static const uint8_t desc_configuration[] = {
    /* bMaxPower 100 mA -- honest for the RP2350 alone, and conservative
     * because phones are stingy USB hosts (plan: risks table). Revisit with
     * measured draw in the hardening phase. */
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0, 100),

    /* CDC-NCM: interface pair + IAD, MAC exposed via string descriptor. */
    TUD_CDC_NCM_DESCRIPTOR(ITF_NUM_NCM, STRID_NCM, STRID_MAC,
                           EPNUM_NCM_NOTIF, 64,
                           EPNUM_NCM_OUT, EPNUM_NCM_IN,
                           CFG_TUD_NET_ENDPOINT_SIZE, CFG_TUD_NET_MTU),

#if PQF_GADGET_CONSOLE
    /* CDC-ACM debug console. */
    TUD_CDC_DESCRIPTOR(ITF_NUM_CDC, STRID_CDC,
                       EPNUM_CDC_NOTIF, 8,
                       EPNUM_CDC_OUT, EPNUM_CDC_IN, 64),
#endif
};

const uint8_t *tud_descriptor_configuration_cb(uint8_t index)
{
    (void) index;
    return desc_configuration;
}

/* ---- String descriptors ---- */

static const char *const string_desc[] = {
    [STRID_MANUFACTURER] = "Bruce",
    [STRID_PRODUCT]      = "PQC FIDO network gadget",
    [STRID_NCM]          = "Management network (NCM)",
#if PQF_GADGET_CONSOLE
    [STRID_CDC]          = "Debug console",
#endif
};

const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
    (void) langid;
    static uint16_t desc[32 + 1];
    unsigned len = 0;

    if (index == STRID_LANGID) {
        desc[1] = 0x0409; /* en-US */
        len = 1;
    } else if (index == STRID_SERIAL) {
        for (; serial_string[len] && len < 32; len++) desc[1 + len] = serial_string[len];
    } else if (index == STRID_MAC) {
        /* iMACAddress: 12 uppercase hex chars, per CDC-ECM/NCM spec. */
        static const char hex[] = "0123456789ABCDEF";
        for (unsigned i = 0; i < 6; i++) {
            desc[1 + len++] = hex[tud_network_mac_address[i] >> 4];
            desc[1 + len++] = hex[tud_network_mac_address[i] & 0xF];
        }
    } else if (index < TU_ARRAY_SIZE(string_desc) && string_desc[index] != NULL) {
        const char *s = string_desc[index];
        for (; s[len] && len < 32; len++) desc[1 + len] = s[len];
    } else {
        return NULL;
    }

    desc[0] = (uint16_t) ((TUSB_DESC_STRING << 8) | (2 * len + 2));
    return desc;
}
