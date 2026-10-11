/* test_usb_descriptors.c -- the bytes a host reads before anything works.
 *
 * USB descriptors are the first thing that happens on every plug-in, and
 * they are the one part of the firmware where a mistake is *silent*: an
 * inconsistent descriptor does not crash, it just makes the device
 * enumerate wrongly, or not at all, or work on one host and not another.
 * The gadget plan noted iOS is intolerant of malformed composite
 * descriptors; so is Windows, in different ways.
 *
 * Nothing has ever checked them. They are built from TinyUSB macros with
 * a hand-written CONFIG_TOTAL_LEN and hand-assigned interface and
 * endpoint numbers, which is exactly the arrangement that drifts: add an
 * interface, forget the total, and the host reads a truncated
 * configuration.
 *
 * These tests walk the real emitted bytes -- the same macros the
 * firmware compiles, via a host tusb_config.h that differs only in the
 * OSAL selection -- rather than re-deriving what they ought to be.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "tusb.h"
#include "usb_descriptors.h"

/* pqf_rand.h shim: the serial randomiser's only dependency (it draws
 * from the entropy picker, not a raw source). Counts up so two calls
 * differ, which is the property the test needs. */
static uint8_t rand_state = 0x01;
void pqf_rand_bytes(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) buf[i] = rand_state++;
}

static int failures, checks;
#define CHECK(cond, ...) do {                                       \
        checks++;                                                   \
        if (!(cond)) {                                              \
            failures++;                                             \
            printf("  [FAIL] " __VA_ARGS__);                        \
            printf("\n         at %s:%d\n", __FILE__, __LINE__);    \
        }                                                           \
    } while (0)

/* Descriptor types (USB 2.0 sec. 9.4). */
#define DT_DEVICE       0x01
#define DT_CONFIG       0x02
#define DT_STRING       0x03
#define DT_INTERFACE    0x04
#define DT_ENDPOINT     0x05
#define DT_IAD          0x0b

static const uint8_t *cfg(void) { return tud_descriptor_configuration_cb(0); }
static uint16_t cfg_total(void) { const uint8_t *c = cfg(); return (uint16_t)(c[2] | (c[3] << 8)); }

/* ---- the configuration descriptor is self-consistent -------------- */

static void t_total_length(void)
{
    printf("--- wTotalLength ---\n");
    const uint8_t *c = cfg();

    /* Walk every descriptor in the block and add up bLength. If the
     * hand-written CONFIG_TOTAL_LEN has drifted from what the macros
     * emit, the host either truncates the configuration or reads past
     * it. This is the classic USB descriptor bug and the reason this
     * file exists. */
    uint16_t total = cfg_total();
    size_t walked = 0;
    int n = 0;
    while (walked < total) {
        uint8_t len = c[walked];
        CHECK(len >= 2, "descriptor %d at offset %zu has bLength %u", n, walked, len);
        if (len < 2) return;
        walked += len;
        n++;
    }
    CHECK(walked == total,
          "the descriptors sum to %zu bytes but wTotalLength says %u -- "
          "a host would read a truncated or over-long configuration",
          walked, total);
    CHECK(n >= 4, "only %d descriptors in the configuration", n);
    printf("  (wTotalLength %u across %d descriptors)\n", total, n);
}

static void t_header(void)
{
    printf("--- configuration header ---\n");
    const uint8_t *c = cfg();
    CHECK(c[0] == 9, "bLength is %u, not 9", c[0]);
    CHECK(c[1] == DT_CONFIG, "bDescriptorType is %#04x, not CONFIG", c[1]);
    CHECK(c[5] == 1, "bConfigurationValue is %u, not 1", c[5]);

    /* bMaxPower is in 2 mA units. A token that asks for more than the
     * 100 mA a host must grant before configuration can be refused by
     * bus-powered hubs. */
    CHECK(c[8] > 0, "bMaxPower is 0");
    CHECK(c[8] <= 250, "bMaxPower is %u (%u mA) -- over the 500 mA ceiling",
          c[8], c[8] * 2);
    printf("  (bMaxPower %u mA)\n", c[8] * 2);
}

static void t_interface_count(void)
{
    printf("--- bNumInterfaces ---\n");
    const uint8_t *c = cfg();
    uint16_t total = cfg_total();

    /* Count the interface descriptors actually present and compare with
     * what the header claims. A mismatch means the host stops binding
     * drivers early -- the FIDO interface is last-but-one, so it is the
     * one that disappears. */
    int seen = 0;
    uint8_t nums[32];
    size_t off = 0;
    while (off + 1 < total) {
        if (c[off + 1] == DT_INTERFACE) {
            if (seen < 32) nums[seen] = c[off + 2];
            seen++;
        }
        off += c[off];
    }
    CHECK(seen == c[4],
          "the header claims %u interfaces but %d are present", c[4], seen);
    CHECK(c[4] == ITF_NUM_TOTAL,
          "bNumInterfaces (%u) disagrees with ITF_NUM_TOTAL (%d)",
          c[4], ITF_NUM_TOTAL);

    /* Interface numbers must run 0..n-1 with no gaps or repeats: the
     * host indexes them, it does not search. */
    for (int want = 0; want < seen && want < 32; want++) {
        int found = 0;
        for (int i = 0; i < seen && i < 32; i++)
            if (nums[i] == want) found++;
        CHECK(found == 1, "bInterfaceNumber %d appears %d times, want once",
              want, found);
    }
    printf("  (%d interfaces)\n", seen);
}

static void t_endpoints_unique(void)
{
    printf("--- endpoint addresses ---\n");
    const uint8_t *c = cfg();
    uint16_t total = cfg_total();

    /* Two interfaces sharing an endpoint address is a descriptor that
     * enumerates and then behaves unpredictably -- traffic for one
     * function arrives on the other. Hand-assigned EPNUM_* constants
     * are exactly where that happens. */
    uint8_t eps[32];
    int n = 0;
    size_t off = 0;
    while (off + 1 < total) {
        if (c[off + 1] == DT_ENDPOINT) {
            uint8_t addr = c[off + 2];
            for (int i = 0; i < n; i++)
                CHECK(eps[i] != addr,
                      "endpoint address %#04x is used twice", addr);
            if (n < 32) eps[n++] = addr;
            /* Endpoint 0 is the control endpoint and must never appear
             * in a configuration descriptor. */
            CHECK((addr & 0x0f) != 0,
                  "an endpoint descriptor claims endpoint 0");
        }
        off += c[off];
    }
    CHECK(n >= 4, "only %d endpoints -- CDC needs 3 and HID needs 2", n);
    printf("  (%d endpoints, all distinct)\n", n);
}

static void t_hid_interface(void)
{
    printf("--- the FIDO HID interface ---\n");
    const uint8_t *c = cfg();
    uint16_t total = cfg_total();

    /* Find the HID interface and its class descriptor. The report
     * descriptor length declared there must match the array the device
     * will actually hand over: a host that asks for N bytes and gets a
     * different number treats the device as broken. */
    size_t off = 0;
    int found_hid = 0;
    while (off + 1 < total) {
        if (c[off + 1] == DT_INTERFACE && c[off + 5] == 0x03 /* HID class */) {
            found_hid = 1;
            CHECK(c[off + 2] == ITF_NUM_HID,
                  "the HID interface is number %u, not ITF_NUM_HID (%d)",
                  c[off + 2], ITF_NUM_HID);
            CHECK(c[off + 4] == 2,
                  "the HID interface has %u endpoints, not 2 (IN + OUT)",
                  c[off + 4]);
            /* The HID class descriptor follows the interface. */
            size_t hid = off + c[off];
            CHECK(c[hid + 1] == 0x21, "no HID class descriptor after the interface");
            uint16_t declared = (uint16_t)(c[hid + 7] | (c[hid + 8] << 8));
            CHECK(declared == pqf_hid_report_desc_len,
                  "the interface declares a %u-byte report descriptor but the "
                  "array is %zu bytes", declared, pqf_hid_report_desc_len);
            break;
        }
        off += c[off];
    }
    CHECK(found_hid, "no HID interface in the configuration");
}

static void t_report_descriptor(void)
{
    printf("--- the FIDO report descriptor ---\n");
    const uint8_t *r = pqf_hid_report_desc;
    size_t n = pqf_hid_report_desc_len;

    CHECK(n > 0, "the report descriptor is empty");

    /* CTAP sec. 11.2.8.2: a FIDO authenticator is identified by usage page
     * 0xF1D0 and usage 0x01. This is how every host -- and this
     * project's own enumerate() -- picks the device out of a bus full
     * of HID. Get it wrong and the token is invisible to every client. */
    int found_page = 0, found_usage = 0;
    for (size_t i = 0; i + 2 < n; i++) {
        if (r[i] == 0x06 && r[i + 1] == 0xd0 && r[i + 2] == 0xf1) found_page = 1;
        if (r[i] == 0x09 && r[i + 1] == 0x01) found_usage = 1;
    }
    CHECK(found_page, "usage page 0xF1D0 is not declared -- no host would "
                      "recognise this as a FIDO authenticator");
    CHECK(found_usage, "usage 0x01 is not declared");

    /* 64-byte reports in each direction: the CTAPHID frame size. */
    int report_count_64 = 0;
    for (size_t i = 0; i + 1 < n; i++)
        if (r[i] == 0x95 && r[i + 1] == 64) report_count_64++;
    CHECK(report_count_64 >= 2,
          "expected an IN and an OUT report of 64 bytes, found %d",
          report_count_64);
}

/* ---- the device descriptor ---------------------------------------- */

static void t_device_descriptor(void)
{
    printf("--- device descriptor ---\n");
    const uint8_t *d = tud_descriptor_device_cb();
    CHECK(d[0] == 18, "bLength is %u, not 18", d[0]);
    CHECK(d[1] == DT_DEVICE, "bDescriptorType is %#04x, not DEVICE", d[1]);
    CHECK(d[7] == CFG_TUD_ENDPOINT0_SIZE,
          "bMaxPacketSize0 is %u but the config says %d",
          d[7], CFG_TUD_ENDPOINT0_SIZE);
    CHECK(d[17] == 1, "bNumConfigurations is %u, not 1", d[17]);

    uint16_t vid = (uint16_t)(d[8] | (d[9] << 8));
    uint16_t pid = (uint16_t)(d[10] | (d[11] << 8));
    CHECK(vid != 0, "idVendor is 0");
    CHECK(pid != 0, "idProduct is 0");

    /* Every string index the device descriptor names must exist, or the
     * host asks for a string that is not there. */
    for (int i = 14; i <= 16; i++) {
        if (d[i] == 0) continue;
        const uint16_t *s = tud_descriptor_string_cb(d[i], 0x0409);
        CHECK(s != NULL, "string index %u (descriptor byte %d) is missing",
              d[i], i);
    }
    printf("  (%04x:%04x)\n", vid, pid);
}

/* ---- strings ------------------------------------------------------- */

static void t_strings(void)
{
    printf("--- string descriptors ---\n");

    /* Index 0 is the language list, not text. */
    const uint16_t *lang = tud_descriptor_string_cb(0, 0x0409);
    CHECK(lang != NULL, "no language descriptor at index 0");
    if (lang) {
        CHECK((lang[0] & 0xff) == 4, "the language descriptor is %u bytes, not 4",
              lang[0] & 0xff);
        CHECK(lang[1] == 0x0409, "the language is %#06x, not en-US", lang[1]);
    }

    /* Every string the configuration references must resolve. */
    const uint8_t *c = cfg();
    uint16_t total = cfg_total();
    size_t off = 0;
    while (off + 1 < total) {
        if (c[off + 1] == DT_INTERFACE && c[off + 8] != 0) {
            const uint16_t *s = tud_descriptor_string_cb(c[off + 8], 0x0409);
            CHECK(s != NULL, "interface %u names string %u, which is missing",
                  c[off + 2], c[off + 8]);
        }
        off += c[off];
    }

    /* An index past the table must return NULL rather than reading off
     * the end -- the host controls this number. */
    for (uint8_t i = 200; i < 210; i++)
        CHECK(tud_descriptor_string_cb(i, 0x0409) == NULL,
              "string index %u returned something", i);
}

static void t_serial_randomises(void)
{
    printf("--- serial randomisation ---\n");

    /* The serial string is randomised per boot so a host does not cache
     * stale interface state across a reflash. Two randomisations must
     * differ, and the result must stay a well-formed string descriptor. */
    pqf_usb_serial_randomize();
    const uint16_t *a = tud_descriptor_string_cb(3, 0x0409);
    CHECK(a != NULL, "no serial string at index 3");
    uint16_t first[64];
    size_t alen = a ? (a[0] & 0xff) / 2 : 0;
    if (a && alen <= 64) memcpy(first, a, alen * 2);

    pqf_usb_serial_randomize();
    const uint16_t *b = tud_descriptor_string_cb(3, 0x0409);
    CHECK(b != NULL, "no serial string after a second randomisation");
    if (a && b && alen <= 64) {
        CHECK(memcmp(first, b, alen * 2) != 0,
              "two randomisations produced the same serial");
        CHECK((b[0] & 0xff) == (uint8_t)(alen * 2),
              "the serial changed length between randomisations");
        CHECK((b[0] >> 8) == DT_STRING, "the serial is not a STRING descriptor");
    }
}

int main(void)
{
    printf("USB descriptor host test\n");
    t_total_length();
    t_header();
    t_interface_count();
    t_endpoints_unique();
    t_hid_interface();
    t_report_descriptor();
    t_device_descriptor();
    t_strings();
    t_serial_randomises();
    printf("%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
