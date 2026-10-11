/* SPDX-License-Identifier: Apache-2.0
 *
 * pqf-gadget -- RP2350 USB network gadget (docs/NETWORK-GADGET.md).
 *
 * Boot sequence: derive the stable identity (MAC + serial from the flash
 * unique ID), bring up TinyUSB as a CDC-NCM composite, attach lwIP to the
 * network function, then start the three on-device services the plan calls
 * for: the trimmed DHCP server (address + mask only), the mDNS responder
 * (pqf-gadget.local, _pqf-mgmt._tcp), and the placeholder HTTP status
 * endpoint that Phase 4 swaps for the TLS management channel.
 *
 * Everything runs on one core, NO_SYS: the main loop pumps TinyUSB, hands
 * received frames to lwIP, and runs stack timeouts. LED heartbeats so a
 * board on a phone shows life without the console image.
 */

#include "pico/stdlib.h"

#include "bsp/board_api.h"
#include "tusb.h"

#include "lwip/apps/mdns.h"

#include <stdio.h>
#include "dhcp_server.h"
#include "http_status.h"
#include "net_glue.h"
#include "usb_descriptors.h"

#define MDNS_HOSTNAME "pqf-gadget"   /* -> pqf-gadget.local */
#define MDNS_SERVICE  "_pqf-mgmt"    /* what the mobile app browses for */
#define MGMT_PORT     80             /* Phase 4: 443/TLS */

static void mdns_txt_cb(struct mdns_service *service, void *userdata)
{
    (void) userdata;
    /* Enough for the app to gate on protocol compatibility before dialing. */
    mdns_resp_add_service_txtitem(service, "api=0", 5);
    mdns_resp_add_service_txtitem(service, "tls=0", 5);
}

static void heartbeat_task(void)
{
#ifdef PICO_DEFAULT_LED_PIN
    static uint32_t last;
    uint32_t now = to_ms_since_boot(get_absolute_time());
    if (now - last >= 500) {
        last = now;
        static bool on;
        on = !on;
        gpio_put(PICO_DEFAULT_LED_PIN, on);
    }
#endif
}

#if PQF_GADGET_CONSOLE && defined(PQF_GADGET_CDC_BOOTSEL)
#include "pico/bootrom.h"       /* rom_reset_usb_boot */

/* TEST-ONLY reflash escape, mirroring the FIDO firmware's
 * PQF_CDC_BOOTSEL_HOOK verbatim.
 *
 * This image is not a FIDO device: it has no CTAPHID, no picotool reset
 * interface (CFG_TUD_VENDOR is 0), and therefore no software route into
 * BOOTSEL at all. Every reflash costs a physical BOOT-hold and RESET,
 * which makes iterating on the network stack about as slow as it can be
 * -- and it is why this firmware sat compile-verified but never run for
 * five weeks.
 *
 * With this compiled in, the harness writes <STX>BOOTSEL<ETX> to the
 * debug console and the device drops into BOOTSEL. Default OFF, and it
 * needs the console, so a shipping NCM-only image cannot have it. */
/// Detach and re-attach from the USB bus, as a replug would.
///
/// A soft reflash is not enough: the device comes back and even reports
/// that the host selected alt-1, but macOS leaves the interface
/// `inactive` and never runs DHCP again, so every attempt at the
/// address-binding problem cost a physical replug. An electrical detach
/// is what makes the host start over, and TinyUSB can do one on request.
///
/// The gap has to be long enough for the host to notice the device has
/// gone; 1.5 s is comfortable and still quick enough to iterate on.
static void usb_cycle(void)
{
    tud_disconnect();
    sleep_ms(1500);
    tud_connect();
}

static void cdc_bootsel_poll(void)
{
    static const char bootsel[] = "\x02" "BOOTSEL" "\x03";
    static const char cycle[]   = "\x02" "USBCYCLE" "\x03";
    static unsigned bi, ci;
    uint8_t b;
    while (tud_cdc_available() && tud_cdc_read(&b, 1) == 1) {
        if (b == (uint8_t)bootsel[bi]) {
            bi++;
            if (bootsel[bi] == '\0')
                rom_reset_usb_boot(0, 0);   /* noreturn */
        } else {
            bi = (b == (uint8_t)bootsel[0]) ? 1 : 0;
        }

        if (b == (uint8_t)cycle[ci]) {
            ci++;
            if (cycle[ci] == '\0') {
                ci = 0;
                usb_cycle();
                return;     /* the FIFO is gone with the connection */
            }
        } else {
            ci = (b == (uint8_t)cycle[0]) ? 1 : 0;
        }
    }
}
#else
#define cdc_bootsel_poll() ((void)0)
#endif

#if PQF_GADGET_CONSOLE
/* Progress marker on the debug console.
 *
 * The console interface enumerates but, until this existed, nothing ever
 * wrote to it -- so reading it returned zero bytes whether the firmware
 * was healthy or wedged, and the heartbeat LED was the only liveness
 * signal. That is a poor position to debug from when the symptom is
 * "enumerates, carries no traffic" (silicon 2026-08-17, see README).
 *
 * Each init step announces itself, so a hang reads as "last line
 * printed". Nothing here can block: tud_cdc_write_str drops into a
 * 256-byte FIFO when no host has the port open, and the tud_task() pump
 * afterwards gives the stack a chance to drain it if one does. */
static void boot_mark(const char *s)
{
    tud_cdc_write_str(s);
    tud_cdc_write_flush();
    tud_task();
}
#else
#define boot_mark(s) ((void)0)
#endif

int main(void)
{
    board_init();
#ifdef PICO_DEFAULT_LED_PIN
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
#endif

    /* Identity before USB: the descriptors reference the MAC + serial. */
    pqf_gadget_identity_init();

    tud_init(0);
    boot_mark("\r\n[pqf-gadget] usb up\r\n");

    /* lwIP on the USB link, then the three services (plan sec. 3.2). */
    boot_mark("[pqf-gadget] net_init ...\r\n");
    pqf_net_init();
    boot_mark("[pqf-gadget] dhcp_server ...\r\n");
    pqf_dhcp_server_start();

    boot_mark("[pqf-gadget] mdns ...\r\n");
    mdns_resp_init();
    mdns_resp_add_netif(&pqf_netif, MDNS_HOSTNAME);
    mdns_resp_add_service(&pqf_netif, "PQC FIDO Gadget", MDNS_SERVICE,
                          DNSSD_PROTO_TCP, MGMT_PORT, mdns_txt_cb, NULL);
    mdns_resp_announce(&pqf_netif);

    boot_mark("[pqf-gadget] http ...\r\n");
    pqf_http_status_start();

    boot_mark("[pqf-gadget] init complete, entering main loop\r\n");

    for (;;) {
        tud_task();      /* USB device events + NCM datapath */
        pqf_net_task();  /* frames -> lwIP; sys timeouts (mDNS, TCP, ARP) */
        heartbeat_task();
        cdc_bootsel_poll();
#if PQF_GADGET_CONSOLE
        /* The failure to diagnose is "host sees the interface but no
         * carrier", so say whether the NCM data path is actually open.
         * tud_network_can_xmit() is false until the host selects the
         * data interface's alt-1 setting -- the top suspect in README. */
        {
            static bool last = false, first = true;
            bool up = tud_ready() && tud_network_can_xmit(64);
            if (first || up != last) {
                boot_mark(up ? "[pqf-gadget] NCM link UP (host selected alt-1)\r\n"
                             : "[pqf-gadget] NCM link DOWN (no alt-1 / not ready)\r\n");
                last = up; first = false;
            }
            /* Frame counters once a second. rx_cb == 0 while the link reports
             * UP means the NCM receive path never delivers and lwIP is not
             * implicated. See README "Silicon findings". */
            {
                static absolute_time_t nxt;
                if (time_reached(nxt)) {
                    char fb[320];
                    snprintf(fb, sizeof fb,
                             "[pqf-gadget] frames rx_cb=%lu rx_in=%lu tx_try=%lu tx=%lu | "
                             "dhcp pkts=%lu disc=%lu req=%lu sent=%lu | "
                             "arp rx=%lu probe=%lu for_us=%lu for_client=%lu | "
                             "ip=%lu icmp=%lu other=%lu | txdrop=%lu\r\n",
                             (unsigned long)pqf_net_rx_cb,
                             (unsigned long)pqf_net_rx_in,
                             (unsigned long)pqf_net_tx_try,
                             (unsigned long)pqf_net_tx,
                             (unsigned long)pqf_dhcp_pkts,
                             (unsigned long)pqf_dhcp_discover,
                             (unsigned long)pqf_dhcp_request,
                             (unsigned long)pqf_dhcp_sent,
                             (unsigned long)pqf_arp_rx,
                             (unsigned long)pqf_arp_probe,
                             (unsigned long)pqf_arp_for_us,
                             (unsigned long)pqf_arp_for_client,
                             (unsigned long)pqf_ip_rx,
                             (unsigned long)pqf_icmp_rx,
                             (unsigned long)pqf_other_rx,
                             (unsigned long)pqf_net_tx_drop);
                    boot_mark(fb);
                    nxt = make_timeout_time_ms(1000);
                }
            }
        }
#endif
    }
}
