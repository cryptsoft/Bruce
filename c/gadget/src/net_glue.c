/* SPDX-License-Identifier: Apache-2.0
 *
 * lwIP <-> TinyUSB network-function glue (docs/NETWORK-GADGET.md sec. 3.2),
 * modelled on TinyUSB's net_lwip_webserver reference: single netif, NO_SYS,
 * frames handed between the class driver's callbacks and ethernet_input().
 *
 * Address plan (sec. 2): the device is 192.168.7.1/24; the handset gets a lease
 * from our DHCP server. No gateway is ever configured or offered -- this
 * link must never look like an internet path to the phone.
 */

#include <string.h>

#include "pico/time.h"   /* to_ms_since_boot -- the transmit deadline */
#include "lwip/etharp.h"
#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/timeouts.h"
#include "netif/ethernet.h"

#include "tusb.h"

#include "net_glue.h"

struct netif pqf_netif;

/* One-frame handoff between tud_network_recv_cb (USB context) and
 * pqf_net_task (main loop) -- the reference driver contract: refuse further
 * frames until the pending one is consumed, then renew. */
static struct pbuf *received_frame;

static const ip4_addr_t dev_ip   = IPADDR4_INIT_BYTES(192, 168, 7, 1);
static const ip4_addr_t dev_mask = IPADDR4_INIT_BYTES(255, 255, 255, 0);
static const ip4_addr_t dev_gw   = IPADDR4_INIT_BYTES(0, 0, 0, 0);

/* ---- lwIP netif ---- */

/* How long to wait for the transmit endpoint before dropping a frame.
 * Generous next to a full-speed bulk transfer, short next to anything a
 * human notices. */
#define TX_WAIT_MS 50

static err_t linkoutput_fn(struct netif *netif, struct pbuf *p)
{
    (void) netif;
#if PQF_GADGET_CONSOLE
    pqf_net_tx_try++;
#endif
    /* Bounded, and that bound is the point.
     *
     * This used to be `for (;;)` with `tud_ready()` as its only exit. A
     * host that is still enumerated but has stopped draining the IN
     * endpoint -- a handset that suspended, which is ordinary behaviour
     * and exactly what Phase 3 walks into -- leaves `tud_ready()` true
     * and `can_xmit` false forever. The device then spins inside lwIP's
     * output path and the main loop never runs again: no console, no
     * heartbeat, and no reflash escape. It looks like dead hardware and
     * it is a stalled endpoint.
     *
     * Dropping a frame is the right answer for a link that cannot accept
     * it. lwIP treats a non-OK linkoutput as a dropped packet, which is
     * what any Ethernet driver does when its ring is full. */
    uint32_t start = to_ms_since_boot(get_absolute_time());
    for (;;) {
        if (!tud_ready()) return ERR_USE;
        if (tud_network_can_xmit(p->tot_len)) {
            tud_network_xmit(p, 0);
#if PQF_GADGET_CONSOLE
            pqf_net_tx++;
#endif
            return ERR_OK;
        }
        if (to_ms_since_boot(get_absolute_time()) - start >= TX_WAIT_MS) {
#if PQF_GADGET_CONSOLE
            pqf_net_tx_drop++;
#endif
            return ERR_WOULDBLOCK;
        }
        /* Let TinyUSB finish the in-flight transfer, then retry. */
        tud_task();
    }
}

static err_t output_fn(struct netif *netif, struct pbuf *p, const ip4_addr_t *addr)
{
    return etharp_output(netif, p, addr);
}

static err_t netif_init_cb(struct netif *netif)
{
    netif->mtu        = CFG_TUD_NET_MTU;
    /* NETIF_FLAG_IGMP is not decoration: lwIP's igmp_joingroup_netif
     * refuses outright without it ("attempt to join on non-IGMP
     * netif"), and the mDNS responder joins 224.0.0.251 the moment
     * mdns_resp_add_netif runs. Without the flag the responder comes up,
     * reports success, and is deaf -- it never receives a query and its
     * announcements reach nobody. That is invisible on hardware for as
     * long as anything else is stopping traffic, which is why it went
     * unnoticed: the first silicon run had no IPv4 address bound, so the
     * missing service looked like a symptom of that. */
    netif->flags      = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP
                      | NETIF_FLAG_IGMP
                      | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;
    netif->name[0]    = 'u';
    netif->name[1]    = 's';
    netif->linkoutput = linkoutput_fn;
    netif->output     = output_fn;
    return ERR_OK;
}

void pqf_net_init(void)
{
    lwip_init();

    /* lwIP's MAC must differ from the host-visible one: same bytes, LSbit of
     * the last octet toggled (identity_init keeps it clear, we set it). */
    pqf_netif.hwaddr_len = 6;
    memcpy(pqf_netif.hwaddr, tud_network_mac_address, 6);
    pqf_netif.hwaddr[5] ^= 0x01;

    netif_add(&pqf_netif, &dev_ip, &dev_mask, &dev_gw, NULL, netif_init_cb, ip_input);
    netif_set_default(&pqf_netif);
}

#if PQF_GADGET_CONSOLE
/* Frame counters for the "host sees the link but nothing reaches
 * 192.168.7.1" investigation (README, Silicon findings 2026-08-17).
 * rx_cb  = frames the NCM class driver handed us
 * rx_in  = frames accepted by ethernet_input()
 * tx     = frames we handed back to the host
 * If rx_cb stays 0 while the console reports the link UP, the receive
 * path is not delivering and lwIP never sees anything -- which is the
 * fork in the diagnosis. */
volatile uint32_t pqf_net_rx_cb, pqf_net_rx_in, pqf_net_tx, pqf_net_tx_try;
/* Frames dropped because the endpoint never drained. Non-zero means a
 * host stopped collecting, which used to hang the device outright. */
volatile uint32_t pqf_net_tx_drop;

/* Per-frame classification, for "the host has an address in its lease
 * but not on its interface".
 *
 * The counters above say frames flow in and almost nothing flows out.
 * They cannot say *what* the host is asking, and the two candidate
 * explanations need different answers: if macOS is ARP-probing for the
 * address it was offered (duplicate address detection) and something
 * replies, it will treat the lease as conflicted and drop the address --
 * so an ARP reply whose target is the *client's* address is the smoking
 * gun. If instead the probe goes unanswered, the fault is on the host
 * side and the DHCP payload is the place to look.
 *
 * `arp_probe` counts ARP requests whose sender protocol address is
 * 0.0.0.0, which is exactly the DAD probe shape (RFC 5227). */
volatile uint32_t pqf_arp_rx, pqf_arp_probe, pqf_arp_for_us, pqf_arp_for_client;
volatile uint32_t pqf_icmp_rx, pqf_ip_rx, pqf_other_rx;
#endif

void pqf_net_task(void)
{
    if (received_frame) {
        /* ethernet_input takes ownership on ERR_OK; free only on refusal. */
#if PQF_GADGET_CONSOLE
        pqf_net_rx_in++;
#endif
        if (ethernet_input(received_frame, &pqf_netif) != ERR_OK) {
            pbuf_free(received_frame);
        }
        received_frame = NULL;
        tud_network_recv_renew();
    }
    sys_check_timeouts();
}

/* ---- TinyUSB net-class callbacks ---- */

bool tud_network_recv_cb(const uint8_t *src, uint16_t size)
{
#if PQF_GADGET_CONSOLE
    pqf_net_rx_cb++;
    /* Classify before lwIP sees it. Offsets are the Ethernet header (14)
     * plus the ARP fields: sender protocol address at +14, target
     * protocol address at +24. */
    if (size >= 42) {
        uint16_t et = (uint16_t)((src[12] << 8) | src[13]);
        if (et == 0x0806) {
            pqf_arp_rx++;
            const uint8_t *spa = src + 14 + 14;
            const uint8_t *tpa = src + 14 + 24;
            if (spa[0] == 0 && spa[1] == 0 && spa[2] == 0 && spa[3] == 0)
                pqf_arp_probe++;
            if (tpa[0] == 192 && tpa[1] == 168 && tpa[2] == 7) {
                if (tpa[3] == 1) pqf_arp_for_us++;
                else             pqf_arp_for_client++;
            }
        } else if (et == 0x0800) {
            pqf_ip_rx++;
            if (size >= 34 && src[14 + 9] == 1) pqf_icmp_rx++;
        } else {
            pqf_other_rx++;
        }
    }
#endif
    if (received_frame) return false; /* previous frame not consumed yet */
    if (size) {
        struct pbuf *p = pbuf_alloc(PBUF_RAW, size, PBUF_POOL);
        if (p) {
            /* A pool pbuf is a chain of fixed-size buffers once the
             * frame is longer than one of them; pbuf_take walks the
             * chain, where a memcpy into the first payload would run
             * off its end. */
            if (pbuf_take(p, src, size) == ERR_OK) {
                received_frame = p;
            } else {
                pbuf_free(p);
            }
        }
    }
    return true;
}

uint16_t tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg)
{
    (void) arg;
    struct pbuf *p = (struct pbuf *) ref;
    return pbuf_copy_partial(p, dst, p->tot_len, 0);
}

void tud_network_init_cb(void)
{
    /* Re-initialize (host re-attach): drop any half-handled frame. */
    if (received_frame) {
        pbuf_free(received_frame);
        received_frame = NULL;
    }
}
