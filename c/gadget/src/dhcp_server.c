/* SPDX-License-Identifier: Apache-2.0
 *
 * Minimal DHCP server for the USB link (docs/NETWORK-GADGET.md sec. 2).
 *
 * The two interoperability-critical decisions live here:
 *
 *   1. The DEVICE runs the DHCP server -- iOS has no way to set a static
 *      address on an ethernet interface, so if we don't lease one, iPhones
 *      never get on the link at all.
 *   2. The offer contains an IP address, subnet mask, lease time and server
 *      id -- and NOTHING ELSE. No option 3 (router), no option 6 (DNS). A
 *      handset that received a default route here would try to send its
 *      internet traffic to us and break the user's connectivity; omitting
 *      them keeps normal traffic on cellular/Wi-Fi while the management app
 *      talks to the private subnet.
 *
 * Four-entry lease table keyed by client MAC, fixed pool 192.168.7.2-.5,
 * 24 h leases. Deliberately no persistence and no NAK sophistication -- a
 * USB link has exactly one real client; the extra entries absorb handsets
 * that randomize their MAC per connection.
 */

#include <string.h>

#include "lwip/ip_addr.h"
#include "lwip/udp.h"

#include "dhcp_server.h"

#define DHCP_PORT_SERVER 67
#define DHCP_PORT_CLIENT 68

/* BOOTP header offsets (RFC 951 / 2131). */
#define BOOTP_OP      0
#define BOOTP_XID     4
#define BOOTP_FLAGS   10
#define BOOTP_YIADDR  16
#define BOOTP_CHADDR  28
#define BOOTP_COOKIE  236
#define BOOTP_OPTIONS 240
#define BOOTP_MIN_LEN BOOTP_OPTIONS
/* RFC 1542 section 2.1: the smallest legal BOOTP message. Replies are
 * padded up to it, because a client is within its rights to drop a
 * shorter one. */
#define DHCP_MIN_MSG_LEN 300

#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_ACK      5

#define OPT_SUBNET_MASK 1
#define OPT_MSG_TYPE    53
#define OPT_SERVER_ID   54
#define OPT_LEASE_TIME  51
#define OPT_END         255

#define LEASE_SECONDS (24u * 60u * 60u)

static const uint8_t server_ip[4] = { 192, 168, 7, 1 };
static const uint8_t subnet[4]    = { 255, 255, 255, 0 };

typedef struct {
    uint8_t mac[6];
    uint8_t in_use;
} lease_t;

/* Pool .2-.5: entry i leases 192.168.7.(2+i). */
static lease_t leases[4];

static struct udp_pcb *pcb;

static int lease_for(const uint8_t *mac)
{
    int free_slot = -1;
    for (int i = 0; i < (int) (sizeof(leases) / sizeof(leases[0])); i++) {
        if (leases[i].in_use && memcmp(leases[i].mac, mac, 6) == 0) return i;
        if (!leases[i].in_use && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) {
        memcpy(leases[free_slot].mac, mac, 6);
        leases[free_slot].in_use = 1;
    }
    return free_slot;
}

/* Find option `code` in the request's options field; NULL if absent, or
 * present but not wholly within `len`.
 *
 * The bounds matter more than they look. This used to loop on
 * `i + 1 < len`, which puts the code and length bytes in range and says
 * nothing about the body -- while every caller goes on to read
 * `opt[2]` and beyond. An option sitting at the very end of a message
 * therefore had its value read from past the data that arrived: either
 * uninitialised stack in the request buffer, or one byte past it when a
 * request fills the buffer exactly. The message type came out as
 * whatever was there, so a packet could be acted on as a DISCOVER or
 * REQUEST it never was, and any USB host can send one. Requiring the
 * whole option to fit is what makes the callers' reads safe. */
static const uint8_t *find_option(const uint8_t *opts, uint16_t len, uint8_t code)
{
    uint16_t i = 0;
    while (i < len && opts[i] != OPT_END) {
        if (opts[i] == 0) { i++; continue; }        /* pad */
        if (i + 1 >= len) return NULL;              /* length byte missing */
        uint16_t body = opts[i + 1];
        if ((uint32_t) i + 2u + body > (uint32_t) len) return NULL;  /* body short */
        if (opts[i] == code) return &opts[i];
        i = (uint16_t) (i + 2u + body);
    }
    return NULL;
}

#if PQF_GADGET_CONSOLE
/* Counters for the "no lease" investigation (README). pkts = UDP
 * datagrams delivered to this handler at all; discover/request = ones
 * that got past the message-type filter; sent = replies handed to
 * udp_sendto(). pkts staying 0 means the host never asks and lwIP never
 * routes anything here -- a very different problem from us not
 * answering. */
volatile uint32_t pqf_dhcp_pkts, pqf_dhcp_discover, pqf_dhcp_request, pqf_dhcp_sent;
#endif

static void dhcp_recv(void *arg, struct udp_pcb *upcb, struct pbuf *p,
                      const ip_addr_t *addr, u16_t port)
{
#if PQF_GADGET_CONSOLE
    pqf_dhcp_pkts++;
#endif
    (void) arg; (void) addr; (void) port;

    /* Zeroed, not just declared: only `req_len` bytes get overwritten by
     * the copy below, and anything that reads past that would otherwise
     * be reading whatever this stack frame last held. Cheap insurance
     * against the whole class, on top of the bounds check in
     * `find_option`. */
    uint8_t req[400] = { 0 };
    if (p->tot_len < BOOTP_MIN_LEN + 4 || p->tot_len > sizeof(req)) {
        pbuf_free(p);
        return;
    }
    uint16_t req_len = pbuf_copy_partial(p, req, sizeof(req), 0);
    pbuf_free(p);
    /* Belt and braces for the subtraction below: the gate above implies
     * this, but the implication lives three lines away and a future
     * change to either could break it silently. */
    if (req_len <= BOOTP_OPTIONS) return;

    if (req[BOOTP_OP] != 1) return; /* not a BOOTREQUEST */

    const uint8_t *mt = find_option(&req[BOOTP_OPTIONS], req_len - BOOTP_OPTIONS, OPT_MSG_TYPE);
    if (mt == NULL || mt[1] != 1) return;
    uint8_t msg_type = mt[2];
#if PQF_GADGET_CONSOLE
    if (msg_type == DHCP_DISCOVER) pqf_dhcp_discover++;
    if (msg_type == DHCP_REQUEST)  pqf_dhcp_request++;
#endif
    if (msg_type != DHCP_DISCOVER && msg_type != DHCP_REQUEST) return;

    int slot = lease_for(&req[BOOTP_CHADDR]);
    if (slot < 0) return; /* pool exhausted */

    /* Build the reply: BOOTP header mirrored, then the trimmed option set. */
    /* 300 octets, not just enough for the options we send.
     *
     * RFC 1542 section 2.1 sets the minimum BOOTP message at 300 octets,
     * and RFC 2131 inherits it: 236 bytes of fixed header, the 4-byte
     * magic cookie, and 60 of options. Clients and relays are entitled
     * to drop anything shorter, and the reply built below comes to 262 --
     * so the buffer used to be sized such that a conformant message was
     * not expressible. Padded with zeroes after OPT_END, which is what
     * the pad option is for. */
    uint8_t rep[DHCP_MIN_MSG_LEN];
    memset(rep, 0, sizeof(rep));
    rep[BOOTP_OP] = 2;                        /* BOOTREPLY */
    rep[1] = 1; rep[2] = 6;                   /* htype ethernet, hlen 6 */
    memcpy(&rep[BOOTP_XID], &req[BOOTP_XID], 4);
    memcpy(&rep[BOOTP_FLAGS], &req[BOOTP_FLAGS], 2);
    rep[BOOTP_YIADDR + 0] = 192; rep[BOOTP_YIADDR + 1] = 168;
    rep[BOOTP_YIADDR + 2] = 7;   rep[BOOTP_YIADDR + 3] = (uint8_t) (2 + slot);
    memcpy(&rep[BOOTP_CHADDR], &req[BOOTP_CHADDR], 16);
    rep[BOOTP_COOKIE + 0] = 99; rep[BOOTP_COOKIE + 1] = 130; /* magic cookie */
    rep[BOOTP_COOKIE + 2] = 83; rep[BOOTP_COOKIE + 3] = 99;

    uint8_t *o = &rep[BOOTP_OPTIONS];
    *o++ = OPT_MSG_TYPE;    *o++ = 1; *o++ = (msg_type == DHCP_DISCOVER) ? DHCP_OFFER : DHCP_ACK;
    *o++ = OPT_SERVER_ID;   *o++ = 4; memcpy(o, server_ip, 4); o += 4;
    *o++ = OPT_LEASE_TIME;  *o++ = 4;
    *o++ = (LEASE_SECONDS >> 24) & 0xFF; *o++ = (LEASE_SECONDS >> 16) & 0xFF;
    *o++ = (LEASE_SECONDS >> 8) & 0xFF;  *o++ = LEASE_SECONDS & 0xFF;
    *o++ = OPT_SUBNET_MASK; *o++ = 4; memcpy(o, subnet, 4); o += 4;
    /* No router. No DNS. That absence is the design. */
    *o++ = OPT_END;

    /* Pad to the RFC 1542 minimum. Everything past OPT_END is already
     * zero from the memset, which is the pad option (code 0). */
    uint16_t rep_len = (uint16_t) (o - rep);
    if (rep_len < DHCP_MIN_MSG_LEN) rep_len = DHCP_MIN_MSG_LEN;
    struct pbuf *rp = pbuf_alloc(PBUF_TRANSPORT, rep_len, PBUF_RAM);
    if (rp == NULL) return;
    memcpy(rp->payload, rep, rep_len);

    /* Client has no address yet -- reply to the ethernet broadcast. */
    udp_sendto(upcb, rp, IP_ADDR_BROADCAST, DHCP_PORT_CLIENT);
#if PQF_GADGET_CONSOLE
    pqf_dhcp_sent++;
#endif
    pbuf_free(rp);
}

void pqf_dhcp_server_start(void)
{
    pcb = udp_new();
    if (pcb == NULL) return;
    ip_set_option(pcb, SOF_BROADCAST);
    udp_bind(pcb, IP_ANY_TYPE, DHCP_PORT_SERVER);
    udp_recv(pcb, dhcp_recv, NULL);
}
