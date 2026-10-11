/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Host tests for the gadget's network stack -- no board required.
 *
 * The gadget spent five weeks compile-verified and then failed on its
 * first hardware run one step short of Phase 1: the interface came up,
 * DHCP completed, and no IPv4 address was ever bound. Nothing in the
 * tree could have caught that earlier, because there was no way to
 * exercise the stack without a token.
 *
 * This runs the real `net_glue.c`, `dhcp_server.c` and lwIP on the
 * development machine, with TinyUSB stubbed, and drives them with
 * hand-built Ethernet frames. Every frame the device sends back is
 * captured and decoded, so the DHCP payload and the ARP/ICMP replies can
 * be asserted on byte by byte.
 *
 * What it can and cannot settle: if the exchange is correct here and
 * still fails on silicon, the fault is in the USB datapath or the host's
 * DHCP client. If it fails here too, the bug is in this code and does not
 * need hardware to find.
 */

#include "host_stubs.h"

#include "lwip/init.h"
#include "lwip/timeouts.h"
#include "lwip/apps/mdns.h"
#include "lwip/netif.h"

#include <stdio.h>
#include <string.h>

/* The gadget's own interface. */
void pqf_net_init(void);
void pqf_net_task(void);
void pqf_dhcp_server_start(void);
void pqf_http_status_start(void);
extern struct netif pqf_netif;

#define DEV_IP_0 192
#define DEV_IP_1 168
#define DEV_IP_2 7
#define DEV_IP_3 1
#define CLIENT_IP_3 2

static int checks, failures;

static void check(int ok, const char *what)
{
    checks++;
    if (!ok) {
        failures++;
        printf("  [FAIL] %s\n", what);
    } else {
        printf("  [PASS] %s\n", what);
    }
}

static void section(const char *s) { printf("\n-- %s\n", s); }

/* A plausible host MAC, distinct from the device's. */
static const uint8_t host_mac[6] = { 0x02, 0xb7, 0x90, 0x52, 0xca, 0x84 };
static const uint8_t bcast[6]    = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* ---- frame builders ---------------------------------------------- */

static uint16_t put_eth(uint8_t *f, const uint8_t *dst, const uint8_t *src, uint16_t ethertype)
{
    memcpy(f, dst, 6);
    memcpy(f + 6, src, 6);
    f[12] = (uint8_t)(ethertype >> 8);
    f[13] = (uint8_t)ethertype;
    return 14;
}

/* opcode 1 = request, 2 = reply. */
static uint16_t build_arp(uint8_t *f, uint16_t op,
                          const uint8_t *sha, const uint8_t *spa,
                          const uint8_t *tha, const uint8_t *tpa)
{
    uint16_t n = put_eth(f, op == 1 ? bcast : tha, sha, 0x0806);
    uint8_t *a = f + n;
    a[0] = 0; a[1] = 1;          /* Ethernet */
    a[2] = 0x08; a[3] = 0x00;    /* IPv4 */
    a[4] = 6; a[5] = 4;
    a[6] = (uint8_t)(op >> 8); a[7] = (uint8_t)op;
    memcpy(a + 8, sha, 6);
    memcpy(a + 14, spa, 4);
    memcpy(a + 18, tha, 6);
    memcpy(a + 24, tpa, 4);
    return n + 28;
}

static uint16_t ip_checksum(const uint8_t *p, uint16_t len)
{
    uint32_t sum = 0;
    for (uint16_t i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)((p[i] << 8) | p[i + 1]);
    if (len & 1) sum += (uint32_t)(p[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* An IPv4 packet with `payload`, protocol `proto`. Returns total length. */
static uint16_t build_ip(uint8_t *f, const uint8_t *dstmac,
                         const uint8_t *sip, const uint8_t *dip,
                         uint8_t proto, const uint8_t *payload, uint16_t plen)
{
    uint16_t n = put_eth(f, dstmac, host_mac, 0x0800);
    uint8_t *ip = f + n;
    uint16_t total = (uint16_t)(20 + plen);
    memset(ip, 0, 20);
    ip[0] = 0x45;
    ip[2] = (uint8_t)(total >> 8); ip[3] = (uint8_t)total;
    ip[6] = 0x40;                /* don't fragment */
    ip[8] = 64;                  /* ttl */
    ip[9] = proto;
    memcpy(ip + 12, sip, 4);
    memcpy(ip + 16, dip, 4);
    uint16_t ck = ip_checksum(ip, 20);
    ip[10] = (uint8_t)(ck >> 8); ip[11] = (uint8_t)ck;
    memcpy(ip + 20, payload, plen);
    return (uint16_t)(n + total);
}

/* A DHCP message. `type` is 1 DISCOVER / 3 REQUEST. */
static uint16_t build_dhcp(uint8_t *f, uint8_t type, const uint8_t *requested_ip)
{
    static uint8_t udp[576];
    memset(udp, 0, sizeof udp);
    /* UDP header: 68 -> 67 */
    udp[0] = 0; udp[1] = 68;
    udp[2] = 0; udp[3] = 67;
    uint8_t *b = udp + 8;
    b[0] = 1;                    /* op = BOOTREQUEST */
    b[1] = 1;                    /* htype ethernet */
    b[2] = 6;                    /* hlen */
    b[4] = 0x70; b[5] = 0x62; b[6] = 0x9a; b[7] = 0x5a;   /* xid */
    memcpy(b + 28, host_mac, 6); /* chaddr */
    b[236] = 0x63; b[237] = 0x82; b[238] = 0x53; b[239] = 0x63; /* magic */
    uint8_t *o = b + 240;
    *o++ = 53; *o++ = 1; *o++ = type;                 /* message type */
    if (requested_ip) { *o++ = 50; *o++ = 4; memcpy(o, requested_ip, 4); o += 4; }
    /* Parameter request list, the shape macOS actually sends. */
    *o++ = 55; *o++ = 4; *o++ = 1; *o++ = 3; *o++ = 6; *o++ = 15;
    *o++ = 255;                                        /* end */
    uint16_t blen = (uint16_t)(o - b);
    uint16_t ulen = (uint16_t)(8 + blen);
    udp[4] = (uint8_t)(ulen >> 8); udp[5] = (uint8_t)ulen;
    /* UDP checksum 0 = not computed, which is legal for IPv4. */
    static const uint8_t any[4] = { 0, 0, 0, 0 };
    static const uint8_t all[4] = { 255, 255, 255, 255 };
    return build_ip(f, bcast, any, all, 17, udp, ulen);
}

/* ---- capture decoding -------------------------------------------- */

/* The captured frame at `i`, if it is a DHCP reply; else NULL. */
static const uint8_t *dhcp_body(unsigned i)
{
    if (i >= pqf_cap_n) return NULL;
    const uint8_t *f = pqf_cap[i];
    if (pqf_cap_len[i] < 14 + 20 + 8 + 240) return NULL;
    if (!(f[12] == 0x08 && f[13] == 0x00)) return NULL;
    if (f[14 + 9] != 17) return NULL;                    /* UDP */
    const uint8_t *udp = f + 14 + 20;
    if (!(udp[0] == 0 && udp[1] == 67)) return NULL;     /* from :67 */
    return udp + 8;
}

/* The BOOTP body length of the captured reply `b` points into. Derived
 * from the UDP header so it measures what actually went on the wire. */
static uint16_t dhcp_len(const uint8_t *b)
{
    const uint8_t *udp = b - 8;
    uint16_t ulen = (uint16_t)((udp[4] << 8) | udp[5]);
    return (uint16_t)(ulen - 8);
}

/* Find DHCP option `code` in a reply body; returns length via `*len`. */
static const uint8_t *dhcp_opt(const uint8_t *b, uint8_t code, uint8_t *len)
{
    const uint8_t *o = b + 240;
    const uint8_t *end = b + 548;
    while (o < end && *o != 255) {
        if (*o == 0) { o++; continue; }
        uint8_t c = o[0], l = o[1];
        if (c == code) { if (len) *len = l; return o + 2; }
        o += 2 + l;
    }
    return NULL;
}

static int frame_is_arp_reply_for(unsigned i, const uint8_t *tpa)
{
    if (i >= pqf_cap_n || pqf_cap_len[i] < 42) return 0;
    const uint8_t *f = pqf_cap[i];
    if (!(f[12] == 0x08 && f[13] == 0x06)) return 0;
    const uint8_t *a = f + 14;
    if (!(a[6] == 0 && a[7] == 2)) return 0;              /* reply */
    return memcmp(a + 14, tpa, 4) == 0;                   /* sender = tpa */
}

static int count_arp_replies(void)
{
    int n = 0;
    for (unsigned i = 0; i < pqf_cap_n; i++) {
        if (pqf_cap_len[i] < 42) continue;
        const uint8_t *f = pqf_cap[i];
        if (f[12] == 0x08 && f[13] == 0x06 && f[14 + 6] == 0 && f[14 + 7] == 2) n++;
    }
    return n;
}

static int find_icmp_echo_reply(void)
{
    for (unsigned i = 0; i < pqf_cap_n; i++) {
        if (pqf_cap_len[i] < 14 + 20 + 8) continue;
        const uint8_t *f = pqf_cap[i];
        if (!(f[12] == 0x08 && f[13] == 0x00)) continue;
        if (f[14 + 9] != 1) continue;                      /* ICMP */
        if (f[14 + 20] == 0) return (int)i;                /* type 0 = echo reply */
    }
    return -1;
}

/* Answer any ARP request the device emitted, the way a real host would.
 *
 * Without this the harness looks broken in a way the firmware is not: a
 * unicast DHCP reply cannot leave until lwIP has resolved the client's
 * MAC, so it queues the reply and emits an ARP request instead. On real
 * hardware macOS answers that immediately. Returns how many it answered.
 */
static int answer_device_arp(void)
{
    static uint8_t reply[64];
    int answered = 0;
    for (unsigned i = 0; i < pqf_cap_n; i++) {
        if (pqf_cap_len[i] < 42) continue;
        const uint8_t *f = pqf_cap[i];
        if (!(f[12] == 0x08 && f[13] == 0x06)) continue;
        const uint8_t *a = f + 14;
        if (!(a[6] == 0 && a[7] == 1)) continue;          /* requests only */
        const uint8_t *tpa = a + 24;                      /* who it wants */
        const uint8_t *sha = a + 8;                       /* the device */
        const uint8_t *spa = a + 14;
        uint16_t n = build_arp(reply, 2, host_mac, tpa, sha, spa);
        tud_network_recv_cb(reply, n);
        for (int k = 0; k < 4; k++) pqf_net_task();
        answered++;
    }
    return answered;
}

/* ---- mDNS and TCP helpers ---------------------------------------- */

/* Bring the responder up the way main.c does. Kept here rather than in
 * the harness prologue so the DHCP and ARP sections run against a stack
 * with nothing else talking on it. */
static void mdns_start_for_test(void)
{
    static int started;
    if (started) return;
    started = 1;
    mdns_resp_init();
    mdns_resp_add_netif(&pqf_netif, "pqf-gadget");
    mdns_resp_announce(&pqf_netif);
}

/* Count captured frames that are UDP to or from port 5353. */
static int count_mdns_frames(void)
{
    int n = 0;
    for (unsigned i = 0; i < pqf_cap_n; i++) {
        if (pqf_cap_len[i] < 14 + 20 + 8) continue;
        const uint8_t *f = pqf_cap[i];
        if (!(f[12] == 0x08 && f[13] == 0x00) || f[14 + 9] != 17) continue;
        const uint8_t *u = f + 14 + 20;
        uint16_t sp = (uint16_t)((u[0] << 8) | u[1]);
        uint16_t dp = (uint16_t)((u[2] << 8) | u[3]);
        if (sp == 5353 || dp == 5353) n++;
    }
    return n;
}

/* The first captured mDNS frame whose DNS header has the QR bit set. */
static int find_mdns_response(void)
{
    for (unsigned i = 0; i < pqf_cap_n; i++) {
        if (pqf_cap_len[i] < 14 + 20 + 8 + 12) continue;
        const uint8_t *f = pqf_cap[i];
        if (!(f[12] == 0x08 && f[13] == 0x00) || f[14 + 9] != 17) continue;
        const uint8_t *u = f + 14 + 20;
        if (((u[0] << 8) | u[1]) != 5353) continue;
        const uint8_t *d = u + 8;
        if (d[2] & 0x80) return (int)i;
    }
    return -1;
}

/* A standard mDNS A query for "<label>.local", sent to 224.0.0.251. */
static uint16_t build_mdns_query(uint8_t *f, const char *label)
{
    static uint8_t udp[256];
    memset(udp, 0, sizeof udp);
    udp[0] = 0xc0; udp[1] = 0x00;      /* arbitrary source port 49152 */
    udp[2] = 0x14; udp[3] = 0xe9;      /* 5353 */
    uint8_t *d = udp + 8;
    d[2] = 0x00;                        /* standard query, QR clear */
    d[5] = 1;                           /* qdcount = 1 */
    uint8_t *q = d + 12;
    size_t ll = strlen(label);
    *q++ = (uint8_t)ll; memcpy(q, label, ll); q += ll;
    *q++ = 5; memcpy(q, "local", 5); q += 5;
    *q++ = 0;                           /* root */
    *q++ = 0; *q++ = 1;                 /* QTYPE A */
    *q++ = 0; *q++ = 1;                 /* QCLASS IN */
    uint16_t ulen = (uint16_t)(8 + (q - d));
    udp[4] = (uint8_t)(ulen >> 8); udp[5] = (uint8_t)ulen;
    /* The mDNS multicast group, and its derived MAC. */
    static const uint8_t mcast_ip[4]  = { 224, 0, 0, 251 };
    static const uint8_t mcast_mac[6] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb };
    static const uint8_t src_ip[4]    = { 192, 168, 7, 2 };
    return build_ip(f, mcast_mac, src_ip, mcast_ip, 17, udp, ulen);
}

/* The TCP/UDP checksum over the RFC 793 pseudo-header plus the segment. */
static uint16_t transport_checksum(const uint8_t *sip, const uint8_t *dip,
                                   uint8_t proto, const uint8_t *seg, uint16_t len)
{
    uint32_t sum = 0;
    for (int i = 0; i < 4; i += 2) sum += (uint32_t)((sip[i] << 8) | sip[i + 1]);
    for (int i = 0; i < 4; i += 2) sum += (uint32_t)((dip[i] << 8) | dip[i + 1]);
    sum += proto;
    sum += len;
    for (uint16_t i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)((seg[i] << 8) | seg[i + 1]);
    if (len & 1) sum += (uint32_t)(seg[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* A TCP segment. `flags` is the TCP flag byte (0x02 SYN, 0x10 ACK,
 * 0x18 PSH|ACK).
 *
 * The checksum is computed for real. It was left zero at first, on the
 * assumption that lwIP would not be checking -- it does, and every
 * segment was silently dropped at `tcp_input: packet discarded due to
 * failing checksum`, which looked exactly like a listener that was
 * never started. */
static uint16_t build_tcp(uint8_t *f, const uint8_t *sip, const uint8_t *dip,
                          uint16_t sport, uint16_t dport,
                          uint32_t seq, uint32_t ack, uint8_t flags,
                          const uint8_t *payload, uint16_t plen)
{
    static uint8_t seg[1500];
    memset(seg, 0, sizeof seg);
    seg[0] = (uint8_t)(sport >> 8); seg[1] = (uint8_t)sport;
    seg[2] = (uint8_t)(dport >> 8); seg[3] = (uint8_t)dport;
    seg[4] = (uint8_t)(seq >> 24); seg[5] = (uint8_t)(seq >> 16);
    seg[6] = (uint8_t)(seq >> 8);  seg[7] = (uint8_t)seq;
    seg[8] = (uint8_t)(ack >> 24); seg[9] = (uint8_t)(ack >> 16);
    seg[10] = (uint8_t)(ack >> 8); seg[11] = (uint8_t)ack;
    seg[12] = 0x50;                 /* data offset 5 words, no options */
    seg[13] = flags;
    seg[14] = 0x20; seg[15] = 0x00; /* window 8192 */
    if (payload && plen) memcpy(seg + 20, payload, plen);
    uint16_t tlen = (uint16_t)(20 + plen);
    uint16_t ck = transport_checksum(sip, dip, 6, seg, tlen);
    seg[16] = (uint8_t)(ck >> 8); seg[17] = (uint8_t)ck;

    uint8_t devmac[6];
    memcpy(devmac, tud_network_mac_address, 6);
    devmac[5] ^= 0x01;
    return build_ip(f, devmac, sip, dip, 6, seg, tlen);
}

static int find_tcp_with_flags(uint8_t want)
{
    for (unsigned i = 0; i < pqf_cap_n; i++) {
        if (pqf_cap_len[i] < 14 + 20 + 20) continue;
        const uint8_t *f = pqf_cap[i];
        if (!(f[12] == 0x08 && f[13] == 0x00) || f[14 + 9] != 6) continue;
        if ((f[14 + 20 + 13] & want) == want) return (int)i;
    }
    return -1;
}

static int find_tcp_payload_prefix(const char *prefix)
{
    size_t n = strlen(prefix);
    for (unsigned i = 0; i < pqf_cap_n; i++) {
        if (pqf_cap_len[i] < 14 + 20 + 20) continue;
        const uint8_t *f = pqf_cap[i];
        if (!(f[12] == 0x08 && f[13] == 0x00) || f[14 + 9] != 6) continue;
        const uint8_t *t = f + 14 + 20;
        uint16_t doff = (uint16_t)((t[12] >> 4) * 4);
        const uint8_t *data = t + doff;
        uint16_t total = (uint16_t)((f[14 + 2] << 8) | f[14 + 3]);
        if (total < 20u + doff) continue;
        uint16_t dlen = (uint16_t)(total - 20 - doff);
        if (dlen >= n && memcmp(data, prefix, n) == 0) return (int)i;
    }
    return -1;
}

/* Hand one frame to the device, let it run, and play the host's part in
 * any address resolution it needs before it can reply. */
static void inject(const uint8_t *frame, uint16_t len)
{
    check(tud_network_recv_cb(frame, len) == true, "device accepted the frame");
    for (int i = 0; i < 8; i++) pqf_net_task();
    if (answer_device_arp())
        for (int i = 0; i < 8; i++) pqf_net_task();
}

/* ---- the tests --------------------------------------------------- */

int main(void)
{
    static uint8_t f[1600];
    uint16_t n;
    const uint8_t dev_ip[4]    = { DEV_IP_0, DEV_IP_1, DEV_IP_2, DEV_IP_3 };
    const uint8_t client_ip[4] = { DEV_IP_0, DEV_IP_1, DEV_IP_2, CLIENT_IP_3 };
    const uint8_t zero_ip[4]   = { 0, 0, 0, 0 };
    const uint8_t zero_mac[6]  = { 0, 0, 0, 0, 0, 0 };

    printf("pqf-gadget network stack, host harness\n");

    pqf_net_init();
    pqf_dhcp_server_start();
    pqf_http_status_start();

    section("DHCP: DISCOVER is answered with an OFFER");
    pqf_cap_reset();
    n = build_dhcp(f, 1, NULL);
    inject(f, n);
    const uint8_t *b = NULL;
    for (unsigned i = 0; i < pqf_cap_n && !b; i++) b = dhcp_body(i);
    check(b != NULL, "an OFFER came back");
    if (b) {
        uint8_t l = 0;
        const uint8_t *mt = dhcp_opt(b, 53, &l);
        check(mt && *mt == 2, "message type is OFFER (2)");
        check(memcmp(b + 16, client_ip, 4) == 0, "yiaddr is 192.168.7.2");
        const uint8_t *mask = dhcp_opt(b, 1, &l);
        check(mask && l == 4 && mask[0] == 255 && mask[3] == 0, "subnet mask 255.255.255.0 present");
    }

    section("DHCP: REQUEST is answered with an ACK");
    pqf_cap_reset();
    n = build_dhcp(f, 3, client_ip);
    inject(f, n);
    b = NULL;
    for (unsigned i = 0; i < pqf_cap_n && !b; i++) b = dhcp_body(i);
    check(b != NULL, "an ACK came back");
    if (b) {
        uint8_t l = 0;
        const uint8_t *mt = dhcp_opt(b, 53, &l);
        check(mt && *mt == 5, "message type is ACK (5)");
        check(memcmp(b + 16, client_ip, 4) == 0, "yiaddr is 192.168.7.2");
        const uint8_t *sid = dhcp_opt(b, 54, &l);
        check(sid && l == 4 && memcmp(sid, dev_ip, 4) == 0, "server identifier is 192.168.7.1");
        const uint8_t *lease = dhcp_opt(b, 51, &l);
        check(lease && l == 4, "lease time present");

        /* Section 2 of the plan: address and mask only, so a handset
         * never routes its traffic at the device. */
        check(dhcp_opt(b, 3, &l) == NULL, "no router option (by design)");
        check(dhcp_opt(b, 6, &l) == NULL, "no DNS option (by design)");

        /* RFC 1542 2.1: 300 octets is the floor, and a client may drop
         * anything shorter. The reply came to 262 before it was padded,
         * with a buffer too small to express a conformant message. */
        check(dhcp_len(b) >= 300, "reply is at least the RFC 1542 minimum of 300 octets");

        /* RFC 2131 4.1: the client matches a reply to its request by
         * xid, and by chaddr when it has no address yet. Getting either
         * wrong makes a reply look like someone else's conversation. */
        check(b[4] == 0x70 && b[5] == 0x62 && b[6] == 0x9a && b[7] == 0x5a,
              "xid is echoed from the request");
        check(memcmp(b + 28, host_mac, 6) == 0, "chaddr is echoed from the request");
        check(b[0] == 2, "op is BOOTREPLY");
        check(b[236] == 99 && b[237] == 130 && b[238] == 83 && b[239] == 99,
              "magic cookie present");
    }

    section("ARP: the device answers for its own address");
    pqf_cap_reset();
    n = build_arp(f, 1, host_mac, client_ip, zero_mac, dev_ip);
    inject(f, n);
    check(frame_is_arp_reply_for(0, dev_ip) || count_arp_replies() > 0,
          "an ARP reply for 192.168.7.1 came back");

    section("ARP: a duplicate-address probe for the CLIENT must go unanswered");
    /* RFC 5227 probe: sender protocol address 0.0.0.0, target the address
     * the client is about to use. If anything answers this, the host
     * declares a conflict and drops the lease -- which is exactly the
     * shape of "BOUND but no address on the interface". */
    pqf_cap_reset();
    n = build_arp(f, 1, host_mac, zero_ip, zero_mac, client_ip);
    inject(f, n);
    check(count_arp_replies() == 0,
          "no ARP reply to a probe for the client's own address");

    section("ARP: a probe for the DEVICE's address is still answered");
    /* Same probe shape, but targeting the device. lwIP is entitled to
     * answer this, and macOS uses it to verify the router it synthesised
     * from the server identifier. */
    pqf_cap_reset();
    n = build_arp(f, 1, host_mac, zero_ip, zero_mac, dev_ip);
    inject(f, n);
    check(count_arp_replies() > 0, "the device answers a probe for its own address");

    section("ICMP: the device answers ping -- the Phase 1 exit criterion");
    pqf_cap_reset();
    {
        /* Teach lwIP the host's MAC first, so the reply is not held
         * pending its own ARP resolution. */
        n = build_arp(f, 2, host_mac, client_ip, tud_network_mac_address, dev_ip);
        tud_network_recv_cb(f, n);
        for (int i = 0; i < 8; i++) pqf_net_task();

        uint8_t icmp[16];
        memset(icmp, 0, sizeof icmp);
        icmp[0] = 8;                    /* echo request */
        icmp[4] = 0x12; icmp[5] = 0x34; /* id */
        icmp[6] = 0x00; icmp[7] = 0x01; /* seq */
        uint16_t ck = ip_checksum(icmp, sizeof icmp);
        icmp[2] = (uint8_t)(ck >> 8); icmp[3] = (uint8_t)ck;

        pqf_cap_reset();
        uint8_t devmac[6];
        memcpy(devmac, tud_network_mac_address, 6);
        devmac[5] ^= 0x01;              /* net_glue toggles the low bit */
        n = build_ip(f, devmac, client_ip, dev_ip, 1, icmp, sizeof icmp);
        tud_network_recv_cb(f, n);
        for (int i = 0; i < 16; i++) { pqf_net_task(); sys_check_timeouts(); }

        int idx = find_icmp_echo_reply();
        check(idx >= 0, "an ICMP echo reply came back");
        if (idx >= 0) {
            const uint8_t *r = pqf_cap[idx];
            check(memcmp(r + 14 + 12, dev_ip, 4) == 0, "reply is from 192.168.7.1");
            check(memcmp(r + 14 + 16, client_ip, 4) == 0, "reply is to 192.168.7.2");
            check(r[14 + 20 + 4] == 0x12 && r[14 + 20 + 5] == 0x34, "echo id preserved");
        }
    }

    section("DHCP: a truncated option must not be acted on");
    /* The message-type option sits at the very end of the message, with
     * its value byte one past what arrived. `find_option` only
     * guarantees the code and length bytes are in range, so the caller
     * reading mt[2] reads whatever follows -- uninitialised stack in the
     * 400-byte request buffer, or one byte past it when a request fills
     * the buffer exactly. Either way the message type is whatever
     * happened to be there, and a packet can be acted on as a DISCOVER
     * or REQUEST it never was. Any USB host can send this. */
    {
        static uint8_t udp[576];
        memset(udp, 0, sizeof udp);
        udp[0] = 0; udp[1] = 68;
        udp[2] = 0; udp[3] = 67;
        uint8_t *bb = udp + 8;
        bb[0] = 1; bb[1] = 1; bb[2] = 6;
        bb[4] = 0xde; bb[5] = 0xad; bb[6] = 0xbe; bb[7] = 0xef;
        memcpy(bb + 28, host_mac, 6);
        bb[236] = 0x63; bb[237] = 0x82; bb[238] = 0x53; bb[239] = 0x63;
        /* Options: two pads, then `53 01` and nothing. 244 octets total,
         * which is the smallest the server accepts. */
        bb[240] = 0; bb[241] = 0;
        bb[242] = 53; bb[243] = 1;
        uint16_t blen = 244;
        uint16_t ulen = (uint16_t)(8 + blen);
        udp[4] = (uint8_t)(ulen >> 8); udp[5] = (uint8_t)ulen;
        static const uint8_t any[4] = { 0, 0, 0, 0 };
        static const uint8_t all[4] = { 255, 255, 255, 255 };
        n = build_ip(f, bcast, any, all, 17, udp, ulen);

        pqf_cap_reset();
        tud_network_recv_cb(f, n);
        for (int i = 0; i < 8; i++) pqf_net_task();
        b = NULL;
        for (unsigned i = 0; i < pqf_cap_n && !b; i++) b = dhcp_body(i);
        check(b == NULL, "a truncated message-type option draws no reply");
    }

    section("mDNS: the responder answers a query for pqf-gadget.local");
    /* Phase 2's discovery half. On silicon this was untestable because
     * nothing could reach the device at all; here the query goes
     * straight in. A response on 5353 with at least one answer record is
     * what a browsing client needs. */
    {
        mdns_start_for_test();
        pqf_cap_reset();
        /* The announce is scheduled, not immediate: lwIP jitters it to
         * avoid a multicast storm on a busy link. The harness clock has
         * to move for the timer to fire -- which is why sys_now is
         * driven by pqf_test_advance_ms rather than the wall clock. */
        for (int i = 0; i < 40; i++) {
            pqf_test_advance_ms(50);
            pqf_net_task();
            sys_check_timeouts();
        }
        /* The announce goes out unsolicited on startup. */
        int announced = count_mdns_frames();
        check(announced > 0, "the responder announces itself unprompted");

        pqf_cap_reset();
        n = build_mdns_query(f, "pqf-gadget");
        tud_network_recv_cb(f, n);
        for (int i = 0; i < 40; i++) {
            pqf_test_advance_ms(25);
            pqf_net_task();
            sys_check_timeouts();
        }
        int idx = find_mdns_response();
        check(idx >= 0, "a query for pqf-gadget.local draws a response");
        if (idx >= 0) {
            const uint8_t *d = pqf_cap[idx] + 14 + 20 + 8;
            uint16_t ancount = (uint16_t)((d[6] << 8) | d[7]);
            check(ancount > 0, "the response carries at least one answer record");
            check((d[2] & 0x80) != 0, "the QR bit marks it a response");
        }
    }

    section("HTTP: the status endpoint completes a TCP handshake and answers");
    /* The Phase-4 TLS channel stands on this. A SYN must be answered with
     * SYN-ACK, and a GET with something that starts HTTP/1. */
    {
        pqf_cap_reset();
        uint32_t cli_seq = 0x1000;
        n = build_tcp(f, client_ip, dev_ip, 40000, 80, cli_seq, 0, 0x02, NULL, 0);
        tud_network_recv_cb(f, n);
        for (int i = 0; i < 12; i++) { pqf_net_task(); sys_check_timeouts(); }
        int syn = find_tcp_with_flags(0x12);          /* SYN|ACK */
        check(syn >= 0, "a SYN to port 80 is answered with SYN-ACK");
        if (syn >= 0) {
            const uint8_t *t = pqf_cap[syn] + 14 + 20;
            uint32_t srv_seq = ((uint32_t)t[4] << 24) | ((uint32_t)t[5] << 16)
                             | ((uint32_t)t[6] << 8) | t[7];
            /* Complete the handshake, then ask. */
            pqf_cap_reset();
            n = build_tcp(f, client_ip, dev_ip, 40000, 80, cli_seq + 1, srv_seq + 1,
                          0x10, NULL, 0);
            tud_network_recv_cb(f, n);
            for (int i = 0; i < 8; i++) { pqf_net_task(); sys_check_timeouts(); }

            static const char get[] = "GET / HTTP/1.1\r\nHost: 192.168.7.1\r\n\r\n";
            pqf_cap_reset();
            n = build_tcp(f, client_ip, dev_ip, 40000, 80, cli_seq + 1, srv_seq + 1,
                          0x18, (const uint8_t *)get, (uint16_t)(sizeof get - 1));
            tud_network_recv_cb(f, n);
            for (int i = 0; i < 16; i++) { pqf_net_task(); sys_check_timeouts(); }
            check(find_tcp_payload_prefix("HTTP/1") >= 0,
                  "a GET / draws an HTTP response");
        }
    }

    section("Transmit: a host that stops draining must not wedge the device");
    /* `linkoutput_fn` used to spin until `tud_ready()` went false. A host
     * that is still enumerated but has stopped collecting -- a suspended
     * handset, which Phase 3 will meet -- leaves that condition true
     * forever, and the main loop never runs again: no console, no
     * heartbeat, no reflash escape. Reaching the end of this section is
     * the assertion; if the bound is ever removed, the suite hangs here
     * rather than failing, which is the symptom to recognise. */
    {
        pqf_cap_reset();
        pqf_test_block_xmit(true);
        uint8_t icmp[16];
        memset(icmp, 0, sizeof icmp);
        icmp[0] = 8;
        icmp[4] = 0x22; icmp[5] = 0x44;
        uint16_t ck2 = ip_checksum(icmp, sizeof icmp);
        icmp[2] = (uint8_t)(ck2 >> 8); icmp[3] = (uint8_t)ck2;

        uint8_t devmac2[6];
        memcpy(devmac2, tud_network_mac_address, 6);
        devmac2[5] ^= 0x01;
        n = build_ip(f, devmac2, client_ip, dev_ip, 1, icmp, sizeof icmp);
        tud_network_recv_cb(f, n);
        for (int i = 0; i < 8; i++) { pqf_net_task(); sys_check_timeouts(); }
        check(1, "output returned instead of spinning on a blocked endpoint");
        check(find_icmp_echo_reply() < 0, "the frame was dropped, not queued forever");
        pqf_test_block_xmit(false);

        /* And the link recovers: the very next request is answered. */
        pqf_cap_reset();
        n = build_ip(f, devmac2, client_ip, dev_ip, 1, icmp, sizeof icmp);
        tud_network_recv_cb(f, n);
        for (int i = 0; i < 12; i++) { pqf_net_task(); sys_check_timeouts(); }
        check(find_icmp_echo_reply() >= 0, "the link recovers once the host drains again");
    }

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
