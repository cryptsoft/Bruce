/* SPDX-License-Identifier: Apache-2.0
 *
 * lwIP configuration for the pqf-gadget: NO_SYS single-loop, IPv4 only,
 * raw API (no sockets/netconn), sized deliberately for the RP2350's SRAM
 * (docs/NETWORK-GADGET.md sec. 3.2 -- pools are explicit so soak testing has
 * fixed numbers to verify against).
 */

#ifndef PQF_GADGET_LWIPOPTS_H
#define PQF_GADGET_LWIPOPTS_H

#include "pico/rand.h"   /* LWIP_RAND -- mDNS probe/announce jitter */

#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0
#define MEM_ALIGNMENT                   4

/* Raw-API only: the services (DHCP server, mDNS, status endpoint) are
 * callback-driven; no threads, no sockets. */
#define LWIP_RAW                        0
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0

#define LWIP_IPV4                       1
#define LWIP_IPV6                       0
#define LWIP_ICMP                       1
#define LWIP_UDP                        1
#define LWIP_TCP                        1
#define LWIP_DHCP                       0   /* we are the DHCP *server* */
#define LWIP_SINGLE_NETIF               1
#define ETH_PAD_SIZE                    0

/* DHCP requests arrive broadcast from 0.0.0.0 before any lease exists --
 * accept them despite no matching local address. */
#define LWIP_IP_ACCEPT_UDP_PORT(p)      ((p) == PP_NTOHS(67))
#define IP_SOF_BROADCAST                1
#define IP_SOF_BROADCAST_RECV           1

/* mDNS responder (Bonjour discovery -- plan sec. 2: the app browses, never
 * hardcodes the address). */
#define LWIP_IGMP                       1
#define LWIP_MDNS_RESPONDER             1
#define LWIP_NUM_NETIF_CLIENT_DATA      1
#define MDNS_MAX_SERVICES               2
#define LWIP_RAND()                     get_rand_32()

/* mDNS uses several concurrent sys_timeouts on top of the stack's own. */
#define MEMP_NUM_SYS_TIMEOUT            (LWIP_NUM_SYS_TIMEOUT_INTERNAL + 8)

/* ---- Memory (explicit, per plan sec. 3.2) ---- */
#define MEM_SIZE                        8000
#define PBUF_POOL_SIZE                  8
#define MEMP_NUM_UDP_PCB                6
#define MEMP_NUM_TCP_PCB                4
#define MEMP_NUM_TCP_PCB_LISTEN         2

#define TCP_MSS                         (1500 - 20 - 20)
#define TCP_SND_BUF                     (2 * TCP_MSS)
#define TCP_WND                         (2 * TCP_MSS)

#define LWIP_MULTICAST_PING             1
#define LWIP_BROADCAST_PING             1

#endif /* PQF_GADGET_LWIPOPTS_H */
