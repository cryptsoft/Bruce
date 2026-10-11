/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Host build: the board's lwIP options, unmodified.
 *
 * Deliberately a two-line include rather than a copy. The first version
 * of this harness had its own hand-written options and omitted
 * LWIP_IP_ACCEPT_UDP_PORT -- the hook that lets a DHCP *server* receive
 * packets whose source is still 0.0.0.0. lwIP dropped every DISCOVER and
 * REQUEST at `ip4_input: packet source is not valid`, and the harness
 * duly reported that the DHCP server was broken. It was not. Any
 * divergence between these two files is a way to reach a confident wrong
 * answer, so there is no longer anywhere for one to hide.
 *
 * `pico/rand.h`, which the board file includes for LWIP_RAND, is stubbed
 * alongside this. mDNS is left enabled: it is part of what Phase 2 has
 * to prove.
 */
#ifndef PQF_GADGET_LWIPOPTS_HOST_H
#define PQF_GADGET_LWIPOPTS_HOST_H

#include "../lwipopts.h"

/* Roomier than the board, so a test can queue frames without tuning
 * pool sizes to each case. Nothing under test depends on these. */
#undef  MEM_SIZE
#define MEM_SIZE      16000
#undef  PBUF_POOL_SIZE
#define PBUF_POOL_SIZE 32

#ifdef PQF_HOST_LWIP_DEBUG
#define LWIP_DEBUG          1
#define LWIP_DBG_MIN_LEVEL  LWIP_DBG_LEVEL_ALL
#define ETHARP_DEBUG        LWIP_DBG_ON
#define NETIF_DEBUG         LWIP_DBG_ON
#define IP_DEBUG            LWIP_DBG_ON
#define UDP_DEBUG           LWIP_DBG_ON
#define ICMP_DEBUG          LWIP_DBG_ON
#define TCP_DEBUG           LWIP_DBG_ON
#define TCP_INPUT_DEBUG     LWIP_DBG_ON
#define MDNS_DEBUG          LWIP_DBG_ON
#endif

#endif
