/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PQF_GADGET_NET_GLUE_H
#define PQF_GADGET_NET_GLUE_H

#include "lwip/netif.h"

/* The USB-link netif (192.168.7.1/24 on the device end). */
extern struct netif pqf_netif;

/* Bring up lwIP on the TinyUSB network function. Call once, after
 * pqf_gadget_identity_init() and tusb_init(). */
void pqf_net_init(void);

/* Pump received frames into lwIP + run stack timeouts. Call every loop. */
void pqf_net_task(void);

#if PQF_GADGET_CONSOLE
/* See net_glue.c -- frame counters for the no-traffic investigation. */
extern volatile uint32_t pqf_net_rx_cb, pqf_net_rx_in, pqf_net_tx, pqf_net_tx_try;
extern volatile uint32_t pqf_net_tx_drop;
extern volatile uint32_t pqf_arp_rx, pqf_arp_probe, pqf_arp_for_us, pqf_arp_for_client;
extern volatile uint32_t pqf_icmp_rx, pqf_ip_rx, pqf_other_rx;
#endif

#endif /* PQF_GADGET_NET_GLUE_H */
