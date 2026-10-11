/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PQF_GADGET_DHCP_SERVER_H
#define PQF_GADGET_DHCP_SERVER_H

/* Start the minimal DHCP server on UDP :67. Offers an address and subnet
 * mask ONLY -- never a router, never DNS (docs/NETWORK-GADGET.md sec. 2: the two
 * decisions that carry the mobile interoperability). */
void pqf_dhcp_server_start(void);

#if PQF_GADGET_CONSOLE
/* See dhcp_server.c -- counters for the no-lease investigation. */
extern volatile uint32_t pqf_dhcp_pkts, pqf_dhcp_discover, pqf_dhcp_request, pqf_dhcp_sent;
#endif

#endif /* PQF_GADGET_DHCP_SERVER_H */
