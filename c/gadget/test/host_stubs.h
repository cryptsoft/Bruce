/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Host stand-ins for the pico-sdk and TinyUSB surfaces the gadget's
 * network glue touches.
 *
 * The point is to run the real net_glue.c, dhcp_server.c and lwIP on a
 * development machine, so the DHCP exchange and the ARP/ICMP replies can
 * be inspected byte by byte without a board. Everything here is a
 * faithful stub of behaviour the glue depends on, not a reimplementation
 * of it: frames handed to `tud_network_xmit` are captured for the test
 * to decode, and `tud_network_can_xmit` reports true so the transmit
 * path is never the thing under test.
 */
#ifndef PQF_GADGET_HOST_STUBS_H
#define PQF_GADGET_HOST_STUBS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define CFG_TUD_NET_MTU 1514

/* ---- TinyUSB net class, as the glue sees it ---- */

extern uint8_t tud_network_mac_address[6];

bool     tud_ready(void);
bool     tud_network_can_xmit(uint16_t size);
void     tud_network_xmit(void *ref, uint16_t arg);
void     tud_network_recv_renew(void);
void     tud_task(void);

/* Implemented by net_glue.c; the harness calls them to inject frames. */
bool     tud_network_recv_cb(const uint8_t *src, uint16_t size);
uint16_t tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg);
void     tud_network_init_cb(void);

/* ---- What the harness inspects ---- */

/* Frames the device handed back to the host, most recent last. */
#define PQF_CAP_MAX      32
#define PQF_CAP_FRAME    1600
extern uint8_t  pqf_cap[PQF_CAP_MAX][PQF_CAP_FRAME];
extern uint16_t pqf_cap_len[PQF_CAP_MAX];
extern unsigned pqf_cap_n;
void pqf_cap_reset(void);

/* ---- pico-sdk odds and ends ---- */

uint32_t get_rand_32(void);
uint32_t sys_now(void);

/* Move lwIP's clock forward, for tests that need a timeout to fire. */
void pqf_test_advance_ms(uint32_t ms);

/* Make the transmit endpoint refuse, standing in for a host that is
 * enumerated but no longer collecting. */
void pqf_test_block_xmit(bool blocked);

#endif /* PQF_GADGET_HOST_STUBS_H */
