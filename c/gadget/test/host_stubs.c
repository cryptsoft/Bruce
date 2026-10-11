/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

#include "host_stubs.h"
#include <string.h>
#include <stdlib.h>

uint8_t tud_network_mac_address[6] = { 0x02, 0x02, 0x84, 0x6a, 0x96, 0x00 };

uint8_t  pqf_cap[PQF_CAP_MAX][PQF_CAP_FRAME];
uint16_t pqf_cap_len[PQF_CAP_MAX];
unsigned pqf_cap_n;

void pqf_cap_reset(void)
{
    pqf_cap_n = 0;
    memset(pqf_cap_len, 0, sizeof pqf_cap_len);
}

/* Force the transmit endpoint to refuse, standing in for a host that is
 * enumerated but has stopped draining. */
static bool xmit_blocked;

bool tud_ready(void) { return true; }

/* Always ready: a stalled transmit endpoint is a USB-side failure and
 * not what this harness exists to find. */
bool tud_network_can_xmit(uint16_t size) { (void) size; return !xmit_blocked; }

void tud_network_xmit(void *ref, uint16_t arg)
{
    if (pqf_cap_n >= PQF_CAP_MAX) return;
    uint16_t n = tud_network_xmit_cb(pqf_cap[pqf_cap_n], ref, arg);
    if (n > PQF_CAP_FRAME) n = PQF_CAP_FRAME;
    pqf_cap_len[pqf_cap_n] = n;
    pqf_cap_n++;
}

void tud_network_recv_renew(void) { }

/* Advances the harness clock.
 *
 * The transmit path waits on a millisecond deadline and calls tud_task()
 * each time round. With a clock that never moved, a test of that
 * deadline would spin forever -- so time passes here, where the firmware
 * expects USB work to happen, and nowhere else. */
void tud_task(void) { pqf_test_advance_ms(1); }

void pqf_test_block_xmit(bool blocked) { xmit_blocked = blocked; }

/* lwIP's clock. Advanced by the harness rather than read from the
 * system, so a test that needs a timer to fire can say so instead of
 * sleeping. */
static uint32_t now_ms;

uint32_t sys_now(void) { return now_ms; }

void pqf_test_advance_ms(uint32_t ms) { now_ms += ms; }

/* Deterministic: mDNS jitter must not make a test flaky. */
uint32_t get_rand_32(void)
{
    static uint32_t x = 0x12345678u;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return x;
}
