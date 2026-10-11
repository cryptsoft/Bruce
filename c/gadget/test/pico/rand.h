/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Stand-in for the pico-sdk's RNG header.
 *
 * The board's lwipopts.h includes this for LWIP_RAND. Providing it here
 * means the host harness can include the *real* lwipopts.h rather than a
 * hand-written copy -- which matters: the first version of this harness
 * had its own options file and silently omitted
 * LWIP_IP_ACCEPT_UDP_PORT, so lwIP dropped every DHCP packet (source
 * 0.0.0.0) before UDP saw it and the harness reported a firmware bug
 * that did not exist.
 */
#ifndef PQF_GADGET_TEST_PICO_RAND_H
#define PQF_GADGET_TEST_PICO_RAND_H
#include <stdint.h>
uint32_t get_rand_32(void);
#endif
