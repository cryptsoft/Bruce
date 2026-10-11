/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Stand-in for TinyUSB's umbrella header.
 *
 * `net_glue.c` includes <tusb.h> for the net-class prototypes and
 * CFG_TUD_NET_MTU. On the host those come from host_stubs.h, which the
 * Makefile force-includes ahead of everything, so this only has to exist
 * and pull in nothing.
 */
#ifndef PQF_GADGET_TUSB_SHIM_H
#define PQF_GADGET_TUSB_SHIM_H
#include "host_stubs.h"
#endif
