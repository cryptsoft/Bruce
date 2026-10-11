/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Stand-in for the pico-sdk timebase.
 *
 * `http_status.c` stamps its status page with milliseconds since boot.
 * Backed by the harness clock (`pqf_test_advance_ms`) so a test can
 * decide what time it is, rather than the page changing under it.
 */
#ifndef PQF_GADGET_TEST_PICO_TIME_H
#define PQF_GADGET_TEST_PICO_TIME_H
#include <stdint.h>

typedef uint64_t absolute_time_t;

uint32_t sys_now(void);   /* the harness clock, in ms */

static inline absolute_time_t get_absolute_time(void) { return (absolute_time_t) sys_now(); }
static inline uint32_t to_ms_since_boot(absolute_time_t t) { return (uint32_t) t; }

#endif
