/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Host shim for pico/rand.h -- pqf_rand.c's fallback source, used by
 * test_qrng, which defines get_rand_64 itself as a counter so the
 * fallback's output is predictable. */
#ifndef PQF_HOST_PICO_RAND_H
#define PQF_HOST_PICO_RAND_H
#include <stdint.h>
uint64_t get_rand_64(void);
#endif
