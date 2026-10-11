/* Host shim for the RP2350 SIO block.
 *
 * core1_arena.c reads exactly one field: cpuid, to decide whether the
 * caller is core 0 or core 1. On the host there is one core, so the
 * test sets it directly and drives both paths.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQF_HOST_SIO_H
#define PQF_HOST_SIO_H

#include <stdint.h>

typedef struct { uint32_t cpuid; } pqf_host_sio_t;
extern pqf_host_sio_t pqf_host_sio;
#define sio_hw (&pqf_host_sio)

#endif
