/* Host shim: the sliver of pico/stdlib.h that flash_store.c needs.
 *
 * The load-bearing part is XIP_BASE. On target the store is read
 * through the execute-in-place window with plain pointer loads
 * (flash_store.c STORE_XIP / KEY_XIP); here that window is a byte array
 * the test can inspect and corrupt. Everything the firmware reads back
 * therefore goes through the same path it does on silicon.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQF_HOST_PICO_STDLIB_H
#define PQF_HOST_PICO_STDLIB_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "pico/platform.h"

/* The simulated die, defined in host_flash_die.c. Declared here rather
 * than left implicit: C11 has no implicit variable declaration, so
 * without this flash_store.c fails to compile at its first XIP read. */
extern uint8_t pqf_host_die[];

#define XIP_BASE ((uintptr_t)pqf_host_die)

#define __compiler_memory_barrier() __asm__ volatile("" ::: "memory")
#endif
