/* Host shim: core 1 is a thread.
 *
 * Not the real thing -- no separate instruction stream, no XIP, no
 * lockout -- but it does make the mailbox a genuine two-party protocol,
 * which a single-threaded stub cannot. What is being tested is the
 * handshake and the state machine, not the parallelism.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQF_HOST_PICO_MULTICORE_H
#define PQF_HOST_PICO_MULTICORE_H
#include <stdint.h>
#include <stdbool.h>

void multicore_launch_core1_with_stack(void (*entry)(void),
                                       uint32_t *stack, size_t stack_size);
void multicore_launch_core1(void (*entry)(void));
void multicore_lockout_victim_init(void);
void multicore_lockout_start_blocking(void);
void multicore_lockout_end_blocking(void);
void multicore_reset_core1(void);

/* Test-only: which core the calling thread is pretending to be. */
void pqf_host_set_core(unsigned c);
#endif
