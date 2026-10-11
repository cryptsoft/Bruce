/* A simulated NOR die for the real flash_store.c.
 *
 * host_flash_stub.c replaces flash_store.c wholesale with RAM
 * variables. This does the opposite: it supplies the hardware
 * underneath the real module, so every line above the write primitive
 * -- the CRC, the versioning, the commit path, the sign-counter
 * reservation -- executes exactly as it does on silicon.
 *
 * The die models NOR properly, which is the whole point. A program may
 * only clear bits, never set them; erase fills 0xFF and only on a
 * sector boundary; the array starts at 0xFF so blank flash reads as a
 * bad magic rather than as zeros. A memcpy-based fake passes tests that
 * a real device would fail -- programming a page over a sector nobody
 * erased, say, or programming the same page twice with different
 * content. Both are silent in a memcpy and both are caught here.
 *
 * The bit-rule check lives in the program primitive rather than in the
 * suite because that is the only place holding both the pre-image and
 * the post-image, and because every test then inherits it without
 * having to remember to ask.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include "hardware/flash.h"
#include "hardware/structs/qmi.h"

#ifndef PICO_FLASH_SIZE_BYTES
#define PICO_FLASH_SIZE_BYTES (32u * 1024u)
#endif

uint8_t pqf_host_die[PICO_FLASH_SIZE_BYTES];
pqf_host_qmi_t pqf_host_qmi;

/* ---- Observability the suite asserts on --------------------------- */

unsigned pqf_die_erases;          /* sector erases performed           */
unsigned pqf_die_programs;        /* program calls performed           */
unsigned pqf_die_bit_violations;  /* programs asking a 0 bit to become 1 */
unsigned pqf_die_unaligned;       /* erases at a non-sector offset     */
unsigned pqf_die_xip_exits;       /* flash_exit_xip calls              */
unsigned pqf_die_xip_enters;      /* flash_enter_cmd_xip calls         */
unsigned pqf_die_flushes;         /* cache flushes                     */
unsigned pqf_die_connects;        /* connect_internal_flash calls      */
uint8_t  pqf_die_last_erase_cmd;  /* the block command byte used       */
uint32_t pqf_die_last_erase_size; /* the block size used               */

/* Ordering: the ROM sequence must be connect -> exit_xip -> {erase,
 * program} -> flush -> enter_cmd_xip. Recorded as a short trace so the
 * suite can assert the order rather than only the counts. */
char pqf_die_trace[256];
static size_t s_trace_len;
static void trace(char c)
{
    if (s_trace_len + 1 < sizeof pqf_die_trace)
        pqf_die_trace[s_trace_len++] = c;
    pqf_die_trace[s_trace_len] = '\0';
}

/* Tear injection: stop applying a program after this many bytes, to
 * model losing power mid-write. 0 = disabled. */
size_t pqf_die_tear_after_n_bytes;

/* Power-loss injection across a whole multi-step write: when >= 0, the
 * next pqf_die_power_budget programmed bytes land, then power is lost
 * -- the program in flight stops there and every later erase and
 * program is dropped until the budget is set again (or the die reset).
 * Unlike the per-call tear above, a write made of several flash ops
 * cannot "finish" its later steps after the cut. -1 = disabled. */
long pqf_die_power_budget = -1;
bool pqf_die_powered_off;

void pqf_die_reset(void)
{
    memset(pqf_host_die, 0xFF, sizeof pqf_host_die);
    memset(&pqf_host_qmi, 0, sizeof pqf_host_qmi);
    pqf_die_erases = pqf_die_programs = pqf_die_bit_violations = 0;
    pqf_die_unaligned = pqf_die_xip_exits = pqf_die_xip_enters = 0;
    pqf_die_flushes = pqf_die_connects = 0;
    pqf_die_last_erase_cmd = 0;
    pqf_die_last_erase_size = 0;
    pqf_die_tear_after_n_bytes = 0;
    pqf_die_power_budget = -1;
    pqf_die_powered_off = false;
    s_trace_len = 0;
    pqf_die_trace[0] = '\0';
}

void pqf_die_clear_trace(void)
{
    s_trace_len = 0;
    pqf_die_trace[0] = '\0';
}

/* ---- The ROM routines flash_store.c looks up ---------------------- */

void pqf_die_connect_internal_flash(void) { pqf_die_connects++; trace('c'); }
void pqf_die_flash_exit_xip(void)         { pqf_die_xip_exits++; trace('x'); }
void pqf_die_flash_flush_cache(void)      { pqf_die_flushes++;   trace('f'); }
void pqf_die_flash_enter_cmd_xip(void)    { pqf_die_xip_enters++; trace('e'); }

void pqf_die_flash_range_erase(uint32_t off, size_t count, uint32_t block_size,
                               uint8_t block_cmd)
{
    pqf_die_erases++;
    pqf_die_last_erase_cmd = block_cmd;
    pqf_die_last_erase_size = block_size;
    trace('E');

    if (off % FLASH_SECTOR_SIZE != 0) {
        pqf_die_unaligned++;
        return;                      /* a real device would misbehave */
    }
    if (pqf_die_powered_off)
        return;
    if (off + count > sizeof pqf_host_die)
        return;
    memset(pqf_host_die + off, 0xFF, count);
}

void pqf_die_flash_range_program(uint32_t off, const uint8_t *data, size_t count)
{
    pqf_die_programs++;
    trace('P');

    if (off + count > sizeof pqf_host_die)
        return;

    size_t limit = count;
    if (pqf_die_tear_after_n_bytes && pqf_die_tear_after_n_bytes < limit)
        limit = pqf_die_tear_after_n_bytes;
    if (pqf_die_powered_off)
        return;
    if (pqf_die_power_budget >= 0) {
        if ((size_t)pqf_die_power_budget <= limit) {
            limit = (size_t)pqf_die_power_budget;
            pqf_die_powered_off = true;
        }
        pqf_die_power_budget -= (long)limit;
    }

    for (size_t i = 0; i < limit; i++) {
        /* NOR: programming can only clear bits. Asking for a 1 where
         * the die holds 0 means this page was not erased first -- on
         * hardware the bit simply stays 0 and the readback silently
         * differs from what was written. */
        if ((pqf_host_die[off + i] & data[i]) != data[i])
            pqf_die_bit_violations++;
        pqf_host_die[off + i] &= data[i];
    }
}

/* flash_store.c hands its flash operation to core 1 so that core can be
 * parked with XIP down (the M1 lockout). There is no core 1 here; run
 * it inline. Linking the real core1_signer.c instead would drag in the
 * entire crypto stack for one function. */
void core1_run_flash_op(void (*cb)(void *), void *arg) { cb(arg); }
