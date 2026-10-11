/* riscv_trap.c -- trap forensics for the Hazard3 (RISC-V) builds.
 *
 * Hazard3 traps on EVERY misaligned load/store (the M33 handles them in
 * hardware) and mtval is hardwired to zero, and pico-sdk's default
 * `isr_riscv_machine_exception` is an ebreak + spin -- a silently dead
 * core. On core 1 that dead core turns the NEXT flash commit's park
 * handshake into a device-wide freeze; on core 0 it kills the device
 * with no forensics either way. Override the (weak) handler:
 *
 *   - record mcause/mepc per core (readable over CDC by main.c, or by a
 *     debugger after a wedge);
 *   - core 1: hand off to pqf_core1_trap_park(). The dual-core signer
 *     (core1_signer.c) provides one that parks in a RAM-resident loop
 *     which still services the flash-park handshake and answers any
 *     future sign request with an error, so flash commits keep working
 *     and signs fail cleanly instead of freezing the device. The
 *     single-core build never runs core 1, so its weak spin below is
 *     never reached;
 *   - core 0: nothing to save -- hand off to pqf_core0_trap_report(),
 *     which main.c overrides with a loop that keeps pumping USB and
 *     prints the record over CDC.
 *
 * Top bit of pqf_trap_mcause[] is a "trap happened" flag (exception
 * causes are tiny; interrupts never reach this handler).
 *
 * This used to live inside core1_signer.c; it moved here so a build
 * without that file (PQF_SINGLE_CORE) keeps the forensics. Compiles to
 * nothing on Arm.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(__riscv)

#include <stdint.h>

#include "pico.h"                    /* __no_inline_not_in_flash_func */
#include "hardware/structs/sio.h"    /* cpuid */

#include "core1_signer.h"

volatile uint32_t pqf_trap_mcause[2];
volatile uint32_t pqf_trap_mepc[2];

/* Core-0 trap reporter: weak default spins; main.c overrides it with a
 * best-effort loop that keeps pumping USB and prints the trap record
 * over CDC -- so a core-0 death during a CTAP dispatch (where main.c's
 * loop-based logger never runs) still talks to the debug terminal.
 * Never returns. */
void __attribute__((weak, noreturn)) pqf_core0_trap_report(uint32_t cause,
                                                           uint32_t epc)
{
    (void)cause; (void)epc;
    for (;;)
        __asm volatile ("");
}

/* Core 1's resting place after a trap. Weak: the dual-core signer
 * replaces it with the loop that keeps the flash-park handshake alive.
 * RAM-resident like the handler, for the same reasons. */
void __attribute__((weak)) __no_inline_not_in_flash_func(pqf_core1_trap_park)(void)
{
    for (;;)
        __asm volatile ("");
}

/* RAM-resident for two reasons: the RAM vector table reaches it with a
 * +-1 MiB JAL (an XIP address doesn't fit), and a trap taken during an
 * XIP-off window must not fetch its own handler from flash. */
void __no_inline_not_in_flash_func(isr_riscv_machine_exception)(void)
{
    uint32_t cause, epc, core;
    __asm volatile ("csrr %0, mcause" : "=r"(cause));
    __asm volatile ("csrr %0, mepc"   : "=r"(epc));
    core = sio_hw->cpuid & 1u;
    pqf_trap_mcause[core] = cause | 0x80000000u;
    pqf_trap_mepc[core]   = epc;
    if (core == 1)
        pqf_core1_trap_park();
    /* Core 0: unrecoverable, but XIP is live in every plausible trap
     * context outside the flash-op window (whose stage markers would
     * already have shown), so hand off to the XIP-resident reporter
     * for best-effort CDC forensics. */
    pqf_core0_trap_report(cause, epc);
}

#endif /* __riscv */
