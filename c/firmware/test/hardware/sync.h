/* Host shim for the pico-sdk sync primitives core1_signer.c uses.
 *
 * The interrupt mask is modelled rather than stubbed: the signer saves
 * and restores it, and a caller already inside a critical section must
 * stay masked. sev/wfe are counted, because a missing sev on silicon
 * means the other core sleeps through a request.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQF_HOST_HARDWARE_SYNC_H
#define PQF_HOST_HARDWARE_SYNC_H
#include <stdint.h>
#include <stdbool.h>

extern volatile bool     pqf_host_irqs_masked;
extern volatile uint32_t pqf_host_sevs;
extern volatile uint32_t pqf_host_wfes;

static inline uint32_t save_and_disable_interrupts(void)
{
    uint32_t was = pqf_host_irqs_masked ? 1u : 0u;
    pqf_host_irqs_masked = true;
    return was;
}
static inline void restore_interrupts(uint32_t saved)
{
    pqf_host_irqs_masked = (saved != 0);
}
static inline void __dmb(void) { __sync_synchronize(); }
static inline void __dsb(void) { __sync_synchronize(); }
static inline void __isb(void) { }
static inline void __sev(void) { pqf_host_sevs++; }
static inline void __wfe(void) { pqf_host_wfes++; }
static inline void __nop(void) { }
#endif
