/* core1_signer.h -- offload the slow hybrid PQC signature to core 1.
 *
 * ML-DSA signing on the Cortex-M33 takes hundreds of milliseconds.
 * If core 0 blocked on it, USB would go unserviced and the host's
 * WebAuthn watchdog would fire. So the hybrid sign runs on core 1
 * while core 0 stays in a wait loop that pumps the USB stack and
 * emits CTAPHID KEEPALIVE frames -- exactly the split the Rust
 * firmware uses (crates/firmware/src/core1_signer.rs).
 *
 * The data handed to core 1 (scalar, seed, message, output buffer)
 * stays owned by the caller and remains valid for the whole call,
 * because core1_hybrid_sign() does not return until core 1 is done.
 *
 * Host builds replace this with a stub (test/host_core1_stub.c) that
 * just calls hybrid_sign() inline -- there's no second core to use.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_CORE1_SIGNER_H
#define PQF_CORE1_SIGNER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Launch the core-1 worker. Call once at boot. */
void core1_signer_init(void);

#ifdef PQF_CORE1_RISCV
/* Mixed build (core1_signer_riscv.c) only: true once the RISC-V core-1
 * blob has launched and taken over signing; false if it never came up
 * and core1_hybrid_sign() is falling back to signing inline on core 0
 * (e.g. a part with the Hazard3 cores fused off). Diagnostics -- lets the
 * boot banner report which path is live. */
bool core1_riscv_blob_running(void);
#endif

/* Hook core 0 calls repeatedly while waiting for core 1: it should
 * service USB and send a CTAPHID KEEPALIVE on the in-flight channel.
 * Set by the USB/CTAPHID layer; left NULL on host builds. */
extern void (*core1_long_op_tick)(void);

#if defined(__riscv)
/* Trap forensics (RISC-V builds -- see isr_riscv_machine_exception in
 * riscv_trap.c). Index = core number. Top bit set => that core took a
 * machine exception; low bits = mcause, with mepc alongside. Core 1
 * survives its own death (park handshake still serviced, signs fail
 * cleanly); main.c reports the record over CDC. */
extern volatile uint32_t pqf_trap_mcause[2];
extern volatile uint32_t pqf_trap_mepc[2];
/* Where a trapped core 1 goes (riscv_trap.c hands off here). The
 * dual-core signer parks it in a loop that keeps the flash handshake
 * alive; the single-core build never reaches it. */
void pqf_core1_trap_park(void) __attribute__((noreturn));
#endif

#if defined(PQF_SINGLE_CORE)
/* Single-core build (core0_signer.c): the signer runs inline on core 0
 * and the crypto's yield hook pumps USB + KEEPALIVE. Counters for the
 * CDC banner. `max_gap_us` is the longest stretch of any op so far
 * with no yield call -- the worst KEEPALIVE gap this build can show a
 * host; `op_*` are the same for the most recent op. */
struct pqf_single_core_stats {
    uint32_t ops;         /* inline ops run (signs, keygens, pub derivations) */
    uint32_t yields;      /* pqf_yield() calls                                 */
    uint32_t ticks;       /* of which fired the USB + KEEPALIVE tick           */
    uint32_t max_gap_us;  /* worst yield-to-yield gap inside any op, with the
                           * time spent inside the tick itself excluded: the
                           * crypto's blind spot, where no keepalive can go   */
    uint32_t max_tick_us; /* longest single tick (USB service + one KEEPALIVE
                           * frame); a slow one is the host, not the crypto   */
    uint32_t op_gap_us;   /* worst blind spot, most recent op                  */
    uint32_t op_tick_us;  /* longest tick, most recent op                      */
    uint32_t op_ticks;    /* ticks fired during the most recent op             */
    uint32_t op_kind;     /* most recent op: 0 hybrid sign, 1 P-256 keygen,
                           * 2 P-256 sign, 3 ML-DSA public key               */
    uint32_t op_gap_at;   /* yield index within the op where its worst gap
                           * ended (0 = before the first yield)               */
    uint32_t op_yields;   /* yields during the most recent op                  */
    uint32_t kind_gap_us[4]; /* worst blind spot per op kind, since boot       */
};
extern struct pqf_single_core_stats pqf_1core;
#endif

/* Produce a hybrid signature on core 1, blocking (but pumping
 * core1_long_op_tick) until it completes. Same contract as
 * hybrid_sign(). Returns 0 / < 0. */
int core1_hybrid_sign(const uint8_t ecdsa_scalar[32],
                      const uint8_t mldsa_seed[32],
                      const uint8_t *msg, size_t msg_len,
                      uint8_t *sig, size_t *sig_len);

/* P-256 keygen / ECDSA-sign through the signing core. In the MIXED
 * build these run on the RISC-V blob: its whole bn/ec stack executes
 * from SRAM, whereas core 0's copy runs from XIP flash where a single
 * scalar multiplication costs ~5 s under cache thrash (silicon-measured
 * 2026-07-16). Single-ISA firmware and host builds run them inline
 * (pqf_p256_keygen / pqf_ecdsa_p256_sign) -- copy_to_ram already makes
 * those fast. Same contracts as the pqf_* originals. */
int core1_p256_keygen(uint8_t priv[32], uint8_t pub_x[32], uint8_t pub_y[32]);
int core1_p256_sign(const uint8_t scalar[32], const uint8_t prehash[32],
                    uint8_t *sig, size_t *sig_len);

/* ML-DSA public key from seed through the signing core. In the MIXED
 * build this MUST run on the blob: the FIPS 204 keygen behind it peaks
 * ~90-100 KiB of heap at level 87, over core 0's ~90 KiB window, and
 * pico_malloc panics on OOM (silicon-observed 2026-07-17 as a hard
 * MakeCredential wedge). Single-ISA and host builds run it inline
 * (their heaps are ample). `pub` must hold PQF_HYBRID_PK_LEN. */
int core1_mldsa_pub(const uint8_t seed[32], uint8_t *pub, size_t *pub_len);

/* Run a flash erase/program callback on core 0 with core 1 parked in a
 * RAM-resident spin for the whole XIP-off window (and core-0 IRQs
 * masked). This REPLACES pico-sdk flash_safe_execute / multicore_lockout
 * for the M1 core-1 lockout: that mechanism rides the inter-core FIFO
 * IRQ, whose handshake does not complete between the RP2350's two
 * Hazard3 (RISC-V) cores -- the lockout-release wait has no timeout, so
 * core 0 hangs there and the device wedges (observed on silicon when a
 * resident credential is committed -- the first runtime flash write with
 * core 1 alive). The explicit park below is arch-neutral and mirrors
 * the Rust port's proven M1 handshake (crates/signer-core/src/
 * signer.rs). `cb` must confine its XIP-off work to the pico-sdk
 * RAM-resident flash_range_* routines. Firmware only (the host build
 * stubs flash out). */
void core1_run_flash_op(void (*cb)(void *), void *arg);

#endif /* PQF_CORE1_SIGNER_H */
