/* core1_signer_riscv.c -- MIXED-architecture core-1 signer (C port).
 *
 * Drop-in replacement for core1_signer.c, selected by the CMake option
 * PQF_CORE1_RISCV. Same public API (core1_signer.h), but core 1 is a
 * Hazard3 (RISC-V) running the embedded blob (core1-riscv-blob/) instead
 * of a second Cortex-M33 running core1_main(). Core 0 stays Arm.
 *
 * At boot we flip core 1 to RISC-V (OTP ARCHSEL), PSM-reset it into the
 * boot ROM, launch the blob at its fixed addresses via the documented
 * FIFO handshake, and hand it the shared-SRAM mailbox address. From then
 * on core 0 drives the blob purely through that mailbox
 * (core1_mailbox.h) -- plain volatile + __dmb(), never an atomic RMW, so
 * nothing depends on the Arm exclusive monitor and the RISC-V AMO unit
 * agreeing across ISAs.
 *
 * This is the C mirror of the Rust mixed mode
 * (crates/firmware/src/core1_launch.rs :: spawn_core1_signer_riscv_blob
 * + crates/signer-core). One deliberate improvement over the Rust path,
 * which .expect()s the launch: if core 1 refuses RISC-V (e.g. a part
 * with the Hazard3 cores fused off via OTP CRIT), we fall back to
 * signing inline on core 0 -- the full crypto is linked into the Arm
 * image anyway -- so the device still works (a long sign just blocks USB
 * briefly) rather than wedging on the first credential.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "pico/multicore.h"     /* __sev/__wfe/__dmb via hardware/sync.h */
#include "pico/sync.h"
#include "pico/platform.h"      /* tight_loop_contents */
#include "pico/time.h"          /* get_absolute_time / time_reached (diag log) */
#include "hardware/sync.h"      /* save_and_disable_interrupts */
#include "tusb.h"                /* tud_cdc_* (diag log -- mirrors main.c's cdc_log) */
#include "hardware/structs/sio.h"
#include "hardware/structs/psm.h"
#include "hardware/structs/otp.h"
#include "hardware/regs/psm.h"  /* PSM_FRCE_OFF_PROC1_BITS */
#include "hardware/regs/otp.h"  /* OTP_ARCHSEL_* */

#include "core1_signer.h"
#include "pqf_cleanse.h"
#include "openssl/rand.h"   /* per-request entropy for the blob (mb.entropy) */
#include "core1_mailbox.h"
#include "hybrid.h"
#include "pqf_crypto.h"          /* inline fallbacks when the blob is down */

/* The shared mailbox: lives in CORE 0's SRAM (this is an Arm image, so
 * it lands in the 320 KiB core-0 window below 0x2005_0000). The blob
 * receives its ADDRESS over the FIFO and accesses it cross-core; SRAM is
 * flat and uncached, so a pointer works from either ISA. */
static core1_mailbox_t s_mb;

/* Set once the blob is confirmed running on a RISC-V core 1. If it never
 * launches, core1_hybrid_sign() signs inline on core 0 instead. */
static bool s_blob_running;

void (*core1_long_op_tick)(void) = NULL;

/* Bring-up diagnostic: report the blob's mailbox dbg_stage/dbg_val over
 * CDC (same interface as main.c's cdc_log) at ~2 Hz while core 0 spins
 * waiting for a sign. Lets a silicon hang be root-caused (which stage,
 * which TRNG attempt) without a debugger attached to the RISC-V core. */
static const char *dbg_stage_name(uint32_t stage)
{
    switch (stage) {
    case MB_DBG_BOOT:         return "BOOT (blob not in worker loop yet)";
    case MB_DBG_IDLE:         return "IDLE";
    case MB_DBG_GOT_REQUEST:  return "GOT_REQUEST (entering hybrid_sign)";
    case MB_DBG_TRNG_ATTEMPT: return "TRNG_ATTEMPT";
    case MB_DBG_TRNG_OK:      return "TRNG_OK";
    case MB_DBG_TRNG_DEAD:    return "TRNG_DEAD (parked -- no healthy entropy)";
    case MB_DBG_SIGN_DONE:    return "SIGN_DONE (publishing result)";
    case MB_DBG_SIGN_ERROR:   return "SIGN_ERROR (hybrid_sign returned nonzero)";
    case MB_DBG_ECDSA_ATTEMPT:return "ECDSA_ATTEMPT";
    case MB_DBG_ECDSA_OK:     return "ECDSA_OK (val=der_len)";
    case MB_DBG_ECDSA_FAIL:   return "ECDSA_FAIL (val=rc)";
    case MB_DBG_MLDSA_ATTEMPT:return "MLDSA_ATTEMPT";
    case MB_DBG_MLDSA_OK:     return "MLDSA_OK (val=sig_len)";
    case MB_DBG_MLDSA_FAIL:   return "MLDSA_FAIL (val=rc)";
    case MB_DBG_ECDSA_R_ZERO: return "ECDSA_R_ZERO (r==0, retrying k)";
    case MB_DBG_ECDSA_S_ZERO: return "ECDSA_S_ZERO (val=retry count)";
    case MB_DBG_ECDSA_TOOMANY:return "ECDSA_TOOMANY (gave up)";
    case MB_DBG_HEAP_OOM:     return "HEAP_OOM (val=bytes in use at OOM)";
    default:                  return "?";
    }
}

static void log_mailbox_diag(void)
{
    if (!tud_cdc_connected())
        return;
    char buf[160];
    snprintf(buf, sizeof buf,
             "  [blob diag] stage=%s val=%lu mb.state=%lu sig_len=%lu heap_hw=%lu\r\n",
             dbg_stage_name(s_mb.dbg_stage), (unsigned long)s_mb.dbg_val,
             (unsigned long)s_mb.state, (unsigned long)s_mb.sig_len,
             (unsigned long)s_mb.dbg_heap_hw);
    tud_cdc_write_str(buf);
    tud_cdc_write_flush();
}

/* Provided by core1_blob.S (.incbin of the objcopy'd blob binary),
 * placed at PQF_BLOB_FLASH_ORIGIN by the mixed linker script. */
extern const uint8_t core1_blob_start[];
extern const uint8_t core1_blob_end[];

/* ==================================================================== *
 *  Inter-core FIFO (raw SIO) -- used only for the launch handshake.
 *  fifo_st: bit0 VLD (rx has data), bit1 RDY (tx has space).
 * ==================================================================== */
#define FIFO_ST_VLD  1u
#define FIFO_ST_RDY  2u

static void fifo_drain(void)
{
    while (sio_hw->fifo_st & FIFO_ST_VLD)
        (void)sio_hw->fifo_rd;
    __dmb();
}

static void fifo_push_blocking(uint32_t v)
{
    while (!(sio_hw->fifo_st & FIFO_ST_RDY))
        tight_loop_contents();
    sio_hw->fifo_wr = v;
    __sev();                                    /* wake core 1 if blocked */
}

static uint32_t fifo_pop_blocking(void)
{
    while (!(sio_hw->fifo_st & FIFO_ST_VLD))
        tight_loop_contents();
    return sio_hw->fifo_rd;
}

/* PSM-reset core 1 so it re-enters the boot ROM wait-for-launch loop,
 * then run the documented [0,0,1,MTVEC,SP,PC] handshake (each word is
 * echoed). Mirrors core1_launch.rs::psm_reset_and_launch. */
static bool psm_reset_and_launch(const uint32_t cmd_seq[6])
{
    hw_set_bits(&psm_hw->frce_off, PSM_FRCE_OFF_PROC1_BITS);
    while (!(psm_hw->frce_off & PSM_FRCE_OFF_PROC1_BITS))
        tight_loop_contents();
    hw_clear_bits(&psm_hw->frce_off, PSM_FRCE_OFF_PROC1_BITS);

    unsigned seq = 0, fails = 0;
    while (seq < 6) {
        uint32_t cmd = cmd_seq[seq];
        if (cmd == 0) {
            fifo_drain();
            __sev();
        }
        fifo_push_blocking(cmd);
        if (fifo_pop_blocking() == cmd) {
            seq++;
        } else {
            seq = 0;
            if (++fails > 16)
                return false;   /* core 1 not echoing the handshake */
        }
    }
    return true;
}

/* Flip core 1 to RISC-V and launch the blob; return false if the switch
 * or handshake fails (caller falls back to inline signing). Mirrors the
 * Rust spawn_core1_signer_riscv_blob sequence exactly. */
static bool spawn_core1_riscv_blob(void)
{
    size_t blob_len = (size_t)(core1_blob_end - core1_blob_start);

    /* Tripwires for a mis-built payload (cheap, keep in release): it
     * must fit its flash window, and its first word must be the trap
     * loop's `wfi` (0x10500073, little-endian 73 00 50 10) -- anything
     * else means the blob.ld layout contract broke. */
    if (blob_len == 0 || blob_len > PQF_BLOB_FLASH_LEN)
        return false;
    if (core1_blob_start[0] != 0x73 || core1_blob_start[1] != 0x00 ||
        core1_blob_start[2] != 0x50 || core1_blob_start[3] != 0x10)
        return false;

    /* 1) Hold core 1 in reset while we change its architecture. */
    hw_set_bits(&psm_hw->frce_off, PSM_FRCE_OFF_PROC1_BITS);
    while (!(psm_hw->frce_off & PSM_FRCE_OFF_PROC1_BITS))
        tight_loop_contents();

    /* 2) ARCHSEL is a live OTP-block register (not a fuse); each core
     *    samples its bit on reset exit. Set CORE1 = RISC-V. */
    hw_set_bits(&otp_hw->archsel, OTP_ARCHSEL_CORE1_BITS);

    /* 3) Release + verify. Fail loudly rather than handshake an Arm boot
     *    ROM with RISC-V launch words. */
    hw_clear_bits(&psm_hw->frce_off, PSM_FRCE_OFF_PROC1_BITS);
    uint32_t spins = 0;
    while (!(otp_hw->archsel_status & OTP_ARCHSEL_STATUS_CORE1_BITS)) {
        if (++spins > 1000000u)
            return false;       /* RISC-V fused off? */
        tight_loop_contents();
    }

    /* 4) Launch the blob at its fixed addresses (see core1_mailbox.h). */
    const uint32_t cmd_seq[6] = {
        0, 0, 1,
        PQF_BLOB_FLASH_ORIGIN + PQF_BLOB_TRAP_OFFSET,   /* MTVEC */
        PQF_BLOB_STACK_TOP,
        PQF_BLOB_FLASH_ORIGIN + PQF_BLOB_ENTRY_OFFSET,  /* PC */
    };
    if (!psm_reset_and_launch(cmd_seq))
        return false;

    /* 5) Rendezvous: the blob's first action after runtime init is one
     *    blocking FIFO read -- this word. The handshake left the FIFO
     *    empty, so it can't be misread. */
    pqf_cleanse(s_mb.entropy, sizeof s_mb.entropy);
    s_mb.state = MB_IDLE;
    __dmb();
    fifo_push_blocking((uint32_t)(uintptr_t)&s_mb);
    return true;
}

void core1_signer_init(void)
{
    s_blob_running = spawn_core1_riscv_blob();
}

/* Is the RISC-V signing core live? (Bring-up / diagnostics -- lets main.c
 * log which path is in use without exposing the mailbox.) */
bool core1_riscv_blob_running(void)
{
    return s_blob_running;
}

/* Every request carries 32 fresh bytes of THIS core's RAND_bytes -- the
 * QRNG when one answered at boot, pico_rand/TRNG otherwise -- which the
 * blob folds into its own RAND_bytes (see core1_mailbox.h `entropy`).
 * Drawn immediately before the request is published so the bytes are
 * per-op, never reused, and wiped once the op is done. */
static void mb_fresh_entropy(void)
{
    RAND_bytes(s_mb.entropy, sizeof s_mb.entropy);
}

int core1_hybrid_sign(const uint8_t ecdsa_scalar[32],
                      const uint8_t mldsa_seed[32],
                      const uint8_t *msg, size_t msg_len,
                      uint8_t *sig, size_t *sig_len)
{
    /* Fallback: no RISC-V core -- sign inline on core 0. The full crypto
     * is linked into this Arm image, and core 0 has a working RAND_bytes
     * (pqf_rand -> pico_rand), so the result is identical; USB just
     * stalls for the sign. */
    if (!s_blob_running)
        return hybrid_sign(ecdsa_scalar, mldsa_seed, msg, msg_len, sig, sig_len);

    if (msg_len > MB_MAX_MSG)
        return -1;

    memcpy(s_mb.scalar, ecdsa_scalar, 32);
    memcpy(s_mb.seed, mldsa_seed, 32);
    memcpy(s_mb.msg, msg, msg_len);
    s_mb.msg_len = (uint32_t)msg_len;
    s_mb.sig_len = 0;
    s_mb.op = MB_OP_SIGN;
    mb_fresh_entropy();
    __dmb();                                    /* publish request before flag */
    s_mb.state = MB_REQUESTED;
    __sev();                                    /* harmless nudge (blob polls) */

    /* Spin until the blob finishes, keeping USB + KEEPALIVE alive.
     * A flat-out spin is fine: with the blob fully RAM-resident
     * (blob.ld) this loop's XIP fetches are cache-hits that evict
     * nothing core 1 needs -- measured CPI on core 1 is ~1.2 whether
     * core 0 spins or sits dead quiet (2026-07-16 contention test). */
    absolute_time_t diag_due = make_timeout_time_ms(100);
    while (s_mb.state == MB_REQUESTED) {
        if (core1_long_op_tick != NULL)
            core1_long_op_tick();
        if (time_reached(diag_due)) {
            log_mailbox_diag();
            diag_due = make_timeout_time_ms(100);
        }
    }
    __dmb();                                    /* acquire sig before reading */
    /* Final outcome. The blob now leaves the specific failing sub-stage
     * latched in dbg_stage (see worker() in blob_main.c), so this line
     * reports exactly which half failed -- e.g.
     *   >>> OUTCOME stage=MLDSA_FAIL (val=rc) val=... mb.state=3
     * instead of the old racy "IDLE". */
    if (tud_cdc_connected()) {
        char b[192];
        snprintf(b, sizeof b,
                 ">>> OUTCOME stage=%s val=%lu mb.state=%lu sig_len=%lu heap_hw=%lu\r\n",
                 dbg_stage_name(s_mb.dbg_stage), (unsigned long)s_mb.dbg_val,
                 (unsigned long)s_mb.state, (unsigned long)s_mb.sig_len,
                 (unsigned long)s_mb.dbg_heap_hw);
        tud_cdc_write_str(b);
        tud_cdc_write_flush();
    }

    size_t out_len = s_mb.sig_len;
    int rc = (s_mb.state == MB_DONE && out_len <= PQF_HYBRID_MAX_SIG) ? 0 : -1;
    if (rc == 0) {
        memcpy(sig, s_mb.sig, out_len);
        *sig_len = out_len;
    }
    pqf_cleanse(s_mb.entropy, sizeof s_mb.entropy);
    s_mb.state = MB_IDLE;
    return rc;
}

/* Wait out a small (sub-second) blob op, keeping USB + KEEPALIVE
 * pumped. Returns 0 on MB_DONE. */
static int blob_wait_done(void)
{
    while (s_mb.state == MB_REQUESTED) {
        if (core1_long_op_tick != NULL)
            core1_long_op_tick();
    }
    __dmb();                                    /* acquire results */
    return (s_mb.state == MB_DONE) ? 0 : -1;
}

int core1_p256_keygen(uint8_t priv[32], uint8_t pub_x[32], uint8_t pub_y[32])
{
    if (!s_blob_running)
        return pqf_p256_keygen(priv, pub_x, pub_y);

    s_mb.msg_len = 0;
    s_mb.sig_len = 0;
    s_mb.op = MB_OP_P256_KEYGEN;
    mb_fresh_entropy();
    __dmb();
    s_mb.state = MB_REQUESTED;
    __sev();

    int rc = blob_wait_done();
    if (rc == 0 && s_mb.sig_len == 96) {
        memcpy(priv,  s_mb.sig,      32);
        memcpy(pub_x, s_mb.sig + 32, 32);
        memcpy(pub_y, s_mb.sig + 64, 32);
    } else {
        rc = -1;
    }
    memset(s_mb.sig, 0, 96);    /* fresh private scalar -- don't leave it */
    pqf_cleanse(s_mb.entropy, sizeof s_mb.entropy);
    s_mb.state = MB_IDLE;
    return rc;
}

int core1_mldsa_pub(const uint8_t seed[32], uint8_t *pub, size_t *pub_len)
{
    /* Inline fallback (blob never launched): risky at level 87 -- the
     * keygen heap peak can overflow core 0's window (see the header) --
     * but the alternative is no hybrid support at all on a part with
     * the RISC-V cores fused off. */
    if (!s_blob_running)
        return pqf_mldsa_pub_from_seed(PQF_HYBRID_MLDSA, seed, pub, pub_len);

    memcpy(s_mb.seed, seed, 32);
    s_mb.msg_len = 0;
    s_mb.sig_len = 0;
    s_mb.op = MB_OP_MLDSA_PUB;
    mb_fresh_entropy();
    __dmb();
    s_mb.state = MB_REQUESTED;
    __sev();

    int rc = blob_wait_done();
    size_t out_len = s_mb.sig_len;
    if (rc == 0 && out_len == PQF_HYBRID_PK_LEN) {
        memcpy(pub, s_mb.sig, out_len);
        *pub_len = out_len;
    } else {
        rc = -1;
    }
    pqf_cleanse(s_mb.entropy, sizeof s_mb.entropy);
    s_mb.state = MB_IDLE;
    return rc;
}

int core1_p256_sign(const uint8_t scalar[32], const uint8_t prehash[32],
                    uint8_t *sig, size_t *sig_len)
{
    if (!s_blob_running)
        return pqf_ecdsa_p256_sign(scalar, prehash, sig, sig_len);

    memcpy(s_mb.scalar, scalar, 32);
    memcpy(s_mb.msg, prehash, 32);
    s_mb.msg_len = 32;
    s_mb.sig_len = 0;
    s_mb.op = MB_OP_P256_SIGN;
    mb_fresh_entropy();
    __dmb();
    s_mb.state = MB_REQUESTED;
    __sev();

    int rc = blob_wait_done();
    size_t out_len = s_mb.sig_len;
    if (rc == 0 && out_len > 0 && out_len <= PQF_P256_MAX_SIG_DER) {
        memcpy(sig, s_mb.sig, out_len);
        *sig_len = out_len;
    } else {
        rc = -1;
    }
    pqf_cleanse(s_mb.entropy, sizeof s_mb.entropy);
    s_mb.state = MB_IDLE;
    return rc;
}

void core1_run_flash_op(void (*cb)(void *), void *arg)
{
    /* No RISC-V core parked on the mailbox: core 1 never launched, so
     * there is nothing to hold off -- just run the flash op with core-0
     * IRQs masked (an ISR fetched from XIP would fault during the
     * XIP-off window). */
    if (!s_blob_running) {
        uint32_t ints = save_and_disable_interrupts();
        cb(arg);
        restore_interrupts(ints);
        return;
    }

    /* 1) Ask the blob to park (M1). It only reaches its idle poll
     *    between signs, and flash commits never overlap a sign (the
     *    signature counter is reserved before the signer runs), so the
     *    ack arrives promptly. */
    s_mb.park_request = 1;
    __dmb();
    __sev();
    while (!s_mb.park_ack)
        tight_loop_contents();
    __dmb();

    /* 2) Blob is now spinning in its RAM window and fetches no XIP. Mask
     *    core-0 IRQs and run the erase/program. */
    uint32_t ints = save_and_disable_interrupts();
    cb(arg);
    restore_interrupts(ints);

    /* 3) Release the blob. */
    __dmb();
    s_mb.park_request = 0;
    __sev();
    while (s_mb.park_ack)
        tight_loop_contents();
}
