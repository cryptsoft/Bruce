/* core1_mailbox.h -- shared-SRAM mailbox ABI for the MIXED-architecture
 * build (PQF_CORE1_RISCV): Arm core 0 + RISC-V core 1.
 *
 * Core 0 (this Arm firmware) launches the embedded RISC-V signing blob
 * (c/firmware/core1-riscv-blob) on core 1 and drives it through this
 * mailbox -- a plain repr-C struct in core 0's SRAM whose address is
 * handed to the blob over the inter-core FIFO at launch. Both link
 * units (the Arm firmware and the RISC-V blob) include THIS header, so
 * the layout is defined in exactly one place.
 *
 * Synchronisation: plain volatile loads/stores + __dmb() only -- never
 * an atomic RMW -- so nothing relies on the Arm exclusive monitor or the
 * RISC-V AMO extension agreeing across ISAs. RP2350 SRAM is uncached
 * (only the XIP flash path has a cache), so a __dmb() release/acquire
 * pair is sufficient. This mirrors the Rust mixed-mode design in
 * pqf_signer_core::signer.
 *
 * The signing worker is the C port's own hybrid_sign() (openssl-mini),
 * compiled into the blob for riscv32 -- NOT the Rust signer. So the
 * mailbox carries hybrid_sign()'s exact arguments.
 *
 * ---- Memory carve-up (mixed build; see CMake memory_core1riscv) ----
 *   FLASH 0x1000_0000 .. 0x1018_0000  Arm firmware image (1.5 MiB)
 *         0x1018_0000 .. 0x1020_0000  RISC-V blob (512 KiB, XIP; ends
 *                                     exactly at the 2 MiB mark so the
 *                                     image loads on FLASH_DEVINFO-
 *                                     unprogrammed boards like Feitian)
 *   RAM   0x2000_0000 .. 0x2002_0000  Arm firmware (128 KiB)
 *         0x2002_0000 .. 0x2008_0000  blob RAM (384 KiB): whole image
 *                                     (.text/.rodata/.data/.bss ~121 KiB)
 *                                     + ~233 KiB malloc heap + 32 KiB
 *                                     stack down from the top.
 * Why 128/384 (2026-07-17; earlier 176/336, 192/320, 256/256):
 * openssl-mini's ML-DSA is the full-fat variant; its sign heap peak is
 * 99/143/199 KiB at level 44/65/87 (host-measured with exact malloc
 * accounting) plus newlib fragmentation on silicon (~+24 KiB observed
 * at level 65: ~167 KiB peak, silicon-confirmed 2026-07-14). The blob
 * ALSO holds its whole ~121 KiB image in RAM (the 2026-07-16 all-RAM
 * relayout that killed the XIP-cache CPI-21 stall). The 336 KiB window
 * (~186 KiB heap) cleared level 65 but OOM'd the level-87 sign on
 * silicon (2026-07-17, MLDSA_FAIL at heap_hw 116 KiB when the big
 * polynomial allocation was refused); 384 KiB gives ~233 KiB. Core 0
 * runs CTAP + CBOR + AES/HMAC credential wrap + PIN-protocol EC
 * (~20 KiB heap peak) -- everything heavy is on the blob, so 128 KiB
 * (~81 KiB bss + ~45 KiB heap/stack) suffices.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQF_CORE1_MAILBOX_H
#define PQF_CORE1_MAILBOX_H

#include <stdint.h>
#include "hybrid.h"   /* PQF_HYBRID_MAX_SIG */

/* Fixed blob addresses (cross-link-unit ABI -- keep in sync with
 * core1-riscv-blob/blob.ld and the CMake memory_core1riscv layout). */
/* Overridable: a DFU build (PQF_APP_OFFSET) relocates the blob inside
 * the app slot, and CMake then defines this to match the generated
 * linker scripts. Standalone images keep 0x10180000. */
#ifndef PQF_BLOB_FLASH_ORIGIN
#define PQF_BLOB_FLASH_ORIGIN  0x10180000u
#endif
#define PQF_BLOB_FLASH_LEN     0x00080000u   /* 512 KiB, ends at 2 MiB */
#define PQF_BLOB_RAM_ORIGIN    0x20020000u
#define PQF_BLOB_RAM_LEN       0x00060000u   /* 384 KiB (was 336/320) -- the
                                              * blob runs its ENTIRE image
                                              * from SRAM (XIP-cache sharing
                                              * with core 0 was the CPI-21
                                              * stall), AND the ML-DSA sign
                                              * heap peak scales 99/143/199
                                              * KiB across level 44/65/87 (+
                                              * newlib fragmentation) -- see
                                              * the carve-up note above */
#define PQF_BLOB_STACK_TOP     (PQF_BLOB_RAM_ORIGIN + PQF_BLOB_RAM_LEN)  /* 0x2008_0000, unchanged */
#define PQF_BLOB_TRAP_OFFSET   0u            /* MTVEC = origin + 0  */
#define PQF_BLOB_ENTRY_OFFSET  8u            /* PC   = origin + 8   */

/* Largest message core 0 asks the blob to sign (authData + clientDataHash;
 * matches the Rust MAX_MSG_LEN). */
#define MB_MAX_MSG   4096u

/* Mailbox state machine. */
enum {
    MB_IDLE      = 0,
    MB_REQUESTED = 1,
    MB_DONE      = 2,
    MB_ERROR     = 3,
};

/* Operation selector (mb->op, valid while state==MB_REQUESTED). The
 * blob owns ALL bn/ec/ML-DSA math in mixed mode: core 0 runs from XIP
 * flash and a single P-256 scalar multiplication from there costs ~5 s
 * under XIP-cache thrash (silicon-measured 2026-07-16), so even the
 * "cheap" EC ops are routed to the blob's RAM-resident code. */
enum {
    MB_OP_SIGN        = 0,  /* hybrid sign: scalar+seed+msg -> sig      */
    MB_OP_P256_KEYGEN = 1,  /* fresh P-256 keypair -> sig = priv||x||y  */
    MB_OP_P256_SIGN   = 2,  /* ECDSA: scalar + msg(32B prehash) -> DER  */
    MB_OP_MLDSA_PUB   = 3,  /* ML-DSA pubkey from seed -> sig = raw pk.
                             * Routed here for HEAP, not just speed: the
                             * FIPS 204 keygen behind pub-from-seed peaks
                             * ~90-100 KiB at level 87 (matrix A alone is
                             * 8x7 KiB), which overflows core 0's ~90 KiB
                             * mixed-build heap and pico_malloc PANICS on
                             * OOM -- silicon-observed 2026-07-17 as a hard
                             * wedge in MakeCredential. The blob's ~186 KiB
                             * heap holds it easily. sig[] (>= the hybrid
                             * sig, which always exceeds the pk at every
                             * level) carries the output. */
};

/* Bring-up diagnostic stages (dbg_stage). dbg_val carries a
 * stage-specific number (attempt count / register snapshot). */
enum {
    MB_DBG_BOOT           = 0,  /* blob_main hasn't reached the worker loop */
    MB_DBG_IDLE           = 1,  /* idle_wait, no request pending */
    MB_DBG_GOT_REQUEST    = 2,  /* MB_REQUESTED observed, entering hybrid_sign */
    MB_DBG_TRNG_ATTEMPT   = 3,  /* trng_refill attempt N (dbg_val = N) */
    MB_DBG_TRNG_OK        = 4,  /* trng_refill succeeded on attempt N */
    MB_DBG_TRNG_DEAD      = 5,  /* trng_refill exhausted all attempts, parked */
    MB_DBG_SIGN_DONE      = 6,  /* hybrid_sign returned 0, publishing result */
    MB_DBG_SIGN_ERROR     = 7,  /* hybrid_sign returned nonzero (dbg_val = rc) */
    MB_DBG_ECDSA_ATTEMPT  = 8,  /* about to call pqf_ecdsa_p256_sign */
    MB_DBG_ECDSA_OK       = 9,  /* pqf_ecdsa_p256_sign returned 0 */
    MB_DBG_ECDSA_FAIL     = 10, /* pqf_ecdsa_p256_sign returned nonzero (dbg_val = rc) */
    MB_DBG_MLDSA_ATTEMPT  = 11, /* about to call pqf_mldsa_sign */
    MB_DBG_MLDSA_OK       = 12, /* pqf_mldsa_sign returned 0 */
    MB_DBG_MLDSA_FAIL     = 13, /* pqf_mldsa_sign returned nonzero (dbg_val = rc) */
    MB_DBG_ECDSA_R_ZERO   = 14, /* ecdsa_sign_setup: r computed as zero, retrying k */
    MB_DBG_ECDSA_S_ZERO   = 15, /* ossl_ecdsa_simple_sign_sig: s==0 (dbg_val = retry count) */
    MB_DBG_ECDSA_TOOMANY  = 16, /* ECDSA gave up after MAX_ECDSA_SIGN_RETRIES */
    MB_DBG_HEAP_OOM       = 17, /* _sbrk refused to grow (dbg_val = heap bytes in use) */
};

/* repr-C, 32-byte aligned (cache-line-ish; deterministic layout across
 * the two toolchains). All cross-core fields are volatile. */
typedef struct __attribute__((aligned(32))) {
    volatile uint32_t state;         /* MB_* */
    volatile uint32_t op;            /* MB_OP_* (set before state=REQUESTED) */
    /* Flash-lockout handshake (M1): core 0 sets park_request before a
     * flash erase/program (credential store etc.), which suspends XIP
     * for the WHOLE QSPI -- including the blob's own flash window -- so
     * the blob must stop fetching. It parks in a RAM-resident spin
     * (sets park_ack) until core 0 clears park_request. */
    volatile uint32_t park_request;
    volatile uint32_t park_ack;
    volatile uint32_t msg_len;       /* input  */
    volatile uint32_t sig_len;       /* output */
    /* Bring-up diagnostics (silicon debugging the mixed build): the
     * blob stamps its progress here so core 0 can report it over CDC
     * while spinning in core1_hybrid_sign(). See MB_DBG_* in
     * core1_signer_riscv.c. Not touched once the blob is proven --
     * cheap enough (2 words) to leave permanently as a diagnostic. */
    volatile uint32_t dbg_stage;
    volatile uint32_t dbg_val;
    volatile uint32_t dbg_heap_hw;   /* blob heap high-water mark (bytes) */
    uint8_t  scalar[32];             /* input: ECDSA-P256 private scalar */
    uint8_t  seed[32];               /* input: ML-DSA seed */
    /* input: 32 bytes of core 0's own RAND_bytes output -- the QRNG when
     * one is present (pqf_qrng.c), the TRNG otherwise -- refreshed for
     * EVERY request. The blob hashes it together with a block from its
     * own TRNG read for its RAND_bytes (ECDSA hedge, P-256 keygen), so
     * the external source reaches core 1 too although only core 0 owns
     * the I2C controller. Wiped by core 0 when the op completes. */
    uint8_t  entropy[32];
    uint8_t  msg[MB_MAX_MSG];        /* input: bytes to sign */
    uint8_t  sig[PQF_HYBRID_MAX_SIG];/* output: ecdsa_der || mldsa_sig */
} core1_mailbox_t;

#endif /* PQF_CORE1_MAILBOX_H */
