/* blob_main.c -- RISC-V (Hazard3) core-1 signing payload for the C
 * port's MIXED-architecture build. Standalone: no pico-sdk, no OS. The
 * Arm core-0 firmware embeds this (objcopy'd flat binary) and launches
 * it on core 1 after flipping that core's OTP ARCHSEL to RISC-V.
 *
 * Responsibilities, in order:
 *   1. startup (called from blob_start.S): copy .data flash->RAM, zero
 *      .bss, then blob_main().
 *   2. blob_main(): read the mailbox address core 0 pushes over the SIO
 *      FIFO, then loop forever running hybrid_sign() on request.
 *   3. provide the freestanding runtime the crypto needs: the malloc
 *      family (a two-ended arena allocator replacing newlib's -- see
 *      its comment for why), RAND_bytes (this core's TRNG read hashed
 *      with the per-request entropy core 0 supplies -- see rng_refill;
 *      the C ECDSA uses a random nonce), and a few libc stubs.
 *
 * The signing math is the C port's own hybrid_sign() (openssl-mini),
 * cross-compiled for riscv32 -- byte-identical to what core 0 would
 * produce itself, so the credential/assertion is unaffected by which
 * core signed.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "hybrid.h"
#include "pqf_crypto.h"   /* diagnostic: per-phase sign (ECDSA vs ML-DSA) */
#include "core1_mailbox.h"

/* ---- inline barriers / hints (RISC-V) ------------------------------ */
static inline void dmb(void)  { __asm__ volatile("fence rw, rw" ::: "memory"); }

/* ---- linker-provided symbols (blob.ld) ----------------------------- */
extern uint32_t __text_load, __text_start, __text_end;
extern uint32_t __data_load, __data_start, __data_end;
extern uint32_t __bss_start, __bss_end;
extern uint8_t  __heap_start, __heap_end;

/* Set once in blob_main() so runtime helpers (RAND_bytes, the
 * allocator OOM hook, pqf_ecdsa_dbg) can stamp bring-up diagnostics
 * core 0 reads and logs over CDC. */
static core1_mailbox_t *s_dbg_mb;

/* ==================================================================== *
 *  Freestanding runtime
 * ==================================================================== */

/* malloc family -> the two-ended arena allocator (blob_alloc.c; see
 * blob_alloc.h for why newlib's malloc-over-_sbrk had to go: ML-DSA-87
 * sign fragmentation, silicon 2026-07-17). These definitions preempt
 * newlib's archive members at link time; the *_r reent shims cover
 * newlib-internal callers. The worker loop resets the arena before
 * each mailbox op. */
#include "blob_alloc.h"

void *malloc(size_t n)                 { return blob_malloc(n); }
void  free(void *p)                    { blob_free(p); }
void *calloc(size_t nmemb, size_t sz)  { return blob_calloc(nmemb, sz); }
void *realloc(void *p, size_t n)       { return blob_realloc(p, n); }

struct _reent;
void *_malloc_r(struct _reent *r, size_t n) { (void)r; return blob_malloc(n); }
void  _free_r(struct _reent *r, void *p) { (void)r; blob_free(p); }
void *_calloc_r(struct _reent *r, size_t a, size_t b) { (void)r; return blob_calloc(a, b); }
void *_realloc_r(struct _reent *r, void *p, size_t n) { (void)r; return blob_realloc(p, n); }

/* Allocation-failure hook (blob_alloc.h): stamp the rejected request
 * size for core 0's CDC diagnostics. NOTE dbg_val here is the REQUEST
 * size (the old _sbrk scheme reported bytes-in-use); dbg_heap_hw is
 * refreshed by the worker after each op. */
void blob_alloc_oom(size_t req)
{
    if (!s_dbg_mb) return;
    s_dbg_mb->dbg_val = (uint32_t)req;
    dmb();
    s_dbg_mb->dbg_stage = MB_DBG_HEAP_OOM;
}

/* ---- RP2350 TRNG (datasheet sec. 12.12) -- the C ECDSA nonce is random, so
 * the blob needs a real hardware RNG. Same enable sequence the Rust
 * trng.rs uses (proven on Hazard3): sw-reset, sample_cnt1=0x1000,
 * config=3 (longest ring), enable, poll VALID, read 6 EHR words.
 * One block feeds one rng_refill() below; nothing here is handed out
 * raw any more. */
#define TRNG_BASE            0x400f0000u
#define TRNG_VALID           (*(volatile uint32_t *)(TRNG_BASE + 0x110))
#define TRNG_EHR_DATA(i)     (*(volatile uint32_t *)(TRNG_BASE + 0x114 + 4u*(i)))
#define TRNG_RND_SOURCE_EN   (*(volatile uint32_t *)(TRNG_BASE + 0x12c))
#define TRNG_SAMPLE_CNT1     (*(volatile uint32_t *)(TRNG_BASE + 0x130))
#define TRNG_CONFIG          (*(volatile uint32_t *)(TRNG_BASE + 0x10c))
#define TRNG_IMR             (*(volatile uint32_t *)(TRNG_BASE + 0x100))
#define TRNG_SW_RESET        (*(volatile uint32_t *)(TRNG_BASE + 0x140))

static uint8_t  s_ent[24];   /* one EHR block = 192 bits */
static uint32_t s_ent_len;   /* bytes remaining, drained front-first */

static void trng_refill(void)
{
    for (int attempt = 0; attempt < 16; attempt++) {
        if (s_dbg_mb) {
            s_dbg_mb->dbg_val = (uint32_t)(attempt + 1);
            dmb();
            s_dbg_mb->dbg_stage = MB_DBG_TRNG_ATTEMPT;
        }
        TRNG_SW_RESET = 1;
        for (volatile int i = 0; i < 16; i++) { }
        TRNG_SAMPLE_CNT1 = 0x1000;
        TRNG_CONFIG = 3;             /* RND_SRC_SEL = 3 */
        TRNG_IMR = 0;
        TRNG_RND_SOURCE_EN = 1;
        uint32_t waited = 0;
        while ((TRNG_VALID & 1u) == 0) {
            if (++waited > 4000000u) break;   /* stuck source -> reset+retry */
        }
        if (TRNG_VALID & 1u) {
            for (int i = 0; i < 6; i++) {
                uint32_t w = TRNG_EHR_DATA(i);
                s_ent[i*4+0] = (uint8_t)(w);
                s_ent[i*4+1] = (uint8_t)(w >> 8);
                s_ent[i*4+2] = (uint8_t)(w >> 16);
                s_ent[i*4+3] = (uint8_t)(w >> 24);
            }
            TRNG_RND_SOURCE_EN = 0;
            s_ent_len = 24;
            if (s_dbg_mb) {
                s_dbg_mb->dbg_val = (uint32_t)(attempt + 1);
                dmb();
                s_dbg_mb->dbg_stage = MB_DBG_TRNG_OK;
            }
            return;
        }
    }
    /* No healthy entropy after retries: park rather than emit weak keys
     * (a dead device is safer). Core 0's sign wait is bounded and will
     * report failure. */
    if (s_dbg_mb) {
        s_dbg_mb->dbg_val = 0;
        dmb();
        s_dbg_mb->dbg_stage = MB_DBG_TRNG_DEAD;
    }
    for (;;) __asm__ volatile("wfi");
}

/* ---- Combining with core 0's entropy -------------------------------
 * The QRNG (src/pqf_qrng.c) hangs off an I2C controller core 0 owns;
 * this core cannot reach it. So core 0 puts 32 bytes of its own
 * RAND_bytes output -- QRNG when one is present, TRNG otherwise -- into
 * mb->entropy with every request (core1_signer_riscv.c), the worker
 * copies it into s_host_ent as the op begins, and RAND_bytes serves
 *
 *     out = SHA-256(host_entropy || fresh EHR block || counter)
 *
 * 32 bytes at a time. Either input alone would carry the output; hashed
 * together, a weak or stuck source on one side is covered by the other,
 * and the preferred external source reaches the signing core without a
 * second bus. TRNG health handling is unchanged: no healthy block after
 * sixteen attempts still parks the core rather than emit weak keys. */
static uint8_t  s_host_ent[32];
static uint8_t  s_out[32];
static uint32_t s_out_len;   /* bytes remaining in s_out, drained front-first */
static uint32_t s_out_ctr;

static void rng_refill(void)
{
    pqf_sha256_ctx_t c;
    uint8_t ctr[4];

    trng_refill();                       /* s_ent = one fresh EHR block, or parks */
    ctr[0] = (uint8_t)(s_out_ctr);
    ctr[1] = (uint8_t)(s_out_ctr >> 8);
    ctr[2] = (uint8_t)(s_out_ctr >> 16);
    ctr[3] = (uint8_t)(s_out_ctr >> 24);
    pqf_sha256_init(&c);
    pqf_sha256_update(&c, s_host_ent, sizeof s_host_ent);
    pqf_sha256_update(&c, s_ent, sizeof s_ent);
    pqf_sha256_update(&c, ctr, sizeof ctr);
    pqf_sha256_final(&c, s_out);
    s_out_ctr++;
    /* The EHR block is spent; do not leave it in RAM. */
    memset(s_ent, 0, sizeof s_ent);
    s_ent_len = 0;
    s_out_len = sizeof s_out;
}

/* openssl-mini's pqf_rand shim resolves to these. */
int RAND_bytes(unsigned char *buf, int num)
{
    int off = 0;
    while (off < num) {
        if (s_out_len == 0) rng_refill();
        uint32_t i = (uint32_t)sizeof s_out - s_out_len;
        buf[off++] = s_out[i];
        s_out[i] = 0;                    /* served exactly once */
        s_out_len--;
    }
    return 1;
}
int RAND_priv_bytes(unsigned char *buf, int num) { return RAND_bytes(buf, num); }
int RAND_bytes_ex(void *ctx, unsigned char *buf, size_t num, unsigned int s)
{ (void)ctx; (void)s; return RAND_bytes(buf, (int)num); }
int RAND_priv_bytes_ex(void *ctx, unsigned char *buf, size_t num, unsigned int s)
{ (void)ctx; (void)s; return RAND_bytes(buf, (int)num); }

/* libc stubs the crypto may reference under error paths. */
void abort(void)              { for (;;) __asm__ volatile("wfi"); }
void _exit(int c)             { (void)c; for (;;) __asm__ volatile("wfi"); }
void __assert_func(const char *f, int l, const char *fn, const char *e)
{ (void)f; (void)l; (void)fn; (void)e; abort(); }

/* ==================================================================== *
 *  Inter-core FIFO (SIO) -- used only for the launch rendezvous
 * ==================================================================== */
#define SIO_BASE     0xd0000000u
#define SIO_FIFO_ST  (*(volatile uint32_t *)(SIO_BASE + 0x50))
#define SIO_FIFO_RD  (*(volatile uint32_t *)(SIO_BASE + 0x58))
#define FIFO_ST_VLD  1u

static uint32_t fifo_read_blocking(void)
{
    while ((SIO_FIFO_ST & FIFO_ST_VLD) == 0) { }
    return SIO_FIFO_RD;
}

/* ==================================================================== *
 *  Mailbox worker
 * ==================================================================== */

/* RAM-resident park spin (M1). MUST NOT fetch from XIP flash while core
 * 0 holds the QSPI in command mode -- placed in .ram_text (copied to RAM
 * by startup, see blob.ld) and does only SRAM loads/stores. */
__attribute__((noinline, section(".ram_text")))
static void park_spin(core1_mailbox_t *mb)
{
    mb->park_ack = 1;
    dmb();
    while (mb->park_request) { dmb(); }
    mb->park_ack = 0;
    dmb();
}

/* RAM-resident idle wait: poll (no wfi -- the M33<->Hazard3 event
 * routing is not hardware-verified, so we never sleep on an event we
 * might miss) until core 0 requests a sign, servicing the flash-park in
 * the same loop; return once MB_REQUESTED is observed.
 *
 * MUST be RAM-resident (.ram_text), for the SAME reason as park_spin but
 * a subtler trigger: core 0's BOOTSEL sampler (bootsel.c) floats the
 * flash chip-select to read the user button, blacking out XIP for BOTH
 * cores for the sample window. A blob idling in an XIP poll loop would
 * bus-fault there and the device wedges intermittently on button
 * activity. This is the C mirror of the Rust blob's RAM-resident
 * idle_wait (commit 3229aab, which fixed exactly this freeze).
 *
 * hybrid_sign() below runs from XIP, which is safe: while a sign is in
 * flight core 0 is parked in core1_hybrid_sign() pumping USB/KEEPALIVE
 * and neither samples BOOTSEL nor touches flash, so no blackout can race
 * the signing fetches. */
__attribute__((noinline, section(".ram_text")))
static void idle_wait(core1_mailbox_t *mb)
{
    for (;;) {
        if (mb->state == MB_REQUESTED)
            return;
        if (mb->park_request)
            park_spin(mb);              /* RAM->RAM call */
        dmb();                          /* re-read flags from SRAM */
    }
}

/* Overrides the weak no-op in ecdsa_ossl.c: stamp ECDSA retry-loop
 * diagnostics into the mailbox core 1 is currently servicing. Relies on
 * s_dbg_mb being set (blob_main() sets it before any sign can occur). */
void pqf_ecdsa_dbg(unsigned stage, unsigned long val)
{
    if (!s_dbg_mb)
        return;
    s_dbg_mb->dbg_val = (uint32_t)val;
    dmb();
    switch (stage) {
    case 1: s_dbg_mb->dbg_stage = MB_DBG_ECDSA_R_ZERO;  break;
    case 2: s_dbg_mb->dbg_stage = MB_DBG_ECDSA_S_ZERO;  break;
    case 3: s_dbg_mb->dbg_stage = MB_DBG_ECDSA_TOOMANY; break;
    default: break;
    }
}

/* Diagnostic-only reimplementation of hybrid.c's hybrid_sign(), split
 * so each half's return code can be stamped into the mailbox. Bring-up
 * instrumentation for the mixed build's first-ever run of this crypto
 * on real riscv32 silicon -- NOT used by the Arm image (hybrid.c is
 * untouched). Same construction as hybrid_sign(): see hybrid.h. */
static int hybrid_sign_diag(core1_mailbox_t *mb,
                            const uint8_t ecdsa_scalar[32],
                            const uint8_t mldsa_seed[32],
                            const uint8_t *msg, size_t msg_len,
                            uint8_t *out, size_t *out_len)
{
    static uint8_t labelled[PQF_HYBRID_LABELLED_MAX];
    if (32 + msg_len + PQF_P256_MAX_SIG_DER > sizeof labelled)
        return -1;

    size_t off = 0;
    memcpy(labelled + off, PQF_HYBRID_LABEL, 32); off += 32;
    memcpy(labelled + off, msg, msg_len);         off += msg_len;
    uint8_t prehash[32];
    pqf_sha256(labelled, off, prehash);

    uint8_t der[PQF_P256_MAX_SIG_DER];
    size_t  der_len = 0;
    mb->dbg_stage = MB_DBG_ECDSA_ATTEMPT;
    dmb();
    int rc = pqf_ecdsa_p256_sign(ecdsa_scalar, prehash, der, &der_len);
    if (rc != 0) {
        mb->dbg_val = (uint32_t)rc;
        dmb();
        mb->dbg_stage = MB_DBG_ECDSA_FAIL;
        return -1;
    }
    mb->dbg_val = der_len;
    dmb();
    mb->dbg_stage = MB_DBG_ECDSA_OK;

    size_t off2 = 0;
    memcpy(labelled + off2, PQF_HYBRID_LABEL, 32); off2 += 32;
    memcpy(labelled + off2, msg, msg_len);         off2 += msg_len;
    memcpy(labelled + off2, der, der_len);         off2 += der_len;
    uint8_t *mldsa_sig = out + der_len;
    size_t   mldsa_len = 0;
    mb->dbg_stage = MB_DBG_MLDSA_ATTEMPT;
    dmb();
    rc = pqf_mldsa_sign(PQF_HYBRID_MLDSA, mldsa_seed, labelled, off2,
                        mldsa_sig, &mldsa_len);
    if (rc != 0) {
        mb->dbg_val = (uint32_t)rc;
        dmb();
        mb->dbg_stage = MB_DBG_MLDSA_FAIL;
        return -1;
    }
    mb->dbg_val = mldsa_len;
    dmb();
    mb->dbg_stage = MB_DBG_MLDSA_OK;

    memmove(out, der, der_len);
    *out_len = der_len + mldsa_len;
    return 0;
}

static void worker(core1_mailbox_t *mb) __attribute__((noreturn));
static void worker(core1_mailbox_t *mb)
{
    for (;;) {
        /* NOTE (2026-07-14 diagnosis): dbg_stage is deliberately NOT
         * reset to IDLE here. The previous sign's outcome -- especially
         * the specific ECDSA_FAIL / MLDSA_FAIL sub-stage that
         * hybrid_sign_diag latches with dbg_val=rc -- must PERSIST
         * through the idle wait so core 0's ~10 Hz mailbox sampler can
         * read which half failed. (Previously this loop set IDLE at the
         * top and, on error, overwrote the sub-stage with the generic
         * SIGN_ERROR, then IDLE -- all before core 0 could sample it, so
         * every failure just showed up as "IDLE, state=ERROR".)
         * GOT_REQUEST below overwrites the stale outcome only once a
         * fresh sign actually begins. */
        idle_wait(mb);                           /* RAM-resident spin */
        dmb();                                   /* acquire request */
        mb->dbg_stage = MB_DBG_GOT_REQUEST;
        dmb();

        /* Core 0's per-request entropy (see rng_refill). Whatever this
         * core still had buffered from the previous op goes with it:
         * every op starts from its own fresh host bytes. */
        memcpy(s_host_ent, mb->entropy, sizeof s_host_ent);
        memset(s_out, 0, sizeof s_out);
        s_out_len = 0;

        /* Fresh arena for every op: each request is self-contained
         * (keys re-derived from the mailbox seed/scalar), so nothing
         * heap-allocated survives op boundaries -- verified: EVP_MD
         * fetch returns statics, the EC group is built per call. This
         * is what makes the ML-DSA-87 sign's 138 KiB contiguous
         * allocation reliable -- see the allocator note above. */
        blob_heap_reset();

        /* Small EC ops (see MB_OP_* in core1_mailbox.h): core 0's bn/ec
         * runs from XIP flash and is ~1000x slower there under cache
         * thrash, so it sends even these here. */
        if (mb->op == MB_OP_P256_KEYGEN) {
            uint8_t x[32], y[32];
            int krc = pqf_p256_keygen(mb->sig, x, y);
            if (krc == 0) {
                memcpy(mb->sig + 32, x, 32);
                memcpy(mb->sig + 64, y, 32);
                mb->sig_len = 96;               /* priv || x || y */
            } else {
                mb->sig_len = 0;
            }
            dmb();                              /* publish before flag */
            mb->state = (krc == 0) ? MB_DONE : MB_ERROR;
            continue;
        }
        if (mb->op == MB_OP_P256_SIGN) {
            size_t der_len = 0;
            int src_rc = (mb->msg_len == 32)
                ? pqf_ecdsa_p256_sign(mb->scalar, mb->msg, mb->sig, &der_len)
                : -1;
            mb->sig_len = (uint32_t)der_len;
            dmb();                              /* publish before flag */
            mb->state = (src_rc == 0) ? MB_DONE : MB_ERROR;
            continue;
        }
        if (mb->op == MB_OP_MLDSA_PUB) {
            /* ML-DSA public key from seed. Runs here (not core 0)
             * because the keygen's heap peak exceeds core 0's mixed-
             * build window at level 87 -- see MB_OP_MLDSA_PUB. */
            size_t pk_len = 0;
            int prc = pqf_mldsa_pub_from_seed(PQF_HYBRID_MLDSA, mb->seed,
                                              mb->sig, &pk_len);
            mb->sig_len = (uint32_t)pk_len;
            dmb();                              /* publish before flag */
            mb->state = (prc == 0) ? MB_DONE : MB_ERROR;
            continue;
        }

        size_t out_len = 0;
        int rc = hybrid_sign_diag(mb, mb->scalar, mb->seed, mb->msg, mb->msg_len,
                                  mb->sig, &out_len);
        mb->sig_len = (uint32_t)out_len;
        /* Success -> SIGN_DONE. Failure -> leave the exact sub-stage and
         * dbg_val=rc that hybrid_sign_diag already stamped
         * (ECDSA_FAIL / MLDSA_FAIL / ECDSA_R_ZERO / ...), so the failing
         * half survives for core 0 to latch. */
        if (rc == 0)
            mb->dbg_stage = MB_DBG_SIGN_DONE;
        /* Arena high-water since boot (both ends combined) -- core 0
         * logs it in the per-sign OUTCOME line. */
        if ((uint32_t)blob_heap_hw() > mb->dbg_heap_hw)
            mb->dbg_heap_hw = (uint32_t)blob_heap_hw();
        dmb();                                   /* publish sig before flag */
        mb->state = (rc == 0) ? MB_DONE : MB_ERROR;
    }
}

void blob_main(void) __attribute__((noreturn));
void blob_main(void)
{
    /* Rendezvous: core 0 pushes &mailbox as the first (and only) FIFO
     * word after the boot-ROM launch handshake (whose echoes it has
     * already drained), so the first word we read IS the mailbox. */
    core1_mailbox_t *mb = (core1_mailbox_t *)fifo_read_blocking();
    s_dbg_mb = mb;
    blob_heap_init(&__heap_start, &__heap_end);
    worker(mb);
}

/* Called from blob_start.S with a valid stack + gp. Does crt0 init
 * (using only linker symbols + locals -- no initialised globals yet),
 * then never returns.
 *
 * MUST live in .boot_text (kept in BFLASH by blob.ld): since 2026-07-16
 * the blob's whole .text/.rodata is RAM-resident, so the code doing the
 * flash->RAM copy cannot itself be part of what it copies. For the same
 * reason blob_main is entered through a volatile function pointer -- a
 * direct call could be linker-relaxed to a +/-1 MiB `jal`, which cannot
 * span BFLASH (0x1018_xxxx) -> BRAM (0x2003_xxxx). */
void blob_startup(void) __attribute__((noreturn, section(".boot_text")));
void blob_startup(void)
{
    uint32_t *src = &__text_load, *dst = &__text_start;
    while (dst < &__text_end) *dst++ = *src++;      /* .text+.rodata -> RAM */
    src = &__data_load; dst = &__data_start;
    while (dst < &__data_end) *dst++ = *src++;      /* .data flash->RAM */
    for (uint32_t *b = &__bss_start; b < &__bss_end; ) *b++ = 0;  /* .bss */
    /* We just wrote instructions: order the stores ahead of fetch from
     * the copied region (Zifencei; Hazard3 prefetches). */
    __asm__ volatile ("fence.i" ::: "memory");
    void (*volatile entry)(void) = blob_main;
    entry();
    for (;;) __asm__ volatile ("wfi");   /* unreachable (blob_main noreturn) */
}
