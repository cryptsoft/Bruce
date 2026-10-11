/* core1_signer.c -- core-1 hybrid signing worker (firmware).
 *
 * Core 0 publishes a sign request into the shared state and raises a
 * "go" flag (NOT the inter-core FIFO -- see below); core 1 wakes, runs
 * hybrid_sign, stores the result, and flips an atomic state flag. Core
 * 0 polls that flag in core1_hybrid_sign() while pumping the long-op
 * tick (USB service + CTAPHID KEEPALIVE).
 *
 * The "go" signal rides a shared volatile flag + __sev()/__wfe(), NOT
 * the inter-core FIFO.
 *
 * M1 flash lockout (core1_run_flash_op): core-0 flash erase/program
 * takes QSPI out of XIP, and core 1's signer .text executes from XIP,
 * so core 1 must be parked during the XIP-off window or it bus-faults.
 * We do this with our OWN handshake -- s_park_request / s_park_ack + a
 * RAM-resident core1_park_spin() -- NOT pico-sdk flash_safe_execute /
 * multicore_lockout. The pico-sdk mechanism rides the inter-core FIFO
 * IRQ, whose handshake does not complete between the RP2350's two
 * Hazard3 (RISC-V) cores: the lockout-release wait has no timeout, so
 * core 0 hangs there and the device wedges. That was observed on
 * silicon the first time a resident credential was committed (the first
 * runtime flash write with core 1 alive). The explicit park is
 * arch-neutral and mirrors the Rust port's proven M1 handshake
 * (crates/signer-core/src/signer.rs). Since we no longer use the FIFO
 * for lockout either, the FIFO is simply left unused.
 *
 * Concurrency notes:
 *   - The request pointers are owned by the caller and outlive the
 *     call (core 0 is parked in the poll loop until DONE), so core 1
 *     can read through them safely.
 *   - A flash commit and a sign never overlap: ctap2 reserves the next
 *     signature-counter value (the only MakeCred/GetAssert flash touch)
 *     BEFORE invoking the signer. Other flash paths (PIN change, config,
 *     resident-store insert/bump, large-blob write) run while core 1
 *     sits idle in the wait loop, where it observes s_park_request and
 *     enters core1_park_spin() -- running from RAM until core 0 clears it.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <string.h>              /* memcpy (P-256 keygen result split) */

#include "pico/multicore.h"
#include "pico/sync.h"
#include "pico/platform.h"      /* __no_inline_not_in_flash_func */
#include "pico/time.h"          /* bounded park waits (RISC-V) */
#include "hardware/structs/sio.h"   /* cpuid in the trap handler   */

#include "core1_signer.h"
#include "hybrid.h"
#include "pqf_crypto.h"          /* inline EC ops (single-ISA fast path) */

#if defined(PQF_SIGN_ARENA)
/* Level-87 builds: the hybrid sign's ~216 KiB heap peak runs on a
 * dedicated two-ended arena instead of newlib (which could neither fit
 * nor defragment it -- see core1_arena.c). Core 1 resets the arena
 * before every sign and records its high-water after. */
#include "core1_arena.h"
#endif

enum { ST_IDLE = 0, ST_REQUESTED = 1, ST_DONE = 2, ST_ERROR = 3 };

/* Request kinds. Historically core 1 only ran the hybrid sign; the
 * level-87 arena builds (PQF_SIGN_ARENA) route the other crypto ops
 * here too -- the image runs from XIP there, so an op left inline on
 * core 0 runs inside the CBOR dispatch with USB unserviced for many
 * seconds (no KEEPALIVEs -> the host aborts MakeCredential; silicon
 * 2026-07-20). On core 1 the op gets the KEEPALIVE pump AND the sign
 * arena. Mirrors the mixed build's MB_OP_* mailbox ops. */
enum {
    OP_HYBRID_SIGN = 0,
    OP_MLDSA_PUB   = 1,
    OP_P256_KEYGEN = 2,
    OP_P256_SIGN   = 3,
};

/* Shared request/response state. All fields are volatile (so the
 * compiler can't reorder or cache them across the publish), and an
 * explicit __dmb() on each side pairs the state-flag store/load with the
 * payload accesses -- __sev() is an event, not a memory barrier, so on a
 * dual Cortex-M33 it doesn't by itself order the SRAM writes. The
 * barriers create the release/acquire edge: core 1's stores into *s_sig
 * become visible before core 0 observes ST_DONE, and core 0's request
 * stores before core 1 reads them. */
static volatile int             s_state = ST_IDLE;
static volatile int             s_req_op = OP_HYBRID_SIGN;
static const uint8_t * volatile s_scalar;
static const uint8_t * volatile s_seed;
static const uint8_t * volatile s_msg;
static volatile size_t          s_msg_len;
static uint8_t       * volatile s_sig;
static volatile size_t          s_sig_len;

/* (M1) Core-0->core-1 flash-lockout handshake, replacing pico-sdk
 * multicore_lockout (which hangs core 0 between the two Hazard3 cores --
 * see core1_run_flash_op / core1_signer.h). Core 0 raises
 * s_park_request and __sev()s; core 1's idle loop observes it and spins
 * in the RAM-resident core1_park_spin() (setting s_park_ack) until core
 * 0 clears the request. While parked, core 1 fetches no XIP flash, so
 * core 0 can drive QSPI into erase/program (XIP off) safely. */
static volatile bool s_park_request;
static volatile bool s_park_ack;

/* RAM-resident park spin. MUST NOT touch XIP flash (no out-of-line
 * calls into .text, no flash reads) while it runs -- core 0 has QSPI in
 * command mode with XIP off. The C analog of the Rust port's
 * Core1Signer::park_spin (.data.ramfunc); __no_inline_not_in_flash_func
 * places it in RAM (copied from flash at boot) -- same mechanism the
 * bootsel sampler uses. */
static void __no_inline_not_in_flash_func(core1_park_spin)(void)
{
    s_park_ack = true;
    __dmb();
    while (s_park_request)
        __dmb();                                /* re-read the flag from SRAM */
    s_park_ack = false;
    __dmb();
}

#if !defined(__riscv)
/* RAM-resident idle wait (Arm builds). A WFE-sleeping M33 genuinely
 * does not fetch, but the instructions AROUND the sleep -- the flag
 * checks after every wake -- do. On an XIP image (the level-87 layout;
 * copy_to_ram images place all code in RAM anyway) a spurious wake
 * (e.g. the SEV a pico-sdk spinlock release broadcasts) could have
 * core 1 fetching flash just as core 0's BOOTSEL sampler floats the
 * flash chip-select, which is a bus fault on this core (bootsel.c's
 * contract: "the other core must not fetch flash during the window").
 * Keeping the whole wake-check loop in SRAM closes that window; on
 * copy_to_ram builds the placement is a no-op. */
static void __no_inline_not_in_flash_func(core1_arm_idle_wait)(void)
{
    while (s_state != ST_REQUESTED) {
        if (s_park_request)
            core1_park_spin();              /* RAM->RAM call */
        else
            __wfe();
        __dmb();                            /* re-read flags from SRAM */
    }
}
#endif

#if defined(__riscv)
/* RAM-resident idle wait (RISC-V builds only). Returns once a sign
 * request is observed; services the flash park in the same loop.
 *
 * Why this exists -- two silicon-observed constraints that only bite on
 * Hazard3 cores:
 *
 *  1. Core 0's BOOTSEL user-presence sampler (bootsel.c) floats the
 *     flash chip-select to read the button, blacking out XIP for BOTH
 *     cores for the sample window (bootsel.c's documented contract:
 *     "the other core must not fetch flash during the window"). An
 *     idle loop fetching XIP will eventually collide with a float
 *     window and wedge this core -- after which the next flash commit's
 *     park handshake waits forever for an ack and the device freezes.
 *     Observed on silicon as "freezes after entering the PIN" (the
 *     first flash commit after boot). So the idle loop must run from
 *     SRAM, never XIP: __no_inline_not_in_flash_func, no out-of-line
 *     calls.
 *
 *  2. It must POLL rather than __wfe(): Hazard3's h3.block falls
 *     through on any interrupt, so a "sleeping" core still periodically
 *     wakes and fetches XIP -- reintroducing (1) at random. Polling from
 *     RAM sidesteps both the fetch hazard and any reliance on the
 *     h3.unblock event routing.
 *
 * This mirrors the mixed-mode RISC-V blob's RAM-resident idle_wait
 * (core1-riscv-blob/blob_main.c) and the Rust port's fix in 3229aab --
 * the same bug class, found three times on three ports.
 *
 * On Arm the __wfe() path below is used instead: a WFE-sleeping M33
 * genuinely does not fetch, and the Arm configurations are
 * silicon-validated with it. */
static void __no_inline_not_in_flash_func(core1_idle_wait)(void)
{
    for (;;) {
        if (s_state == ST_REQUESTED)
            return;
        if (s_park_request) {
            s_park_ack = true;
            __dmb();
            while (s_park_request)
                __dmb();                        /* re-read from SRAM */
            s_park_ack = false;
        }
        __dmb();
    }
}
#endif

void (*core1_long_op_tick)(void) = NULL;

#if defined(__riscv)
/* Core 1's resting place after a trap -- riscv_trap.c's exception
 * handler hands off here (the trap forensics themselves live there so
 * the single-core build keeps them without this file). Park permanently
 * in a RAM-resident loop that still services the M1 flash-park
 * handshake and answers any future sign request with ST_ERROR -- flash
 * commits keep working and signs fail cleanly (mirrors the mixed-mode
 * blob's panic-poison design) instead of freezing the device. Overrides
 * the weak spin in riscv_trap.c. */
void __no_inline_not_in_flash_func(pqf_core1_trap_park)(void)
{
    for (;;) {
        if (s_park_request) {
            s_park_ack = true;
            __dmb();
            while (s_park_request)
                __dmb();
            s_park_ack = false;
        }
        if (s_state == ST_REQUESTED) {
            s_state = ST_ERROR;             /* fail the sign cleanly */
            __sev();
        }
        __dmb();
    }
}
#endif

/* Core-1 entry: forever wait for a "go" (or a park request), sign,
 * signal. */
static void core1_main(void)
{
    for (;;) {
        /* Wait for core 0 to publish a request. Core 0 only ever sets
         * ST_REQUESTED once per call and core 1 immediately advances it
         * to ST_DONE/ST_ERROR, so observing ST_REQUESTED always means a
         * genuine new request.
         *
         * (M1) A raised s_park_request means core 0 is about to erase/
         * program flash: branch into the RAM-resident park spin and
         * stay there (fetching only from SRAM) until core 0 clears it.
         * The branch itself is fetched from XIP here, but core 0 only
         * turns XIP off AFTER it observes s_park_ack, which
         * core1_park_spin sets once already executing from RAM.
         *
         * On Arm this idles in __wfe() (real cross-core SEV/WFE, no
         * fetches while sleeping -- silicon-validated), inside a
         * RAM-resident loop so the post-wake flag checks never fetch
         * XIP (see core1_arm_idle_wait). On RISC-V the idle wait must
         * be a RAM-resident poll instead -- see core1_idle_wait above
         * for the two Hazard3-specific hazards (BOOTSEL CS-float vs
         * XIP fetch; h3.block waking on any interrupt). */
#if defined(__riscv)
        core1_idle_wait();
#else
        core1_arm_idle_wait();
#endif
        __dmb();                                /* acquire request fields */
        size_t out_len = 0;
        int rc;
#if defined(PQF_SIGN_ARENA)
        core1_arena_reset();                    /* fresh arena per op */
        switch (s_req_op) {
        case OP_MLDSA_PUB: {
            size_t pk_len = 0;
            rc = pqf_mldsa_pub_from_seed(PQF_HYBRID_MLDSA, s_seed,
                                         s_sig, &pk_len);
            out_len = pk_len;
            break;
        }
        case OP_P256_KEYGEN:
            /* priv || x || y into the caller's 96-byte buffer. */
            rc = pqf_p256_keygen(s_sig, s_sig + 32, s_sig + 64);
            out_len = 96;
            break;
        case OP_P256_SIGN: {
            size_t der_len = 0;
            rc = (s_msg_len == 32)
                ? pqf_ecdsa_p256_sign(s_scalar, s_msg, s_sig, &der_len)
                : -1;
            out_len = der_len;
            break;
        }
        default:
            rc = hybrid_sign(s_scalar, s_seed, s_msg, s_msg_len,
                             s_sig, &out_len);
            break;
        }
        core1_arena_note_hw();                  /* published by the dmb below */
#else
        rc = hybrid_sign(s_scalar, s_seed, s_msg, s_msg_len,
                         s_sig, &out_len);
#endif
        s_sig_len = out_len;
        __dmb();                                /* publish sig before flag */
        s_state = (rc == 0) ? ST_DONE : ST_ERROR;
        __sev();                                /* nudge core 0      */
    }
}

/* Dedicated core-1 stack in main-RAM .bss. The pico-sdk default
 * (multicore_launch_core1) is a 2 KiB `.stack1` in the 4 KiB SCRATCH_X
 * bank -- and the hybrid signing chain measurably needs MORE than that:
 * summing the linked frames (core1_main + hybrid_sign +
 * pqf_mldsa_sign + ossl_ml_dsa_sign + matrix_mult_vector + the Keccak
 * leaves) gives a ~2.9-3.1 KiB peak, i.e. every ML-DSA sign ran the
 * default stack ~1 KiB past its bottom into the (currently unused) top
 * of the newlib heap region. That it "worked" was luck, not layout.
 * 16 KiB matches the workload with the same kind of headroom the Rust
 * port gives its core-1 stack (64 KiB there, but its worker also keeps
 * whole polynomials on the stack; ours heap-allocates them). */
static uint32_t core1_stack[16 * 1024 / sizeof(uint32_t)];

void core1_signer_init(void)
{
#if defined(PQF_SIGN_ARENA)
    core1_arena_init();      /* bounds set before core 1 can allocate */
#endif
    multicore_launch_core1_with_stack(core1_main, core1_stack,
                                      sizeof core1_stack);
}

/* Publish a request, wake core 1, and spin (pumping USB + KEEPALIVE)
 * until it answers. Core 0 only; calls never nest (single-threaded
 * CBOR dispatch). */
static int core1_request(int op,
                         const uint8_t *scalar, const uint8_t *seed,
                         const uint8_t *msg, size_t msg_len,
                         uint8_t *out, size_t *out_len)
{
    s_req_op  = op;
    s_scalar  = scalar;
    s_seed    = seed;
    s_msg     = msg;
    s_msg_len = msg_len;
    s_sig_len = 0;
    s_sig     = out;
    __dmb();                                    /* publish request before flag */
    s_state   = ST_REQUESTED;
    __sev();                                    /* wake core 1 (no FIFO) */

    /* Spin until core 1 finishes, keeping USB + KEEPALIVE alive. */
    while (s_state == ST_REQUESTED) {
        if (core1_long_op_tick != NULL)
            core1_long_op_tick();
    }
    __dmb();                                    /* acquire result before reading */

    *out_len = s_sig_len;
    int rc = (s_state == ST_DONE) ? 0 : -1;
    s_state = ST_IDLE;
    return rc;
}

/* Single-ISA builds at levels 44/65 run the small EC ops and the
 * ML-DSA keygen inline on core 0 -- the image is copy_to_ram, so they
 * are fast and their heap peaks fit the full-SRAM newlib heap. The
 * level-87 arena builds (PQF_SIGN_ARENA) run from XIP instead, where
 * these ops take whole seconds inside the CBOR dispatch -- with USB
 * unserviced the host aborts the ceremony (silicon 2026-07-20). So at
 * 87 they go through the core-1 worker like the hybrid sign does:
 * core 0 pumps KEEPALIVEs, and the op runs on the dedicated arena
 * (whose reset-per-op also makes the ~116 KiB level-87 keygen peak a
 * non-event). This mirrors the mixed build's MB_OP_* routing. */
int core1_p256_keygen(uint8_t priv[32], uint8_t pub_x[32], uint8_t pub_y[32])
{
#if defined(PQF_SIGN_ARENA)
    uint8_t buf[96];
    size_t  n = 0;
    if (core1_request(OP_P256_KEYGEN, NULL, NULL, NULL, 0, buf, &n) != 0
        || n != 96)
        return -1;
    memcpy(priv,  buf,      32);
    memcpy(pub_x, buf + 32, 32);
    memcpy(pub_y, buf + 64, 32);
    return 0;
#else
    return pqf_p256_keygen(priv, pub_x, pub_y);
#endif
}

int core1_p256_sign(const uint8_t scalar[32], const uint8_t prehash[32],
                    uint8_t *sig, size_t *sig_len)
{
#if defined(PQF_SIGN_ARENA)
    return core1_request(OP_P256_SIGN, scalar, NULL, prehash, 32,
                         sig, sig_len);
#else
    return pqf_ecdsa_p256_sign(scalar, prehash, sig, sig_len);
#endif
}

int core1_mldsa_pub(const uint8_t seed[32], uint8_t *pub, size_t *pub_len)
{
#if defined(PQF_SIGN_ARENA)
    return core1_request(OP_MLDSA_PUB, NULL, seed, NULL, 0, pub, pub_len);
#else
    /* Inline is fine here: 44/65 copy-to-RAM builds keep the full SRAM
     * heap, so the keygen peak fits. Only the mixed build and the 87
     * arena build route this to the signing core (core1_signer.h). */
    return pqf_mldsa_pub_from_seed(PQF_HYBRID_MLDSA, seed, pub, pub_len);
#endif
}

int core1_hybrid_sign(const uint8_t ecdsa_scalar[32],
                      const uint8_t mldsa_seed[32],
                      const uint8_t *msg, size_t msg_len,
                      uint8_t *sig, size_t *sig_len)
{
    return core1_request(OP_HYBRID_SIGN, ecdsa_scalar, mldsa_seed,
                         msg, msg_len, sig, sig_len);
}

/* Bring-up diagnostic (riscv32 first-flash-write freeze): weak no-op
 * hook, overridden in main.c to emit a CDC marker. Lets a hang inside
 * this function show up as "last stage printed" over serial. stage:
 * 1=park requested, 2=park acked, 3=cb returned, 4=released,
 * 9=park-ack TIMEOUT (proceeding anyway), 10=release-ack TIMEOUT. */
void __attribute__((weak)) pqf_flash_op_dbg(unsigned stage) { (void)stage; }

void core1_run_flash_op(void (*cb)(void *), void *arg)
{
    /* 1) Ask core 1 to park, and wake it if it's in __wfe(). Core 1
     *    only reaches its idle loop between signs, and flash commits
     *    never overlap a sign (the signature counter is reserved before
     *    the signer runs; the resident credential is committed after it
     *    finishes), so the ack always arrives promptly. */
    s_park_request = true;
    __dmb();
    __sev();
    pqf_flash_op_dbg(1);
#if defined(__riscv)
    /* Bounded wait: an unresponsive core 1 (the historical RISC-V
     * freeze mode) must surface as a CDC breadcrumb and a
     * completed-anyway commit, never a silent device wedge. 1 s is
     * ~1000x the worst honest ack latency (core 1's RAM idle poll
     * observes the flag within a few instructions). If the timeout
     * fires, core 1 is already dead or wedged -- running the flash op
     * regardless costs nothing it hadn't already lost. */
    {
        absolute_time_t ack_deadline = make_timeout_time_ms(1000);
        while (!s_park_ack) {
            if (time_reached(ack_deadline)) { pqf_flash_op_dbg(9); break; }
            tight_loop_contents();
        }
    }
#else
    while (!s_park_ack)
        tight_loop_contents();
#endif
    __dmb();
    pqf_flash_op_dbg(2);

    /* 2) Core 1 is now spinning in RAM and will not fetch XIP. Mask
     *    core-0 interrupts (an ISR fetched from XIP would fault while
     *    QSPI is in command mode) and run the erase/program. `cb` may
     *    live in XIP, but XIP is still live when it is entered; only the
     *    pico-sdk flash_range_* routines it calls turn XIP off, and those
     *    are RAM-resident and restore XIP before returning. */
    uint32_t ints = save_and_disable_interrupts();
    cb(arg);
    restore_interrupts(ints);
    pqf_flash_op_dbg(3);

    /* 3) Release core 1. */
    __dmb();
    s_park_request = false;
    __sev();
#if defined(__riscv)
    {
        absolute_time_t rel_deadline = make_timeout_time_ms(1000);
        while (s_park_ack) {
            if (time_reached(rel_deadline)) { pqf_flash_op_dbg(10); break; }
            tight_loop_contents();
        }
    }
#else
    while (s_park_ack)
        tight_loop_contents();
#endif
    pqf_flash_op_dbg(4);
}
