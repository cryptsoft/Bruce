// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Core 1 signing worker -- runs the hybrid ECDSA-P256 + ML-DSA sign
//! while core 0 keeps the USB / CTAP HID transport alive.
//!
//! ## Why this module exists
//!
//! The low-memory bouncy castle ML-DSA crate trades ~10x less RAM for
//! ~3x slower signing. On the RP2350 @ 125 MHz a single hybrid
//! `authenticatorMakeCredential` takes ~5-7 s end-to-end. Chrome's
//! CTAP HID watchdog drops the connection if no `KEEPALIVE` arrives for
//! a few hundred milliseconds. Firefox is more forgiving (it tolerated
//! the previous monolithic single-core code path), Chrome on macOS is
//! not. OpenSK's solution on Tock OS is a kernel timer that fires every
//! 100 ms; we have no OS, but we *do* have a second core sitting idle.
//! So:
//!
//! * Core 1 spins in [`Core1Signer::worker`] (or [`worker_poll`] in
//!   the mixed-architecture build -- see below), waiting for a sign
//!   request to land in the shared SRAM region.
//! * When core 0 needs a hybrid signature it calls [`submit`] and
//!   spins (pumping USB + KEEPALIVE every ~50 ms) until the result is
//!   ready.
//! * Core 1 ignores USB entirely; its only job is to grind through
//!   `keygen_from_seed` -> `MuBuilder` -> `sign_mu_deterministic_out` and
//!   ECDSA in front of it.
//!
//! This crate compiles the identical worker for both of the RP2350's
//! instruction sets: the firmware links it for its own target (both
//! cores Arm, or both RISC-V), and the `pqf-core1-riscv` blob links it
//! for riscv32imac so the `core1_riscv` firmware feature can run an
//! Arm core 0 next to a RISC-V core 1.
//!
//! ## Synchronization
//!
//! All state is in one [`Core1Signer`] value (the firmware owns the
//! actual `static`) -- no `mut`, interior mutability via `UnsafeCell`s
//! guarded by an `AtomicU8` state flag. The state machine is the
//! minimal three-state cycle:
//!
//! ```text
//!   IDLE  --[submit]-->  REQUESTED  --[worker observes]-->  RUNNING
//!                                                              |
//!                                                            (work)
//!                                                              |
//!                                                              v
//!   IDLE  <--[take_result]--   DONE                       (worker sets)
//! ```
//!
//! Acquire/Release ordering on the state flag pairs with the data
//! buffers: writes by core 0 to the input buffers happen-before
//! `state.store(REQUESTED, Release)`, which happens-before core 1's
//! `state.load(Acquire) == REQUESTED`, which happens-before its reads.
//! Symmetrically on the way back with `DONE`.
//!
//! RP2350 SRAM is unified and uncached (only the XIP flash path has a
//! cache), so plain atomic loads/stores with Acquire/Release are
//! enough -- deliberately NO atomic read-modify-write ops are used, so
//! the protocol never depends on the Arm exclusive monitor or the
//! RISC-V AMO/LR-SC machinery, which keeps it sound when the two
//! cores run different instruction sets. (On all-Arm builds the HAL
//! additionally sets `ACTLR.EXTEXCLALL` in `Multicore::new`; the
//! mailbox doesn't need it, but other firmware atomics benefit.)
//!
//! ## Waking: `worker` vs `worker_poll`
//!
//! Same-architecture builds use [`Core1Signer::worker`]: core 1 parks
//! in `wfe` (Arm) / `h3.block` (RISC-V) and core 0 pokes it with the
//! matching send-event after `submit`. In the mixed build the blob
//! uses [`Core1Signer::worker_poll`], which busy-polls with `nop`
//! instead of blocking on an event: the cross-architecture routing of
//! the event/unblock signal between an M33 and a Hazard3 is not
//! something we have hardware-verified, and a missed wake there would
//! wedge the signer. A `nop` poll burns a few mA more and nothing
//! else -- this is a security key, not a battery product. `sev()` from
//! core 0 stays in `submit`/`take_result` unconditionally; it is
//! harmless when nobody is blocked on it.

#![allow(clippy::module_name_repetitions)]

extern crate alloc;

use alloc::vec::Vec as AllocVec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};

use bouncycastle_core_interface::key_material::{KeyMaterial, KeyType};
// `MLDSA` and `MLDSA_SIG_LEN` are the cfg-aliased variant chosen by
// the `mldsa44` / `mldsa65` / `mldsa87` cargo feature. Everything
// downstream (the shared SRAM signature buffer size, the COSE alg
// the firmware emits on the wire) follows from these two.
use crate::mldsa_alg::{MLDSA, MLDSA_SIG_LEN};
use bouncycastle_core_interface::traits::Hash;
use bouncycastle_mldsa_lowmemory::{MLDSAPrivateKeyTrait, MLDSATrait, MuBuilder};
use bouncycastle_sha2::SHA256;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use zeroize::Zeroize;

/// State machine values shared between the two cores.
pub const STATE_IDLE: u8 = 0;
pub const STATE_REQUESTED: u8 = 1;
pub const STATE_RUNNING: u8 = 2;
pub const STATE_DONE: u8 = 3;
pub const STATE_ERROR: u8 = 4;

/// Largest message body we'll ever ask core 1 to sign. Bound by the
/// CTAP2 MakeCredential auth_data + clientDataHash. The worst case
/// is an ML-DSA-87 build: the COSE_Key carries a 2592 B pubkey
/// (CBOR-framed to ~2673 B), plus authData header (~100 B),
/// credentialId (161 B), Phase-4 extension outputs (<=80 B), and the
/// 32 B clientDataHash. That sums to ~3050 B. We round up to 4 KiB
/// (4096 B) so even ML-DSA-87 + all extensions + a chunky rp_id is
/// comfortably below the cap, and the shared SRAM region stays well
/// under 16 KiB total.
pub const MAX_MSG_LEN: usize = 4096;

/// 32-byte LABEL constant -- domain separation for the hybrid PQC
/// signing scheme. MUST match byte-for-byte with every
/// OpenSK-PQC-fork-aware relying party; any mismatch causes the RP to
/// reject the credential with "device can't be used".
///
/// ---------- Attribution ----------
///
/// These 32 bytes are reproduced verbatim from the OpenSK PQC fork
/// (`OpenSK/libraries/crypto/src/hybrid.rs::LABEL`),
/// Copyright (c) 2019-2023 Google LLC, licensed under the Apache
/// License, Version 2.0. Full licence text in `LICENSE-APACHE-OPENSK`
/// at the repository root.
///
/// The constant is reproduced unmodified -- required for wire
/// compatibility with OpenSK-PQC-fork relying parties -- and is the
/// only piece of OpenSK source reproduced verbatim in this project.
/// All other CTAP / WebAuthn / hybrid-signing logic is independently
/// implemented against the published FIDO Alliance / W3C / IETF
/// specifications.
pub const HYBRID_LABEL: [u8; 32] = [
    43, 253, 32, 250, 19, 51, 24, 237, 138, 49, 47, 182, 4, 194, 133, 183, 177, 218, 115, 58, 92,
    117, 45, 172, 156, 5, 214, 176, 248, 103, 55, 216,
];

/// Stack size for core 1, in `usize` words. 64 KiB = 16384 words on
/// 32-bit RP2350. Sized empirically: ML-DSA-65 keygen / signing on the
/// low-memory crate keeps a SHAKE state plus one polynomial in flight
/// (~3.5 KiB worst-case), and neither core's codegen is spill-heavy,
/// but compiler choice of inlining can push it higher. 64 KiB leaves
/// comfortable headroom. Used by all three core-1 stack owners: the
/// HAL `Stack` on Arm firmware builds, `core1_launch`'s own static on
/// RISC-V firmware builds, and the blob RAM carve-up in the mixed
/// build (`crate::mixed`).
pub const CORE1_STACK_WORDS: usize = 64 * 1024 / 4;

/// Shared region in SRAM, addressable from both cores.
///
/// `#[repr(C, align(32))]` -- alignment of 32 (a cache-line-ish unit)
/// makes the field layout deterministic and minimises false sharing
/// between the state flag and the bulk input/output buffers, in case a
/// future revision of this code adds out-of-line atomic operations.
/// In the mixed-architecture build this layout is cross-link-unit ABI:
/// the blob receives `&CORE1_SIGNER` as a raw address over the SIO
/// FIFO and both sides must have compiled the identical struct (same
/// crate, same `MLDSA_SIG_LEN` feature -- enforced by feature
/// forwarding in the two Cargo.tomls).
#[repr(C, align(32))]
pub struct Core1Signer {
    /// State machine flag (see `STATE_*`).
    state: AtomicU8,
    /// (M1) Core-0->core-1 flash-lockout handshake. Core 0 sets
    /// `park_request` (and `sev()`s) before a flash erase/program;
    /// core 1's idle loop observes it, sets `park_ack`, and spins in a
    /// RAM-resident loop ([`Core1Signer::park_spin`]) until core 0
    /// clears `park_request`. This keeps core 1 from fetching any
    /// XIP-flash instruction while QSPI is in command mode. Public so
    /// the RAM-resident flash routines in the firmware's `ramfunc`
    /// module can drive them.
    pub park_request: AtomicBool,
    pub park_ack: AtomicBool,
    /// Actual length of `msg`. Input.
    msg_len: AtomicU16,
    /// Actual length of `ecdsa_der`. Output.
    ecdsa_der_len: AtomicU16,
    /// P-256 private scalar. Input.
    ecdsa_scalar: UnsafeCell<[u8; 32]>,
    /// ML-DSA seed. Input.
    mldsa_seed: UnsafeCell<[u8; 32]>,
    /// Message to sign (length in `msg_len`). Input.
    msg: UnsafeCell<[u8; MAX_MSG_LEN]>,
    /// ECDSA-P256 DER signature output (real length in `ecdsa_der_len`).
    /// 80 bytes is the worst-case DER P-256 signature length.
    ecdsa_der: UnsafeCell<[u8; 80]>,
    /// ML-DSA raw signature. Output.
    mldsa_sig: UnsafeCell<[u8; MLDSA_SIG_LEN]>,
}

// SAFETY: we synchronize via the `state` atomic and only ever access
// the `UnsafeCell` payloads when the state machine guarantees
// exclusive access (see the state diagram in the module doc-comment).
unsafe impl Sync for Core1Signer {}

impl Core1Signer {
    /// Construct an empty signer at IDLE. Used to populate the
    /// firmware's global static; not callable from anywhere else.
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(STATE_IDLE),
            park_request: AtomicBool::new(false),
            park_ack: AtomicBool::new(false),
            msg_len: AtomicU16::new(0),
            ecdsa_der_len: AtomicU16::new(0),
            ecdsa_scalar: UnsafeCell::new([0u8; 32]),
            mldsa_seed: UnsafeCell::new([0u8; 32]),
            msg: UnsafeCell::new([0u8; MAX_MSG_LEN]),
            ecdsa_der: UnsafeCell::new([0u8; 80]),
            mldsa_sig: UnsafeCell::new([0u8; MLDSA_SIG_LEN]),
        }
    }

    /// Submit a new sign request from core 0. Spinwaits on `state == IDLE`
    /// so back-to-back submissions are serialised. Returns Err if `msg`
    /// is larger than [`MAX_MSG_LEN`].
    pub fn submit(
        &self,
        ecdsa_scalar: &[u8; 32],
        mldsa_seed: &[u8; 32],
        msg: &[u8],
    ) -> Result<(), &'static str> {
        if msg.len() > MAX_MSG_LEN {
            return Err("msg longer than MAX_MSG_LEN");
        }
        while self.state.load(Ordering::Acquire) != STATE_IDLE {
            core::hint::spin_loop();
        }
        // SAFETY: state == IDLE means core 1 has either never started
        // a request or already observed our previous DONE and yielded
        // the buffers back. We have exclusive access until we publish
        // the new state below. We take explicit `&mut` of each
        // `UnsafeCell` to avoid the recent nightly's
        // `dangerous_implicit_autorefs` lint, which would otherwise
        // fire on `(*cell.get())[..]`.
        unsafe {
            let scalar_buf: &mut [u8; 32] = &mut *self.ecdsa_scalar.get();
            scalar_buf.copy_from_slice(ecdsa_scalar);
            let seed_buf: &mut [u8; 32] = &mut *self.mldsa_seed.get();
            seed_buf.copy_from_slice(mldsa_seed);
            let msg_buf: &mut [u8; MAX_MSG_LEN] = &mut *self.msg.get();
            msg_buf[..msg.len()].copy_from_slice(msg);
        }
        self.msg_len.store(msg.len() as u16, Ordering::Relaxed);
        self.state.store(STATE_REQUESTED, Ordering::Release);
        // Wake core 1 in case it's parked on `wfe`.
        crate::arch::sev();
        Ok(())
    }

    /// Single-core builds: run one hybrid sign to completion on the
    /// calling core and leave the result exactly where [`take_result`]
    /// expects it, so the caller's `is_done()` / `take_result()` sequence
    /// is unchanged. There is no worker to hand the request to; the
    /// KEEPALIVE cadence that core 0 would otherwise pump while waiting
    /// comes from a timer interrupt in the firmware
    /// (`keepalive_timer.rs`), which is why nothing here needs to yield.
    /// Same error contract as [`submit`]: `Err` only for an oversized
    /// message. A failed sign parks the state at ERROR like the worker
    /// does, and `errored()` reports it.
    ///
    /// [`take_result`]: Self::take_result
    /// [`submit`]: Self::submit
    pub fn sign_here(
        &self,
        ecdsa_scalar: &[u8; 32],
        mldsa_seed: &[u8; 32],
        msg: &[u8],
    ) -> Result<(), &'static str> {
        self.submit(ecdsa_scalar, mldsa_seed, msg)?;
        self.state.store(STATE_RUNNING, Ordering::Release);
        let msg_len = self.msg_len.load(Ordering::Relaxed) as usize;
        // SAFETY: state == RUNNING and this is the only core touching
        // the buffers (no worker was ever started in this build).
        let (msg_buf, scalar, seed) = unsafe {
            let msg_arr: &[u8; MAX_MSG_LEN] = &*self.msg.get();
            let scalar_arr: &[u8; 32] = &*self.ecdsa_scalar.get();
            let seed_arr: &[u8; 32] = &*self.mldsa_seed.get();
            (&msg_arr[..msg_len], scalar_arr, seed_arr)
        };
        let outcome = self.run_sign(scalar, seed, msg_buf);
        self.state.store(
            if outcome.is_ok() {
                STATE_DONE
            } else {
                STATE_ERROR
            },
            Ordering::Release,
        );
        Ok(())
    }

    /// Has core 1 finished and parked the result?
    pub fn is_done(&self) -> bool {
        let s = self.state.load(Ordering::Acquire);
        s == STATE_DONE || s == STATE_ERROR
    }

    /// True if core 1 reported an error rather than a real signature.
    pub fn errored(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_ERROR
    }

    /// Copy `ecdsa_der || mldsa_sig` into `out` and return us to IDLE.
    /// Caller must observe `is_done()` first.
    pub fn take_result(&self, out: &mut AllocVec<u8>) {
        let der_len = self.ecdsa_der_len.load(Ordering::Relaxed) as usize;
        out.clear();
        out.reserve(der_len + MLDSA_SIG_LEN);
        // SAFETY: state == DONE (caller-observed) means core 1 has
        // released the buffers and won't touch them again until we
        // transition back to IDLE / REQUESTED. The whole body runs
        // inside this DONE-exclusive window -- core 1 cannot re-enter the
        // buffers until we publish STATE_IDLE below -- so the input wipe
        // is safe and the cross-core access invariant holds.
        unsafe {
            let der_buf: &[u8; 80] = &*self.ecdsa_der.get();
            out.extend_from_slice(&der_buf[..der_len]);
            let sig_buf: &[u8; MLDSA_SIG_LEN] = &*self.mldsa_sig.get();
            out.extend_from_slice(sig_buf);

            // (#17) Wipe the recovered signing secrets out of the
            // long-lived cross-core static. `submit()` copied the
            // credential's P-256 private scalar and ML-DSA seed (the
            // root signing secrets) into these fixed SRAM buffers; the
            // signature is now staged into `out`, so the inputs are no
            // longer needed. Without this they would linger in a fixed
            // static SRAM location until the next `submit()` happened to
            // overwrite them. `zeroize()` is a non-elidable volatile
            // write, matching the cleanse discipline used for the
            // stack/heap copies elsewhere (e.g. credential_id.rs).
            let scalar_buf: &mut [u8; 32] = &mut *self.ecdsa_scalar.get();
            scalar_buf.zeroize();
            let seed_buf: &mut [u8; 32] = &mut *self.mldsa_seed.get();
            seed_buf.zeroize();
            let msg_len = self.msg_len.load(Ordering::Relaxed) as usize;
            let msg_buf: &mut [u8; MAX_MSG_LEN] = &mut *self.msg.get();
            msg_buf[..msg_len.min(MAX_MSG_LEN)].zeroize();
        }
        self.msg_len.store(0, Ordering::Relaxed);
        self.state.store(STATE_IDLE, Ordering::Release);
        crate::arch::sev();
    }

    /// RAM-resident spin loop core 1 enters when core 0 requests a
    /// park before a flash erase/program (M1).
    ///
    /// Acknowledges the park request, then busy-waits -- entirely from
    /// RAM, using only an inline `nop` -- until core 0 clears the
    /// request. While here, core 1 issues no XIP fetch, so core 0 can
    /// safely drive the flash into command mode. The `.data.ramfunc`
    /// placement works in every link unit this crate lands in: the
    /// firmware's linker scripts glob `.data.*` into RAM and the
    /// runtime copies it; the blob's `blob.x` does the same into the
    /// blob RAM window (and the blob startup does the copy).
    ///
    /// Called only from the worker idle loops below, which are the
    /// sole core-1 entry points.
    // `#[export_name]` in addition to `#[inline(never)]`: fat LTO has
    // been observed (see the firmware's board/bootsel.rs) to inline a
    // link_section'd RAM function into its flash-resident caller and
    // drop the symbol, silently moving the code back to XIP. An
    // exported symbol forces a real out-of-line RAM copy.
    #[inline(never)]
    #[export_name = "pqf_signer_park_spin"]
    // Only on the RP2350: `.data.ramfunc` is an ELF section name, and a
    // host build (which exists so this crate can be unit-tested) links
    // Mach-O, whose section specifiers need a segment too. RAM residency
    // is meaningless off-target anyway -- there is no XIP window to lose.
    #[cfg_attr(
        any(target_arch = "arm", target_arch = "riscv32"),
        link_section = ".data.ramfunc"
    )]
    pub fn park_spin(&self) {
        // Tell core 0 we're parked and won't touch XIP.
        self.park_ack.store(true, Ordering::Release);
        // Spin in RAM until the request clears. A tight RAM spin is
        // simplest to reason about and the park window is only the
        // ~tens-of-ms of a single erase/program.
        while self.park_request.load(Ordering::Acquire) {
            crate::arch::nop();
        }
        self.park_ack.store(false, Ordering::Release);
    }

    /// RAM-resident idle wait for the polling (mixed-architecture)
    /// worker: spin until a sign request lands, servicing the M1 park
    /// handshake in place. Returns with `state == REQUESTED`.
    ///
    /// Why this must run from RAM -- and not just when a park is
    /// requested: the polling worker never sleeps, so an idle core 1
    /// otherwise fetches its spin loop from XIP flash CONTINUOUSLY.
    /// The BOOTSEL user-presence sampler on core 0
    /// (`board/bootsel.rs`) floats the QSPI chip-select for ~10-20 us
    /// per sample -- every 2 ms for the whole WaitForUp window -- and
    /// its documented contract is that core 1 issues NO flash fetch
    /// during those blackouts. The event-driven worker satisfies that
    /// by parking in WFE (not fetching at all); a flash-resident poll
    /// loop does not: the RP2350's XIP cache is shared, core 0's
    /// concurrent code churn can evict the loop's lines at any time,
    /// and a refill fetch that lands inside a blackout clocks garbage
    /// into core 1 -> trap -> dead worker -> the sign submitted right
    /// after the button press is never picked up (observed on
    /// hardware as an intermittent post-press freeze). With the whole
    /// idle wait in RAM, an idle core 1 touches XIP exactly never.
    ///
    /// The park handshake is serviced inline (this loop already IS
    /// RAM-resident, which is all `park_spin` exists to guarantee).
    #[inline(never)]
    #[export_name = "pqf_signer_idle_wait"]
    // Only on the RP2350: `.data.ramfunc` is an ELF section name, and a
    // host build (which exists so this crate can be unit-tested) links
    // Mach-O, whose section specifiers need a segment too. RAM residency
    // is meaningless off-target anyway -- there is no XIP window to lose.
    #[cfg_attr(
        any(target_arch = "arm", target_arch = "riscv32"),
        link_section = ".data.ramfunc"
    )]
    fn idle_wait(&self) {
        loop {
            if self.park_request.load(Ordering::Acquire) {
                self.park_ack.store(true, Ordering::Release);
                while self.park_request.load(Ordering::Acquire) {
                    crate::arch::nop();
                }
                self.park_ack.store(false, Ordering::Release);
            }
            if self.state.load(Ordering::Acquire) == STATE_REQUESTED {
                return;
            }
            crate::arch::nop();
        }
    }

    /// Poison the mailbox from a dying core 1 (the blob's panic
    /// handler calls this before parking for good). Core 0's
    /// `wait_for_done` path sees `errored()`, drains via
    /// `take_result`, and surfaces a clean signing failure instead of
    /// spinning against a dead worker.
    pub fn poison(&self) {
        self.state.store(STATE_ERROR, Ordering::Release);
        crate::arch::sev();
    }

    /// Body of the core-1 task, event-driven variant. Loops forever;
    /// one iteration per signing request. Used when both cores run the
    /// same instruction set (the firmware's own builds): core 1 parks
    /// in `wfe` / `h3.block` and `submit()` pokes it with the matching
    /// send-event.
    pub fn worker(&'static self) -> ! {
        self.worker_inner(true)
    }

    /// Body of the core-1 task, polling variant -- the mixed-
    /// architecture blob uses this. Identical protocol, but the idle
    /// wait busy-polls with `nop` instead of blocking on an event, so
    /// it cannot miss a wake even if the cross-architecture event
    /// routing between an M33 and a Hazard3 drops the signal (see the
    /// module doc). The whole idle wait runs from RAM -- see
    /// [`Self::idle_wait`] for why that is load-bearing.
    pub fn worker_poll(&'static self) -> ! {
        self.worker_inner(false)
    }

    fn worker_inner(&'static self, use_wfe: bool) -> ! {
        loop {
            // Wait for a request.
            //
            // Event mode (same-architecture builds): WFE parks until
            // any cross-core event arrives -- `submit()` pokes us with
            // `sev()`. (M1) While idle we also watch `park_request`:
            // core 0 sets it before a flash erase/program. When it's
            // set we branch into the RAM-resident park loop and stay
            // there (executing only from RAM) until core 0 clears the
            // request, so we never fetch this XIP-flash idle loop
            // while QSPI is in command mode. The branch instruction
            // itself is still fetched from XIP here, but core 0 only
            // suspends XIP AFTER it observes our `park_ack`, which
            // `park_spin` sets once it is already executing from RAM.
            //
            // Polling mode (mixed-architecture blob): the entire idle
            // wait -- request poll AND park handshake -- runs from RAM
            // via `idle_wait`, because a continuously-fetching poll
            // loop in XIP would race the BOOTSEL sampler's chip-select
            // blackouts (see idle_wait's doc for the failure this
            // fixed).
            if use_wfe {
                while self.state.load(Ordering::Acquire) != STATE_REQUESTED {
                    if self.park_request.load(Ordering::Acquire) {
                        self.park_spin();
                        continue;
                    }
                    crate::arch::wfe();
                }
            } else {
                self.idle_wait();
            }
            self.state.store(STATE_RUNNING, Ordering::Release);

            let msg_len = self.msg_len.load(Ordering::Relaxed) as usize;
            // SAFETY: we own the buffers while state == RUNNING.
            let (msg_buf, scalar, seed) = unsafe {
                let msg_arr: &[u8; MAX_MSG_LEN] = &*self.msg.get();
                let scalar_arr: &[u8; 32] = &*self.ecdsa_scalar.get();
                let seed_arr: &[u8; 32] = &*self.mldsa_seed.get();
                (&msg_arr[..msg_len], scalar_arr, seed_arr)
            };

            if self.run_sign(scalar, seed, msg_buf).is_err() {
                self.state.store(STATE_ERROR, Ordering::Release);
                crate::arch::sev();
                continue;
            }

            self.state.store(STATE_DONE, Ordering::Release);
            crate::arch::sev();
        }
    }

    /// Inner sign routine. Splits out so we can use `?` for error
    /// propagation and keep the worker flat.
    fn run_sign(&self, scalar: &[u8; 32], seed: &[u8; 32], msg_buf: &[u8]) -> Result<(), ()> {
        // 1) ECDSA-P256: deterministic sign of SHA-256(LABEL || msg).
        let ecdsa_prehash: [u8; 32] = {
            let mut out = [0u8; 32];
            let mut h = SHA256::default();
            h.do_update(&HYBRID_LABEL);
            h.do_update(msg_buf);
            h.do_final_out(&mut out);
            out
        };
        let sk = SigningKey::from_bytes(scalar.into()).map_err(|_| ())?;
        let sig: Signature = sk.sign_prehash(&ecdsa_prehash).map_err(|_| ())?;
        let der = sig.to_der();
        let der_bytes = der.as_bytes();

        // Stage the DER output. SAFETY: state == RUNNING.
        let der_len = unsafe {
            let dst = &mut *self.ecdsa_der.get();
            let n = der_bytes.len().min(dst.len());
            dst[..n].copy_from_slice(&der_bytes[..n]);
            n
        };
        self.ecdsa_der_len.store(der_len as u16, Ordering::Relaxed);

        // 2) ML-DSA half. Re-derive sk from the seed (we don't
        // carry the expanded sk across calls; the lowmem crate makes
        // that explicit).
        let seed_km = KeyMaterial::<32>::from_bytes_as_type(seed, KeyType::Seed).map_err(|_| ())?;
        let (_mldsa_pk, mldsa_sk) = MLDSA::keygen_from_seed(&seed_km).map_err(|_| ())?;
        let tr = mldsa_sk.tr();
        let mut mb = MuBuilder::do_init(&tr, Some(b"")).map_err(|_| ())?;
        mb.do_update(&HYBRID_LABEL);
        mb.do_update(msg_buf);
        mb.do_update(&der_bytes[..der_len]);
        let mu = mb.do_final();

        // rnd = 0^32: FIPS 204 Algorithm 2 step 6, the deterministic
        // variant, so rho' = SHAKE-256(K || 0^32 || mu). This matches
        // the C port (pqf_mldsa_sign) and the published FIPS 204 / ACVP
        // deterministic vectors.
        //
        // This used to be SHA-256(LABEL || msg || ecdsaDER). That was
        // equally secure but matched no published vector, and it bought
        // nothing: rnd only defends against fault and DPA attacks that
        // exploit REPEATED identical signing, and a message-derived rnd
        // is just as repeatable as a zero one. Genuine hedging would
        // need a live TRNG draw here, which neither port does.
        //
        // rnd is signer-only -- ML-DSA.Verify takes no rnd and it is not
        // recoverable from the signature -- so this change is invisible
        // to relying parties and does not affect existing credentials.
        let rnd: [u8; 32] = [0u8; 32];

        // SAFETY: state == RUNNING.
        unsafe {
            let dst = &mut *self.mldsa_sig.get();
            MLDSA::sign_mu_deterministic_out(&mldsa_sk, &mu, rnd, dst).map_err(|_| ())?;
        }
        Ok(())
    }
}

impl Default for Core1Signer {
    fn default() -> Self {
        Self::new()
    }
}
