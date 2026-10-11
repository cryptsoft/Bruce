// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The Secure world's storage modules, compiled for the host.
//!
//! `fw-secure` is a bin crate for `thumbv8m.main-none-eabihf` with
//! `cmse_nonsecure_entry` veneers, so `cargo test` can never reach it
//! directly. The modules that matter here touch the machine in only two
//! places -- `crate::flash::flash_op` and six `rom_data` calls -- and read
//! flash through a single pointer helper. That is a narrow enough seam to
//! pull the real source in by path and substitute both.
//!
//! Nothing is reimplemented. `credstore.rs` and `counter.rs` are the
//! files that ship; if a test here passes, it passes against the code on
//! the token.

extern crate alloc;

/// Stands in for `crate::trng::Trng`.
///
/// The real one drives the RP2350's ring-oscillator entropy source and
/// checks its on-die health bits. Neither exists here, and neither is
/// what the PIN protocol tests are about -- they are about what the
/// protocol does with the bytes, not where the bytes came from. This is
/// a counter, so a test can say exactly what key agreement will use and
/// get the same answer twice.
pub mod trng {
    pub struct Trng {
        next: u8,
    }

    impl Trng {
        /// Deterministic and non-zero: a p256 secret key of all zeroes is
        /// invalid, and `clientpin::init` would loop retrying it.
        pub fn new_for_test() -> Self {
            Self { next: 1 }
        }

        pub fn fill(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                *b = self.next;
                self.next = self.next.wrapping_add(1);
                if self.next == 0 {
                    self.next = 1;
                }
            }
        }
    }
}

/// Stands in for `crate::flash`.
///
/// On the board `flash_op` parks core 1, masks interrupts and holds the
/// XIP-down window open for the duration. None of that has meaning on a
/// host, and none of it is what these tests are about -- the storage
/// *logic* is. The cross-core handshake it wraps is covered by
/// `real_flash` above and by `pqf-signer-core`'s own tests.
pub mod flash {
    pub fn flash_op<R>(f: impl FnOnce() -> R) -> R {
        f()
    }

    /// On the board this parks core 1 before the caller floats the QSPI
    /// chip select, because a core-1 flash fetch re-asserts CS through
    /// the QMI and the button then reads as released no matter what it is
    /// doing -- a silent failure, which is how it went unnoticed. Here
    /// there is no second core and no chip select; the parking is
    /// exercised on silicon and by `pqf-signer-core`'s own tests.
    pub fn with_core1_parked<R>(f: impl FnOnce() -> R) -> R {
        f()
    }
}

/// The Secure signer's mailbox, without the core-1 stack.
///
/// `fw-secure/src/signer.rs` also declares a
/// `rp235x_hal::multicore::Stack`, which the simulated HAL has no
/// notion of and which nothing under test uses. This provides the one
/// item `flash.rs` reaches for -- the real `Core1Signer` from
/// `pqf-signer-core`, with its real park handshake atomics.
pub mod signer {
    pub use pqf_signer_core::signer::*;
    pub static CORE1_SIGNER: Core1Signer = Core1Signer::new();
}

/// The **real** BOOTSEL sampler: float the QSPI chip select, look at
/// the pad, put it back.
///
/// Distinct from the `bootsel` stub below, which other suites use.
///
/// The restore is the whole safety property. Leave OEOVER disabled and
/// the flash chip select stays floated -- XIP is dead, and the device
/// wedges with no error anywhere.
#[allow(dead_code)]
#[path = "../../fw-secure/src/bootsel.rs"]
pub mod real_bootsel;

/// The Secure world's **real** flash guard: park core 1, suspend XIP,
/// restore the QMI window.
///
/// Distinct from the `flash` stub below, which the storage suites use as
/// a pass-through. This one is the firmware's own, so the park handshake
/// and the QMI restore can be checked -- including the case that matters
/// at boot, where core 1 has not started and waiting for its
/// acknowledgement would hang forever.
#[allow(dead_code)]
#[path = "../../fw-secure/src/flash.rs"]
pub mod real_flash;

/// Stands in for `crate::bootsel`: the button, as the simulator holds it.
pub mod bootsel {
    pub fn pressed() -> bool {
        rp235x_hal::pressed()
    }
}

#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../fw-secure/src/counter.rs"]
pub mod counter;

#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../fw-secure/src/credstore.rs"]
pub mod credstore;

#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../fw-secure/src/pinstore.rs"]
pub mod pinstore;

#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../fw-secure/src/keystore.rs"]
pub mod keystore;

/// No flash, no hardware, no seam: the CBOR writer is pure.
#[allow(dead_code)]
#[path = "../../fw-secure/src/cborw.rs"]
pub mod cborw;

/// The **Non-secure** world's CBOR *reader*. It lives here rather than
/// in a crate of its own because it is entirely self-contained -- no
/// `use`, no `crate::`, no cfg gates -- and because it is the other
/// half of the pair: `cborw` writes what Secure returns, `cborr` parses
/// what an attacker sent. Of the two, this is the one on the untrusted
/// side, and it had no tests at all.
#[allow(dead_code)]
#[path = "../../fw-nonsecure/src/cborr.rs"]
pub mod cborr;

/// CTAP2 request parsing, also from the Non-secure world. This is what
/// turns attacker-controlled CBOR into the fixed-layout arrays handed
/// across the TrustZone boundary -- the most valuable thing in that
/// image to get right. It sits on top of `cborr` and touches no
/// hardware, so it comes in the same way.
#[allow(dead_code)]
#[path = "../../fw-nonsecure/src/ctapreq.rs"]
pub mod ctapreq;

/// CTAPHID routing, from the same image. `handle_message` used to decide
/// this inline in a match that needed a USB bus and the Secure gateway
/// both present, which is why the Non-secure image had its parsers and
/// its transport covered and the routing between them not covered at
/// all -- including the presence gate, which is the part of that file
/// most worth being sure about. Pure, so it comes in by path like the
/// rest.
#[allow(dead_code)]
#[path = "../../fw-nonsecure/src/route.rs"]
pub mod route;

/// Response builders. Reaches for `credstore`'s field limits and the
/// signer's ML-DSA sizes, both of which are already here.
/// The user-presence gate: a state machine over a debounce, a sample
/// interval and a window, all of which the harness can sit exactly on.
#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../fw-secure/src/upgate.rs"]
pub mod upgate;

/// The CTAP2 PIN protocol: ECDH, AES-256-CBC by hand over the block
/// cipher, and the HMAC that authenticates it.
#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../fw-secure/src/clientpin.rs"]
pub mod clientpin;

#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../fw-secure/src/ctap.rs"]
pub mod ctap;

/// Put the simulated die back to erased and zero the operation counters.
pub fn fresh_die() {
    rp235x_hal::reset();
    rp235x_hal::reset_counts();
    rp235x_hal::reset_clock_and_button();
}
