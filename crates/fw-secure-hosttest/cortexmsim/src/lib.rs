// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Host stand-in for the `cortex-m` intrinsics the Secure world uses.
//!
//! Only what the modules under test actually call. `sev` and `wfe` are
//! inter-core signalling on the real chip and have no meaning with one
//! core, but the *interrupt mask* does: `flash.rs` disables interrupts
//! around a flash operation and restores the caller's state afterwards,
//! and a caller already inside a critical section must stay masked.
//! That is a real property, so it is modelled rather than stubbed away.
//!
//! Calls are counted so a test can assert the signalling happened at
//! all -- on silicon a missing `sev` means core 1 sleeps through a park
//! request and core 0 spins forever.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static SEVS: AtomicU32 = AtomicU32::new(0);
static WFES: AtomicU32 = AtomicU32::new(0);
static MASKED: AtomicBool = AtomicBool::new(false);

pub mod asm {
    use super::*;

    pub fn sev() {
        SEVS.fetch_add(1, Ordering::SeqCst);
    }
    pub fn wfe() {
        WFES.fetch_add(1, Ordering::SeqCst);
    }
    pub fn nop() {}
    pub fn isb() {}
    pub fn dsb() {}
    pub fn delay(_cycles: u32) {}
}

pub mod interrupt {
    use super::*;

    pub fn disable() {
        MASKED.store(true, Ordering::SeqCst);
    }
    /// # Safety
    /// Mirrors `cortex_m::interrupt::enable`, which is unsafe because it
    /// can break a critical section. Nothing here is unsafe.
    pub unsafe fn enable() {
        MASKED.store(false, Ordering::SeqCst);
    }
}

pub mod register {
    pub mod primask {
        use super::super::MASKED;
        use std::sync::atomic::Ordering;

        #[derive(Clone, Copy)]
        pub struct Primask(bool);
        impl Primask {
            pub fn is_active(&self) -> bool {
                !self.0
            }
            pub fn is_inactive(&self) -> bool {
                self.0
            }
        }
        pub fn read() -> Primask {
            Primask(MASKED.load(Ordering::SeqCst))
        }
    }
}

/// Test helpers. Not part of the real crate's surface.
pub mod sim {
    use super::*;

    pub fn sevs() -> u32 {
        SEVS.load(Ordering::SeqCst)
    }
    pub fn wfes() -> u32 {
        WFES.load(Ordering::SeqCst)
    }
    pub fn irqs_masked() -> bool {
        MASKED.load(Ordering::SeqCst)
    }
    pub fn set_irqs_masked(v: bool) {
        MASKED.store(v, Ordering::SeqCst);
    }
    pub fn reset() {
        SEVS.store(0, Ordering::SeqCst);
        WFES.store(0, Ordering::SeqCst);
        MASKED.store(false, Ordering::SeqCst);
    }
}
