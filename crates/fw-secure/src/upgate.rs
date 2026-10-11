// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! User presence, decided in the Secure world.
//!
//! FIDO requires a human gesture per operation. In a TrustZone split
//! that check is worthless unless the Secure side both samples the
//! button and holds the verdict: if NS could assert "the user touched
//! it", a compromised NS would sign anything it liked with keys it can
//! never read, which defeats most of the point of moving them.
//!
//! ## Why this is two-phase
//!
//! The obvious shape -- block inside the veneer until the button is
//! pressed -- does not work. The wait is seconds long, and during it
//! NS has to keep pumping USB and sending CTAPHID KEEPALIVE or the host
//! gives up on the transaction. Secure cannot call back into NS to do
//! that.
//!
//! So the gate is split. NS calls `begin`, then polls while it pumps
//! USB, and the operation veneers refuse to act until a confirmation
//! exists. NS drives the *timing*; Secure owns the *decision*. All NS
//! can do by lying is deny itself service.
//!
//! ## The gesture
//!
//! A press already held when the window opens does not count: the
//! sampler must first see the button released, then pressed. Otherwise
//! a user resting a finger on the pad -- or tape over it -- would
//! silently authorise every operation that followed.
//!
//! Confirmation is single-use and expires, so one touch authorises one
//! operation.

use rp235x_hal as hal;

/// How long a window stays open waiting for the gesture.
const WINDOW_US: u64 = 10_000_000;
/// How long a confirmation remains usable once given.
const VALID_US: u64 = 10_000_000;
/// The button is polled through a flash blackout; rate-limit it the way
/// the FIDO firmware's board profile does.
const SAMPLE_INTERVAL_US: u64 = 2_000;

/// Poll results, as returned across the boundary.
pub const UP_PENDING: u8 = 0;
pub const UP_CONFIRMED: u8 = 1;
pub const UP_TIMEOUT: u8 = 2;

struct State {
    open: bool,
    saw_release: bool,
    started_us: u64,
    confirmed_at: Option<u64>,
    last_sample_us: u64,
}

static mut STATE: State = State {
    open: false,
    saw_release: false,
    started_us: 0,
    confirmed_at: None,
    last_sample_us: 0,
};

/// Free-running microsecond timer. TIMER0 is not in ACCESSCTRL's NS
/// allow-list, so NS cannot skew it to stretch a window.
#[cfg(any(target_arch = "arm", target_arch = "riscv32"))]
fn now_us() -> u64 {
    // SAFETY: read-only access to a Secure-owned peripheral.
    unsafe {
        let t = &*hal::pac::TIMER0::ptr();
        // Latch low first: reading TIMELR latches TIMEHR on RP2350.
        let lo = t.timelr().read().bits() as u64;
        let hi = t.timehr().read().bits() as u64;
        (hi << 32) | lo
    }
}

/// Host build: a clock the test drives.
///
/// The gate is a state machine over elapsed time -- a debounce, a sample
/// interval, a window -- and every one of those is a boundary worth
/// testing. Against a free-running peripheral a test could only wait and
/// hope; against a clock it sets, it can sit exactly on the debounce
/// threshold and check which side of it the gate lands. See
/// `crates/fw-secure-hosttest`.
#[cfg(not(any(target_arch = "arm", target_arch = "riscv32")))]
fn now_us() -> u64 {
    hal::now_us()
}

/// Test-only: one pending simulated gesture.
///
/// Lets the gate be exercised from both sides without a finger on the
/// board -- without it a window must time out, with it the same window
/// must confirm. Modelled as a **one-shot** rather than a level, for
/// two reasons: a stuck-high level could never satisfy the
/// release-then-press rule and so could not confirm at all, and
/// one-shot is what a real touch is, so a test that passes here is
/// testing the same state machine a finger drives.
///
/// Additive: the real sampler still runs on every poll, so this cannot
/// paper over a broken button path. Behind `dev-escape`, with
/// everything else that weakens the device.
#[cfg(feature = "dev-escape")]
static mut INJECT_PENDING: bool = false;

#[cfg(feature = "dev-escape")]
pub fn inject_press() {
    // SAFETY: single-threaded.
    unsafe {
        INJECT_PENDING = true;
    }
}

/// Test-only: treat every window as satisfied.
///
/// The one-shot injection above models a real touch and is what the
/// presence gate was actually validated with. This is cruder and exists
/// for one reason: a CTAP2 conformance suite performs dozens of
/// operations back to back and has no idea this token wants a gesture,
/// so without it the suite simply times out on every command. It is
/// the TrustZone equivalent of the FIDO firmware's
/// PQF_TEST_NO_USER_BUTTON, and like that flag it makes the device
/// answer to anyone -- dev builds only.
#[cfg(feature = "dev-escape")]
static mut AUTO_PRESENT: bool = false;

#[cfg(feature = "dev-escape")]
pub fn set_auto(on: bool) {
    // SAFETY: single-threaded.
    unsafe {
        AUTO_PRESENT = on;
    }
}

#[cfg(feature = "dev-escape")]
fn auto_present() -> bool {
    // SAFETY: single-threaded.
    unsafe { AUTO_PRESENT }
}

#[cfg(not(feature = "dev-escape"))]
fn auto_present() -> bool {
    false
}

/// Take the injected gesture, if one is queued.
#[cfg(feature = "dev-escape")]
fn take_injected() -> bool {
    // SAFETY: single-threaded.
    unsafe {
        let p = &mut *(&raw mut INJECT_PENDING);
        let was = *p;
        *p = false;
        was
    }
}

#[cfg(not(feature = "dev-escape"))]
fn take_injected() -> bool {
    false
}

/// Test-only: the raw sampler, with no gesture state machine in front
/// of it. Distinguishes "the button never got pressed" from "the
/// sampler cannot see a press" -- two very different bugs that look
/// identical through the presence gate.
#[cfg(feature = "dev-escape")]
pub fn raw_pressed() -> bool {
    crate::flash::with_core1_parked(crate::bootsel::pressed)
}

/// The real button. Deliberately not consulted for the injected
/// gesture: `begin` uses this alone, so a queued injection cannot be
/// mistaken for a finger already resting on the pad.
fn sample() -> bool {
    // Core 1 must not fetch from flash while the chip select is
    // floated: its fetch re-asserts CS through the QMI and the read
    // comes back "released" no matter what the button is doing. That is
    // a silent failure, which is how it went unnoticed.
    crate::flash::with_core1_parked(crate::bootsel::pressed)
}

/// Open a user-presence window. Any previous confirmation is discarded,
/// so a caller cannot bank one touch and spend it later.
pub fn begin() {
    let t = now_us();
    // SAFETY: single-threaded; Secure-only state.
    unsafe {
        let s = &mut *(&raw mut STATE);
        s.open = true;
        s.saw_release = !sample(); // a held button starts un-released
        s.started_us = t;
        s.confirmed_at = None;
        s.last_sample_us = 0;
    }
}

/// Sample the button and report progress.
pub fn poll() -> u8 {
    let t = now_us();
    // SAFETY: single-threaded; Secure-only state.
    let s = unsafe { &mut *(&raw mut STATE) };
    if s.confirmed_at.is_some() {
        return UP_CONFIRMED;
    }
    if !s.open {
        return UP_TIMEOUT;
    }
    if t.saturating_sub(s.started_us) > WINDOW_US {
        s.open = false;
        return UP_TIMEOUT;
    }
    if t.saturating_sub(s.last_sample_us) < SAMPLE_INTERVAL_US {
        return UP_PENDING;
    }
    s.last_sample_us = t;
    // The real sampler runs every time, injected gesture or not.
    let pressed = sample() || auto_present() || (s.saw_release && take_injected());
    if !pressed {
        s.saw_release = true;
    } else if s.saw_release {
        // Release then press: a fresh gesture, not a resting finger.
        s.confirmed_at = Some(t);
        s.open = false;
        return UP_CONFIRMED;
    }
    UP_PENDING
}

/// Spend a confirmation. True only for one that exists and has not
/// expired; either way the confirmation is gone afterwards, so a
/// refused operation cannot be retried onto someone else's touch.
pub fn consume() -> bool {
    let t = now_us();
    // SAFETY: single-threaded; Secure-only state.
    let s = unsafe { &mut *(&raw mut STATE) };
    let ok = match s.confirmed_at {
        Some(at) => t.saturating_sub(at) <= VALID_US,
        None => false,
    };
    s.confirmed_at = None;
    s.open = false;
    ok
}
