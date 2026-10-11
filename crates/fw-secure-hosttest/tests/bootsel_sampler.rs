// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The BOOTSEL sampler.
//!
//! `pressed()` reads the BOOTSEL button, which on this chip shares a pin
//! with the flash chip select. To see it, the sampler floats CS by
//! writing OEOVER, waits, reads the pad, and puts OEOVER back.
//!
//! **The restore is the whole safety property.** Leave OEOVER disabled
//! and the flash chip select stays floated: XIP is dead, the next
//! instruction fetch is undefined, and the device wedges with no error
//! anywhere. The module's own comment makes the point that this code is
//! "tiny and hot enough to sit in the XIP cache, so it usually works --
//! the worst kind of latent bug".
//!
//! The registers here are simulated cells the firmware writes through
//! raw pointers, so a test can see the state before and after and what
//! the sample returns. It cannot see the instant of the float; that part
//! stays a silicon claim.

use pqf_fw_secure_hosttest as fw;

use fw::real_bootsel;
use rp235x_hal::qspi;
use std::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const OEOVER_LSB: u32 = 14;
const OEOVER_BITS: u32 = 0b11 << OEOVER_LSB;
const OEOVER_DISABLE: u32 = 2 << OEOVER_LSB;
const OEOVER_NORMAL: u32 = 0 << OEOVER_LSB;

fn oeover(v: u32) -> u32 {
    v & OEOVER_BITS
}

// ---- the restore ------------------------------------------------------

#[test]
fn the_chip_select_override_is_put_back() {
    // The one that matters. If OEOVER is left at DISABLE the flash CS
    // stays floated and the device is dead -- and the failure is silent,
    // because this code runs from RAM and the fetch that dies is the
    // next one from flash.
    let _g = lock();
    qspi::reset();
    qspi::set_csn_low(false);

    let _ = real_bootsel::pressed();

    assert_eq!(
        oeover(qspi::ss_ctrl()),
        OEOVER_NORMAL,
        "OEOVER was left at {:#x} -- the flash chip select is still floated \
         and XIP is dead",
        oeover(qspi::ss_ctrl())
    );
}

#[test]
fn the_override_is_put_back_whether_or_not_the_button_is_down() {
    // A restore that only happened on one branch would be a device that
    // wedges when the user does (or does not) hold the button -- an
    // intermittent nobody would connect to this code.
    for down in [false, true] {
        let _g = lock();
        qspi::reset();
        qspi::set_csn_low(down);
        let _ = real_bootsel::pressed();
        assert_eq!(
            oeover(qspi::ss_ctrl()),
            OEOVER_NORMAL,
            "OEOVER was left floated with the button {}",
            if down { "down" } else { "up" }
        );
    }
}

#[test]
fn repeated_sampling_always_ends_restored() {
    // The sampler runs on a timer in the idle loop, so it is not a
    // one-off. State that leaked a little each time would take a while
    // to show up and be miserable to trace.
    let _g = lock();
    qspi::reset();
    for i in 0..64 {
        qspi::set_csn_low(i % 2 == 0);
        let _ = real_bootsel::pressed();
        assert_eq!(
            oeover(qspi::ss_ctrl()),
            OEOVER_NORMAL,
            "OEOVER was left floated on iteration {i}"
        );
    }
}

// ---- everything else in that register is somebody else's -------------

#[test]
fn only_the_override_bits_are_touched() {
    // gpio_ctrl carries the pad's function select and other overrides.
    // The sampler must read-modify-write only OEOVER: clobbering the
    // rest would reconfigure the flash chip select pin itself.
    let _g = lock();
    qspi::reset();
    let others = 0xdead_0000u32 & !OEOVER_BITS | 0x0000_beefu32 & !OEOVER_BITS;
    qspi::set_ss_ctrl(others);
    qspi::set_csn_low(false);

    let _ = real_bootsel::pressed();

    assert_eq!(
        qspi::ss_ctrl() & !OEOVER_BITS,
        others & !OEOVER_BITS,
        "the sampler modified bits outside OEOVER -- it reconfigured the \
         flash chip-select pad"
    );
}

#[test]
fn a_preexisting_override_is_not_preserved_but_normalised() {
    // If OEOVER was already set to something odd before the sample, the
    // sampler ends by writing NORMAL rather than restoring whatever was
    // there. That is the documented behaviour -- NORMAL is the only
    // correct state for the CS pad in operation -- and worth pinning so
    // a future "restore the old value" change is a deliberate one.
    let _g = lock();
    qspi::reset();
    qspi::set_ss_ctrl(OEOVER_DISABLE);
    qspi::set_csn_low(false);
    let _ = real_bootsel::pressed();
    assert_eq!(
        oeover(qspi::ss_ctrl()),
        OEOVER_NORMAL,
        "the sampler left a pre-existing DISABLE in place"
    );
}

// ---- the reading itself ----------------------------------------------

#[test]
fn a_low_chip_select_reads_as_pressed() {
    // The polarity: BOOTSEL pulls the shared pin low. Inverted, the
    // token would report a press whenever nobody was touching it -- and
    // on a build where BOOTSEL triggers a reboot, that is a device that
    // will not stay up.
    let _g = lock();
    qspi::reset();
    qspi::set_csn_low(true);
    assert!(real_bootsel::pressed(), "a low CSN did not read as pressed");
}

#[test]
fn a_high_chip_select_reads_as_not_pressed() {
    let _g = lock();
    qspi::reset();
    qspi::set_csn_low(false);
    assert!(!real_bootsel::pressed(), "a high CSN read as pressed");
}

#[test]
fn the_reading_follows_the_pad_across_calls() {
    // Not latched, not cached: each call samples afresh. A stuck reading
    // would make the button work once per boot.
    let _g = lock();
    qspi::reset();
    for down in [true, false, true, true, false, false, true] {
        qspi::set_csn_low(down);
        assert_eq!(
            real_bootsel::pressed(),
            down,
            "the sampler did not follow the pad (wanted {down})"
        );
    }
}

// ---- interrupts -------------------------------------------------------

#[test]
fn interrupts_are_restored_after_the_sample() {
    // The window is opened with interrupts masked, because an ISR
    // fetched from XIP while CS is floated is the exact fault this
    // guards. The caller's state has to come back.
    let _g = lock();
    qspi::reset();
    qspi::set_csn_low(false);

    cortex_m::sim::set_irqs_masked(false);
    let _ = real_bootsel::pressed();
    assert!(
        !cortex_m::sim::irqs_masked(),
        "interrupts were left masked after the sample"
    );
}

#[test]
fn a_caller_that_had_interrupts_masked_stays_masked() {
    // Same discipline as the flash guard: a caller inside its own
    // critical section must not have it reopened underneath.
    let _g = lock();
    qspi::reset();
    qspi::set_csn_low(false);

    cortex_m::sim::set_irqs_masked(true);
    let _ = real_bootsel::pressed();
    assert!(
        cortex_m::sim::irqs_masked(),
        "a caller's interrupt mask was dropped by the sampler"
    );
}
