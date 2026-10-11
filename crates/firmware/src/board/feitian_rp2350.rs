// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Feitian RP2350 dev board -- an RP2350A board following the
//! Raspberry Pi Pico 2 reference design.
//!
//! Board profile written against the reference design plus the
//! board's own schematic (`PICO2_G9_QE09_V1.0`):
//!
//!   * **Single user LED on GP25, active-HIGH** -- drive high to
//!     light, as on the Pico / Pico 2 (schematic: GP25 -> 510 ohm -> two
//!     green LEDs to GND). Note this is the OPPOSITE polarity to the
//!     XIAO RP2350's GP25 LED, so the two modules can't share a
//!     profile despite using the same pin. The three logical
//!     channels (`r`/`g`/`b`) OR-merge onto the one LED via a state
//!     bitfield; you lose the colour cue but keep the "device is
//!     doing something" signal.
//!
//!   * **User presence = the BOOTSEL button.** The board's one
//!     button (schematic: `K1` -> 1 kohm -> QSPI_SS) isn't on a GPIO --
//!     it shorts the flash chip-select to ground, which only the
//!     bootrom senses at reset. But the line is sampleable at
//!     runtime by briefly floating the CS pad and reading it through
//!     SIO's HI register bank -- see [`super::bootsel`] (BSD-3-Clause
//!     derivation from Raspberry Pi `pico-examples`, attributed in
//!     `THIRD_PARTY.md`). Each sample costs a few microseconds of
//!     flash blackout, so [`Board::user_present`] rate-limits to one
//!     sample per 2 ms (the cadence FIDO firmware in the wild uses
//!     for the same trick) and serves a cached level in between.
//!     `HAS_USER_BUTTON = true`, so `main.rs` enforces a real
//!     press-then-release gesture in the CTAP `WaitForUp` gate.
//!
//!     The button stays shared with the bootrom: held while plugging
//!     in, the chip still enters BOOTSEL/USB-bootloader mode (that's
//!     how this firmware is flashed); tapped at runtime it's just a
//!     level the sampler reads, with no reset side effects. Polling
//!     only -- no IRQ path exists for QSPI_SS, and samples must not
//!     overlap a flash write or an in-flight sign (they don't:
//!     `user_present` is only polled from the `WaitForUp` gate,
//!     which completes before any sign is submitted and before any
//!     credential is persisted).
//!
//!   * **4 MiB QSPI flash assumed** (the reference design's W25Q32,
//!     matching the schematic). `memory.x` places the credential
//!     store in the last 12 KiB below the 4 MiB mark; a larger
//!     physical chip just leaves the surplus unused, but a chip
//!     SMALLER than 4 MiB would put the store past the end of flash
//!     and must not use this profile without shrinking
//!     `LENGTH(FLASH)`.
//!
//! No display panel, no power-gate quirks, no WS2812.

use core::ffi::CStr;

use crate::hal;
use embedded_hal::digital::OutputPin;
use hal::gpio::PinState;

/// Single user LED -- GP25, push-pull output, active-HIGH (reference
/// design: GP25 through a resistor to the LED(s), drive high to
/// light).
type LedPin = hal::gpio::Pin<
    hal::gpio::bank0::Gpio25,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;

/// Minimum spacing between two BOOTSEL samples, in us. Each sample
/// blacks out flash for a few us with interrupts masked, so the
/// `WaitForUp` polling loop must not hammer it; 2 ms keeps the
/// blackout duty cycle around 1% while still giving the 20 ms
/// debounce in `main.rs` ten samples to count.
const SAMPLE_INTERVAL_US: u64 = 2_000;

pub struct Board {
    /// Per-channel state bitfield: bit 0 = R, bit 1 = G, bit 2 = B.
    /// Any non-zero value lights the physical LED.
    state: u8,
    led: LedPin,
    /// us timestamp source for the sampler rate limit.
    timer: super::Timer,
    /// When the BOOTSEL line was last actually sampled.
    last_sample_us: u64,
    /// The level that sample returned; served to callers between
    /// samples.
    last_pressed: bool,
}

impl Board {
    /// Take ownership of GP25 (LED) and initialise it to off, and
    /// keep the (Copy) timer handle for the BOOTSEL sampler's rate
    /// limit. The remaining [`BoardSetup`] fields (SPI0/1, RESETS,
    /// peripheral clock) are dropped -- no display, no quirk pins.
    /// The BOOTSEL button needs no pin setup at all: it lives on
    /// QSPI_SS, which the flash interface owns.
    pub fn setup(setup: super::BoardSetup<'_>) -> Self {
        let super::BoardSetup { pins, timer, .. } = setup;
        // Latch the initial level atomically with the function switch
        // (same rationale as the XIAO profile: no transient wrong
        // level during bring-up after a warm reset).
        // active-high LED -> start LOW (off).
        let led = pins.gpio25.into_push_pull_output_in_state(PinState::Low);
        Self {
            state: 0,
            led,
            timer,
            last_sample_us: 0,
            last_pressed: false,
        }
    }

    // -------- LED channel API (OR-merged onto GP25) --------

    pub fn r_on(&mut self) {
        self.state |= 0b001;
        self.refresh();
    }
    pub fn r_off(&mut self) {
        self.state &= !0b001;
        self.refresh();
    }
    pub fn g_on(&mut self) {
        self.state |= 0b010;
        self.refresh();
    }
    pub fn g_off(&mut self) {
        self.state &= !0b010;
        self.refresh();
    }
    pub fn b_on(&mut self) {
        self.state |= 0b100;
        self.refresh();
    }
    pub fn b_off(&mut self) {
        self.state &= !0b100;
        self.refresh();
    }

    fn refresh(&mut self) {
        // Any channel on -> LED on (active-high -> drive high).
        if self.state != 0 {
            let _ = self.led.set_high();
        } else {
            let _ = self.led.set_low();
        }
    }

    /// Reads the BOOTSEL button (active-low on QSPI_SS, reported
    /// here as `true` = pressed) through the rate-limited sampler --
    /// a fresh sample at most every [`SAMPLE_INTERVAL_US`], the
    /// cached level otherwise. See the module doc and
    /// [`super::bootsel`] for the mechanism and its constraints.
    pub fn user_present(&mut self) -> bool {
        let now = self.timer.get_counter().ticks();
        if now.saturating_sub(self.last_sample_us) >= SAMPLE_INTERVAL_US {
            self.last_sample_us = now;
            self.last_pressed = super::bootsel::pressed();
        }
        self.last_pressed
    }

    /// No display panel on this board -- `tick` is a no-op.
    pub fn tick(&mut self, _stats: &super::Stats) {}
}

/// Human-readable board name. Part of the per-board interface
/// contract documented in `board/mod.rs`. Currently unused -- kept
/// for future log / panic surfaces that want to print which board
/// the firmware was built for. Suppresses the `dead_code` warning
/// at the module level rather than at every call site.
#[allow(dead_code)]
pub const NAME: &str = "Feitian RP2350";

/// USB product string for this board's build.
pub const USB_PRODUCT: &str = "Feitian RP2350 PQC";

/// The BOOTSEL button doubles as a firmware-readable user-presence
/// button via the QSPI chip-select sampling in [`super::bootsel`],
/// so `main.rs` enforces a real press gesture in the CTAP
/// `WaitForUp` gate rather than auto-confirming.
pub const HAS_USER_BUTTON: bool = true;

/// K1 is also the bootrom's button: held while plugging in, the chip
/// enters the ROM bootloader (that is how this firmware is flashed), so
/// the board can always be reflashed by hand. That is what lets
/// `CTAPHID_CMD_REBOOT` stay touch-gated here by default
/// (`reboot_policy.rs`). The sealed USB-C token that reuses this
/// profile's `Board` does NOT have this, and says so in its own module.
pub const HAS_POWER_ON_BOOTSEL: bool = true;

/// picotool program feature naming this board, so `picotool info -a
/// <file.uf2>` identifies an image before it is flashed.
pub const BI_BOARD: &CStr = c"pqf-board=feitian_rp2350";

/// picotool program description for this board's build.
pub const BI_DESCRIPTION: &CStr = c"Hybrid PQC FIDO2 authenticator on RP2350 (Feitian RP2350)";
