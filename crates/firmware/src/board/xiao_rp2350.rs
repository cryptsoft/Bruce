// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Seeed Studio XIAO RP2350 ([product page][product]) -- a
//! 21 x 17.5 mm RP2350A board in the XIAO form factor.
//!
//! Two pin quirks vs. the Tiny 2350 that drive the differences in
//! this module:
//!
//!   1. **Single dual-colour user LED on GP25** (active-low). No
//!      RGB. The three logical channels (`r`/`g`/`b`) OR-merge onto
//!      this one pin via a state bitfield; you lose the colour cue
//!      but keep the "device is doing something" signal.
//!
//!   2. **GP23 is the WS2812 NeoPixel power-enable**, gating U7
//!      (SX1801CCR load switch) -- see [Seeed XIAO RP2350 schematic
//!      v1.0][schematic]. We MUST drive it LOW: leaving it as a
//!      pull-up input drives it HIGH through the internal pull-up,
//!      turns on the NeoPixel power rail, and with GP22 (NeoPixel
//!      data) floating the WS2812 latches and pulls
//!      VBUS-disturbing transient currents -> USB enumeration fails
//!      intermittently. Driving low keeps the NeoPixel unpowered
//!      and the 5V rail clean.
//!
//! There's no firmware-readable user button on this board either
//! (the BOOT button is on QSPI_SS, only readable by the bootrom),
//! so [`Board::user_present`] always returns `false`.
//!
//! [product]: https://www.seeedstudio.com/Seeed-XIAO-RP2350-p-5944.html
//! [schematic]: https://files.seeedstudio.com/wiki/XIAO-RP2350/res/Seeed-Studio-XIAO-RP2350-v1.0.pdf

use core::ffi::CStr;

use crate::hal;
use embedded_hal::digital::OutputPin;
use hal::gpio::PinState;

/// Single user LED -- GP25, push-pull output, active-low.
type LedPin = hal::gpio::Pin<
    hal::gpio::bank0::Gpio25,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;
/// NeoPixel power-gate -- GP23, push-pull output, driven LOW.
type NeoPowerGate = hal::gpio::Pin<
    hal::gpio::bank0::Gpio23,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;

pub struct Board {
    /// Per-channel state bitfield: bit 0 = R, bit 1 = G, bit 2 = B.
    /// Any non-zero value lights the physical LED.
    state: u8,
    led: LedPin,
    /// NeoPixel power-gate. Parked LOW for the lifetime of `main`;
    /// the field is held to retain ownership of GP23 so nothing else
    /// in the firmware accidentally reclaims it.
    #[allow(dead_code)]
    neopixel_power_off: NeoPowerGate,
}

impl Board {
    /// Take ownership of GP25 (LED) and GP23 (NeoPixel power-gate),
    /// initialise the LED to off, and drive GP23 LOW. Non-pin fields
    /// of [`BoardSetup`] are dropped -- XIAO RP2350 has no display.
    pub fn setup(setup: super::BoardSetup<'_>) -> Self {
        let super::BoardSetup { pins, .. } = setup;
        // Drive the initial level atomically with the function switch:
        // `into_push_pull_output_in_state` latches GPIO_OUT *before* the
        // pad becomes an output, so a warm/RUN-pin reset that left the
        // output latch set can't momentarily drive the pin to the wrong
        // level during bring-up. Critically for GP23 this prevents a
        // transient HIGH from powering the NeoPixel rail and re-creating
        // the USB-enumeration glitch the gate exists to prevent.
        // active-low LED -> start HIGH (off).
        let led = pins.gpio25.into_push_pull_output_in_state(PinState::High);
        // NeoPixel power-gate -> start LOW (rail off).
        let neopixel_power_off = pins.gpio23.into_push_pull_output_in_state(PinState::Low);
        Self {
            state: 0,
            led,
            neopixel_power_off,
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
        // Any channel on -> LED on (active-low -> drive low).
        if self.state != 0 {
            let _ = self.led.set_low();
        } else {
            let _ = self.led.set_high();
        }
    }

    /// No firmware-readable button on this board -- always returns
    /// `false`. The Tiny 2350 has an equivalent placeholder on a
    /// physically-present pin; the XIAO doesn't even have that
    /// option because GP23 is repurposed for the NeoPixel
    /// power-gate.
    pub fn user_present(&mut self) -> bool {
        false
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
pub const NAME: &str = "Seeed Studio XIAO RP2350";

/// USB product string for this board's build.
pub const USB_PRODUCT: &str = "XIAO RP2350 PQC";

/// No firmware-readable user-presence button wired on this board, so the
/// CTAP `WaitForUp` gate auto-confirms (see `main.rs`); `user_present`
/// stays `false`. Wire a touch/momentary button and flip this to enforce
/// a real gesture, mirroring the Tiny 2350's GP0 setup.
pub const HAS_USER_BUTTON: bool = false;

/// The BOOT button sits on QSPI_SS, where only the bootrom reads it:
/// held while plugging in, it enters the ROM bootloader. (With no
/// firmware-readable button, `CTAPHID_CMD_REBOOT` needs no touch here
/// either way -- see `reboot_policy.rs`.)
pub const HAS_POWER_ON_BOOTSEL: bool = true;

/// picotool program feature naming this board, so `picotool info -a
/// <file.uf2>` identifies an image before it is flashed.
pub const BI_BOARD: &CStr = c"pqf-board=xiao_rp2350";

/// picotool program description for this board's build.
pub const BI_DESCRIPTION: &CStr =
    c"Hybrid PQC FIDO2 authenticator on RP2350 (Seeed Studio XIAO RP2350)";
