// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Spotpear RP2350-LCD-1.28 -- round 1.28" IPS LCD (240 x 240,
//! GC9A01 controller) on a Pico-form-factor RP2350A board with
//! USB-C, 4 MB QSPI flash, an on-board QMI8658 6-axis IMU, and a
//! lithium-charge MX1.25 connector.
//!
//! Sometimes badged "RP2350-LCD-1.28-B" with a metal case option;
//! the bare PCB and the cased version share the same pinout.
//!
//! ## What this firmware does on this board
//!
//! - Drives the on-board **1.28" GC9A01 round LCD** with a centred
//!   status panel. Sub-module [`lcd`] does the controller / SPI
//!   bus setup and the `embedded-graphics` drawing.
//! - **Does not touch the QMI8658 IMU** (I2C pins GP6 / GP7 + the
//!   INT1/INT2 lines on GP23 / GP24 are left at their boot-time
//!   high-Z input defaults -- the IMU stays unaddressed).
//! - **Does not touch the battery-ADC pin** (GP29).
//! - **No firmware-readable user button.** RST is a hard chip-
//!   reset; BOOT is on QSPI_SS (bootrom-only). [`Board::user_present`]
//!   always returns `false`.
//!
//! ## LCD pin map
//!
//! Per the Spotpear vendor pinout diagram (printed on the silkscreen
//! AND in the product listing's pin map). Same `DC=8 / CS=9 / CLK=10 /
//! DIN=11 / RST=12 / BL=25` convention as the Waveshare Pico-LCD-1.28
//! add-on board and several other RP-series add-on LCDs.
//!
//! | GPIO  | Direction          | Function                            |
//! | ---   | ---                | ---                                 |
//! | GP8   | Push-pull output   | LCD_DC                              |
//! | GP9   | Push-pull output   | LCD_CS (software-toggled chip-sel)  |
//! | GP10  | SPI1 SCK alt-func  | LCD_CLK                             |
//! | GP11  | SPI1 TX  alt-func  | LCD_DIN / MOSI                      |
//! | GP12  | Push-pull output   | LCD_RST                             |
//! | GP25  | Push-pull output   | LCD_BL (backlight, active-high)     |

mod lcd;

use core::ffi::CStr;

use crate::hal;

/// LCD backlight -- GP25, push-pull output, driven HIGH at boot.
type BacklightPin = hal::gpio::Pin<
    hal::gpio::bank0::Gpio25,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;

/// State held between `setup` and program exit.
pub struct Board {
    /// LCD backlight pin. Once high, never touched again -- kept in
    /// the struct purely to retain ownership of GP25 so nothing
    /// else in the firmware can reclaim it.
    #[allow(dead_code)]
    backlight: BacklightPin,
    /// The configured GC9A01 display. All drawing goes through this.
    display: lcd::Display,
    /// Per-field cached state so `tick` knows which lines to redraw.
    cached: lcd::Cached,
    /// Most-recent timer tick we drew at, in microseconds. Used to
    /// throttle `tick` so we redraw at ~5 Hz max (every 200 ms).
    last_redraw_us: u64,
    /// Owned copy of the Copyable timer handle.
    timer: super::Timer,
}

impl Board {
    /// Take ownership of the LCD pins (GP8/9/10/11/12/25) and the
    /// SPI1 peripheral. Initialise the GC9A01 and paint the static
    /// + initial-dynamic content. Non-pin `BoardSetup` fields
    /// (`resets`, `peripheral_clock_freq`, `timer`) all get consumed
    /// by the LCD init path.
    pub fn setup(setup: super::BoardSetup<'_>) -> Self {
        let super::BoardSetup {
            pins,
            spi0: _spi0, // unused on this board; SPI0 left idle
            spi1,
            resets,
            peripheral_clock_freq,
            timer,
        } = setup;

        let (display, backlight) = lcd::build(
            spi1,
            resets,
            peripheral_clock_freq,
            pins.gpio10,
            pins.gpio11,
            pins.gpio9,
            pins.gpio8,
            pins.gpio12,
            pins.gpio25,
            timer,
        );

        Self {
            backlight,
            display,
            cached: lcd::Cached::empty(),
            last_redraw_us: 0,
            timer,
        }
    }

    // -------- LED channel API (no-op) --------
    //
    // This board has no discrete user LED. The status indicator is
    // the LCD; the six R/G/B channel methods are no-ops, the LCD
    // driven from `tick` below carries the visible state instead.

    pub fn r_on(&mut self) {}
    pub fn r_off(&mut self) {}
    pub fn g_on(&mut self) {}
    pub fn g_off(&mut self) {}
    pub fn b_on(&mut self) {}
    pub fn b_off(&mut self) {}

    /// No firmware-readable user button on this board.
    pub fn user_present(&mut self) -> bool {
        false
    }

    /// Periodic refresh callback. Throttles to ~5 Hz internally;
    /// per-field redraws only paint the rectangles that changed.
    pub fn tick(&mut self, stats: &super::Stats) {
        let now = self.timer.get_counter().ticks();
        if self.cached.is_initialised() && now.saturating_sub(self.last_redraw_us) < 200_000 {
            return;
        }
        self.last_redraw_us = now;
        if !self.cached.is_initialised() {
            lcd::paint_initial(&mut self.display, stats);
            self.cached.mark_initialised();
        }
        lcd::refresh(&mut self.display, stats, &mut self.cached);
    }
}

/// Human-readable board name. Used by `lcd` for the secondary
/// title line on the panel.
pub const NAME: &str = "RP2350-LCD-1.28";

/// USB product string for this board's build.
pub const USB_PRODUCT: &str = "RP2350-LCD-1.28 PQC";

/// No firmware-readable user-presence button wired on this board, so the
/// CTAP `WaitForUp` gate auto-confirms (see `main.rs`).
pub const HAS_USER_BUTTON: bool = false;

/// The BOOT button sits on QSPI_SS, where only the bootrom reads it:
/// held while plugging in, it enters the ROM bootloader. (With no
/// firmware-readable button, `CTAPHID_CMD_REBOOT` needs no touch here
/// either way -- see `reboot_policy.rs`.)
pub const HAS_POWER_ON_BOOTSEL: bool = true;

/// picotool program feature naming this board, so `picotool info -a
/// <file.uf2>` identifies an image before it is flashed.
pub const BI_BOARD: &CStr = c"pqf-board=spotpear_rp2350_lcd_1_28";

/// picotool program description for this board's build.
pub const BI_DESCRIPTION: &CStr =
    c"Hybrid PQC FIDO2 authenticator on RP2350 (Spotpear RP2350-LCD-1.28)";
