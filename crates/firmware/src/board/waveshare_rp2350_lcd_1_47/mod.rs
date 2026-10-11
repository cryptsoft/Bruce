// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Waveshare RP2350-LCD-1.47-B / -B-M (Pico 2 footprint + 1.47" LCD +
//! micro-SD + WS2812 RGB). Sold variously as "Waveshare RP2350-LCD-1.47"
//! and re-branded by spotpear / Elshare on AliExpress as
//! `RP2350-LCD-1.47-B`. The `-B-M` suffix indicates the variant with
//! soldered headers; -B is the bare-board version. Both have identical
//! pinouts. The earlier `-A` variant (micro-USB connector instead of
//! USB-C) is also supported -- the GPIO pinout is identical, only the
//! USB connector differs.
//!
//! Reference: <https://www.waveshare.com/rp2350-lcd-1.47.htm>
//!
//! ## What this firmware does on this board
//!
//! - Drives the on-board **1.47" ST7789V2 LCD** (172 x 320) with a
//!   live status panel. Sub-module [`lcd`] handles the controller +
//!   SPI bus setup and the `embedded-graphics` drawing. The LCD
//!   shows: firmware version, board name, algorithm summary, USB
//!   serial, PIN state + retries, resident credential count, uptime,
//!   most-recent CTAP operation, total operation count.
//! - Holds the **WS2812 NeoPixel data line on GP23 LOW**, putting
//!   the on-board RGB lamps into their reset state. The LEDs stay
//!   dark -- driving them as actual RGB indicators needs a PIO
//!   program with strict 800 kHz timing, which is a future task.
//! - **Does not touch the micro-SD slot** (SPI0 pins are left at
//!   their boot-time defaults; the slot is electrically idle).
//! - **No firmware-readable user button** -- RST is a hard chip-reset,
//!   BOOT is on QSPI_SS (bootrom-only). [`Board::user_present`]
//!   always returns `false`.
//!
//! ## LCD pin map
//!
//! See [`lcd`] for the full layout. The pins claimed in this profile
//! (verified against Waveshare's reference C driver at
//! DrJonEA/RP2350LCDProbe/lib/Config/DEV_Config.h):
//!
//! | GPIO  | Direction          | Function                           |
//! | ---   | ---                | ---                                |
//! | GP16  | Push-pull output   | LCD_DC                             |
//! | GP17  | Push-pull output   | LCD_CS (software-toggled chip-sel) |
//! | GP18  | SPI0 SCK alt-func  | LCD_SCK                            |
//! | GP19  | SPI0 TX  alt-func  | LCD_MOSI / DIN                     |
//! | GP20  | Push-pull output   | LCD_RST (panel reset)              |
//! | GP21  | Push-pull output   | LCD_BL (backlight, active-high)    |
//! | GP23  | Push-pull output   | WS2812 data, held LOW (LEDs dark)  |

mod lcd;

use core::ffi::CStr;

use crate::hal;
use embedded_hal::digital::OutputPin;

/// WS2812 NeoPixel data line -- GP23, push-pull output, parked LOW.
type WsDataPin = hal::gpio::Pin<
    hal::gpio::bank0::Gpio23,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;
/// LCD backlight -- GP21 (NOT GP25 -- that's a different Waveshare
/// board's BL pin), push-pull output, driven HIGH at boot.
type BacklightPin = hal::gpio::Pin<
    hal::gpio::bank0::Gpio21,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;

/// State required to drive the LCD between `setup` and program exit
/// (which never happens -- the firmware loops forever in `main`).
///
/// The `Timer<CopyableTimer0>` we hold is a `Copy`-able value (per
/// rp235x-hal's `CopyableTimer0` witness), so we don't need any
/// lifetime gymnastics -- the `Board` owns its own copy independently
/// of the one `main.rs` keeps for time tracking.
pub struct Board {
    /// WS2812 data pin held LOW. Owned-but-never-touched; the field
    /// just retains GP23 so nothing else in the firmware reclaims it.
    #[allow(dead_code)]
    ws_data: WsDataPin,
    /// LCD backlight pin. Once high, never touched again -- we could
    /// PWM-dim this in a future change but the firmware-design
    /// budget for that is zero right now.
    #[allow(dead_code)]
    backlight: BacklightPin,
    /// The configured ST7789 display. All drawing goes through this.
    display: lcd::Display,
    /// Cached per-field state so `tick` knows which lines to redraw.
    cached: lcd::Cached,
    /// Most-recent timer tick we drew at, in microseconds. Used to
    /// throttle `tick` so we redraw at ~5 Hz max (every 200 ms).
    last_redraw_us: u64,
    /// Owned copy of the Copyable timer handle, used for time
    /// tracking inside `tick` and for the LCD's internal delay.
    timer: super::Timer,
}

impl Board {
    /// Take ownership of the LCD pins, the SPI0 peripheral, GP23
    /// (WS2812 data), and GP21 (backlight). Initialise the LCD and
    /// paint the static + initial-dynamic content. The non-pin
    /// `BoardSetup` fields (`resets`, `peripheral_clock_freq`,
    /// `timer`) all get consumed by the LCD init path.
    pub fn setup(setup: super::BoardSetup<'_>) -> Self {
        let super::BoardSetup {
            pins,
            spi0,
            spi1: _spi1, // unused on this board; SPI1 left idle
            resets,
            peripheral_clock_freq,
            timer,
        } = setup;

        // WS2812 data line -- drive LOW to hold the LED chain dark.
        let mut ws_data = pins.gpio23.into_push_pull_output();
        let _ = ws_data.set_low();

        // Bring up the LCD on SPI0. Consumes SPI0, &mut RESETS, and
        // six GPIO pins (GP16 DC, GP17 CS, GP18 SCK, GP19 MOSI,
        // GP20 RST, GP21 BL -- per Waveshare's reference driver, see
        // `lcd.rs` module doc).
        let (display, backlight) = lcd::build(
            spi0,
            resets,
            peripheral_clock_freq,
            pins.gpio18,
            pins.gpio19,
            pins.gpio17,
            pins.gpio16,
            pins.gpio20,
            pins.gpio21,
            timer,
        );

        Self {
            ws_data,
            backlight,
            display,
            cached: lcd::Cached::empty(),
            last_redraw_us: 0,
            timer,
        }
    }

    // -------- LED channel API (no-op -- see module docs) --------
    //
    // The Waveshare board's status indicators are the WS2812 chain
    // (held dark by GP23-low) and the LCD itself (driven by `tick`
    // below). Logical R/G/B channels have no meaningful mapping to
    // the hardware on this board, so all six methods compile down
    // to nothing.

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

    /// Periodic refresh callback. Compares the incoming
    /// [`super::Stats`] against the cached state and redraws any
    /// lines whose values changed. Throttled to ~5 Hz internally --
    /// calling this on every USB-poll iteration is fine; redraws
    /// only happen at most every 200 ms.
    ///
    /// On first call, the static labels + initial values get painted
    /// by `paint_initial`; subsequent calls go through `refresh`
    /// which only touches the small per-field rectangles that need
    /// updating. A typical idle frame redraws just the uptime line
    /// (~80 bytes of SPI = ~25 us at 32 MHz); a busy frame after a
    /// CTAP completion might also redraw last-op + op-count + creds
    /// (still well under 500 us total).
    pub fn tick(&mut self, stats: &super::Stats) {
        let now = self.timer.get_counter().ticks();
        if self.cached.is_initialised() {
            // Past the first frame -- throttle to 5 Hz.
            if now.saturating_sub(self.last_redraw_us) < 200_000 {
                return;
            }
        }
        self.last_redraw_us = now;
        if !self.cached.is_initialised() {
            lcd::paint_initial(&mut self.display, stats);
            self.cached.mark_initialised();
        }
        lcd::refresh(&mut self.display, stats, &mut self.cached);
    }
}

/// Human-readable board name. Part of the per-board interface
/// contract documented in `board/mod.rs`. Used by `lcd` for the
/// title line on the panel.
pub const NAME: &str = "Waveshare RP2350-LCD-1.47";

/// USB product string for this board's build.
pub const USB_PRODUCT: &str = "RP2350-LCD-1.47 PQC";

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
pub const BI_BOARD: &CStr = c"pqf-board=waveshare_rp2350_lcd_1_47";

/// picotool program description for this board's build.
pub const BI_DESCRIPTION: &CStr =
    c"Hybrid PQC FIDO2 authenticator on RP2350 (Waveshare RP2350-LCD-1.47)";
