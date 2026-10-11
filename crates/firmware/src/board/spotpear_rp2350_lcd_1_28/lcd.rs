// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! GC9A01 LCD driver wiring for the Spotpear RP2350-LCD-1.28.
//!
//! Panel: 1.28" IPS round, 240 x 240 pixels, 262 K colours (RGB565
//! on the wire), GC9A01 controller. The panel is rectangular at the
//! pixel level but masked to a circle by the bezel -- software still
//! addresses a full 240 x 240 framebuffer, but anything near the
//! corners (within ~10-15 px of the bounding rectangle's edges) is
//! hidden behind the round mask. The status-panel layout in this
//! module insets text well clear of that boundary.
//!
//! Pin map per the Spotpear board's silkscreen / vendor pinout
//! diagram. Same Waveshare/Spotpear convention as several other
//! RP2350 boards in this product family (the "DC=8, CS=9, CLK=10,
//! DIN=11, RST=12, BL=25" pattern is the most common LCD layout
//! on RP-series Pico-form-factor add-on boards):
//!
//! | Pin   | Function                          | SPI peripheral |
//! | ---   | ---                               | ---            |
//! | GP8   | LCD_DC (data / command select)    | --              |
//! | GP9   | LCD_CS (chip select, active-low)  | --              |
//! | GP10  | LCD_CLK (SPI clock)               | SPI1 SCK       |
//! | GP11  | LCD_DIN (MOSI)                    | SPI1 TX        |
//! | GP12  | LCD_RST (panel reset, active-low) | --              |
//! | GP25  | LCD_BL (backlight, active-high)   | --              |
//!
//! Notably this board uses **SPI1**, in contrast to the Waveshare
//! RP2350-LCD-1.47-B (which uses SPI0). The DC + CS + RST + BL
//! pins are claimed as plain GPIOs (CS is software-toggled by
//! `embedded_hal_bus::spi::ExclusiveDevice`, not the SPI
//! peripheral's hardware CSn).

extern crate alloc;

use alloc::string::String;

use core::fmt::Write;

use embedded_graphics::mono_font::ascii::{FONT_6X10, FONT_8X13_BOLD};
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{Circle, PrimitiveStyle, Rectangle};
use embedded_graphics::text::{Alignment, Baseline, Text};
use embedded_hal::digital::OutputPin;
use embedded_hal_bus::spi::ExclusiveDevice;
use mipidsi::interface::SpiInterface;
use mipidsi::models::GC9A01;
use mipidsi::options::{Orientation, Rotation};
use mipidsi::Builder;

use crate::board::Stats;
use crate::hal;
use crate::hal::fugit::RateExtU32;

/// SPI staging buffer for `mipidsi::interface::SpiInterface`. Bigger
/// = faster bulk drawing. 2 KiB is comfortable for the 57.6 KB
/// worst-case full-screen 240x240 RGB565 redraw (which we only do
/// once at boot -- subsequent updates are per-line partial redraws).
static mut LCD_SPI_BUFFER: [u8; 2048] = [0; 2048];

// ---------- Per-pin type aliases ----------

type SpiSck = hal::gpio::Pin<hal::gpio::bank0::Gpio10, hal::gpio::FunctionSpi, hal::gpio::PullNone>;
type SpiMosi =
    hal::gpio::Pin<hal::gpio::bank0::Gpio11, hal::gpio::FunctionSpi, hal::gpio::PullNone>;
type PinCs = hal::gpio::Pin<
    hal::gpio::bank0::Gpio9,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;
type PinDc = hal::gpio::Pin<
    hal::gpio::bank0::Gpio8,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;
type PinRst = hal::gpio::Pin<
    hal::gpio::bank0::Gpio12,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;
pub type PinBl = hal::gpio::Pin<
    hal::gpio::bank0::Gpio25,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;

type SpiBus = hal::Spi<hal::spi::Enabled, hal::pac::SPI1, (SpiMosi, SpiSck), 8>;
type SpiDev = ExclusiveDevice<SpiBus, PinCs, super::super::Timer>;
type DisplayInterface = SpiInterface<'static, SpiDev, PinDc>;
/// Concrete display handle returned by [`build`].
pub type Display = mipidsi::Display<DisplayInterface, GC9A01, PinRst>;

// ---------- Build + init ----------

const DISPLAY_SIZE: u32 = 240;

/// Build + initialise the LCD. Owns the SPI bus, the four control
/// pins (CS, DC, RST, BL), and the rp235x-hal `Timer` (used as a
/// `DelayNs` source for `mipidsi`'s reset sequence + the
/// `ExclusiveDevice` wrapper). Returns the configured `Display`
/// and the backlight pin (which we drive high once and then keep
/// alive in the `Board` struct so it doesn't get reclaimed).
#[allow(clippy::too_many_arguments)]
pub fn build(
    spi1: hal::pac::SPI1,
    resets: &mut hal::pac::RESETS,
    peripheral_clock_freq: hal::fugit::HertzU32,
    sck: hal::gpio::Pin<hal::gpio::bank0::Gpio10, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    mosi: hal::gpio::Pin<hal::gpio::bank0::Gpio11, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    cs: hal::gpio::Pin<hal::gpio::bank0::Gpio9, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    dc: hal::gpio::Pin<hal::gpio::bank0::Gpio8, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    rst: hal::gpio::Pin<hal::gpio::bank0::Gpio12, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    bl: hal::gpio::Pin<hal::gpio::bank0::Gpio25, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    timer: super::super::Timer,
) -> (Display, PinBl) {
    let sck: SpiSck = sck.reconfigure();
    let mosi: SpiMosi = mosi.reconfigure();
    let cs: PinCs = cs.into_push_pull_output();
    let dc: PinDc = dc.into_push_pull_output();
    let rst: PinRst = rst.into_push_pull_output();
    let mut bl: PinBl = bl.into_push_pull_output();

    // Backlight on (active-high per Spotpear schematic).
    let _ = bl.set_high();

    // SPI1 init. GC9A01 datasheet allows up to 60 MHz SPI; 32 MHz
    // is comfortable headroom and matches the Waveshare 1.47" port.
    // Drop to 16 MHz if you see artefacts on a particular sample.
    let spi = hal::Spi::<_, _, _, 8>::new(spi1, (mosi, sck)).init(
        resets,
        peripheral_clock_freq,
        32u32.MHz(),
        embedded_hal::spi::MODE_0,
    );

    let spi_dev = ExclusiveDevice::new(spi, cs, timer).expect("SPI exclusive device init");

    // SAFETY: `LCD_SPI_BUFFER` is touched only here; `Board::setup`
    // is called exactly once from `main` before any concurrent CTAP
    // work begins. After setup returns, the `&'static mut` is owned
    // by the `Display`, so no other reference to the buffer exists.
    let buf: &'static mut [u8] = unsafe {
        #[allow(static_mut_refs)]
        &mut LCD_SPI_BUFFER
    };
    let di = SpiInterface::new(spi_dev, dc, buf);

    // GC9A01 is the de-facto controller for 1.28" round 240x240
    // panels. No display offset (the panel is 240x240, same as the
    // controller's native framebuffer -- unlike the 172x320 Waveshare
    // 1.47 which had to be centred within a 240-wide buffer).
    let mut init_delay = timer;
    let display = Builder::new(GC9A01, di)
        .display_size(DISPLAY_SIZE as u16, DISPLAY_SIZE as u16)
        .orientation(Orientation::new().rotate(Rotation::Deg0))
        .reset_pin(rst)
        .init(&mut init_delay)
        .expect("GC9A01 init");

    (display, bl)
}

// ---------- Drawing: layout + redraw ----------
//
// The panel is rectangular 240x240 at the pixel level but the bezel
// mask is a circle of ~120 px radius. Anything outside that circle
// (the four corners) is hidden. To keep all text legible without
// having to do per-line bounds checks against the circle, the
// layout below confines drawing to a square inscribed in the
// circle: roughly 30 <= x <= 210 and 30 <= y <= 210 (180 x 180 px,
// 30 chars wide at FONT_6X10, 18 lines tall at 10 px each).

// Colours -- Rgb565 quantises to 16 bits.
const FG_TITLE: Rgb565 = Rgb565::new(0x1F, 0x3F, 0x1F); // white
const FG_BOARD: Rgb565 = Rgb565::new(0x07, 0x2F, 0x1F); // cyan
const FG_LABEL: Rgb565 = Rgb565::new(0x14, 0x29, 0x14); // light grey
const FG_VALUE: Rgb565 = Rgb565::new(0x1F, 0x2F, 0x00); // soft yellow
const FG_GOOD: Rgb565 = Rgb565::new(0x07, 0x3F, 0x07); // green
const FG_WARN: Rgb565 = Rgb565::new(0x1F, 0x1F, 0x07); // amber
const BG: Rgb565 = Rgb565::new(0x02, 0x04, 0x06); // near-black

// Y coordinates of each row (text baseline). Spaced 14 px apart to
// give the rendering a bit of breathing room on the circular panel.
const CENTER_X: i32 = 120;
const Y_TITLE: i32 = 38;
const Y_BOARD: i32 = 60;
const Y_ALG: i32 = 86;
const Y_SERIAL_LABEL: i32 = 108;
const Y_SERIAL_VALUE: i32 = 120;
const Y_PIN: i32 = 142;
const Y_CREDS: i32 = 156;
const Y_UPTIME: i32 = 170;
const Y_LAST_OP: i32 = 192;
const Y_OP_COUNT: i32 = 206;

// Field clear-rectangle widths. The round mask narrows the safe
// horizontal range as you move toward the top / bottom of the
// panel; mid-panel rows (y ~ 120) get a wider safe region than
// the top / bottom rows (y < 50 or y > 190). The clear widths
// below are conservative -- narrower than the geometric max -- so
// every redraw stays clear of the mask.
const SAFE_W_NARROW: u32 = 140; // near top / bottom
const SAFE_W_WIDE: u32 = 180; // near mid-panel
const FONT_H: u32 = 11; // FONT_6X10 + 1 px slack

/// Cached snapshot of the values currently shown on the LCD. Same
/// pattern as the Waveshare 1.47 profile -- `Board::tick` diffs the
/// incoming `Stats` against this and only redraws fields that
/// actually changed.
pub struct Cached {
    initialised: bool,
    pin_set: bool,
    pin_retries: u8,
    resident_cred_count: u32,
    last_op: Option<&'static str>,
    op_count: u32,
    uptime_secs: u32,
}

impl Cached {
    pub const fn empty() -> Self {
        // Sentinel values guarantee that the first `refresh()` sees
        // every numeric field as "changed" and draws an initial
        // value. Without this, fields starting at 0 (creds, op
        // count, retries when PIN is unset) would stay blank
        // because `cached == stats` on the first compare.
        Self {
            initialised: false,
            pin_set: false,
            pin_retries: u8::MAX,
            resident_cred_count: u32::MAX,
            last_op: None,
            op_count: u32::MAX,
            uptime_secs: u32::MAX,
        }
    }

    pub fn is_initialised(&self) -> bool {
        self.initialised
    }
    pub fn mark_initialised(&mut self) {
        self.initialised = true;
    }
}

/// One-time draw of the static + initial-dynamic content. Called
/// from `Board::setup` after the panel is initialised.
pub fn paint_initial(display: &mut Display, stats: &Stats<'_>) {
    // Solid background. We clear the whole rectangle -- drawing
    // outside the circle is harmless (it just renders behind the
    // bezel).
    let _ = display.clear(BG);

    // Optional: draw a faint outline circle so the screen edge is
    // visible even when the user-data fields are sparse. Comment
    // out if you find it visually noisy.
    let _ = Circle::new(Point::new(0, 0), 240)
        .into_styled(PrimitiveStyle::with_stroke(
            Rgb565::new(0x06, 0x0c, 0x06), // dim slate
            1,
        ))
        .draw(display);

    let title_style = MonoTextStyle::new(&FONT_8X13_BOLD, FG_TITLE);
    let board_style = MonoTextStyle::new(&FONT_6X10, FG_BOARD);
    let value_style = MonoTextStyle::new(&FONT_6X10, FG_VALUE);
    let label_style = MonoTextStyle::new(&FONT_6X10, FG_LABEL);

    let _ = Text::with_text_style(
        stats.firmware,
        Point::new(CENTER_X, Y_TITLE),
        title_style,
        embedded_graphics::text::TextStyleBuilder::new()
            .alignment(Alignment::Center)
            .baseline(Baseline::Bottom)
            .build(),
    )
    .draw(display);

    let _ = Text::with_text_style(
        super::NAME,
        Point::new(CENTER_X, Y_BOARD),
        board_style,
        embedded_graphics::text::TextStyleBuilder::new()
            .alignment(Alignment::Center)
            .baseline(Baseline::Bottom)
            .build(),
    )
    .draw(display);

    let _ = Text::with_text_style(
        stats.algorithm,
        Point::new(CENTER_X, Y_ALG),
        value_style,
        embedded_graphics::text::TextStyleBuilder::new()
            .alignment(Alignment::Center)
            .baseline(Baseline::Bottom)
            .build(),
    )
    .draw(display);

    let _ = Text::with_text_style(
        "Serial",
        Point::new(CENTER_X, Y_SERIAL_LABEL),
        label_style,
        embedded_graphics::text::TextStyleBuilder::new()
            .alignment(Alignment::Center)
            .baseline(Baseline::Bottom)
            .build(),
    )
    .draw(display);

    let _ = Text::with_text_style(
        stats.serial,
        Point::new(CENTER_X, Y_SERIAL_VALUE),
        value_style,
        embedded_graphics::text::TextStyleBuilder::new()
            .alignment(Alignment::Center)
            .baseline(Baseline::Bottom)
            .build(),
    )
    .draw(display);
}

/// Diff against the cached state and redraw any value lines whose
/// content has changed.
pub fn refresh(display: &mut Display, stats: &Stats<'_>, cached: &mut Cached) {
    let value_style = MonoTextStyle::new(&FONT_6X10, FG_VALUE);
    let good_style = MonoTextStyle::new(&FONT_6X10, FG_GOOD);
    let warn_style = MonoTextStyle::new(&FONT_6X10, FG_WARN);

    let centered = || {
        embedded_graphics::text::TextStyleBuilder::new()
            .alignment(Alignment::Center)
            .baseline(Baseline::Bottom)
            .build()
    };

    // PIN line.
    if cached.pin_set != stats.pin_set || cached.pin_retries != stats.pin_retries {
        cached.pin_set = stats.pin_set;
        cached.pin_retries = stats.pin_retries;
        clear_centered_row(display, Y_PIN, SAFE_W_WIDE);
        let mut buf: String = String::new();
        if stats.pin_set {
            let _ = write!(buf, "PIN: set ({}/8)", stats.pin_retries);
            let style = if stats.pin_retries >= 3 {
                good_style
            } else {
                warn_style
            };
            let _ = Text::with_text_style(&buf, Point::new(CENTER_X, Y_PIN), style, centered())
                .draw(display);
        } else {
            let _ = Text::with_text_style(
                "PIN: not set",
                Point::new(CENTER_X, Y_PIN),
                warn_style,
                centered(),
            )
            .draw(display);
        }
    }

    // Creds line.
    if cached.resident_cred_count != stats.resident_cred_count {
        cached.resident_cred_count = stats.resident_cred_count;
        clear_centered_row(display, Y_CREDS, SAFE_W_WIDE);
        let mut buf: String = String::new();
        let _ = write!(buf, "Creds: {}", stats.resident_cred_count);
        let _ = Text::with_text_style(&buf, Point::new(CENTER_X, Y_CREDS), value_style, centered())
            .draw(display);
    }

    // Uptime line.
    if cached.uptime_secs != stats.uptime_secs {
        cached.uptime_secs = stats.uptime_secs;
        clear_centered_row(display, Y_UPTIME, SAFE_W_WIDE);
        let h = stats.uptime_secs / 3600;
        let m = (stats.uptime_secs / 60) % 60;
        let s = stats.uptime_secs % 60;
        let mut buf: String = String::new();
        let _ = write!(buf, "Up: {}:{:02}:{:02}", h, m, s);
        let _ = Text::with_text_style(
            &buf,
            Point::new(CENTER_X, Y_UPTIME),
            value_style,
            centered(),
        )
        .draw(display);
    }

    // Last-op line.
    if cached.last_op != stats.last_op {
        cached.last_op = stats.last_op;
        clear_centered_row(display, Y_LAST_OP, SAFE_W_NARROW);
        let text = stats.last_op.unwrap_or("(none)");
        let _ = Text::with_text_style(
            text,
            Point::new(CENTER_X, Y_LAST_OP),
            good_style,
            centered(),
        )
        .draw(display);
    }

    // Op-count line.
    if cached.op_count != stats.op_count {
        cached.op_count = stats.op_count;
        clear_centered_row(display, Y_OP_COUNT, SAFE_W_NARROW);
        let mut buf: String = String::new();
        let _ = write!(buf, "Ops: {}", stats.op_count);
        let _ = Text::with_text_style(
            &buf,
            Point::new(CENTER_X, Y_OP_COUNT),
            value_style,
            centered(),
        )
        .draw(display);
    }
}

/// Clear a horizontal row of width `w` centred on `CENTER_X` at the
/// given baseline `y`. The row covers (FONT_H + slack) px tall so
/// glyph descenders from a previous draw get fully wiped.
fn clear_centered_row(display: &mut Display, baseline_y: i32, w: u32) {
    let x = CENTER_X - (w as i32) / 2;
    let _ = Rectangle::new(Point::new(x, baseline_y - 10), Size::new(w, FONT_H + 2))
        .into_styled(PrimitiveStyle::with_fill(BG))
        .draw(display);
}
