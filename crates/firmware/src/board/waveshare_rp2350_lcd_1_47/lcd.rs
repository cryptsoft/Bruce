// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! ST7789V2 / V3 LCD driver wiring for the Waveshare RP2350-LCD-1.47.
//!
//! Panel: 1.47" IPS, 172 x 320 pixels, 262 K colours (RGB565 on the
//! wire), ST7789-family controller.
//!
//! Pin map per Waveshare's reference C demo
//! (DrJonEA/RP2350LCDProbe/lib/Config/DEV_Config.h, copied from the
//! Waveshare-supplied driver bundle). Identical across the A, B,
//! and B-M variants of this board -- only the USB connector and pin
//! headers differ between them.
//!
//! | Pin   | Function                          | SPI peripheral |
//! | ---   | ---                               | ---            |
//! | GP16  | LCD_DC (data / command select)    | --              |
//! | GP17  | LCD_CS (chip select, active-low)  | --              |
//! | GP18  | LCD_SCK (SPI clock)               | SPI0 SCK       |
//! | GP19  | LCD_MOSI (SPI MOSI / DIN)         | SPI0 TX        |
//! | GP20  | LCD_RST (panel reset, active-low) | --              |
//! | GP21  | LCD_BL (backlight, active-high)   | --              |
//!
//! Note that CS is a plain GPIO (not the SPI peripheral's hardware
//! CSn) -- `ExclusiveDevice` toggles it in software around each
//! transaction. We don't use MISO; the ST7789 is write-only as far
//! as this firmware is concerned. We also don't PWM the backlight;
//! GP21 is driven high once at boot to turn the panel on and stays
//! on for the lifetime of the firmware.
//!
//! The 172 x 320 panel maps onto the ST7789's 240 x 320 internal
//! framebuffer with a (34, 0) X-offset (so X coordinates 0-171 on
//! the panel are columns 34-205 in the controller). `mipidsi`'s
//! `display_offset` builder method handles this. Rotation is left
//! at 0 deg (portrait, USB connector at the bottom). Color inversion
//! ON (INVON, ST7789 cmd 0x21) is required -- without it the panel
//! still lights but renders the bitwise complement of every pixel,
//! which on a near-black background looks blank-with-light-text.

extern crate alloc;

use alloc::string::String;

use core::fmt::Write;

use embedded_graphics::mono_font::ascii::FONT_10X20;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{PrimitiveStyle, Rectangle};
use embedded_graphics::text::{Baseline, Text};
use embedded_hal::digital::OutputPin;
use embedded_hal_bus::spi::ExclusiveDevice;
use mipidsi::interface::SpiInterface;
use mipidsi::models::ST7789;
use mipidsi::options::{ColorInversion, Orientation, Rotation};
use mipidsi::Builder;

/// Static buffer mipidsi's `SpiInterface` uses to batch SPI writes.
/// Bigger = faster bulk drawing (full-screen clears, pixel-blocks
/// for `embedded_graphics` primitive fills). 2 KiB is comfortable
/// headroom for our worst case (~5 KB-equivalent text + clears per
/// `paint_initial`) without crowding the 256 KiB heap.
static mut LCD_SPI_BUFFER: [u8; 2048] = [0; 2048];

use crate::board::Stats;
use crate::hal;
use crate::hal::fugit::RateExtU32;
use crate::mldsa_alg::{COSE_ALG_MLDSA44_ES256, COSE_ALG_MLDSA65_ES256, COSE_ALG_MLDSA87_ES384};

// ---------- Per-pin type aliases ----------

type SpiSck = hal::gpio::Pin<hal::gpio::bank0::Gpio18, hal::gpio::FunctionSpi, hal::gpio::PullNone>;
type SpiMosi =
    hal::gpio::Pin<hal::gpio::bank0::Gpio19, hal::gpio::FunctionSpi, hal::gpio::PullNone>;
type PinCs = hal::gpio::Pin<
    hal::gpio::bank0::Gpio17,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;
type PinDc = hal::gpio::Pin<
    hal::gpio::bank0::Gpio16,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;
type PinRst = hal::gpio::Pin<
    hal::gpio::bank0::Gpio20,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;
pub type PinBl = hal::gpio::Pin<
    hal::gpio::bank0::Gpio21,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;

// Concrete type of the configured SPI bus.
type SpiBus = hal::Spi<hal::spi::Enabled, hal::pac::SPI0, (SpiMosi, SpiSck), 8>;
// `ExclusiveDevice` wraps `SpiBus + CS` so `mipidsi` can treat it as
// a single-target SPI device. The delay parameter here is the
// rp235x-hal `Timer<CopyableTimer0>` -- owned by value (the
// `CopyableTimer0` witness makes it `Copy`).
type SpiDev = ExclusiveDevice<SpiBus, PinCs, super::super::Timer>;
type DisplayInterface = SpiInterface<'static, SpiDev, PinDc>;
/// Concrete display handle returned by [`build`].
pub type Display = mipidsi::Display<DisplayInterface, ST7789, PinRst>;

// ---------- Panel + drawing setup ----------

/// 172-wide panel needs an X-offset on the ST7789's 240-wide
/// internal framebuffer. Vertical stays at 0; horizontal centres
/// at (240 - 172) / 2 = 34.
const DISPLAY_OFFSET_X: u16 = 34;
const DISPLAY_OFFSET_Y: u16 = 0;
const DISPLAY_W: i32 = 172;
const DISPLAY_H: i32 = 320;

/// Build + initialise the LCD. Owns the SPI bus, the four control
/// pins (CS, DC, RST, BL), and the rp235x-hal `Timer` used as a
/// `DelayNs` source for `mipidsi`'s reset sequence + the
/// `ExclusiveDevice` wrapper. Returns the configured `Display`
/// and the backlight pin (which we drive high once and then keep
/// alive in the `Board` struct so it doesn't get reclaimed).
#[allow(clippy::too_many_arguments)]
pub fn build(
    spi0: hal::pac::SPI0,
    resets: &mut hal::pac::RESETS,
    peripheral_clock_freq: hal::fugit::HertzU32,
    sck: hal::gpio::Pin<hal::gpio::bank0::Gpio18, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    mosi: hal::gpio::Pin<hal::gpio::bank0::Gpio19, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    cs: hal::gpio::Pin<hal::gpio::bank0::Gpio17, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    dc: hal::gpio::Pin<hal::gpio::bank0::Gpio16, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    rst: hal::gpio::Pin<hal::gpio::bank0::Gpio20, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    bl: hal::gpio::Pin<hal::gpio::bank0::Gpio21, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    timer: super::super::Timer,
) -> (Display, PinBl) {
    // Reconfigure pins into their bus / GPIO functions.
    let sck: SpiSck = sck.reconfigure();
    let mosi: SpiMosi = mosi.reconfigure();
    let cs: PinCs = cs.into_push_pull_output();
    let dc: PinDc = dc.into_push_pull_output();
    let rst: PinRst = rst.into_push_pull_output();
    let mut bl: PinBl = bl.into_push_pull_output();

    // Backlight on. Active-high per the Waveshare reference driver
    // (DrJonEA/RP2350LCDProbe/lib/Config/DEV_Config.h calls
    // `gpio_put(LCD_BL_PIN, 1)` to enable the backlight). On this
    // board the BL pin gates a PNP / level-shifter to the LED
    // string; driving high lights the panel.
    let _ = bl.set_high();

    // SPI bus init on SPI0. 32 MHz is well within the ST7789's spec
    // (datasheet allows up to 62.5 MHz for write-only operation) and
    // comfortably below the RP2350 SSI's max. If you see drawing
    // artefacts, drop this to 16 MHz first before suspecting the
    // init sequence.
    let spi = hal::Spi::<_, _, _, 8>::new(spi0, (mosi, sck)).init(
        resets,
        peripheral_clock_freq,
        32u32.MHz(),
        embedded_hal::spi::MODE_0,
    );

    // Wrap (bus + CS + delay) for mipidsi. ExclusiveDevice does the
    // CS-toggling around each transaction so the bus is reusable
    // with other peripherals in principle (we don't share it). The
    // `Timer` here is `Copy`-able, so we hand it by value and the
    // caller still has its own copy.
    let spi_dev = ExclusiveDevice::new(spi, cs, timer).expect("SPI exclusive device init");

    // `mipidsi::interface::SpiInterface` separates the DC line from
    // the data stream so the ST7789 knows whether each byte is a
    // command or pixel/data. The `&'static mut [u8]` buffer is used
    // internally to batch SPI writes -- see `LCD_SPI_BUFFER` above.
    //
    // SAFETY: this is the only code path that touches
    // `LCD_SPI_BUFFER`, and `Board::setup` is called exactly once
    // from `main` before any concurrent CTAP work begins. After
    // setup returns, the `&'static mut` is owned by the `Display`
    // (and indirectly by the `Board` that owns the `Display`), so
    // no other reference to the buffer can exist.
    let buf: &'static mut [u8] = unsafe {
        #[allow(static_mut_refs)]
        &mut LCD_SPI_BUFFER
    };
    let di = SpiInterface::new(spi_dev, dc, buf);

    // Build + init the display. The (172, 320) physical size +
    // (34, 0) offset + ColorInversion::Inverted is the standard
    // recipe for the Waveshare 1.47" panel -- derived from their
    // micropython reference driver (which sets the equivalent
    // INVON command 0x21 after init). `mipidsi` needs a separate
    // `DelayNs` provider for the reset sequence; we hand it another
    // copy of the same timer.
    let mut init_delay = timer;
    let display = Builder::new(ST7789, di)
        .display_size(172, 320)
        .display_offset(DISPLAY_OFFSET_X, DISPLAY_OFFSET_Y)
        .orientation(Orientation::new().rotate(Rotation::Deg0))
        .invert_colors(ColorInversion::Inverted)
        .reset_pin(rst)
        .init(&mut init_delay)
        .expect("ST7789 init");

    (display, bl)
}

// ---------- Drawing: layout + redraw ----------

// Foreground colours we use. Rgb565 quantises to 16 bits, so these
// aren't perfectly matched to their RGB888 names -- close enough for
// status-text legibility.
const FG_TITLE: Rgb565 = Rgb565::new(0x1F, 0x3F, 0x1F); // white
const FG_LABEL: Rgb565 = Rgb565::new(0x1F, 0x3F, 0x1F); // white
const FG_VALUE: Rgb565 = Rgb565::new(0x1F, 0x2F, 0x00); // soft yellow
const FG_GOOD: Rgb565 = Rgb565::new(0x07, 0x3F, 0x07); // green
const FG_WARN: Rgb565 = Rgb565::new(0x1F, 0x1F, 0x07); // amber
const FG_ACCENT: Rgb565 = Rgb565::new(0x07, 0x2F, 0x1F); // cyan
const BG: Rgb565 = Rgb565::new(0x02, 0x04, 0x06); // near-black

// Layout coordinates. Y advances down the panel; X is the left margin.
const MARGIN_X: i32 = 4;
// Y baselines for each line, with `Baseline::Bottom` semantics -- a
// glyph drawn at `(_, Y)` occupies pixel rows `Y - h + 1 ..= Y`. All
// lines use FONT_10X20 (the largest stock embedded-graphics ASCII
// mono font). Glyph height is 20, line spacing is 22 within a
// section, 27 between sections so the user can visually group
// "label + value" pairs. 13 lines total fit comfortably in 320 px.
const TITLE_Y: i32 = 22; // first row.
const BOARD_Y: i32 = 47; // +25 (light gap after title).
const ALG_LABEL_Y: i32 = 78; // +31 (section break).
const ALG_VALUE_Y: i32 = 100; // +22.
const SERIAL_LABEL_Y: i32 = 131; // +31.
const SERIAL_VALUE_Y: i32 = 153;
const PIN_Y: i32 = 184; // +31.
const CREDS_Y: i32 = 206;
const UPTIME_Y: i32 = 228;
const LAST_OP_LABEL_Y: i32 = 259; // +31.
const LAST_OP_VALUE_Y: i32 = 281;
const OP_COUNT_Y: i32 = 303;
const FOOTER_Y: i32 = DISPLAY_H - 2;

// Value-line text spans -- pre-computed rectangles we clear before
// redrawing each changing field, so the new text doesn't overlap
// stale glyphs from the previous frame.
const VALUE_FIELD_W: u32 = (DISPLAY_W - MARGIN_X * 2) as u32;
// FONT_10X20 cell metrics (glyph + 1 row of inter-line spacing).
const FONT_H_10X20: u32 = 21;
// Glyph width for FONT_10X20 -- used to advance past label text when
// computing where the value text starts on the same line.
const GLYPH_W_10X20: i32 = 10;

/// Cached snapshot of the values currently shown on the LCD. The
/// `Board::tick` path compares this with the incoming `Stats` and
/// only redraws fields that changed. Saves a lot of SPI traffic
/// between frames where nothing's happening.
pub struct Cached {
    initialised: bool,
    pin_set: bool,
    pin_retries: u8,
    resident_cred_count: u32,
    op_count: u32,
    uptime_secs: u32,
    serial_drawn: bool,
    /// Snapshot of the last drawn `pubKeyCredParams` list, so the
    /// LCD only redraws when the contents actually change. `[i64; 8]`
    /// rather than `Vec<i64>` to avoid touching the heap on every
    /// frame; matches the on-device cap of 8 algs.
    last_algs: [i64; 8],
    last_alg_count: u8,
}

impl Cached {
    pub const fn empty() -> Self {
        // Numeric fields are seeded with sentinel values guaranteed
        // to differ from any real `Stats` reading, so `refresh()`'s
        // change-detection forces a draw on the very first refresh.
        // Without this, fields whose real value happens to be 0 at
        // boot (resident-cred count, op count, pin-retries when the
        // PIN is unset) would never appear -- the label would be
        // drawn by `paint_initial` but the value space next to it
        // would stay blank until the field's first real change.
        Self {
            initialised: false,
            // `pin_set` change-detection compares both `pin_set` and
            // `pin_retries`. Setting `pin_set` to `false` and
            // `pin_retries` to `u8::MAX` guarantees a mismatch on
            // the first refresh -- the retries-left value coming in
            // from the firmware is 0..=8.
            pin_set: false,
            pin_retries: u8::MAX,
            resident_cred_count: u32::MAX,
            op_count: u32::MAX,
            uptime_secs: u32::MAX,
            serial_drawn: false,
            // Sentinel: alg id 1 isn't a valid COSE alg (the registry
            // skips it), so any real `last_make_cred_algs` reading
            // will be different and trigger the first redraw.
            last_algs: [1i64; 8],
            last_alg_count: u8::MAX,
        }
    }

    /// `true` once `paint_initial` has been called and the static
    /// labels are on the panel. Used by `Board::tick` to decide
    /// whether to skip the throttling check (we always draw the
    /// initial frame, no matter when in the loop we first get
    /// called).
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }

    /// Flip the initialised flag after `paint_initial` returns.
    pub fn mark_initialised(&mut self) {
        self.initialised = true;
    }
}

/// One-time draw of the static + initial-dynamic content: title,
/// board name, algorithm, all labels, and the first values. Called
/// from `Board::setup` after the panel is initialised. The full
/// clear + redraw here is ~5-10 ms over SPI at 32 MHz; subsequent
/// per-field updates via [`refresh`] are sub-millisecond each.
pub fn paint_initial(display: &mut Display, stats: &Stats<'_>) {
    let _ = display.clear(BG);

    let title_style = MonoTextStyle::new(&FONT_10X20, FG_TITLE);
    let label_style = MonoTextStyle::new(&FONT_10X20, FG_LABEL);
    let value_style = MonoTextStyle::new(&FONT_10X20, FG_VALUE);
    let accent_style = MonoTextStyle::new(&FONT_10X20, FG_ACCENT);

    let _ = Text::with_baseline(
        stats.firmware,
        Point::new(MARGIN_X, TITLE_Y),
        title_style,
        Baseline::Bottom,
    )
    .draw(display);
    let _ = Text::with_baseline(
        super::NAME,
        Point::new(MARGIN_X, BOARD_Y),
        accent_style,
        Baseline::Bottom,
    )
    .draw(display);

    let _ = Text::with_baseline(
        "Algorithm",
        Point::new(MARGIN_X, ALG_LABEL_Y),
        label_style,
        Baseline::Bottom,
    )
    .draw(display);
    let _ = Text::with_baseline(
        stats.algorithm,
        Point::new(MARGIN_X, ALG_VALUE_Y),
        value_style,
        Baseline::Bottom,
    )
    .draw(display);

    let _ = Text::with_baseline(
        "USB serial",
        Point::new(MARGIN_X, SERIAL_LABEL_Y),
        label_style,
        Baseline::Bottom,
    )
    .draw(display);
    let _ = Text::with_baseline(
        stats.serial,
        Point::new(MARGIN_X, SERIAL_VALUE_Y),
        value_style,
        Baseline::Bottom,
    )
    .draw(display);

    // Labels for the dynamic lines (the values themselves go in via `refresh`).
    let _ = Text::with_baseline(
        "PIN:",
        Point::new(MARGIN_X, PIN_Y),
        label_style,
        Baseline::Bottom,
    )
    .draw(display);
    let _ = Text::with_baseline(
        "Creds:",
        Point::new(MARGIN_X, CREDS_Y),
        label_style,
        Baseline::Bottom,
    )
    .draw(display);
    let _ = Text::with_baseline(
        "Uptime:",
        Point::new(MARGIN_X, UPTIME_Y),
        label_style,
        Baseline::Bottom,
    )
    .draw(display);
    // Diagnostic line -- what `pubKeyCredParams` the browser actually
    // forwarded to the device during the last `authenticatorMakeCredential`.
    // Filled in by `refresh()` below.
    let _ = Text::with_baseline(
        "RP algs:",
        Point::new(MARGIN_X, LAST_OP_LABEL_Y),
        label_style,
        Baseline::Bottom,
    )
    .draw(display);
    let _ = Text::with_baseline(
        "Op count:",
        Point::new(MARGIN_X, OP_COUNT_Y),
        label_style,
        Baseline::Bottom,
    )
    .draw(display);

    // Footer -- a single line of cyan text near the bottom edge,
    // re-used as a "live" indicator (changes never; just a sanity
    // check that the LCD is connected).
    let _ = Text::with_baseline(
        "Bruce alive",
        Point::new(MARGIN_X, FOOTER_Y),
        accent_style,
        Baseline::Bottom,
    )
    .draw(display);
}

/// Diff against the cached state and redraw any value lines whose
/// content has changed. Each line is cleared (small filled rectangle
/// in `BG`) before the new text is drawn, so partial pixels from the
/// previous value can't leak through.
pub fn refresh(display: &mut Display, stats: &Stats<'_>, cached: &mut Cached) {
    let value_style = MonoTextStyle::new(&FONT_10X20, FG_VALUE);
    let good_style = MonoTextStyle::new(&FONT_10X20, FG_GOOD);
    let warn_style = MonoTextStyle::new(&FONT_10X20, FG_WARN);

    // Serial (drawn once on first refresh -- paint_initial already
    // wrote it, but if Stats.serial ever changes mid-boot we'd
    // catch it here).
    if !cached.serial_drawn {
        cached.serial_drawn = true;
    }

    // PIN line: "set (8/8)" or "not set".
    if cached.pin_set != stats.pin_set || cached.pin_retries != stats.pin_retries {
        cached.pin_set = stats.pin_set;
        cached.pin_retries = stats.pin_retries;
        let x = MARGIN_X + GLYPH_W_10X20 * 5; // after "PIN: "
        clear_value_field(display, x, PIN_Y);
        if stats.pin_set {
            let mut buf: String = String::new();
            let _ = write!(buf, "set ({}/8)", stats.pin_retries);
            let style = if stats.pin_retries >= 3 {
                good_style
            } else {
                warn_style
            };
            let _ = Text::with_baseline(&buf, Point::new(x, PIN_Y), style, Baseline::Bottom)
                .draw(display);
        } else {
            let _ = Text::with_baseline(
                "not set",
                Point::new(x, PIN_Y),
                warn_style,
                Baseline::Bottom,
            )
            .draw(display);
        }
    }

    // Creds line.
    if cached.resident_cred_count != stats.resident_cred_count {
        cached.resident_cred_count = stats.resident_cred_count;
        let x = MARGIN_X + GLYPH_W_10X20 * 7; // after "Creds: "
        clear_value_field(display, x, CREDS_Y);
        let mut buf: String = String::new();
        let _ = write!(buf, "{}", stats.resident_cred_count);
        let _ = Text::with_baseline(&buf, Point::new(x, CREDS_Y), value_style, Baseline::Bottom)
            .draw(display);
    }

    // Uptime -- H:MM:SS.
    if cached.uptime_secs != stats.uptime_secs {
        cached.uptime_secs = stats.uptime_secs;
        let x = MARGIN_X + GLYPH_W_10X20 * 8; // after "Uptime: "
        clear_value_field(display, x, UPTIME_Y);
        let h = stats.uptime_secs / 3600;
        let m = (stats.uptime_secs / 60) % 60;
        let s = stats.uptime_secs % 60;
        let mut buf: String = String::new();
        let _ = write!(buf, "{}:{:02}:{:02}", h, m, s);
        let _ = Text::with_baseline(&buf, Point::new(x, UPTIME_Y), value_style, Baseline::Bottom)
            .draw(display);
    }

    // RP-algs value line -- the alg ids the browser forwarded with
    // the most recent MakeCredential. Compare the (count, contents)
    // pair against the cache; redraw on any change.
    let incoming_count = stats.last_make_cred_algs.len();
    let incoming: &[i64] = stats.last_make_cred_algs;
    let cached_count = cached.last_alg_count as usize;
    let differs = cached_count != incoming_count
        || cached.last_algs[..cached_count.min(8)] != incoming[..incoming_count.min(8)];
    if differs {
        // Update the cache snapshot.
        cached.last_alg_count = incoming_count.min(8) as u8;
        for i in 0..cached.last_alg_count as usize {
            cached.last_algs[i] = incoming[i];
        }
        clear_value_field(display, MARGIN_X, LAST_OP_VALUE_Y);
        let mut buf: String = String::new();
        if incoming.is_empty() {
            let _ = write!(buf, "(none yet)");
        } else {
            // Render up to 17 chars (FONT_10X20 cell count at
            // 172-px panel width). With 3-char negative numbers
            // ("-55") + 1 separator, 4 algs use 4*4 = 16 chars,
            // 5 algs would overflow -- truncate with a trailing
            // ellipsis if we run out of room.
            let mut first = true;
            for &a in incoming.iter() {
                let chunk: alloc::string::String = if first {
                    first = false;
                    let mut s = alloc::string::String::new();
                    let _ = write!(s, "{}", a);
                    s
                } else {
                    let mut s = alloc::string::String::from(" ");
                    let _ = write!(s, "{}", a);
                    s
                };
                if buf.len() + chunk.len() > 17 {
                    let _ = write!(buf, "..");
                    break;
                }
                buf.push_str(&chunk);
            }
        }
        // Green when the host offered any composite this firmware
        // family can mint (not only this build's level).
        let style = if incoming.iter().any(|&a| {
            a == COSE_ALG_MLDSA44_ES256
                || a == COSE_ALG_MLDSA65_ES256
                || a == COSE_ALG_MLDSA87_ES384
        }) {
            good_style
        } else {
            warn_style
        };
        let _ = Text::with_baseline(
            &buf,
            Point::new(MARGIN_X, LAST_OP_VALUE_Y),
            style,
            Baseline::Bottom,
        )
        .draw(display);
    }

    // Op-count line.
    if cached.op_count != stats.op_count {
        cached.op_count = stats.op_count;
        let x = MARGIN_X + GLYPH_W_10X20 * 10; // after "Op count: "
        clear_value_field(display, x, OP_COUNT_Y);
        let mut buf: String = String::new();
        let _ = write!(buf, "{}", stats.op_count);
        let _ = Text::with_baseline(
            &buf,
            Point::new(x, OP_COUNT_Y),
            value_style,
            Baseline::Bottom,
        )
        .draw(display);
    }
}

/// Clear a rectangular value field running from `(x, baseline_y-9)`
/// to the right margin, height = FONT_H + slack. Used before
/// redrawing a numeric / short-string value so stale digits don't
/// hang around.
fn clear_value_field(display: &mut Display, x: i32, baseline_y: i32) {
    let _ = Rectangle::new(
        Point::new(x, baseline_y - 19),
        Size::new(
            VALUE_FIELD_W.saturating_sub(x as u32 - MARGIN_X as u32),
            FONT_H_10X20 + 2,
        ),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(display);
    let _ = FONT_H_10X20; // referenced for symmetry with FONT_H_10X20; not used here.
}
