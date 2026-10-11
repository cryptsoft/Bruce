// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Board-specific configuration -- one submodule per supported board.
//!
//! Each submodule defines a `Board` struct that owns the GPIO + state
//! for one particular RP2350 dev board's status LED(s) and any
//! board-quirk pins (such as the XIAO RP2350's WS2812 power-enable
//! that must be driven low for clean USB enumeration). The cfg
//! dispatch at the bottom of this file aliases the active submodule
//! as `board::*` so the rest of the firmware never has to use
//! `#[cfg(feature = "board_...")]` at LED / button call sites.
//!
//! ## Adding a new board
//!
//! Four steps, no edits to `main.rs` or `Cargo.lock` required:
//!
//! 1. Add a `board_<name> = []` line under `[features]` in
//!    `Cargo.toml`.
//! 2. Drop a new `src/board/<name>.rs` into this directory
//!    implementing the surface below. Decide `HAS_POWER_ON_BOOTSEL`
//!    from the hardware, not from the schematic's intent: `true` only
//!    if holding a button while plugging in has been SEEN to bring up
//!    the ROM bootloader on this board. If in doubt, `false`. A wrong
//!    `false` costs a `CTAPHID_CMD_REBOOT` that needs no touch; a wrong
//!    `true` on a board with a presence input gates the only way back
//!    into the bootloader on a touch, and one that never registers is
//!    a board that can never be reflashed (`reboot_policy.rs`).
//! 3. Add a `#[cfg(feature = "board_<name>")] mod <name>;` arm and
//!    a matching `pub use <name>::*;` arm at the bottom of this
//!    file. List the new feature in the "no board selected" guard
//!    and in every guard message, and add one pairwise
//!    `compile_error!` guard against each existing board.
//! 4. Add the board to `crates/firmware-hosttest/tests/reboot_policy.rs`
//!    (the `BOARDS` list and the two expectation tables), which reads
//!    the new module's consts from its source and fails until the
//!    board's reboot policy is written down there. `build.sh` needs the
//!    name in its board list too.
//!
//! A board that differs from an existing one only in its case or
//! identity (not its pins) re-exports that profile's `Board` instead of
//! copying it -- `feitian_rp2350_usbc.rs` is the example -- and
//! defines only its own consts.
//!
//! Document any board-specific quirks (USB power gate pins, weirdly-
//! wired BOOT buttons, alternative LED arrangements) in the
//! submodule's top doc-comment alongside the existing examples in
//! `tiny2350.rs` and `xiao_rp2350.rs`. The point of the submodule is
//! to be self-contained: a reader debugging a board issue should
//! find the schematic-level "why" in the same file as the pin
//! numbers.
//!
//! ## Interface contract
//!
//! Each submodule MUST expose:
//!
//! ```ignore
//! pub struct Board { /* board-specific fields */ }
//!
//! impl Board {
//!     /// Take ownership of the board-relevant subset of [`BoardSetup`],
//!     /// claim whatever pins / peripherals the board uses (LEDs,
//!     /// power-gate, button input, optional LCD bus + reset/DC pins),
//!     /// perform any one-time init (e.g. drive a power-gate pin
//!     /// low, ST7789 init sequence), and return the configured
//!     /// `Board`. Called exactly once from `main`, before USB
//!     /// enumeration. Boards that don't use the optional fields
//!     /// (SPI bus, RESETS, timer) simply drop them.
//!     pub fn setup(setup: BoardSetup<'_>) -> Self;
//!
//!     /// Logical LED channel control. Three independent channels
//!     /// (`r` = crypto-in-flight, `g` = user-presence wait + wink,
//!     /// `b` = idle heartbeat). Boards with a single physical LED
//!     /// OR-merge the channels onto it. Boards with NO LED
//!     /// (currently: Waveshare RP2350-LCD-1.47, until we add a
//!     /// PIO-driven WS2812 path) implement these as no-ops.
//!     pub fn r_on(&mut self);
//!     pub fn r_off(&mut self);
//!     pub fn g_on(&mut self);
//!     pub fn g_off(&mut self);
//!     pub fn b_on(&mut self);
//!     pub fn b_off(&mut self);
//!
//!     /// User-presence button state. Returns `true` if a button is
//!     /// currently pressed; `false` if no button is wired or none
//!     /// pressed. Boards that also export `HAS_USER_BUTTON = true`
//!     /// have this polled by `main.rs`'s `WaitForUp` gates as the
//!     /// real CTAP presence check. Currently: the Feitian RP2350 and
//!     /// the Tiny 2350, both through their BOOT button sampled on the
//!     /// QSPI chip-select line (see `bootsel.rs`), and the RP2350
//!     /// USB-C token's touch pad through the same sampler; the Tiny
//!     /// also accepts an external GP0 touch input with boot-time
//!     /// polarity auto-detection. On
//!     /// `HAS_USER_BUTTON = false` boards `WaitForUp` auto-confirms
//!     /// after a 500 ms LED-blink stub and this method exists only
//!     /// to keep the interface uniform.
//!     pub fn user_present(&mut self) -> bool;
//!
//!     /// Periodic callback for boards with display panels or other
//!     /// peripherals that benefit from regular refresh. Called from
//!     /// the main loop on every iteration with the current device
//!     /// stats snapshot -- implementations are expected to throttle
//!     /// internally (the Waveshare board profile redraws the LCD
//!     /// at ~5 Hz; Tiny / XIAO have no display so their `tick` is
//!     /// a no-op). The `Stats` reference is borrowed across the
//!     /// call, so implementations MUST NOT retain it.
//!     pub fn tick(&mut self, stats: &Stats);
//! }
//!
//! /// Human-readable board name; used in some log / panic surfaces.
//! pub const NAME: &'static str;
//!
//! /// USB product string advertised in the device descriptor
//! /// (`main.rs` passes it to `UsbDeviceBuilder`). Keep it short --
//! /// this is what host UIs (Chrome, fido2-token -L) show for the
//! /// authenticator.
//! pub const USB_PRODUCT: &'static str;
//!
//! /// Whether the board wires a firmware-readable user-presence
//! /// button. `true` -> `main.rs`'s `WaitForUp` gates block on a
//! /// real `user_present()` gesture; `false` -> auto-confirm stub.
//! pub const HAS_USER_BUTTON: bool;
//!
//! /// Whether the board has a physical way into the RP2350 ROM
//! /// bootloader at power-on: a BOOT / BOOTSEL button you can hold
//! /// while plugging it in. `true` on every dev board; `false` on the
//! /// sealed Feitian RP2350 USB-C token, whose only route back into the
//! /// bootloader is the host-issued `CTAPHID_CMD_REBOOT`. With
//! /// `HAS_USER_BUTTON` it decides whether that command waits for a
//! /// touch (`reboot_policy.rs`): only a board with BOTH may gate it,
//! /// because only there does a gate that fails to register cost a
//! /// replug with the button held rather than the board. FIDO presence
//! /// does not read this.
//! pub const HAS_POWER_ON_BOOTSEL: bool;
//!
//! /// picotool program-feature string `pqf-board=<board id>`, the
//! /// board id being the cargo feature name minus `board_`. With the
//! /// `pqf-reboot=` / `pqf-fido-up=` entries `main.rs` derives from
//! /// the consts above, it lets `picotool info -a <file.uf2>` say
//! /// which board an image is for and what its presence policies are
//! /// BEFORE it is flashed -- which, on a board with no power-on
//! /// BOOTSEL, is the only time the answer can still help.
//! pub const BI_BOARD: &'static CStr;
//!
//! /// picotool program description, naming the board:
//! /// `Hybrid PQC FIDO2 authenticator on RP2350 (<board>)`.
//! pub const BI_DESCRIPTION: &'static CStr;
//! ```
//!
//! Adhere to the surface exactly (same method names, same
//! signatures, same `Board` and `NAME` exports) and `main.rs` will
//! work unchanged.

use crate::hal;

/// The `Timer<D>` flavour we use across the whole firmware. RP2350
/// has two hardware timers; we use `timer0`. The `CopyableTimer0`
/// witness makes the wrapper `Copy` + `Clone` so we can pass it by
/// value into the board profile without losing access in `main`.
pub type Timer = hal::Timer<hal::timer::CopyableTimer0>;

/// Bundle of board-init resources passed once from `main` into the
/// active board profile's [`Board::setup`].
///
/// Boards that need only a few of these fields drop the rest. Tiny
/// 2350 and XIAO RP2350 only use `pins`; the Waveshare RP2350-LCD-
/// 1.47 also uses `spi0`, `resets`, `peripheral_clock_freq`, and
/// `timer` to bring up the ST7789V2 LCD (the Spotpear LCD board uses
/// `spi1` instead).
// Which of these a build reads depends on the board feature: the LCD
// boards take the SPI blocks, the button boards take none of them.
#[allow(dead_code)]
pub struct BoardSetup<'a> {
    /// Every bank-0 pin a board profile may claim. This is
    /// `hal::gpio::Pins` minus the QW/ST pair the optional QRNG bus takes
    /// before the board sees them (GP12/GP13 -- see [`BoardPins::split`]);
    /// field names and types are the HAL's, so a profile written against
    /// `Pins` compiles unchanged. The Spotpear board keeps GP12/GP13 (its
    /// LCD reset is GP12) and gets no QRNG.
    pub pins: BoardPins,
    /// SPI0 peripheral. Used by the Waveshare RP2350-LCD-1.47 board
    /// to drive its on-board ST7789V2 LCD (GP18 SCK / GP19 MOSI per
    /// Waveshare's reference design). Tiny 2350 and XIAO RP2350
    /// drop this field; other future boards with LCDs / displays
    /// on SPI0 would claim it here.
    pub spi0: hal::pac::SPI0,
    /// SPI1 peripheral. Used by the Spotpear RP2350-LCD-1.28 board to
    /// drive its GC9A01 round LCD (GP10 SCK / GP11 MOSI); the Waveshare
    /// board uses SPI0 instead and leaves this idle. Tiny 2350 and XIAO
    /// RP2350 drop this field.
    pub spi1: hal::pac::SPI1,
    /// Reset/enable controller used by `Spi::init`. Borrowed for the
    /// duration of `Board::setup` so the caller can keep using it
    /// afterwards if it wants (we don't, currently -- `main.rs`
    /// hands it over for good).
    pub resets: &'a mut hal::pac::RESETS,
    pub peripheral_clock_freq: hal::fugit::HertzU32,
    /// Copyable timer handle -- `CopyableTimer0` lets us pass this by
    /// value (boards that need timing keep a copy; boards that
    /// don't just drop it). `main.rs` retains its own copy for the
    /// USB-poll loop's time tracking.
    pub timer: Timer,
}

/// Snapshot of device state worth showing on a board with a display
/// panel. Built fresh in `main.rs` on every loop iteration and
/// passed to [`Board::tick`].
///
/// Boards without a display (Tiny 2350, XIAO RP2350) ignore this
/// entirely -- their `tick` is a no-op. We pay the trivial cost of
/// constructing the struct (~16 stack bytes, all `&str` / numeric)
/// on every iteration regardless so that the dispatch stays uniform.
// Read only by the boards with a display; silenced for the rest.
#[allow(dead_code)]
pub struct Stats<'a> {
    /// Static build-time string identifying the firmware. Currently
    /// derived from `CARGO_PKG_NAME` + `CARGO_PKG_VERSION`.
    pub firmware: &'a str,
    /// Human-readable algorithm signature, e.g. "ML-DSA-87 + ES256"
    /// or "ML-DSA-65 + ES256 + Ed25519". Build-time constant --
    /// reflects this firmware's actual implemented algorithms, not
    /// the wider list advertised in `getInfo`.
    pub algorithm: &'a str,
    /// The randomized USB serial number this boot -- typically 8 hex
    /// characters from the TRNG, but the value is whatever `main.rs`
    /// has set on the USB descriptor.
    pub serial: &'a str,
    /// `true` if a clientPin has been set on the device.
    pub pin_set: bool,
    /// PIN retry counter (8 = full, 0 = locked, needs full power
    /// cycle + reset). Only meaningful when `pin_set` is true.
    pub pin_retries: u8,
    /// Count of resident (rk=true) credentials currently stored in
    /// flash. Updated as MakeCred adds creds, CredentialManagement
    /// deleteCredential removes them, and authenticatorReset wipes
    /// everything.
    pub resident_cred_count: u32,
    /// Most recent CTAP operation that completed, or `None` if none
    /// have run yet this boot. The string is a build-time constant
    /// per operation type (e.g. "register", "login", "reset"), not
    /// a heap-allocated message -- hence the `'static` rather than
    /// `'a` lifetime (the value is always a string literal).
    pub last_op: Option<&'static str>,
    /// Total count of CTAP operations completed this boot.
    pub op_count: u32,
    /// Uptime in seconds since boot. Wraps after ~136 years -- we'll
    /// take that risk.
    pub uptime_secs: u32,
    /// Diagnostic: the COSE alg ids the most-recent
    /// `authenticatorMakeCredential` request carried in its
    /// `pubKeyCredParams` field, after the browser's libfido2 (or
    /// equivalent) layer has done any filtering. Empty when no
    /// MakeCredential has run yet this boot. LCD-equipped boards
    /// render this so the user can see what algs the browser is
    /// actually forwarding to the authenticator -- useful for
    /// diagnosing Chrome-vs-Firefox alg-stripping differences.
    pub last_make_cred_algs: &'a [i64],
}

/// `hal::gpio::Pins` with the QRNG bus pins removed.
///
/// `hal::gpio::Pins` is one struct, and a board profile takes it by value,
/// so the pins the QRNG driver needs have to come out BEFORE the
/// board gets the rest -- a partial move would leave `Pins` unusable as a
/// whole. This is the remainder. The missing pair is the Tiny 2350's QW/ST
/// connector (SDA GP12, SCL GP13 = I2C0; `crate::qrng::hw` documents it).
/// The Spotpear RP2350-LCD-1.28 drives its LCD reset from GP12, so on
/// that board nothing is removed and `split` returns no QRNG pins: the
/// probe is skipped and the TRNG serves alone. Only RP2350A pins
/// (GP0-GP29) are carried: the package has no others, and the HAL's
/// GP30-47 fields are simply dropped.
macro_rules! board_pins {
    (@struct $($name:ident: $id:ident),*) => {
        // Which fields a build reads depends on the board profile; the
        // rest exist so the next profile can claim them.
        #[allow(dead_code)]
        pub struct BoardPins {
            $(pub $name: hal::gpio::Pin<
                hal::gpio::bank0::$id,
                <hal::gpio::bank0::$id as hal::gpio::DefaultTypeState>::Function,
                <hal::gpio::bank0::$id as hal::gpio::DefaultTypeState>::PullType,
            >,)*
        }
    };
    (with_qrng; $($name:ident: $id:ident),* $(,)?) => {
        board_pins!(@struct $($name: $id),*);
        impl BoardPins {
            /// Take the QW/ST pair out of the HAL's pin set; everything
            /// else goes to the board profile.
            pub fn split(p: hal::gpio::Pins) -> (Self, Option<crate::qrng::hw::Pins>) {
                let hal::gpio::Pins { $($name,)* gpio12, gpio13, .. } = p;
                (
                    Self { $($name,)* },
                    Some(crate::qrng::hw::Pins { sda: gpio12, scl: gpio13 }),
                )
            }
        }
    };
    (without_qrng; $($name:ident: $id:ident),* $(,)?) => {
        board_pins!(@struct $($name: $id),*);
        impl BoardPins {
            /// This board needs the QW/ST pins itself: no QRNG.
            pub fn split(p: hal::gpio::Pins) -> (Self, Option<crate::qrng::hw::Pins>) {
                let hal::gpio::Pins { $($name,)* .. } = p;
                (Self { $($name,)* }, None)
            }
        }
    };
}
#[cfg(not(feature = "board_spotpear_rp2350_lcd_1_28"))]
board_pins!(with_qrng;
    gpio0: Gpio0, gpio1: Gpio1, gpio2: Gpio2, gpio3: Gpio3, gpio4: Gpio4,
    gpio5: Gpio5, gpio6: Gpio6, gpio7: Gpio7, gpio8: Gpio8, gpio9: Gpio9,
    gpio10: Gpio10, gpio11: Gpio11, gpio14: Gpio14, gpio15: Gpio15,
    gpio16: Gpio16, gpio17: Gpio17, gpio18: Gpio18, gpio19: Gpio19, gpio20: Gpio20,
    gpio21: Gpio21, gpio22: Gpio22, gpio23: Gpio23, gpio24: Gpio24, gpio25: Gpio25,
    gpio26: Gpio26, gpio27: Gpio27, gpio28: Gpio28, gpio29: Gpio29,
);
#[cfg(feature = "board_spotpear_rp2350_lcd_1_28")]
board_pins!(without_qrng;
    gpio0: Gpio0, gpio1: Gpio1, gpio2: Gpio2, gpio3: Gpio3, gpio4: Gpio4,
    gpio5: Gpio5, gpio6: Gpio6, gpio7: Gpio7, gpio8: Gpio8, gpio9: Gpio9,
    gpio10: Gpio10, gpio11: Gpio11, gpio12: Gpio12, gpio13: Gpio13, gpio14: Gpio14,
    gpio15: Gpio15, gpio16: Gpio16, gpio17: Gpio17, gpio18: Gpio18, gpio19: Gpio19,
    gpio20: Gpio20, gpio21: Gpio21, gpio22: Gpio22, gpio23: Gpio23, gpio24: Gpio24,
    gpio25: Gpio25, gpio26: Gpio26, gpio27: Gpio27, gpio28: Gpio28, gpio29: Gpio29,
);

// ---------- Mutual-exclusion + must-pick-one guards ----------

// One-board guard. Enumerated six-way because Cargo doesn't have a
// clean "exactly one of" idiom. The pairwise mutex checks below
// catch the multi-feature case; this one catches "zero features".
#[cfg(not(any(
    feature = "board_tiny2350",
    feature = "board_xiao_rp2350",
    feature = "board_feitian_rp2350",
    feature = "board_feitian_rp2350_usbc",
    feature = "board_waveshare_rp2350_lcd_1_47",
    feature = "board_spotpear_rp2350_lcd_1_28",
)))]
compile_error!(
    "no board selected: enable exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);

// Pairwise mutual-exclusion checks. C(6,2) = 15 pairs. They name the
// actual mistake; without them the only errors would be "`USB_PRODUCT`
// is ambiguous" and the like, from two boards' glob re-exports below
// colliding at the use sites.
#[cfg(all(feature = "board_tiny2350", feature = "board_xiao_rp2350"))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(
    feature = "board_tiny2350",
    feature = "board_waveshare_rp2350_lcd_1_47"
))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(feature = "board_tiny2350", feature = "board_spotpear_rp2350_lcd_1_28"))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(
    feature = "board_xiao_rp2350",
    feature = "board_waveshare_rp2350_lcd_1_47"
))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(
    feature = "board_xiao_rp2350",
    feature = "board_spotpear_rp2350_lcd_1_28"
))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(
    feature = "board_waveshare_rp2350_lcd_1_47",
    feature = "board_spotpear_rp2350_lcd_1_28"
))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(feature = "board_feitian_rp2350", feature = "board_tiny2350"))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(feature = "board_feitian_rp2350", feature = "board_xiao_rp2350"))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(
    feature = "board_feitian_rp2350",
    feature = "board_waveshare_rp2350_lcd_1_47"
))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(
    feature = "board_feitian_rp2350",
    feature = "board_spotpear_rp2350_lcd_1_28"
))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(feature = "board_feitian_rp2350_usbc", feature = "board_tiny2350"))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(feature = "board_feitian_rp2350_usbc", feature = "board_xiao_rp2350"))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(
    feature = "board_feitian_rp2350_usbc",
    feature = "board_feitian_rp2350"
))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(
    feature = "board_feitian_rp2350_usbc",
    feature = "board_waveshare_rp2350_lcd_1_47"
))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);
#[cfg(all(
    feature = "board_feitian_rp2350_usbc",
    feature = "board_spotpear_rp2350_lcd_1_28"
))]
compile_error!(
    "multiple board features enabled: pick exactly one of `board_tiny2350`, `board_xiao_rp2350`, `board_feitian_rp2350`, `board_feitian_rp2350_usbc`, `board_waveshare_rp2350_lcd_1_47`, or `board_spotpear_rp2350_lcd_1_28`"
);

// ---------- Shared helpers ----------

// Runtime BOOTSEL-button sampling via the QSPI chip-select line
// (BSD-3-Clause derivation from pico-examples -- see the module doc
// and THIRD_PARTY.md). Compiled only for boards that use the BOOTSEL
// line for user presence -- the Feitian RP2350, its USB-C token (touch pad
// assumed on the same line) and the Tiny 2350; chip-level rather than
// board-level, so other boards whose BOOT button sits on QSPI_SS can
// adopt it by adding their feature here.
#[cfg(any(
    feature = "board_feitian_rp2350",
    feature = "board_feitian_rp2350_usbc",
    feature = "board_tiny2350",
))]
mod bootsel;

// ---------- Active-board cfg dispatch ----------

#[cfg(feature = "board_tiny2350")]
mod tiny2350;
#[cfg(feature = "board_tiny2350")]
pub use tiny2350::*;

#[cfg(feature = "board_xiao_rp2350")]
mod xiao_rp2350;
#[cfg(feature = "board_xiao_rp2350")]
pub use xiao_rp2350::*;

// Compiled for the USB-C token too, which re-exports this `Board`
// (same die, same pins, different case). There only `Board` is used,
// so the dev board's own consts are dead code by design.
#[cfg(any(
    feature = "board_feitian_rp2350",
    feature = "board_feitian_rp2350_usbc"
))]
#[cfg_attr(feature = "board_feitian_rp2350_usbc", allow(dead_code))]
mod feitian_rp2350;
#[cfg(feature = "board_feitian_rp2350")]
pub use feitian_rp2350::*;

#[cfg(feature = "board_feitian_rp2350_usbc")]
mod feitian_rp2350_usbc;
#[cfg(feature = "board_feitian_rp2350_usbc")]
pub use feitian_rp2350_usbc::*;

#[cfg(feature = "board_waveshare_rp2350_lcd_1_47")]
mod waveshare_rp2350_lcd_1_47;
#[cfg(feature = "board_waveshare_rp2350_lcd_1_47")]
pub use waveshare_rp2350_lcd_1_47::*;

#[cfg(feature = "board_spotpear_rp2350_lcd_1_28")]
mod spotpear_rp2350_lcd_1_28;
#[cfg(feature = "board_spotpear_rp2350_lcd_1_28")]
pub use spotpear_rp2350_lcd_1_28::*;
