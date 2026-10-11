// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Pimoroni Tiny 2350 ([product page][product]) -- a 22.9 x 18.2 mm
//! RP2350A dev board with an on-board common-anode RGB LED on GP18
//! (R), GP19 (G), GP20 (B) -- all active-low.
//!
//! **User presence = the BOOT button**, as on the Feitian. The button
//! is wired to **QSPI_SS**, the flash chip-select, not to a GPIO -- but
//! the line is sampleable at runtime by briefly floating the CS pad and
//! reading it through SIO's HI register bank: [`super::bootsel`], the
//! same sampler the Feitian profile uses, rate-limited here to one
//! sample per 2 ms with the cached level served in between. Held while
//! plugging in, the button still enters the bootloader; tapped at
//! runtime it is just a level the sampler reads.
//!
//! An external **touch/button input on GP0** is read as well, so a
//! TTP223 pad or a switch wired there keeps working: presence is
//! either input.
//!
//! ## GP0 polarity auto-detection
//!
//! Touch hardware comes in several flavours and hard-coding one broke
//! in the field: TTP223 modules ship push-pull active-HIGH by default
//! but are strappable to active-LOW, other modules are open-drain,
//! and a plain mechanical switch to GND has no driver at all. So
//! [`Board::setup`] probes the pin once at boot instead of assuming:
//!
//! 1. Wait ~500 ms for an attached module to finish its power-on
//!    calibration (TTP223 needs ~0.5 s before its output is valid;
//!    it must not be touched during that window).
//! 2. Sample GP0 with a pull-down, then again with a pull-up.
//! 3. Same reading under both pulls -> something push-pull is driving
//!    the pin. That level is "idle"; the opposite level is "touched".
//!    The pull is parked on the idle side so a later disconnect still
//!    reads idle rather than floating.
//! 4. Different readings (the pin just follows our pull) -> nothing
//!    drives the pin: a plain switch to GND, an open-drain module, or
//!    a disconnected/unpowered one. Configure pull-up and treat LOW
//!    as "touched" -- the only wiring that works without an external
//!    resistor.
//!
//! The verdict is shown on the RGB LED for ~400 ms at the end of
//! setup, before USB comes up:
//!
//! * **green** -- a driven (push-pull) module was found and its
//!   polarity learned; either TTP223 variant works.
//! * **red** -- the pin floats: assuming switch/open-drain to GND. If
//!   a powered touch module was expected, check its VCC/OUT wiring.
//!
//! While idle, `main.rs` additionally mirrors the live touch state
//! onto the red LED channel, so a touch is visible the moment the
//! firmware sees it -- wiring and polarity are verifiable without a
//! debugger.
//!
//! Caveats: don't touch the pad (or hold the button) while plugging
//! the board in, or the probe learns the touched level as "idle" and
//! inverts the polarity until the next power cycle -- the red mirror
//! makes that state obvious (red on while untouched). An open-drain
//! active-HIGH module is indistinguishable from a floating pin and
//! is not supported.
//!
//! [product]: https://shop.pimoroni.com/products/tiny-2350

use core::ffi::CStr;

use crate::hal;
use embedded_hal::digital::{InputPin, OutputPin};

/// LED pin (R) -- GP18, push-pull output, active-low.
type LedR = hal::gpio::Pin<
    hal::gpio::bank0::Gpio18,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;
/// LED pin (G) -- GP19, push-pull output, active-low.
type LedG = hal::gpio::Pin<
    hal::gpio::bank0::Gpio19,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;
/// LED pin (B) -- GP20, push-pull output, active-low.
type LedB = hal::gpio::Pin<
    hal::gpio::bank0::Gpio20,
    hal::gpio::FunctionSio<hal::gpio::SioOutput>,
    hal::gpio::PullDown,
>;
/// GP0 input, pull-up -- the idle-high configurations: active-LOW
/// driven modules, plain switch to GND, open-drain to GND.
type TouchPullUp = hal::gpio::Pin<
    hal::gpio::bank0::Gpio0,
    hal::gpio::FunctionSio<hal::gpio::SioInput>,
    hal::gpio::PullUp,
>;
/// GP0 input, pull-down -- the idle-low configuration: active-HIGH
/// driven modules (the TTP223 factory default).
type TouchPullDown = hal::gpio::Pin<
    hal::gpio::bank0::Gpio0,
    hal::gpio::FunctionSio<hal::gpio::SioInput>,
    hal::gpio::PullDown,
>;

/// The GP0 touch input in whichever pull configuration the boot-time
/// polarity probe settled on. Two typestate variants instead of a
/// dynamic-pull pin keeps everything in safe, obvious HAL calls.
enum TouchInput {
    PullUp(TouchPullUp),
    PullDown(TouchPullDown),
}

impl TouchInput {
    /// Raw pin level, pull-configuration-agnostic. GPIO reads are
    /// infallible on RP2350, so the `unwrap_or` arm is dead -- but it
    /// keeps the embedded-hal signature honest: on error, report
    /// `default` (callers pass the idle level, i.e. "not touched").
    fn is_high(&mut self, default: bool) -> bool {
        match self {
            TouchInput::PullUp(p) => p.is_high().unwrap_or(default),
            TouchInput::PullDown(p) => p.is_high().unwrap_or(default),
        }
    }
}

/// Minimum spacing between two BOOTSEL samples, in us. Each sample
/// blacks out flash for a few us with interrupts masked, so the
/// `WaitForUp` polling loop must not hammer it; 2 ms keeps the blackout
/// duty cycle around 1% while still giving the 20 ms debounce in
/// `main.rs` ten samples to count. Same figure as the Feitian profile.
const SAMPLE_INTERVAL_US: u64 = 2_000;

pub struct Board {
    led_r: LedR,
    led_g: LedG,
    led_b: LedB,
    touch: TouchInput,
    /// GP0 level the boot probe saw while untouched. A reading at the
    /// opposite level means "touched".
    touch_idle_high: bool,
    /// us timestamp source for the BOOTSEL sampler rate limit.
    timer: super::Timer,
    /// When the BOOTSEL line was last actually sampled.
    last_sample_us: u64,
    /// The level that sample returned; served between samples.
    last_pressed: bool,
}

impl Board {
    /// Take ownership of GP18/19/20 (RGB LED) and GP0 (touch input),
    /// initialise the LEDs to off (active-low: high), then run the
    /// GP0 polarity probe described in the module docs -- including
    /// its ~0.9 s of settle/verdict delays, which happen before USB
    /// enumeration and only cost boot latency. The BOOT button needs
    /// no pin setup: it lives on QSPI_SS, which the flash interface
    /// owns; the (Copy) timer handle is kept for its sampler's rate
    /// limit. The remaining [`BoardSetup`] fields (SPI0/1, RESETS,
    /// peripheral clock) are dropped -- Tiny 2350 has no display panel.
    pub fn setup(setup: super::BoardSetup<'_>) -> Self {
        let super::BoardSetup { pins, timer, .. } = setup;
        let mut led_r = pins.gpio18.into_push_pull_output();
        let mut led_g = pins.gpio19.into_push_pull_output();
        let mut led_b = pins.gpio20.into_push_pull_output();
        // active-low common-anode RGB: drive high to extinguish.
        let _ = led_r.set_high();
        let _ = led_g.set_high();
        let _ = led_b.set_high();

        // Busy-wait on the 1 MHz system timer. Nothing else is
        // running yet, so blocking is fine here.
        let wait_us = |us: u64| {
            let t0 = timer.get_counter().ticks();
            while timer.get_counter().ticks().saturating_sub(t0) < us {}
        };

        // --- GP0 polarity probe (see module docs) ---
        wait_us(500_000); // module power-on calibration window
        let mut probe = pins.gpio0.into_pull_down_input();
        wait_us(2_000); // let the pull settle before sampling
        let read_down = probe.is_high().unwrap_or(false);
        let mut probe = probe.into_pull_up_input();
        wait_us(2_000);
        let read_up = probe.is_high().unwrap_or(true);

        // Same level under opposing pulls -> a push-pull driver holds
        // the pin at its idle level. Divergent -> the pin floats.
        let driven = read_down == read_up;
        let (touch, touch_idle_high) = if driven {
            if read_up {
                (TouchInput::PullUp(probe), true)
            } else {
                (TouchInput::PullDown(probe.into_pull_down_input()), false)
            }
        } else {
            // Plain switch / open-drain to GND (or a dead module):
            // pull up, touched = LOW.
            (TouchInput::PullUp(probe), true)
        };

        // Probe verdict on the LED: green = driven module found,
        // red = floating pin (switch-to-GND assumed -- check module
        // wiring if a touch module was expected).
        if driven {
            let _ = led_g.set_low();
        } else {
            let _ = led_r.set_low();
        }
        wait_us(400_000);
        let _ = led_g.set_high();
        let _ = led_r.set_high();

        Self {
            led_r,
            led_g,
            led_b,
            touch,
            touch_idle_high,
            timer,
            last_sample_us: 0,
            last_pressed: false,
        }
    }

    // -------- LED channel API (active-low GPIO) ----------

    pub fn r_on(&mut self) {
        let _ = self.led_r.set_low();
    }
    pub fn r_off(&mut self) {
        let _ = self.led_r.set_high();
    }
    pub fn g_on(&mut self) {
        let _ = self.led_g.set_low();
    }
    pub fn g_off(&mut self) {
        let _ = self.led_g.set_high();
    }
    pub fn b_on(&mut self) {
        let _ = self.led_b.set_low();
    }
    pub fn b_off(&mut self) {
        let _ = self.led_b.set_high();
    }

    /// `true` while the BOOT button is pressed or the GP0 input is
    /// touched.
    ///
    /// The BOOT button (active-low on QSPI_SS) goes through the
    /// rate-limited sampler -- a fresh sample at most every
    /// [`SAMPLE_INTERVAL_US`], the cached level otherwise; see
    /// [`super::bootsel`] for the mechanism and its constraints. GP0 is
    /// read against the polarity the boot probe learned: touched means
    /// the opposite level from its idle one, which gives both TTP223
    /// variants, a plain switch to GND and open-drain modules the right
    /// sense.
    pub fn user_present(&mut self) -> bool {
        let now = self.timer.get_counter().ticks();
        if now.saturating_sub(self.last_sample_us) >= SAMPLE_INTERVAL_US {
            self.last_sample_us = now;
            self.last_pressed = super::bootsel::pressed();
        }
        let idle = self.touch_idle_high;
        self.last_pressed || self.touch.is_high(idle) != idle
    }

    /// No display panel on this board -- `tick` is a no-op. Stays
    /// optimised away in release builds.
    pub fn tick(&mut self, _stats: &super::Stats) {}
}

/// Human-readable board name. Part of the per-board interface
/// contract documented in `board/mod.rs`. Currently unused -- kept
/// for future log / panic surfaces that want to print which board
/// the firmware was built for. Suppresses the `dead_code` warning
/// at the module level rather than at every call site.
#[allow(dead_code)]
pub const NAME: &str = "Pimoroni Tiny 2350";

/// USB product string for this board's build. Unchanged from the
/// pre-`USB_PRODUCT` firmware, which hardcoded this board's name for
/// every build -- hosts that have seen a Tiny keep seeing the same
/// product string.
pub const USB_PRODUCT: &str = "Tiny 2350 PQC";

/// The BOOT button doubles as a firmware-readable user-presence button
/// via the QSPI chip-select sampling in [`super::bootsel`] (and GP0
/// still counts), so `main.rs` enforces a real press gesture in the
/// CTAP `WaitForUp` gate rather than auto-confirming.
pub const HAS_USER_BUTTON: bool = true;

/// The BOOT button is also the bootrom's: held while plugging in, it
/// still enters the ROM bootloader (the bootrom senses QSPI_SS at
/// reset), so this board can always be reflashed by hand. That is what
/// lets `CTAPHID_CMD_REBOOT` stay touch-gated here by default -- a gate
/// the owner cannot satisfy costs a replug with the button held, not
/// the token (`reboot_policy.rs`).
pub const HAS_POWER_ON_BOOTSEL: bool = true;

/// picotool program feature naming this board, so `picotool info -a
/// <file.uf2>` identifies an image before it is flashed.
pub const BI_BOARD: &CStr = c"pqf-board=tiny2350";

/// picotool program description for this board's build.
pub const BI_DESCRIPTION: &CStr = c"Hybrid PQC FIDO2 authenticator on RP2350 (Pimoroni Tiny 2350)";
