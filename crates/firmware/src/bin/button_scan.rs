// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Hardware bring-up tool -- NOT part of the FIDO2 authenticator.
//!
//! Standalone diagnostic firmware for discovering whether a given
//! RP2350 board has a firmware-readable button/touch pad wired to
//! *any* spare GPIO, and if so which one. Written for the Feitian
//! RP2350 board (Pi Pico 2 reference design, GP25 active-high user
//! LED -- see `board::feitian_rp2350`), whose datasheet documents no
//! firmware-readable button, but the physical board may add one on
//! a pin the reference design leaves free.
//!
//! ## What it does
//!
//! Scans every GPIO the reference design doesn't already commit to a
//! defined role (see "Excluded pins" below) in ascending order
//! starting at GP0, learns each one's idle level the same way
//! `board::tiny2350` does for its GP0 touch input (sample under a
//! pull-down, then a pull-up; agreement = a driven pin, disagreement
//! = floating), then watches all of them continuously. The moment any
//! candidate departs from its learned idle level, the LED blinks out
//! that candidate's position in `GPIO_NUMBERS` (1 blink = the first
//! entry, GP0; 2 = the second, GP1; and so on -- see the table below,
//! there being no serial log on this board). While nothing is active,
//! the LED gives one short heartbeat blink every second so you know
//! the firmware is alive.
//!
//! ## Excluded pins
//!
//! GP23 (SMPS power-save, driven), GP24 (VBUS sense, driven), GP25
//! (the LED itself -- this firmware's own output), and GP29 (ADC3 /
//! VSYS-3 sense) are the reference design's committed pins per the
//! Pico 2 datasheet sec. 3.1 and are not scanned, both because they're
//! not candidates for a button and to avoid disturbing the on-board
//! power-management sensing while this runs.
//!
//! ## Usage
//!
//!   cargo build --release -p bruce --bin button_scan \
//!       --no-default-features --features board_feitian_rp2350
//!   picotool uf2 convert -t elf \
//!       target/thumbv8m.main-none-eabihf/release/button_scan \
//!       button_scan.uf2 --family rp2350-arm-s
//!   # BOOTSEL, then: ./wipe.sh && ./flash.sh button_scan.uf2
//!
//! Touch/press candidate points on the board one at a time and count
//! LED blinks against the table below. Reflash the real firmware
//! (`./build.sh feitian_rp2350`) when done -- this binary has no CTAP
//! surface at all.
//!
//! Blink count -> GPIO:
//!   1  GP0    7  GP6    13 GP12   19 GP18   25 GP26
//!   2  GP1    8  GP7    14 GP13   20 GP19   26 GP27
//!   3  GP2    9  GP8    15 GP14   21 GP20   27 GP28
//!   4  GP3    10 GP9    16 GP15   22 GP21
//!   5  GP4    11 GP10   17 GP16   23 GP22
//!   6  GP5    12 GP11   18 GP17

#![no_std]
#![no_main]

use embedded_hal::digital::{InputPin, OutputPin};
use panic_halt as _;
use rp235x_hal as hal;

use hal::gpio::{DynPinId, FunctionSio, Pin, PullUp, SioInput};

const XTAL_FREQ_HZ: u32 = 12_000_000;

#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

#[link_section = ".bi_entries"]
#[used]
pub static PICOTOOL_ENTRIES: [hal::binary_info::EntryAddr; 2] = [
    hal::binary_info::rp_cargo_bin_name!(),
    hal::binary_info::rp_program_description!(
        c"GPIO button-scan bring-up tool (not FIDO firmware)"
    ),
];

/// Number of candidate GPIOs scanned -- must match the literal count
/// in `main`'s pin array below (compiler enforces it: the array
/// literal's inferred length has to unify with this const).
const N: usize = 26;

/// Physical GPIO number for each position in the scan order, kept in
/// lockstep with the pin array below purely for documentation /
/// future console output -- the LED feedback itself only encodes the
/// position, not this table (see the module doc's blink-count key).
#[allow(dead_code)]
const GPIO_NUMBERS: [u8; N] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 26, 27, 28,
];

#[hal::entry]
fn main() -> ! {
    let mut pac = hal::pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);

    let clocks = hal::clocks::init_clocks_and_plls(
        XTAL_FREQ_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .unwrap();

    let timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);
    let wait_us = |us: u64| {
        let t0 = timer.get_counter().ticks();
        while timer.get_counter().ticks().saturating_sub(t0) < us {}
    };

    let sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );

    // GP25 -- user LED, active-HIGH (Feitian / Pico 2 reference design).
    let mut led = pins.gpio25.into_push_pull_output();
    let _ = led.set_low();

    // Power-on settle window: a driven touch module needs time to
    // finish its own calibration before its output means anything.
    wait_us(500_000);

    // Every GPIO the reference design leaves free, ascending from
    // GP0 (see the module doc for the excluded set and the
    // rationale). `into_dyn_pin()` erases each pin's distinct
    // compile-time ID so they can share one array element type;
    // `try_into_function` moves each into a plain SIO input at
    // runtime (infallible here -- SIO input is valid on every one of
    // these pins) starting in the reset default pull (pull-down).
    let inputs: [Pin<DynPinId, FunctionSio<SioInput>, hal::gpio::PullDown>; N] = [
        pins.gpio0.into_dyn_pin(),
        pins.gpio1.into_dyn_pin(),
        pins.gpio2.into_dyn_pin(),
        pins.gpio3.into_dyn_pin(),
        pins.gpio4.into_dyn_pin(),
        pins.gpio5.into_dyn_pin(),
        pins.gpio6.into_dyn_pin(),
        pins.gpio7.into_dyn_pin(),
        pins.gpio8.into_dyn_pin(),
        pins.gpio9.into_dyn_pin(),
        pins.gpio10.into_dyn_pin(),
        pins.gpio11.into_dyn_pin(),
        pins.gpio12.into_dyn_pin(),
        pins.gpio13.into_dyn_pin(),
        pins.gpio14.into_dyn_pin(),
        pins.gpio15.into_dyn_pin(),
        pins.gpio16.into_dyn_pin(),
        pins.gpio17.into_dyn_pin(),
        pins.gpio18.into_dyn_pin(),
        pins.gpio19.into_dyn_pin(),
        pins.gpio20.into_dyn_pin(),
        pins.gpio21.into_dyn_pin(),
        pins.gpio22.into_dyn_pin(),
        pins.gpio26.into_dyn_pin(),
        pins.gpio27.into_dyn_pin(),
        pins.gpio28.into_dyn_pin(),
    ]
    .map(|p| {
        p.try_into_function::<FunctionSio<SioInput>>()
            .unwrap_or_else(|_| panic!("SIO input must be valid on every scanned pin"))
    });

    // Per-pin idle-polarity probe (same technique as `board::tiny2350`):
    // sample under the current pull-down, then flip to a pull-up and
    // sample again. Agreement between the two means a push-pull
    // driver holds the pin at that level regardless of our pull -- a
    // weak (~50-80kOhm) pull can't fight a driven output, so this is
    // safe on every polarity including a plain switch to GND. That
    // agreed level is "idle"; disagreement means nothing drives the
    // pin (a floating/unpopulated pad), and it's parked pulled-up
    // with idle = HIGH, the only reading a floating pin gives safely.
    //
    // Every candidate ends up parked pull-up regardless of outcome:
    // for a driven pin the weak pull doesn't change what we read, so
    // there's no need to track two different final pull types. Each
    // pin is paired with its learned idle level in one array -- `.map`
    // moves each element through by value, so there's no placeholder
    // / uninitialised state at any point.
    let mut candidates: [(Pin<DynPinId, FunctionSio<SioInput>, PullUp>, bool); N] =
        inputs.map(|mut input| {
            wait_us(2_000);
            let read_down = input.is_high().unwrap_or(false);
            let mut input = input.into_pull_type::<PullUp>();
            wait_us(2_000);
            let read_up = input.is_high().unwrap_or(true);
            let driven = read_down == read_up;
            let idle_high = if driven { read_up } else { true };
            (input, idle_high)
        });

    let mut last_heartbeat = timer.get_counter().ticks();
    loop {
        let mut found: Option<usize> = None;
        for (i, (pin, idle_high)) in candidates.iter_mut().enumerate() {
            let level_high = pin.is_high().unwrap_or(*idle_high);
            if level_high != *idle_high {
                found = Some(i);
                break;
            }
        }

        match found {
            Some(i) => {
                for _ in 0..=i {
                    let _ = led.set_high();
                    wait_us(150_000);
                    let _ = led.set_low();
                    wait_us(150_000);
                }
                wait_us(700_000);
            }
            None => {
                let now = timer.get_counter().ticks();
                if now.saturating_sub(last_heartbeat) >= 1_000_000 {
                    last_heartbeat = now;
                    let _ = led.set_high();
                    wait_us(30_000);
                    let _ = led.set_low();
                }
            }
        }
    }
}
