// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The user-presence gate, driven by a clock the test sets.
//!
//! The gate is a state machine over elapsed time -- a sample interval, a
//! ten-second window, and a validity period on a confirmation once it
//! exists. Against the board's free-running timer a test can only wait
//! and hope; here it can sit exactly on a boundary and check which side
//! the gate lands on.
//!
//! What this is *not*: proof that the sampler can see a finger. That
//! needs silicon, has been done, and stays done -- the note in
//! `TRUSTZONE.md` about a real press is not superseded by any of this.
//! What is testable here is everything between the sampler and the
//! answer, which is where the rules live.

use pqf_fw_secure_hosttest as fws;
use std::sync::{Mutex, MutexGuard};

use fws::upgate::{self, UP_CONFIRMED, UP_PENDING, UP_TIMEOUT};

static SERIAL: Mutex<()> = Mutex::new(());

const SAMPLE_US: u64 = 2_000;
const WINDOW_US: u64 = 10_000_000;
/// How long a confirmation stays spendable, mirroring `upgate::VALID_US`.
const VALID_US: u64 = 10_000_000;

fn fresh() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fws::fresh_die();
    reset_gate();
    g
}

/// Drain whatever a previous test left in the gate.
///
/// `upgate`'s state is a boot-lifetime static and there is no reset --
/// which is right on the token, where the only reset is a reboot, and
/// means the cleaning up has to happen here instead. Without this, a
/// confirmation or a queued injection from an earlier test leaks into the
/// next one, and the suite passes or fails depending on the order the
/// harness happens to run it in.
fn reset_gate() {
    let _ = upgate::consume();
    // A queued one-shot injection is only cleared by being taken, so open
    // a window with the button released and let it be taken.
    upgate::begin();
    rp235x_hal::set_pressed(false);
    for _ in 0..8 {
        rp235x_hal::advance_us(SAMPLE_US);
        let _ = upgate::poll();
    }
    let _ = upgate::consume();
    rp235x_hal::set_now_us(0);
}

/// Advance far enough that the next `poll` actually samples.
fn tick() -> u8 {
    rp235x_hal::advance_us(SAMPLE_US);
    upgate::poll()
}

fn press(down: bool) {
    rp235x_hal::set_pressed(down);
}

// ---- the basic contract ---------------------------------------------

#[test]
fn a_window_with_no_gesture_times_out() {
    let _g = fresh();
    upgate::begin();
    assert_eq!(
        upgate::poll(),
        UP_PENDING,
        "a fresh window is not immediately done"
    );
    rp235x_hal::advance_us(WINDOW_US + 1);
    assert_eq!(upgate::poll(), UP_TIMEOUT, "the window never closed");
}

#[test]
fn a_press_inside_the_window_confirms() {
    let _g = fresh();
    upgate::begin();
    tick(); // released
    press(true);
    assert_eq!(
        tick(),
        UP_CONFIRMED,
        "a press in an open window did not confirm"
    );
}

#[test]
fn a_confirmation_can_be_spent_exactly_once() {
    // The gate hands out one use. If `consume` were idempotent, a single
    // touch would authorise every operation that followed it.
    let _g = fresh();
    upgate::begin();
    tick();
    press(true);
    assert_eq!(tick(), UP_CONFIRMED);
    assert!(upgate::consume(), "the confirmation could not be spent");
    assert!(!upgate::consume(), "the same touch was spent twice");
}

#[test]
fn nothing_can_be_spent_without_a_gesture() {
    let _g = fresh();
    assert!(
        !upgate::consume(),
        "consume succeeded with no window at all"
    );
    upgate::begin();
    tick();
    assert!(!upgate::consume(), "consume succeeded on a pending window");
    rp235x_hal::advance_us(WINDOW_US + 1);
    assert_eq!(upgate::poll(), UP_TIMEOUT);
    assert!(
        !upgate::consume(),
        "consume succeeded on a timed-out window"
    );
}

// ---- the rule that stops a resting finger ---------------------------

#[test]
fn a_finger_already_on_the_pad_does_not_confirm() {
    // Release-then-press, not level. Otherwise anything resting on the
    // button -- a case, a pocket, a strap -- authorises every operation
    // the host asks for, with nobody present at all.
    let _g = fresh();
    press(true); // held before the window opens
    upgate::begin();
    for _ in 0..50 {
        assert_ne!(
            tick(),
            UP_CONFIRMED,
            "a button held from before the window confirmed"
        );
    }
    // Let go, press again: now it is a gesture.
    press(false);
    tick();
    press(true);
    assert_eq!(
        tick(),
        UP_CONFIRMED,
        "a real release-then-press was refused"
    );
}

#[test]
fn a_release_during_the_window_arms_the_next_press() {
    let _g = fresh();
    press(true);
    upgate::begin();
    tick();
    press(false);
    tick(); // the release is seen
    press(true);
    assert_eq!(tick(), UP_CONFIRMED);
}

// ---- windows do not bank ---------------------------------------------

#[test]
fn opening_a_window_discards_an_earlier_confirmation() {
    // A caller must not be able to collect a touch, sit on it, and spend
    // it against a later operation the user never saw.
    let _g = fresh();
    upgate::begin();
    tick();
    press(true);
    assert_eq!(tick(), UP_CONFIRMED);

    upgate::begin(); // second operation, no new gesture
    press(false);
    tick();
    assert_ne!(
        upgate::poll(),
        UP_CONFIRMED,
        "a touch banked from a previous window was spent on a new one"
    );
    assert!(
        !upgate::consume(),
        "the stale confirmation was still spendable"
    );
}

#[test]
fn a_timed_out_window_stays_timed_out() {
    // Once closed it must not reopen on a late press: the user has walked
    // away, and the host asking again is not the same as being present.
    let _g = fresh();
    upgate::begin();
    tick();
    rp235x_hal::advance_us(WINDOW_US + 1);
    assert_eq!(upgate::poll(), UP_TIMEOUT);
    press(true);
    for _ in 0..10 {
        assert_ne!(tick(), UP_CONFIRMED, "a press after the timeout confirmed");
    }
}

// ---- the boundaries themselves ---------------------------------------

#[test]
fn the_window_boundary_is_where_it_says_it_is() {
    // Just inside, still open. Just outside, closed. Worth pinning
    // because an off-by-one here is invisible in use and turns a
    // ten-second window into an indefinite one.
    let _g = fresh();
    upgate::begin();
    rp235x_hal::advance_us(WINDOW_US);
    assert_ne!(
        upgate::poll(),
        UP_TIMEOUT,
        "the window closed at exactly WINDOW_US"
    );

    fws::fresh_die();
    reset_gate();
    upgate::begin();
    rp235x_hal::advance_us(WINDOW_US + 1);
    assert_eq!(upgate::poll(), UP_TIMEOUT, "the window outlived WINDOW_US");
}

#[test]
fn polling_faster_than_the_sample_interval_does_not_sample() {
    // The gate rate-limits itself: each sample floats the QSPI chip
    // select, and doing that as fast as a caller can loop would be a
    // great deal of chip-select traffic for no extra fidelity.
    let _g = fresh();
    upgate::begin();
    tick(); // establishes release
    press(true);
    // Advance less than one interval: no sample, so no confirmation yet.
    rp235x_hal::advance_us(SAMPLE_US - 1);
    assert_eq!(
        upgate::poll(),
        UP_PENDING,
        "the gate sampled sooner than SAMPLE_INTERVAL_US"
    );
    // Cross the interval and it does.
    rp235x_hal::advance_us(2);
    assert_eq!(upgate::poll(), UP_CONFIRMED);
}

#[test]
fn a_press_shorter_than_one_sample_interval_can_be_missed() {
    // Not a defect, and worth writing down so it is not mistaken for one:
    // sampling at 2 ms cannot see a 1 ms press. The gesture a human makes
    // is three orders of magnitude longer. A test that asserted the
    // opposite would be asserting that the rate limit does not exist.
    let _g = fresh();
    upgate::begin();
    tick();
    press(true);
    rp235x_hal::advance_us(SAMPLE_US / 4);
    press(false);
    rp235x_hal::advance_us(SAMPLE_US);
    assert_ne!(
        upgate::poll(),
        UP_CONFIRMED,
        "a press far shorter than the sample interval was somehow seen"
    );
}

// ---- the injected gesture --------------------------------------------

#[test]
fn an_injected_gesture_confirms_exactly_one_window() {
    // The test hook is a one-shot rather than a level, so a harness
    // cannot arm it once and have every later window confirm itself.
    let _g = fresh();
    upgate::inject_press();
    upgate::begin();
    tick();
    assert_eq!(tick(), UP_CONFIRMED, "an injected gesture did not confirm");
    assert!(upgate::consume());

    upgate::begin();
    tick();
    for _ in 0..10 {
        assert_ne!(
            tick(),
            UP_CONFIRMED,
            "one injection confirmed a second window"
        );
    }
}

#[test]
fn an_injection_still_requires_the_window_to_be_open() {
    let _g = fresh();
    upgate::inject_press();
    // No begin(): nothing is open.
    for _ in 0..10 {
        assert_ne!(
            tick(),
            UP_CONFIRMED,
            "an injection confirmed with no window open"
        );
    }
    assert!(!upgate::consume());
}

// ---- the clock going backwards, and the validity boundary ------------
//
// Mutation testing found five lines in upgate.rs that no test here
// constrained: the three `saturating_sub`s and the `<=` in `consume`.
// They are all about what happens when the clock does something
// unexpected, which is the case nobody writes a test for because it does
// not happen on a bench.
//
// It can happen on a token. TIMER0 is 64 bits assembled from two 32-bit
// reads, latched low-then-high; a bug in that assembly, a counter reset,
// or a resume from a low-power state can all produce a `now` earlier
// than a timestamp already recorded. With `saturating_sub` that reads as
// "no time has passed". With plain subtraction it underflows to roughly
// 2^64 microseconds, and every comparison in the gate flips: a window
// that just opened looks expired, a sample interval never elapses, and a
// confirmation from a moment ago looks ancient.

#[test]
fn a_clock_that_goes_backwards_does_not_expire_an_open_window() {
    // `t - started_us > WINDOW_US` with the subtraction wrapping makes a
    // fresh window look ten thousand years old, so the gate answers
    // TIMEOUT to a user whose finger is on its way to the button.
    let _g = fresh();
    // Start well past zero: rewinding to 0 from a window that also
    // started at 0 subtracts nothing, and the underflow this is about
    // never happens.
    rp235x_hal::set_now_us(5_000_000);
    upgate::begin();
    press(false);
    rp235x_hal::advance_us(SAMPLE_US * 4);
    assert_eq!(upgate::poll(), UP_PENDING, "the window did not open");

    // The clock jumps back to before the window started.
    rp235x_hal::set_now_us(0);
    assert_eq!(
        upgate::poll(),
        UP_PENDING,
        "a backwards clock expired a window that had just opened"
    );
}

#[test]
fn a_rewound_clock_freezes_the_gate_rather_than_confirming_or_timing_out() {
    // What `saturating_sub` on `last_sample_us` actually buys, stated
    // honestly. With the clock behind its own last sample, the interval
    // check reads zero and the gate stops sampling until real time
    // catches back up -- and the window check reads zero too, so it does
    // not time out either. The gate freezes.
    //
    // That is not ideal, but it is the safe direction: it neither
    // confirms a gesture nobody made nor refuses one that is coming. The
    // unsafe direction is what plain subtraction gives, and that is what
    // the test above pins.
    //
    // I first wrote this test asserting the gate keeps sampling through
    // a rewind. It does not, and the assertion was something I had
    // invented rather than something the code promises.
    let _g = fresh();
    rp235x_hal::set_now_us(5_000_000);
    upgate::begin();
    press(false);
    rp235x_hal::advance_us(SAMPLE_US * 4);
    assert_eq!(upgate::poll(), UP_PENDING);

    rp235x_hal::set_now_us(0);
    press(true);
    for _ in 0..16 {
        assert_eq!(
            tick(),
            UP_PENDING,
            "a rewound clock produced a verdict instead of holding"
        );
    }
    assert!(
        !upgate::consume(),
        "a rewound clock manufactured a confirmation out of nothing"
    );
}

#[test]
fn the_gate_works_normally_again_once_the_clock_has_caught_up() {
    // The other half: freezing must be temporary, or a single clock
    // glitch bricks user presence until the next reboot.
    let _g = fresh();
    rp235x_hal::set_now_us(5_000_000);
    upgate::begin();
    press(false);
    rp235x_hal::advance_us(SAMPLE_US * 4);
    assert_eq!(upgate::poll(), UP_PENDING);

    rp235x_hal::set_now_us(0);
    let _ = upgate::poll();
    // Time moves forward past where it was, within the window.
    rp235x_hal::set_now_us(5_009_000);
    press(true);
    let mut confirmed = false;
    for _ in 0..16 {
        if tick() == UP_CONFIRMED {
            confirmed = true;
            break;
        }
    }
    assert!(
        confirmed,
        "the gate never recovered after the clock caught back up"
    );
}

#[test]
fn a_confirmation_is_valid_at_exactly_the_boundary_and_not_past_it() {
    // `consume` uses `<=`, so a confirmation exactly VALID_US old still
    // counts. Off by one either way is a real difference: `<` would
    // discard a touch at the moment the window closes and the user sees
    // a refused operation for a finger they did put on the button.
    let _g = fresh();
    upgate::begin();
    press(false);
    let _ = tick();
    press(true);
    let mut ok = false;
    for _ in 0..16 {
        if tick() == UP_CONFIRMED {
            ok = true;
            break;
        }
    }
    assert!(ok, "no confirmation to test with");

    // Exactly at the limit: still good.
    rp235x_hal::advance_us(VALID_US);
    assert!(
        upgate::consume(),
        "a confirmation exactly {VALID_US} us old was rejected"
    );
}

#[test]
fn a_confirmation_one_microsecond_past_the_boundary_is_refused() {
    let _g = fresh();
    upgate::begin();
    press(false);
    let _ = tick();
    press(true);
    let mut ok = false;
    for _ in 0..16 {
        if tick() == UP_CONFIRMED {
            ok = true;
            break;
        }
    }
    assert!(ok, "no confirmation to test with");

    rp235x_hal::advance_us(VALID_US + 1);
    assert!(
        !upgate::consume(),
        "a confirmation older than {VALID_US} us was spent"
    );
}

#[test]
fn a_confirmation_survives_a_clock_that_goes_backwards() {
    // saturating_sub in `consume`: a rewound clock must not make a fresh
    // confirmation look expired, or a touch the user just made is
    // silently discarded and the operation refused.
    let _g = fresh();
    rp235x_hal::set_now_us(5_000_000);
    upgate::begin();
    press(false);
    let _ = tick();
    press(true);
    let mut ok = false;
    for _ in 0..16 {
        if tick() == UP_CONFIRMED {
            ok = true;
            break;
        }
    }
    assert!(ok, "no confirmation to test with");

    rp235x_hal::set_now_us(0); // back before the confirmation
    assert!(
        upgate::consume(),
        "a backwards clock discarded a confirmation that had just been made"
    );
}
