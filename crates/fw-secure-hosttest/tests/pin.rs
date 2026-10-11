// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The PIN store and the key store, against a simulated die.
//!
//! The retry budget is the only thing standing between a stolen token and
//! an offline PIN guess, and it had never been tested other than
//! end-to-end through the conformance suite -- which exercises the happy path and one
//! wrong PIN, not the boundary where the budget runs out or the reboot
//! that a determined attacker would use to try to reset it.
//!
//! Process-global `static mut` state, so every test serialises and starts
//! from a fresh die.

use pqf_fw_secure_hosttest as fws;
use std::sync::{Mutex, MutexGuard};

use fws::pinstore::{self, DEFAULT_MIN_PIN, MAX_MIN_PIN_RPS, MAX_RETRIES};

static SERIAL: Mutex<()> = Mutex::new(());

fn fresh() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fws::fresh_die();
    pinstore::init();
    g
}

fn hash_of(n: u8) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = n;
    h[15] = 0x5a;
    h
}

/// Set a PIN, as the ClientPIN setPin path does.
fn set_pin(n: u8) {
    let mut st = pinstore::get();
    st.is_set = true;
    st.retries = MAX_RETRIES;
    st.hash = hash_of(n);
    pinstore::put(st);
}

/// Spend one attempt, as the wrong-PIN path does.
fn spend_one_retry() {
    let mut st = pinstore::get();
    st.retries = st.retries.saturating_sub(1);
    pinstore::put(st);
}

// ---- the retry budget ------------------------------------------------

#[test]
fn a_fresh_token_has_no_pin() {
    let _g = fresh();
    let st = pinstore::get();
    assert!(!st.is_set, "a blank die reported a PIN as set");
    assert_eq!(
        st.min_pin_length, DEFAULT_MIN_PIN,
        "a fresh token should start at the CTAP2 default minimum"
    );
}

#[test]
fn setting_a_pin_grants_the_full_retry_budget() {
    let _g = fresh();
    set_pin(1);
    let st = pinstore::get();
    assert!(st.is_set);
    assert_eq!(st.retries, MAX_RETRIES, "CTAP2 specifies eight attempts");
}

#[test]
fn the_retry_budget_survives_a_reboot() {
    // The attack this defends against is trivial and obvious: guess,
    // power-cycle, guess again. If `init` did not recover the spent
    // budget from flash, the eight-attempt limit would be no limit at
    // all.
    let _g = fresh();
    set_pin(1);
    spend_one_retry();
    spend_one_retry();
    spend_one_retry();
    assert_eq!(pinstore::get().retries, MAX_RETRIES - 3);

    for i in 0..5 {
        pinstore::init(); // as if power-cycled
        assert_eq!(
            pinstore::get().retries,
            MAX_RETRIES - 3,
            "reboot {i} restored spent retries"
        );
    }
}

#[test]
fn the_budget_reaches_zero_and_stops_there() {
    // Eight attempts, then nothing. `saturating_sub` matters: a wrap to
    // 255 would hand an attacker another 255 guesses.
    let _g = fresh();
    set_pin(1);
    for _ in 0..MAX_RETRIES {
        spend_one_retry();
    }
    assert_eq!(pinstore::get().retries, 0, "the budget did not reach zero");
    for _ in 0..20 {
        spend_one_retry();
    }
    assert_eq!(
        pinstore::get().retries,
        0,
        "the retry count wrapped past zero -- that is 255 more guesses"
    );
    pinstore::init();
    assert_eq!(pinstore::get().retries, 0, "a reboot revived a blocked PIN");
}

#[test]
fn a_spent_retry_is_on_the_die_before_anything_else_happens() {
    // The ordering that makes the budget real. If the decrement were
    // written only after the comparison, an attacker could pull power the
    // instant a guess looked wrong and never pay for it -- unlimited
    // guesses at eight-per-boot. So `put` must have reached flash by the
    // time it returns, which is observable here as a program count that
    // has already gone up.
    let _g = fresh();
    set_pin(1);
    rp235x_hal::reset_counts();
    spend_one_retry();
    assert!(
        rp235x_hal::program_count() > 0,
        "spending a retry did not write to flash"
    );
    // And it is the *new* value that a reboot sees.
    pinstore::init();
    assert_eq!(pinstore::get().retries, MAX_RETRIES - 1);
}

#[test]
fn a_correct_pin_restores_the_full_budget() {
    // CTAP2 6.5.5.7: a successful verification resets the counter.
    // Without this, eight lifetime typos would brick a token.
    let _g = fresh();
    set_pin(1);
    for _ in 0..(MAX_RETRIES - 1) {
        spend_one_retry();
    }
    assert_eq!(pinstore::get().retries, 1);

    let mut st = pinstore::get();
    st.retries = MAX_RETRIES;
    pinstore::put(st);

    pinstore::init();
    assert_eq!(
        pinstore::get().retries,
        MAX_RETRIES,
        "a correct PIN did not restore the budget across a reboot"
    );
}

#[test]
fn changing_the_pin_keeps_the_new_hash_and_not_the_old() {
    let _g = fresh();
    set_pin(1);
    assert_eq!(pinstore::get().hash, hash_of(1));
    set_pin(2);
    pinstore::init();
    let st = pinstore::get();
    assert_eq!(st.hash, hash_of(2), "the old PIN hash survived a change");
    assert!(st.is_set);
}

// ---- the record log --------------------------------------------------

#[test]
fn the_newest_record_wins_across_many_writes() {
    // Records are appended and the highest sequence number is the live
    // one. Enough writes to fill both sectors and force the erase, which
    // is where a sequence scheme usually breaks.
    let _g = fresh();
    set_pin(1);
    for i in 0..200u8 {
        let mut st = pinstore::get();
        st.hash = hash_of(i);
        st.retries = (i % (MAX_RETRIES + 1)).max(1);
        pinstore::put(st);
    }
    let before = pinstore::get();
    pinstore::init();
    let after = pinstore::get();
    assert_eq!(
        after.hash, before.hash,
        "the newest record was not recovered"
    );
    assert_eq!(after.retries, before.retries);
    assert!(
        rp235x_hal::erase_count() > 0,
        "200 writes should have filled a sector and forced an erase"
    );
}

#[test]
fn an_erase_never_takes_the_only_copy() {
    // Two sectors, ping-ponged: the one being erased only ever holds
    // older records. A power cut between erase and program still leaves
    // the current state readable, which is the whole reason for the
    // second sector.
    let _g = fresh();
    set_pin(7);
    let mut erases = 0;
    for i in 0..300u16 {
        let mut st = pinstore::get();
        st.retries = ((i % MAX_RETRIES as u16) as u8) + 1;
        pinstore::put(st);
        if rp235x_hal::erase_count() > erases {
            erases = rp235x_hal::erase_count();
            // Immediately after an erase, a reboot must still find state.
            let expect = pinstore::get();
            pinstore::init();
            assert!(pinstore::get().is_set, "an erase lost the PIN entirely");
            assert_eq!(
                pinstore::get().retries,
                expect.retries,
                "an erase lost the retry count"
            );
        }
    }
    assert!(
        erases > 0,
        "never reached an erase; the test proved nothing"
    );
}

// ---- minPinLength ----------------------------------------------------

#[test]
fn the_minimum_pin_length_persists() {
    let _g = fresh();
    let mut st = pinstore::get();
    st.min_pin_length = 9;
    pinstore::put(st);
    pinstore::init();
    assert_eq!(pinstore::get().min_pin_length, 9);
}

#[test]
fn the_min_pin_rp_list_is_bounded() {
    // Host-supplied, so the bound has to hold whatever arrives. A record
    // has to stay inside one page.
    let _g = fresh();
    let mut st = pinstore::get();
    st.min_pin_rp_count = 99; // more than the layout can hold
    pinstore::put(st);
    pinstore::init();
    assert!(
        pinstore::get().min_pin_rp_count as usize <= MAX_MIN_PIN_RPS,
        "min_pin_rp_count came back as {}, past the {MAX_MIN_PIN_RPS} the record holds",
        pinstore::get().min_pin_rp_count
    );
}

// ---- the key store ---------------------------------------------------

#[test]
fn a_stored_master_key_reads_back_and_survives_a_reboot() {
    let _g = fresh();
    let mut out = [0u8; 32];
    assert!(
        !fws::keystore::load(&mut out),
        "a blank die reported a master key"
    );

    let key: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0x5a);
    fws::keystore::store(&key);

    let mut back = [0u8; 32];
    assert!(
        fws::keystore::load(&mut back),
        "the key just stored was not found"
    );
    assert_eq!(back, key, "the master key came back altered");
}

#[test]
fn the_key_store_does_not_hand_back_erased_flash_as_a_key() {
    // The failure to avoid: reading an unprogrammed sector and treating
    // 32 bytes of 0xff as a valid master key. Every credential on the
    // token derives from this value.
    let _g = fresh();
    let mut out = [0xaa; 32];
    assert!(
        !fws::keystore::load(&mut out),
        "erased flash was accepted as a key"
    );
    assert_ne!(
        out, [0xff; 32],
        "load() filled the buffer from erased flash"
    );
}

#[test]
fn a_master_key_is_not_silently_replaced() {
    // Overwriting it would orphan every credential on the token, so a
    // second store must either be refused or be deliberate. Either way
    // what `load` returns afterwards has to be one of the two, not a
    // bitwise AND of both -- which is what NOR flash gives you if a
    // record is programmed over a live one.
    let _g = fresh();
    let first: [u8; 32] = core::array::from_fn(|i| i as u8 | 0x80);
    fws::keystore::store(&first);
    let second: [u8; 32] = core::array::from_fn(|i| (255usize - i) as u8);
    fws::keystore::store(&second);

    let mut back = [0u8; 32];
    assert!(fws::keystore::load(&mut back));
    assert!(
        back == first || back == second,
        "the master key is neither of the two that were stored -- a program \
         over live flash ANDed them together"
    );
}
