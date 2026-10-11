// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! A torn or lost main sector never removes the PIN.
//!
//! The master keys live in their own sector and survive any routine
//! write; the PIN lives in the main sector, which every routine write
//! erases and reprograms. Before the PIN-armed word, a power loss in
//! the middle of that write booted a token with no PIN and every old
//! credential id still decrypting: anyone holding it could set a PIN
//! of their own and get user-verified assertions. These tests cut the
//! power at every byte that matters and require the token to come back
//! with its PIN, or PIN-blocked until authenticatorReset -- never
//! PIN-less, and never with its retry counter refilled.

use pqf_cbor::Value;
use pqf_firmware_hosttest as fw;

use fw::client_pin::{PinSession, ERR_PIN_AUTH_INVALID, ERR_PIN_BLOCKED, PERM_GET_ASSERTION};
use fw::ctap2::{CredStore, HostOp, CTAP2_CLIENT_PIN, CTAP2_GET_INFO, CTAP2_OK, CTAP2_RESET_CMD};
use fw::flash_store;
use fw::testclient::{Device, TEST_PIN};

const DIE_TOP: usize = 4 * 1024 * 1024;
const SECTOR: usize = 4096;
const PAGE: usize = 256;
const KEYS: usize = DIE_TOP - 3 * SECTOR;
/// The PIN-armed word: the first word of the key sector's page 1.
const ARMED: usize = KEYS + PAGE;
/// Bytes one main-sector write programs: the slot pages (15 pages),
/// then the header page twice (the magic in the second pass).
const SLOTS_LEN: usize = SECTOR - PAGE;
const WRITE_LEN: usize = SLOTS_LEN + 2 * PAGE;
/// The write is complete once the magic -- the first four bytes of the
/// last pass -- is down.
const COMPLETE_AT: usize = SLOTS_LEN + PAGE + 4;

fn die(off: usize, len: usize) -> Vec<u8> {
    let base = rp235x_hal::window();
    unsafe { core::slice::from_raw_parts(base.add(off), len).to_vec() }
}

fn put_die(off: usize, bytes: &[u8]) {
    let base = rp235x_hal::window() as *mut u8;
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(off), bytes.len()) }
}

/// The key, large-blob and main sectors, for restoring between cuts.
fn snapshot() -> Vec<u8> {
    die(KEYS, 3 * SECTOR)
}

/// A power cycle: RAM is lost, flash is not.
fn reboot(d: &mut Device) {
    d.store = CredStore::load(&mut d.trng);
    d.session = PinSession::new(&mut d.trng);
}

fn restore(d: &mut Device, snap: &[u8]) {
    put_die(KEYS, snap);
    reboot(d);
}

fn armed_on_die() -> bool {
    die(ARMED, 4) != [0xff; 4]
}

fn bare(d: &mut Device, cmd: u8) -> Vec<u8> {
    let mut host = |_op: HostOp| true;
    fw::ctap2::handle_cbor(
        &[cmd],
        &mut d.trng,
        &mut d.session,
        &mut d.store,
        &mut host,
        0,
        [0, 0, 0, 1],
    )
    .to_vec()
}

/// getInfo's `clientPin` option.
fn client_pin_option(d: &mut Device) -> bool {
    let r = bare(d, CTAP2_GET_INFO);
    assert_eq!(r[0], CTAP2_OK);
    match Device::field(&r, 0x04) {
        Some(Value::Map(m)) => m
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Text(t), Value::Bool(b)) if t == "clientPin" => Some(*b),
                _ => None,
            })
            .expect("getInfo has no clientPin option"),
        other => panic!("getInfo options are {other:?}"),
    }
}

/// getPinRetries (clientPIN 0x01) `pinRetries`.
fn retries(d: &mut Device) -> u64 {
    let r = d.send(
        CTAP2_CLIENT_PIN,
        &Value::Map(vec![
            (Value::Uint(1), Value::Uint(1)),
            (Value::Uint(2), Value::Uint(1)),
        ]),
    );
    assert_eq!(r[0], CTAP2_OK);
    match Device::field(&r, 0x03) {
        Some(Value::Uint(n)) => n,
        other => panic!("pinRetries is {other:?}"),
    }
}

/// The cut points worth testing in one main-sector write: a few in the
/// slot pages, and every byte of the two header-page passes.
fn cuts() -> Vec<usize> {
    let mut v = vec![0, 1, PAGE, 2000, SLOTS_LEN - 1];
    v.extend(SLOTS_LEN..=WRITE_LEN);
    v
}

/// A blank device with `TEST_PIN` set (and so the word armed).
fn with_pin() -> Device {
    let mut d = Device::bare();
    assert_eq!(d.set_pin(TEST_PIN)[0], CTAP2_OK);
    d
}

/// Put the token into the state a lost main sector leaves: the PIN-armed
/// word set, the main sector erased.
fn lose_the_main_sector(d: &mut Device) {
    put_die(DIE_TOP - SECTOR, &[0xff; SECTOR]);
    reboot(d);
}

#[test]
fn setting_a_pin_arms_the_word_and_leaves_the_keys() {
    let mut d = Device::bare();
    assert!(!flash_store::pin_armed(), "a blank device is armed");
    assert!(!armed_on_die());
    let keys = die(KEYS, PAGE);
    assert_eq!(d.set_pin(TEST_PIN)[0], CTAP2_OK);
    assert!(
        flash_store::pin_armed(),
        "setting a PIN did not arm the word"
    );
    assert_eq!(die(ARMED, 4), [0, 0, 0, 0]);
    assert_eq!(die(KEYS, PAGE), keys, "arming touched the keys' page");
    assert_eq!(
        die(ARMED + 4, PAGE - 4),
        vec![0xff; PAGE - 4],
        "arming programmed more than its word"
    );
}

#[test]
fn a_lost_main_sector_boots_pin_blocked() {
    let mut d = with_pin();
    lose_the_main_sector(&mut d);
    assert!(client_pin_option(&mut d), "the token boots PIN-less");
    assert_eq!(retries(&mut d), 0, "the token is not PIN-blocked");
    // Neither the old PIN nor a new one gets in.
    assert_eq!(d.mint(PERM_GET_ASSERTION as u64, None)[0], ERR_PIN_BLOCKED);
    assert_eq!(
        d.set_pin(b"5678")[0],
        ERR_PIN_AUTH_INVALID,
        "a new PIN could be set over the lost one"
    );
    assert_eq!(d.change_pin(TEST_PIN, b"5678")[0], ERR_PIN_BLOCKED);
    // And it stays that way across power cycles and routine writes.
    d.store.persist();
    reboot(&mut d);
    assert!(client_pin_option(&mut d));
    assert_eq!(retries(&mut d), 0);
}

#[test]
fn reset_is_the_way_out_of_a_lost_pin() {
    let mut d = with_pin();
    let old_keys = die(KEYS + 8, 64);
    lose_the_main_sector(&mut d);
    assert_eq!(bare(&mut d, CTAP2_RESET_CMD)[0], CTAP2_OK);
    assert_ne!(
        die(KEYS + 8, 64),
        old_keys,
        "the reset kept the keys every old credential id needs"
    );
    assert!(!armed_on_die(), "the reset left the word armed");
    reboot(&mut d);
    assert!(!client_pin_option(&mut d));
    assert_eq!(retries(&mut d), 8);
    assert_eq!(d.set_pin(b"5678")[0], CTAP2_OK);
    assert!(armed_on_die(), "the new PIN did not arm the word again");
    reboot(&mut d);
    assert_eq!(d.mint(PERM_GET_ASSERTION as u64, None)[0], CTAP2_OK);
}

#[test]
fn a_torn_write_after_a_pin_never_refills_or_removes_it() {
    // A wrong PIN costs one retry, persisted with one main-sector
    // write. Cut that write at every byte that matters: the token must
    // come back with one retry fewer (the write landed) or PIN-blocked
    // (it did not) -- never with the PIN gone, and never with the
    // counter back at 8, which is what an erased retries byte under a
    // valid magic used to load as.
    let mut d = with_pin();
    let keys = die(KEYS, PAGE);
    let snap = snapshot();
    for cut in cuts() {
        restore(&mut d, &snap);
        d.pin = b"9999".to_vec();
        rp235x_hal::set_tear_after_bytes(Some(cut));
        let _ = d.mint(PERM_GET_ASSERTION as u64, None);
        assert!(rp235x_hal::torn(), "cut {cut}: the write finished first");
        rp235x_hal::set_tear_after_bytes(None);
        reboot(&mut d);

        assert!(client_pin_option(&mut d), "cut {cut}: the PIN is gone");
        let want = if cut >= COMPLETE_AT { 7 } else { 0 };
        assert_eq!(retries(&mut d), want, "cut {cut}: wrong retry count");
        assert_eq!(die(KEYS, PAGE), keys, "cut {cut}: the keys moved");
        if want == 7 {
            d.pin = TEST_PIN.to_vec();
            assert_eq!(
                d.mint(PERM_GET_ASSERTION as u64, None)[0],
                CTAP2_OK,
                "cut {cut}: the PIN no longer works"
            );
        }
    }
}

#[test]
fn a_torn_set_pin_leaves_no_pin_or_an_armed_one() {
    // setPIN writes the main sector, then arms the word. Cut anywhere:
    // either the PIN never landed (no PIN, no word), or it did and the
    // next boot arms the word if setPIN did not get to.
    let mut d = Device::bare();
    let snap = snapshot();
    let mut cuts = cuts();
    cuts.extend([
        WRITE_LEN + 1,
        WRITE_LEN + 2,
        WRITE_LEN + 4,
        WRITE_LEN + PAGE,
    ]);
    for cut in cuts {
        restore(&mut d, &snap);
        rp235x_hal::set_tear_after_bytes(Some(cut));
        let _ = d.set_pin(TEST_PIN);
        assert!(rp235x_hal::torn(), "cut {cut}: the write finished first");
        rp235x_hal::set_tear_after_bytes(None);
        reboot(&mut d);

        if cut >= COMPLETE_AT {
            assert!(client_pin_option(&mut d), "cut {cut}: the PIN was lost");
            assert!(
                armed_on_die(),
                "cut {cut}: a set PIN is not armed after boot"
            );
            assert_eq!(retries(&mut d), 8, "cut {cut}");
        } else {
            assert!(!client_pin_option(&mut d), "cut {cut}: a PIN appeared");
            assert!(!armed_on_die(), "cut {cut}: armed with no PIN ever set");
            assert_eq!(
                retries(&mut d),
                8,
                "cut {cut}: blocked with no PIN ever set"
            );
        }
    }
}

#[test]
fn a_torn_write_with_no_pin_is_not_blocked() {
    let mut d = Device::bare();
    rp235x_hal::set_tear_after_bytes(Some(100));
    d.store.persist();
    assert!(rp235x_hal::torn());
    rp235x_hal::set_tear_after_bytes(None);
    reboot(&mut d);
    assert!(!client_pin_option(&mut d));
    assert_eq!(retries(&mut d), 8);
    assert!(!armed_on_die());
}

#[test]
fn a_pin_from_an_older_build_is_armed_at_boot() {
    let mut d = with_pin();
    // What a build without the word leaves: the PIN, the word erased.
    put_die(ARMED, &[0xff; 4]);
    assert!(!armed_on_die());
    reboot(&mut d);
    assert!(armed_on_die(), "the first boot did not arm the word");
    assert_eq!(retries(&mut d), 8);
    assert_eq!(d.mint(PERM_GET_ASSERTION as u64, None)[0], CTAP2_OK);
    // Now a lost main sector blocks, as on a token that set its PIN
    // under this build.
    lose_the_main_sector(&mut d);
    assert_eq!(retries(&mut d), 0);
}
