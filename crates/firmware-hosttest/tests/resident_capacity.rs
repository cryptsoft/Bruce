// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Discoverable-credential capacity: the main store sector plus the
//! optional overflow sectors (`PQF_RESIDENT_EXTRA_SECTORS`).
//!
//! Run at the default (no overflow sectors) this pins the main sector's
//! bytes, so the option provably changes nothing on a token built
//! without it, and saves a default-layout die for the next run. Run
//! with `PQF_RESIDENT_EXTRA_SECTORS=3` (tools/host-tests.sh does both,
//! default first) it fills past the main sector and checks every
//! consumer of the slots -- getInfo, credential management, the
//! counter, reset -- across all of them, plus the two paths that matter
//! on a token in the field: enlarging the capacity over the store a
//! default build left, and a torn write of an overflow sector.

use pqf_cbor::Value;
use pqf_firmware_hosttest as fw;

use fw::client_pin::{PERM_CREDENTIAL_MGMT, PERM_GET_ASSERTION, PERM_MAKE_CREDENTIAL};
use fw::ctap2::{
    CredStore, HostOp, CTAP2_CREDENTIAL_MANAGEMENT as CM, CTAP2_ERR_KEY_STORE_FULL,
    CTAP2_ERR_NO_CREDENTIALS, CTAP2_GET_ASSERTION, CTAP2_GET_INFO, CTAP2_MAKE_CREDENTIAL, CTAP2_OK,
    CTAP2_RESET_CMD,
};
use fw::flash_store::{
    self, overflow_offset, StoredCredential, StoredImage, MAX_SLOTS, OVERFLOW_SLOTS,
    RESIDENT_EXTRA_SECTORS as EXTRA, STATE_ACTIVE, STORED_CRED_ID_LEN, TOTAL_SLOTS,
};
use fw::testclient::{auth_param, Device, TEST_PIN};

const DIE_TOP: usize = 4 * 1024 * 1024;
const SECTOR: usize = 4096;
const MAIN: usize = DIE_TOP - SECTOR;
const KEYS: usize = DIE_TOP - 3 * SECTOR;

const METADATA: u64 = 0x01;
const RPS_BEGIN: u64 = 0x02;
const RPS_NEXT: u64 = 0x03;
const CREDS_BEGIN: u64 = 0x04;
const DELETE: u64 = 0x06;
const UPDATE_USER: u64 = 0x07;

const ALL_PERMS: u64 = (PERM_CREDENTIAL_MGMT | PERM_MAKE_CREDENTIAL | PERM_GET_ASSERTION) as u64;

/// Where the default run leaves its die for the enlarged run to boot.
fn saved_die_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("pqf-rk-default-layout.die")
}
/// The top of the die the saved file covers: the three fixed sectors
/// and the eight below them that the largest overflow build would use.
const SAVED_LEN: usize = 11 * SECTOR;

fn die(off: usize, len: usize) -> Vec<u8> {
    let base = rp235x_hal::window();
    unsafe { core::slice::from_raw_parts(base.add(off), len).to_vec() }
}

fn put_die(off: usize, bytes: &[u8]) {
    let base = rp235x_hal::window() as *mut u8;
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(off), bytes.len()) }
}

fn overflow(k: usize) -> Vec<u8> {
    die(overflow_offset(k) as usize, SECTOR)
}

fn erased(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0xff)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn manager() -> Device {
    Device::authenticated(ALL_PERMS, None)
}

/// A power cycle: RAM is lost, flash is not.
fn reboot(d: &mut Device) {
    d.store = CredStore::load(&mut d.trng);
}

fn rp(i: usize) -> String {
    format!("rp{i}.example")
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

/// A bare command byte (getInfo, reset), presence confirmed.
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

/// MakeCredential(rk) at `rp` for user id `[user; 4]`, raw response.
fn register_raw(d: &mut Device, rp: &str, user: u8) -> Vec<u8> {
    let mut e = vec![
        (Value::Uint(1), Value::Bytes(vec![0x11; 32])),
        (Value::Uint(2), Value::Map(vec![(text("id"), text(rp))])),
        (
            Value::Uint(3),
            Value::Map(vec![
                (text("id"), Value::Bytes(vec![user; 4])),
                (text("name"), text("u")),
                (text("displayName"), text("u")),
            ]),
        ),
        (
            Value::Uint(4),
            Value::Array(vec![Value::Map(vec![
                (text("alg"), Value::Nint(-7)),
                (text("type"), text("public-key")),
            ])]),
        ),
        (
            Value::Uint(7),
            Value::Map(vec![(text("rk"), Value::Bool(true))]),
        ),
        (
            Value::Uint(8),
            Value::Bytes(auth_param(&d.token, &[0x11u8; 32])),
        ),
        (Value::Uint(9), Value::Uint(1)),
    ];
    e.sort_by_key(|(k, _)| if let Value::Uint(n) = k { *n } else { 0 });
    d.send(CTAP2_MAKE_CREDENTIAL, &Value::Map(e))
}

/// Discoverable GetAssertion at `rp`; returns (status, signCount).
fn assert_at(d: &mut Device, rp: &str) -> (u8, u32) {
    let ga = Value::Map(vec![
        (Value::Uint(1), text(rp)),
        (Value::Uint(2), Value::Bytes(vec![0x22; 32])),
    ]);
    let r = d.send(CTAP2_GET_ASSERTION, &ga);
    if r[0] != CTAP2_OK {
        return (r[0], 0);
    }
    let ad = match Device::field(&r, 0x02) {
        Some(Value::Bytes(b)) => b,
        other => panic!("authData is {other:?}"),
    };
    (
        CTAP2_OK,
        u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]),
    )
}

fn uint(resp: &[u8], key: u64) -> u64 {
    match Device::field(resp, key) {
        Some(Value::Uint(n)) => n,
        other => panic!("field {key:#04x} is {other:?}, not an integer"),
    }
}

/// getInfo 0x14 remainingDiscoverableCredentials.
fn remaining_in_get_info(d: &mut Device) -> u64 {
    let r = bare(d, CTAP2_GET_INFO);
    assert_eq!(r[0], CTAP2_OK);
    uint(&r, 0x14)
}

/// credentialManagement getCredsMetadata: (existing, remaining).
fn metadata(d: &mut Device) -> (u64, u64) {
    let r = d.subcommand(CM, METADATA, None);
    assert_eq!(r[0], CTAP2_OK);
    (uint(&r, 0x01), uint(&r, 0x02))
}

fn rp_hash_param(rp: &str) -> Value {
    Value::Map(vec![(
        Value::Uint(1),
        Value::Bytes(fw::bc_crypto::sha256(rp.as_bytes()).to_vec()),
    )])
}

fn cred_param(id: &[u8]) -> Value {
    Value::Map(vec![(
        Value::Uint(2),
        Value::Map(vec![(text("id"), Value::Bytes(id.to_vec()))]),
    )])
}

fn cred_id_of(resp: &[u8]) -> Vec<u8> {
    let ad = match Device::field(resp, 2).expect("no authData") {
        Value::Bytes(b) => b,
        other => panic!("authData is {other:?}"),
    };
    let len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    ad[55..55 + len].to_vec()
}

/// Register `n` passkeys at rp0..rp{n-1}; returns their credential ids.
fn fill(d: &mut Device, n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let r = register_raw(d, &rp(i), i as u8 + 1);
            assert_eq!(
                r[0], CTAP2_OK,
                "registration {i} of {n} failed: {:#04x}",
                r[0]
            );
            cred_id_of(&r)
        })
        .collect()
}

fn cred(n: u8) -> StoredCredential {
    let mut c = StoredCredential::empty();
    c.state = STATE_ACTIVE;
    c.credential_id = [n; STORED_CRED_ID_LEN];
    c.rp_id_hash = [n ^ 0x5a; 32];
    c.counter = 0x0102_0300 | n as u32;
    c.user_id_len = 4;
    c.user_id[..4].copy_from_slice(&[n; 4]);
    c.creation_order = n as u32;
    c
}

/// Skip a test that needs overflow sectors in a default build.
macro_rules! needs_overflow {
    () => {
        if EXTRA == 0 {
            eprintln!("skipped: needs PQF_RESIDENT_EXTRA_SECTORS > 0");
            return;
        }
    };
}

// ---- the default layout is byte-for-byte what it was ------------------

#[test]
fn the_capacity_is_what_the_option_says() {
    assert_eq!(MAX_SLOTS, 6, "the main sector's slot count moved");
    assert_eq!(OVERFLOW_SLOTS, 7);
    assert_eq!(TOTAL_SLOTS, 6 + 7 * EXTRA);
    let mut d = manager();
    assert_eq!(remaining_in_get_info(&mut d), TOTAL_SLOTS as u64);
    assert_eq!(metadata(&mut d), (0, TOTAL_SLOTS as u64));
}

#[test]
fn the_primary_sector_image_is_byte_identical() {
    // write_sector over a deterministic image, hashed straight off the
    // die. The hash was taken from the firmware BEFORE the capacity
    // option existed; if this changes, a token flashed with the new
    // build reads its existing store differently.
    let _g = fw::testlock::acquire();
    rp235x_hal::reset();
    let mut img: StoredImage = unsafe { core::mem::zeroed() };
    img.pin_hash = [0x42; 16];
    img.pin_set = 1;
    img.retries_left = 7;
    img.min_pin_length = 6;
    img.force_pin_change = 1;
    for i in 0..MAX_SLOTS {
        img.creds[i] = cred(i as u8 + 1);
    }
    flash_store::write_sector(&img);
    let h = fw::bc_crypto::sha256(&die(MAIN, SECTOR));
    assert_eq!(
        hex(&h),
        GOLDEN_PRIMARY,
        "the primary store sector's bytes changed"
    );
}

#[test]
fn six_registrations_write_the_same_primary_and_key_sectors() {
    // End to end through CredStore: PIN set, six passkeys registered.
    // With overflow sectors configured the first six still land in the
    // main sector, so the bytes must match the default build's -- and
    // no overflow sector may have been written at all.
    let mut d = manager();
    for i in 0..6u8 {
        d.register(&format!("rp{i}.example"), i + 1, &format!("user{i}"));
    }
    // The PIN-armed word (the first word of the key sector's page 1) is
    // the one thing these sectors hold that the firmware the hash was
    // taken from did not write: check it is armed, then hash the rest
    // exactly as that firmware left it.
    let mut bytes = die(KEYS, 3 * SECTOR);
    assert_eq!(bytes[256..260], [0; 4], "the PIN did not arm the word");
    bytes[256..260].fill(0xff);
    let h = fw::bc_crypto::sha256(&bytes);
    assert_eq!(
        hex(&h),
        GOLDEN_SIX,
        "six registrations wrote different bytes"
    );
    for k in 0..EXTRA {
        assert!(erased(&overflow(k)), "overflow sector {k} was written");
    }
}

/// Both hashes were taken from the firmware before the option existed.
const GOLDEN_PRIMARY: &str = "ec4bd0c88e6a4a53454e369021d3afac0bafc6e1fb099348457bb5951cf9b429";
const GOLDEN_SIX: &str = "0d4a4a2659b05dcf5d19ff88638fdb7f9c7f5d8ce95ca756ca07e650500970e5";

// ---- enlarging the capacity over an existing store --------------------

#[test]
fn a_default_build_leaves_its_die_for_the_enlarged_build() {
    // Only in the default build: a token with a PIN and six passkeys,
    // two of them used, exactly as a default image leaves the flash. The
    // enlarged run boots this die (the next test).
    if EXTRA != 0 {
        eprintln!("skipped: only the default build writes the saved die");
        return;
    }
    let mut d = manager();
    fill(&mut d, 6);
    assert_eq!(assert_at(&mut d, &rp(0)).0, CTAP2_OK);
    assert_eq!(assert_at(&mut d, &rp(0)).0, CTAP2_OK);
    assert_eq!(assert_at(&mut d, &rp(5)).0, CTAP2_OK);
    std::fs::write(saved_die_path(), die(DIE_TOP - SAVED_LEN, SAVED_LEN)).unwrap();
}

#[test]
fn enlarging_keeps_the_pin_and_passkeys_a_default_build_left() {
    needs_overflow!();
    let saved = match std::fs::read(saved_die_path()) {
        Ok(b) if b.len() == SAVED_LEN => b,
        _ => {
            eprintln!(
                "skipped: no saved default-layout die; run the default build of this \
                 test first (tools/host-tests.sh does)"
            );
            return;
        }
    };
    let mut d = Device::bare();
    put_die(DIE_TOP - SAVED_LEN, &saved);
    reboot(&mut d);
    // The PIN survived: a token can be minted with it.
    d.pin = TEST_PIN.to_vec();
    assert_eq!(
        d.mint(ALL_PERMS, None)[0],
        CTAP2_OK,
        "the default build's PIN no longer works"
    );
    assert_eq!(
        metadata(&mut d),
        (6, TOTAL_SLOTS as u64 - 6),
        "the six passkeys are not all there"
    );
    assert_eq!(remaining_in_get_info(&mut d), TOTAL_SLOTS as u64 - 6);
    // Every one still signs, and the counters carry on from where they
    // were rather than restarting.
    let (s0, c0) = assert_at(&mut d, &rp(0));
    assert_eq!(s0, CTAP2_OK);
    assert!(c0 >= 3, "rp0's counter restarted: {c0}");
    for i in 1..6 {
        assert_eq!(
            assert_at(&mut d, &rp(i)).0,
            CTAP2_OK,
            "rp{i} no longer signs"
        );
    }
    // A seventh lands in the first overflow sector, and the main
    // sector -- the PIN and the six -- is not rewritten for it.
    let main_before = die(MAIN, SECTOR);
    let r = register_raw(&mut d, "seventh.example", 77);
    assert_eq!(r[0], CTAP2_OK);
    assert_eq!(
        die(MAIN, SECTOR),
        main_before,
        "adding the seventh rewrote the main sector"
    );
    assert!(
        !erased(&overflow(0)[..16]),
        "the seventh did not reach overflow sector 0"
    );
    reboot(&mut d);
    assert_eq!(
        metadata(&mut d),
        (7, (TOTAL_SLOTS as u64).saturating_sub(7))
    );
    assert_eq!(assert_at(&mut d, "seventh.example").0, CTAP2_OK);
    assert_eq!(assert_at(&mut d, &rp(3)).0, CTAP2_OK);
}

#[test]
fn a_store_with_only_the_main_sector_boots_with_empty_overflow() {
    // The same path without the saved file: six passkeys never touch an
    // overflow sector (checked above against the default build's hash),
    // so this die is a default build's. Boot it again.
    needs_overflow!();
    let mut d = manager();
    fill(&mut d, 6);
    reboot(&mut d);
    assert_eq!(metadata(&mut d), (6, TOTAL_SLOTS as u64 - 6));
    for i in 0..6 {
        assert_eq!(assert_at(&mut d, &rp(i)).0, CTAP2_OK);
    }
}

// ---- filling every sector ---------------------------------------------

#[test]
fn every_slot_in_every_sector_is_usable_and_then_the_store_is_full() {
    needs_overflow!();
    let mut d = manager();
    for i in 0..TOTAL_SLOTS {
        assert_eq!(remaining_in_get_info(&mut d), (TOTAL_SLOTS - i) as u64);
        let r = register_raw(&mut d, &rp(i), i as u8 + 1);
        assert_eq!(r[0], CTAP2_OK, "registration {i} failed");
    }
    assert_eq!(remaining_in_get_info(&mut d), 0);
    assert_eq!(metadata(&mut d), (TOTAL_SLOTS as u64, 0));
    for k in 0..EXTRA {
        assert!(
            !erased(&overflow(k)[..16]),
            "overflow sector {k} was never written"
        );
    }
    // Full: a new account is refused, not evicted...
    let r = register_raw(&mut d, "one-too-many.example", 200);
    assert_eq!(r[0], CTAP2_ERR_KEY_STORE_FULL);
    assert_eq!(d.store.active_count(), TOTAL_SLOTS);
    // ...but re-registering one in the last sector replaces it in place.
    let last = TOTAL_SLOTS - 1;
    let r = register_raw(&mut d, &rp(last), last as u8 + 1);
    assert_eq!(r[0], CTAP2_OK, "re-registration in a full store failed");
    assert_eq!(d.store.active_count(), TOTAL_SLOTS);

    reboot(&mut d);
    assert_eq!(
        d.store.active_count(),
        TOTAL_SLOTS,
        "not everything came back after a reboot"
    );
    for i in [
        0,
        MAX_SLOTS - 1,
        MAX_SLOTS,
        MAX_SLOTS + OVERFLOW_SLOTS - 1,
        last,
    ] {
        assert_eq!(
            assert_at(&mut d, &rp(i)).0,
            CTAP2_OK,
            "rp{i} does not sign after a reboot"
        );
    }

    // Credential management sees every sector.
    let first = d.subcommand(CM, RPS_BEGIN, None);
    assert_eq!(first[0], CTAP2_OK);
    assert_eq!(uint(&first, 0x05), TOTAL_SLOTS as u64, "totalRPs");
    for _ in 1..TOTAL_SLOTS {
        assert_eq!(d.subcommand(CM, RPS_NEXT, None)[0], CTAP2_OK);
    }
    let r = d.subcommand(CM, CREDS_BEGIN, Some(rp_hash_param(&rp(last))));
    assert_eq!(
        r[0], CTAP2_OK,
        "a credential in the last overflow sector is not enumerated"
    );
    assert_eq!(uint(&r, 0x09), 1);
}

#[test]
fn a_counter_bump_in_an_overflow_slot_rewrites_only_that_sector() {
    needs_overflow!();
    let mut d = manager();
    fill(&mut d, MAX_SLOTS + 2);
    let target = rp(MAX_SLOTS + 1); // overflow sector 0, second slot
    let main_before = die(MAIN, SECTOR);
    let keys_before = die(KEYS, 2 * SECTOR);
    let others: Vec<Vec<u8>> = (1..EXTRA).map(overflow).collect();
    rp235x_hal::reset_counts();
    let (s, c1) = assert_at(&mut d, &target);
    assert_eq!(s, CTAP2_OK);
    assert_eq!(
        rp235x_hal::erase_count(),
        1,
        "one assertion erased more than one sector"
    );
    assert_eq!(
        die(MAIN, SECTOR),
        main_before,
        "the main sector was rewritten"
    );
    assert_eq!(die(KEYS, 2 * SECTOR), keys_before);
    for k in 1..EXTRA {
        assert_eq!(
            overflow(k),
            others[k - 1],
            "overflow sector {k} was rewritten"
        );
    }
    reboot(&mut d);
    let (_, c2) = assert_at(&mut d, &target);
    assert!(
        c2 > c1,
        "the counter in an overflow slot did not persist: {c1} then {c2}"
    );

    // And a counter bump in the main sector leaves the overflow alone.
    let ov0 = overflow(0);
    assert_eq!(assert_at(&mut d, &rp(0)).0, CTAP2_OK);
    assert_eq!(
        overflow(0),
        ov0,
        "a main-sector bump rewrote an overflow sector"
    );
}

#[test]
fn delete_and_update_work_on_an_overflow_credential_and_persist() {
    needs_overflow!();
    let mut d = manager();
    let ids = fill(&mut d, (MAX_SLOTS + OVERFLOW_SLOTS + 1).min(TOTAL_SLOTS));
    let last = ids.len() - 1;

    // Rename the last one.
    let mut p = match cred_param(&ids[last]) {
        Value::Map(m) => m,
        _ => unreachable!(),
    };
    p.push((
        Value::Uint(3),
        Value::Map(vec![
            (text("id"), Value::Bytes(vec![last as u8 + 1; 4])),
            (text("name"), text("renamed")),
            (text("displayName"), text("Renamed")),
        ]),
    ));
    assert_eq!(
        d.subcommand(CM, UPDATE_USER, Some(Value::Map(p)))[0],
        CTAP2_OK
    );

    // Delete one in overflow sector 0.
    let victim = MAX_SLOTS + 3;
    let main_before = die(MAIN, SECTOR);
    assert_eq!(
        d.subcommand(CM, DELETE, Some(cred_param(&ids[victim])))[0],
        CTAP2_OK
    );
    assert_eq!(
        die(MAIN, SECTOR),
        main_before,
        "deleting an overflow credential rewrote the main sector"
    );

    reboot(&mut d);
    assert_eq!(d.store.active_count(), ids.len() - 1);
    assert_eq!(
        assert_at(&mut d, &rp(victim)).0,
        CTAP2_ERR_NO_CREDENTIALS,
        "the deleted one still signs"
    );
    let r = d.subcommand(CM, CREDS_BEGIN, Some(rp_hash_param(&rp(last))));
    assert_eq!(r[0], CTAP2_OK);
    let name = match Device::field(&r, 0x06) {
        Some(Value::Map(m)) => m.iter().find_map(|(k, v)| match (k, v) {
            (Value::Text(a), Value::Text(b)) if a == "name" => Some(b.clone()),
            _ => None,
        }),
        _ => None,
    };
    assert_eq!(
        name.as_deref(),
        Some("renamed"),
        "the rename did not persist"
    );

    // The freed slot is reused.
    let r = register_raw(&mut d, "reuse.example", 250);
    assert_eq!(r[0], CTAP2_OK);
    assert_eq!(d.store.active_count(), ids.len());
}

// ---- reset --------------------------------------------------------------

#[test]
fn reset_wipes_every_sector() {
    needs_overflow!();
    let mut d = manager();
    fill(&mut d, TOTAL_SLOTS.min(MAX_SLOTS + OVERFLOW_SLOTS + 2));
    assert_eq!(bare(&mut d, CTAP2_RESET_CMD)[0], CTAP2_OK, "reset failed");
    assert_eq!(d.store.active_count(), 0);
    for k in 0..EXTRA {
        assert!(erased(&overflow(k)), "overflow sector {k} survived reset");
    }
    reboot(&mut d);
    assert_eq!(
        d.store.active_count(),
        0,
        "credentials came back after reset"
    );
    assert_eq!(remaining_in_get_info(&mut d), TOTAL_SLOTS as u64);
}

#[test]
fn overflow_sectors_left_behind_by_a_smaller_build_reset_stay_dead() {
    // A default build's reset rotates the master keys and wipes the
    // main sector, but it does not know about the overflow sectors. When
    // the enlarged build is flashed again, those sectors must read as
    // empty: their credential ids no longer decrypt.
    needs_overflow!();
    let mut d = manager();
    fill(&mut d, MAX_SLOTS + 3);
    let ov0 = overflow(0);
    // What the default build's reset does to flash: new keys, main
    // sector rewritten empty; the overflow sector is not touched.
    flash_store::write_key_sector(&[0x99; 32], &[0x98; 32]);
    let empty: StoredImage = unsafe { core::mem::zeroed() };
    flash_store::write_sector(&empty);
    assert_eq!(overflow(0), ov0);
    reboot(&mut d);
    assert_eq!(
        d.store.active_count(),
        0,
        "stale overflow credentials resurrected"
    );
}

#[test]
fn a_sector_copied_to_the_wrong_index_is_refused() {
    needs_overflow!();
    if EXTRA < 2 {
        return;
    }
    let mut d = manager();
    fill(&mut d, MAX_SLOTS + 2);
    let before = d.store.active_count();
    put_die(overflow_offset(1) as usize, &overflow(0));
    reboot(&mut d);
    assert_eq!(
        d.store.active_count(),
        before,
        "sector 0's header was accepted at index 1"
    );
}

// ---- torn writes ------------------------------------------------------------

#[test]
fn a_torn_overflow_write_loses_at_most_that_sector() {
    needs_overflow!();
    // The last overflow sector holds three; every sector before it is
    // full. A fourth is added there with the power failing after `tear`
    // programmed bytes. One overflow write programs the whole sector
    // (4096 bytes, header bytes left erased) and then page 0 again with
    // the header (bytes 4096..4112 of the budget are the header).
    let t = EXTRA.saturating_sub(1);
    let before_t = MAX_SLOTS + t * OVERFLOW_SLOTS;
    let tears = [
        0usize,
        1,
        15,
        16,
        1000,
        SECTOR - 1,
        SECTOR,
        SECTOR + 1,
        SECTOR + 11,
        SECTOR + 12,
        SECTOR + 15,
        SECTOR + 16,
        SECTOR + 100,
    ];
    for tear in tears {
        let mut d = manager();
        fill(&mut d, before_t + 3);
        let main_before = die(MAIN, SECTOR);
        let keys_before = die(KEYS, 2 * SECTOR);
        let others: Vec<(usize, Vec<u8>)> = (0..EXTRA)
            .filter(|&k| k != t)
            .map(|k| (k, overflow(k)))
            .collect();
        rp235x_hal::set_tear_after_bytes(Some(tear));
        let _ = register_raw(&mut d, "torn.example", 111);
        assert!(
            rp235x_hal::torn(),
            "tear {tear}: the write finished before the tear"
        );
        rp235x_hal::set_tear_after_bytes(None);

        reboot(&mut d);
        // Nothing outside the torn sector moved.
        assert_eq!(
            die(MAIN, SECTOR),
            main_before,
            "tear {tear}: the main sector changed"
        );
        assert_eq!(
            die(KEYS, 2 * SECTOR),
            keys_before,
            "tear {tear}: the key/large-blob sectors changed"
        );
        for (k, b) in &others {
            assert_eq!(&overflow(*k), b, "tear {tear}: overflow sector {k} changed");
        }
        // The torn sector reads as empty, or -- once every slot byte and
        // the whole header are down -- as the complete new content.
        // Never a valid header over a partial slot.
        let in_t = d.store.active_count() - before_t;
        if tear < SECTOR + 12 {
            assert_eq!(in_t, 0, "tear {tear}: an incomplete header was accepted");
        } else if tear >= SECTOR + 16 {
            assert_eq!(in_t, 4, "tear {tear}: a complete write was not accepted");
        } else {
            assert!(
                in_t == 0 || in_t == 4,
                "tear {tear}: {in_t} credentials in the torn sector"
            );
        }
        if in_t == 4 {
            assert_eq!(assert_at(&mut d, "torn.example").0, CTAP2_OK);
        } else {
            assert_eq!(
                assert_at(&mut d, "torn.example").0,
                CTAP2_ERR_NO_CREDENTIALS
            );
        }
        // The main sector's passkeys and PIN are intact.
        for i in 0..MAX_SLOTS {
            assert_eq!(
                assert_at(&mut d, &rp(i)).0,
                CTAP2_OK,
                "tear {tear}: rp{i} lost"
            );
        }
        d.pin = TEST_PIN.to_vec();
        assert_eq!(
            d.mint(ALL_PERMS, None)[0],
            CTAP2_OK,
            "tear {tear}: the PIN was lost"
        );
    }
}

#[test]
fn a_torn_main_sector_write_leaves_the_overflow_sectors() {
    // The main sector's own guarantee is unchanged (a torn write reads
    // as a fresh main sector); the overflow sectors are independent of
    // it and keep their passkeys, which still decrypt under the intact
    // master keys.
    needs_overflow!();
    let mut d = manager();
    fill(&mut d, MAX_SLOTS + 2);
    let ov0 = overflow(0);
    rp235x_hal::set_tear_after_bytes(Some(100));
    let _ = d.change_pin(TEST_PIN, b"5678");
    assert!(rp235x_hal::torn());
    rp235x_hal::set_tear_after_bytes(None);
    reboot(&mut d);
    assert_eq!(overflow(0), ov0);
    assert_eq!(
        d.store.active_count(),
        2,
        "the overflow passkeys did not survive a torn main write"
    );
    assert_eq!(assert_at(&mut d, &rp(MAX_SLOTS)).0, CTAP2_OK);
    assert_eq!(assert_at(&mut d, &rp(MAX_SLOTS + 1)).0, CTAP2_OK);
}
