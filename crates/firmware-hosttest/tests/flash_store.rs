// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The Rust firmware's flash store, against a simulated die.
//!
//! Three sectors: the credential store, the device master keys, and the
//! largeBlob array. The master keys are the root of everything -- every
//! credential id on the token is sealed under them, so losing or
//! corrupting that sector orphans every passkey the user has.
//!
//! The simulator models NOR properly: a program may only clear bits,
//! never set them. It also counts erases, which is what lets "this
//! design avoids erasing" be a test rather than a claim.

use pqf_firmware_hosttest as fw;
use std::sync::{Mutex, MutexGuard};

use fw::flash_store::{
    self, StoredCredential, StoredImage, MAX_LARGE_BLOB_LEN, MAX_SLOTS, STATE_ACTIVE, STATE_EMPTY,
    STATE_TOMBSTONE, STORED_CRED_ID_LEN,
};

static SERIAL: Mutex<()> = Mutex::new(());

fn fresh() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    rp235x_hal::reset();
    rp235x_hal::reset_counts();
    g
}

fn cred(n: u8) -> StoredCredential {
    let mut c: StoredCredential = unsafe { core::mem::zeroed() };
    c.state = STATE_ACTIVE;
    c.credential_id = [n; STORED_CRED_ID_LEN];
    c.rp_id_hash = [n ^ 0x5a; 32];
    c
}

// ---- the master key sector -------------------------------------------

#[test]
fn a_blank_die_reports_no_master_keys() {
    // The distinction that matters at first boot: "no keys yet, mint
    // some" versus "keys that happen to be all ones". Getting it wrong
    // means every credential derives from 0xff repeated.
    let _g = fresh();
    assert!(
        flash_store::read_key_sector().is_none(),
        "erased flash was read back as a valid key sector"
    );
}

#[test]
fn master_keys_round_trip_and_survive_a_reread() {
    let _g = fresh();
    let aes: [u8; 32] = core::array::from_fn(|i| i as u8 ^ 0x33);
    let hmac: [u8; 32] = core::array::from_fn(|i| i as u8 ^ 0xcc);
    flash_store::write_key_sector(&aes, &hmac);

    let (a, h) = flash_store::read_key_sector().expect("the keys just written were not found");
    assert_eq!(a, aes, "the AES key came back altered");
    assert_eq!(h, hmac, "the HMAC key came back altered");

    // And again -- a read must not be destructive.
    let (a2, h2) = flash_store::read_key_sector().unwrap();
    assert_eq!(a2, aes);
    assert_eq!(h2, hmac);
}

#[test]
fn the_two_master_keys_are_kept_distinct() {
    // They are used for different purposes -- one seals the credential
    // id, one authenticates it. Swapping or aliasing them would still
    // "work" for round trips while destroying the separation.
    let _g = fresh();
    let aes = [0x11u8; 32];
    let hmac = [0x22u8; 32];
    flash_store::write_key_sector(&aes, &hmac);
    let (a, h) = flash_store::read_key_sector().unwrap();
    assert_eq!(a, aes);
    assert_eq!(h, hmac);
    assert_ne!(a, h, "the two keys came back identical");
}

#[test]
fn rewriting_the_key_sector_replaces_rather_than_ands() {
    // NOR programming can only clear bits, so writing over a live sector
    // without erasing first yields the bitwise AND of old and new. That
    // would be a master key that is neither, and every existing
    // credential would stop decrypting.
    let _g = fresh();
    let first = [0xf0u8; 32];
    flash_store::write_key_sector(&first, &first);
    let second = [0x0fu8; 32];
    flash_store::write_key_sector(&second, &second);
    let (a, _) = flash_store::read_key_sector().expect("the key sector vanished");
    assert_ne!(a, [0x00u8; 32], "the two writes were ANDed together");
    assert_eq!(a, second, "the rewrite did not take");
}

// ---- the credential sector -------------------------------------------

#[test]
fn a_blank_die_reports_no_credential_image() {
    let _g = fresh();
    assert!(
        flash_store::read_sector().is_none(),
        "erased flash was read back as a valid credential image"
    );
}

#[test]
fn a_credential_image_round_trips() {
    let _g = fresh();
    let mut img: StoredImage = unsafe { core::mem::zeroed() };
    img.creds[0] = cred(1);
    img.creds[1] = cred(2);
    flash_store::write_sector(&img);

    let back = flash_store::read_sector().expect("the image just written was not found");
    assert_eq!(back.creds[0].state, STATE_ACTIVE);
    assert_eq!(
        back.creds[0].credential_id, img.creds[0].credential_id,
        "a credential id changed"
    );
    assert_eq!(back.creds[1].rp_id_hash, img.creds[1].rp_id_hash);
}

#[test]
fn an_empty_slot_stays_empty_and_a_tombstone_stays_dead() {
    // The three states have to survive a round trip distinctly, because
    // they are what the allocator reads to decide where a new credential
    // goes and which ones to enumerate.
    let _g = fresh();
    let mut img: StoredImage = unsafe { core::mem::zeroed() };
    img.creds[0] = cred(1);
    img.creds[1].state = STATE_EMPTY;
    img.creds[2] = cred(3);
    img.creds[2].state = STATE_TOMBSTONE;
    flash_store::write_sector(&img);

    let back = flash_store::read_sector().unwrap();
    assert_eq!(back.creds[0].state, STATE_ACTIVE);
    assert_eq!(back.creds[1].state, STATE_EMPTY);
    assert_eq!(back.creds[2].state, STATE_TOMBSTONE);
}

#[test]
fn every_slot_the_layout_claims_is_usable() {
    // MAX_SLOTS is derived from the sector size and the record size. If
    // the arithmetic were wrong the last slot would straddle the sector
    // boundary, and the failure would be a credential that vanishes.
    let _g = fresh();
    let mut img: StoredImage = unsafe { core::mem::zeroed() };
    for i in 0..MAX_SLOTS {
        img.creds[i] = cred((i % 250) as u8 + 1);
    }
    flash_store::write_sector(&img);
    let back = flash_store::read_sector().expect("a full image was not readable");
    for i in 0..MAX_SLOTS {
        assert_eq!(
            back.creds[i].state, STATE_ACTIVE,
            "slot {i} of {MAX_SLOTS} did not survive the round trip"
        );
        assert_eq!(
            back.creds[i].credential_id, img.creds[i].credential_id,
            "slot {i} corrupted"
        );
    }
}

#[test]
fn rewriting_the_credential_sector_replaces_rather_than_ands() {
    let _g = fresh();
    let mut a: StoredImage = unsafe { core::mem::zeroed() };
    a.creds[0] = cred(0xf0);
    flash_store::write_sector(&a);

    let mut b: StoredImage = unsafe { core::mem::zeroed() };
    b.creds[0] = cred(0x0f);
    flash_store::write_sector(&b);

    let back = flash_store::read_sector().unwrap();
    assert_eq!(
        back.creds[0].credential_id, b.creds[0].credential_id,
        "the second image was ANDed into the first instead of replacing it"
    );
}

// ---- the largeBlob sector --------------------------------------------

#[test]
fn a_blank_die_has_no_large_blob_array() {
    let _g = fresh();
    assert!(
        flash_store::read_large_blob_sector().is_none(),
        "erased flash was read back as a largeBlob array"
    );
}

#[test]
fn a_large_blob_array_round_trips() {
    let _g = fresh();
    let blob: Vec<u8> = (0..512u16).map(|i| i as u8).collect();
    flash_store::write_large_blob_sector(&blob);
    let back = flash_store::read_large_blob_sector().expect("the array was not found");
    assert_eq!(back, blob, "the largeBlob array came back altered");
}

#[test]
fn an_array_of_the_maximum_length_round_trips() {
    // MAX_LARGE_BLOB_LEN is what getInfo advertises as
    // maxSerializedLargeBlobArray. If the last byte did not survive, a
    // client filling the array to the advertised limit would silently
    // lose data.
    let _g = fresh();
    let blob: Vec<u8> = (0..MAX_LARGE_BLOB_LEN).map(|i| (i % 251) as u8).collect();
    flash_store::write_large_blob_sector(&blob);
    let back = flash_store::read_large_blob_sector().expect("a maximum array was not found");
    assert_eq!(back.len(), MAX_LARGE_BLOB_LEN, "the array was truncated");
    assert_eq!(back, blob);
}

#[test]
fn an_empty_array_is_distinguishable_from_no_array() {
    // A client can legitimately store an empty serialised array, and
    // that is not the same as a token that has never had one.
    let _g = fresh();
    flash_store::write_large_blob_sector(&[]);
    let back = flash_store::read_large_blob_sector();
    assert!(back.is_some(), "an empty array read back as absent");
    assert!(back.unwrap().is_empty());
}

#[test]
fn resetting_the_array_returns_the_sector_to_absent() {
    let _g = fresh();
    flash_store::write_large_blob_sector(&[1, 2, 3, 4]);
    assert!(flash_store::read_large_blob_sector().is_some());
    flash_store::reset_large_blob_sector();
    let back = flash_store::read_large_blob_sector();
    assert!(
        back.is_none() || back.unwrap().is_empty(),
        "a reset array still held its old contents"
    );
}

#[test]
fn the_large_blob_array_can_be_rewritten_shorter() {
    // Shrinking is the case a bitwise-AND bug hides in: the tail of the
    // old array is still on the die, and a length that was not rewritten
    // would hand it back.
    let _g = fresh();
    let long: Vec<u8> = (0..1024u16).map(|i| i as u8).collect();
    flash_store::write_large_blob_sector(&long);
    let short = vec![0xAAu8; 16];
    flash_store::write_large_blob_sector(&short);
    let back = flash_store::read_large_blob_sector().expect("the array vanished");
    assert_eq!(back.len(), short.len(), "the array kept its old length");
    assert_eq!(back, short, "the array kept some of its old contents");
}

// ---- the sectors do not collide --------------------------------------

#[test]
fn the_three_sectors_are_independent() {
    // They are adjacent in flash and each is written with a sector
    // erase. An off-by-one in an offset would have one write wipe its
    // neighbour, and the symptom would be losing every credential the
    // first time a largeBlob is stored.
    let _g = fresh();
    let aes = [0x11u8; 32];
    let hmac = [0x22u8; 32];
    flash_store::write_key_sector(&aes, &hmac);

    let mut img: StoredImage = unsafe { core::mem::zeroed() };
    img.creds[0] = cred(7);
    flash_store::write_sector(&img);

    let blob = vec![0x5Au8; 300];
    flash_store::write_large_blob_sector(&blob);

    // All three still there, after all three writes.
    let (a, h) = flash_store::read_key_sector().expect("the key sector was wiped");
    assert_eq!(a, aes);
    assert_eq!(h, hmac);
    let back = flash_store::read_sector().expect("the credential sector was wiped");
    assert_eq!(back.creds[0].credential_id, img.creds[0].credential_id);
    let lb = flash_store::read_large_blob_sector().expect("the largeBlob sector was wiped");
    assert_eq!(lb, blob);
}

#[test]
fn writing_a_credential_does_not_disturb_the_master_keys() {
    // The one ordering that matters most: credentials are written far
    // more often than keys, so a collision here would surface as a token
    // that works until it is used.
    let _g = fresh();
    let aes = [0xA5u8; 32];
    flash_store::write_key_sector(&aes, &aes);
    for round in 0..8u8 {
        let mut img: StoredImage = unsafe { core::mem::zeroed() };
        img.creds[0] = cred(round + 1);
        flash_store::write_sector(&img);
        let (a, _) = flash_store::read_key_sector()
            .unwrap_or_else(|| panic!("the key sector was lost on round {round}"));
        assert_eq!(a, aes, "the master key changed on round {round}");
    }
}
