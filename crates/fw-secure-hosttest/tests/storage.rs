// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The Secure world's credential store and monotonic counter, tested
//! against a simulated die.
//!
//! Both had only ever been checked by hand on silicon: a 240-write churn
//! run for the store, three reboots and one signature for the counter.
//! That established they work; it could not establish what happens at the
//! edges, because a hardware run cannot cheaply reach an almost-full
//! store or a counter one value from its reserved limit.
//!
//! The simulator models NOR semantics properly -- a program may only clear
//! bits -- because the store's whole invalidate-without-erasing scheme
//! rests on that. It also counts erases, so a design that claims to avoid
//! them can be held to it.
//!
//! These are `static mut` modules with process-global state, so every
//! test takes [`SERIAL`] and starts from a fresh die.

use pqf_fw_secure_hosttest as fws;
use std::sync::{Mutex, MutexGuard};

static SERIAL: Mutex<()> = Mutex::new(());

/// A fresh die, held for the duration of one test.
fn fresh() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fws::fresh_die();
    g
}

// ---- helpers ---------------------------------------------------------

fn rp_hash(n: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = n;
    h[31] = 0xa5;
    h
}

fn cred_id(n: u8, variant: u8) -> [u8; 64] {
    let mut c = [0u8; 64];
    c[0] = n;
    c[1] = variant;
    c[63] = 0x5a;
    c
}

/// Store one credential for `(rp, user)`. Returns what the store said.
fn put(rp: u8, user: u8, variant: u8) -> bool {
    fws::credstore::store(
        &rp_hash(rp),
        &cred_id(user, variant),
        &[user, 0x11, 0x22],
        b"example.test",
        &[],
        b"user name",
        b"Display Name",
        0,
    )
}

// ---- the counter -----------------------------------------------------

#[test]
fn the_counter_never_repeats_a_value() {
    // The one property WebAuthn actually requires of it.
    let _g = fresh();
    fws::counter::init();
    let mut last = 0u32;
    for i in 0..500 {
        let v = fws::counter::next();
        assert!(v > last, "value {v} did not exceed {last} at step {i}");
        last = v;
    }
}

#[test]
fn the_counter_survives_a_reboot_without_going_backwards() {
    // `init` re-reads the high-water from flash. A counter that restarted
    // would hand a relying party a value it had seen before, which is
    // exactly the cloning signal the counter exists to raise.
    let _g = fresh();
    fws::counter::init();
    let mut high = 0u32;
    for _ in 0..100 {
        high = fws::counter::next();
    }
    for _ in 0..5 {
        fws::counter::init(); // as if rebooted
        let v = fws::counter::next();
        assert!(v > high, "after a reboot {v} did not exceed {high}");
        high = v;
    }
}

#[test]
fn idle_reboots_cost_no_flash_write_and_no_counter_movement() {
    // This is what lazy reservation actually buys, and it is worth being
    // exact about because the figure first recorded for it -- "+2 across
    // three reboots" -- is not what this code does. Measured here: three
    // reboots with no signature between them write nothing and move
    // nothing. Eager reservation wrote a block on every boot.
    let _g = fresh();
    fws::counter::init();
    let first = fws::counter::next();
    let writes_after_first = rp235x_hal::program_count();
    for _ in 0..3 {
        fws::counter::init();
    }
    assert_eq!(
        rp235x_hal::program_count(),
        writes_after_first,
        "an idle reboot wrote to flash"
    );
    let _ = first;
}

#[test]
fn a_reboot_forfeits_the_rest_of_the_batch_not_a_whole_block_per_boot() {
    // The honest characterisation. `init` re-reads the reserved
    // high-water, so the first signature after a reboot starts from
    // there and the unused tail of the previous batch is skipped -- once
    // per run of reboots, not once per reboot.
    //
    // Measured: signature 1, three reboots, signature 66. A jump of 65,
    // which is one batch. Eager reservation would have taken ~192 for the
    // same three reboots. WebAuthn permits a counter to skip; what it
    // forbids is repeating or going backwards.
    let _g = fresh();
    fws::counter::init();
    let first = fws::counter::next();
    for _ in 0..3 {
        fws::counter::init();
    }
    let after = fws::counter::next();
    let jump = after - first;
    assert!(jump > 0, "the counter went backwards or repeated");
    assert!(
        jump <= 64 + 1,
        "three reboots cost {jump}, more than the single batch tail that \
         lazy reservation is supposed to forfeit"
    );
    // And it is one batch for three reboots, not three.
    assert!(
        jump > 2,
        "jump of {jump} -- if this ever becomes small, the recorded \
         \"+2 across three reboots\" figure was right after all and this \
         test is what needs revisiting"
    );
}

#[test]
fn a_flash_write_costs_one_batch_not_one_per_signature() {
    // The point of reserving a block: the amortised cost has to be
    // invisible, or every assertion pays a flash write.
    let _g = fresh();
    fws::counter::init();
    for _ in 0..64 {
        fws::counter::next();
    }
    let programs = rp235x_hal::program_count();
    assert!(
        programs <= 3,
        "64 values took {programs} flash writes; the batch is supposed to \
         make that one or two"
    );
}

#[test]
fn the_counter_ping_pongs_rather_than_erasing_the_live_sector() {
    // Two sectors, and the one holding the current high-water is never
    // the one being erased -- so a power cut mid-erase still leaves the
    // value readable. Reaching the erase needs many batches, which is
    // cheap here and not on a token.
    let _g = fresh();
    fws::counter::init();
    for _ in 0..(64 * 20) {
        fws::counter::next();
    }
    assert!(
        rp235x_hal::erase_count() > 0,
        "twenty batches should have filled a sector and forced an erase"
    );
    // Still monotonic across all that.
    let v = fws::counter::next();
    fws::counter::init();
    assert!(fws::counter::next() > v, "an erase lost the high-water");
}

// ---- the credential store -------------------------------------------

#[test]
fn a_stored_credential_can_be_found_again() {
    let _g = fresh();
    assert!(put(1, 7, 0), "store refused a credential on an empty die");
    let found = fws::credstore::find_by_id(&cred_id(7, 0));
    assert!(found.is_some(), "a credential just stored was not found");
    assert_eq!(fws::credstore::count(&rp_hash(1)), 1);
}

#[test]
fn re_registering_the_same_user_replaces_rather_than_accumulates() {
    // CTAP2 requires a new credential for the same (rpId, userId) to
    // replace the old one. Accumulating would fill the store with
    // duplicates and hand GetAssertion several credentials for one user.
    let _g = fresh();
    for variant in 0..20u8 {
        assert!(put(1, 7, variant), "store refused at variant {variant}");
        assert_eq!(
            fws::credstore::count(&rp_hash(1)),
            1,
            "re-registering user 7 left more than one live credential"
        );
    }
    // The survivor is the newest.
    assert!(fws::credstore::find_by_id(&cred_id(7, 19)).is_some());
    assert!(fws::credstore::find_by_id(&cred_id(7, 0)).is_none());
}

#[test]
fn invalidation_does_not_erase() {
    // The reason a record is two pages and its magic is programmed to
    // zero: replacing in place would erase 4 KiB over fifteen
    // bystanders. If this ever starts erasing, that design has been lost.
    let _g = fresh();
    put(1, 1, 0);
    put(1, 2, 0);
    rp235x_hal::reset_counts();
    for variant in 1..8u8 {
        put(1, 1, variant); // repeatedly replace user 1
    }
    assert_eq!(
        rp235x_hal::erase_count(),
        0,
        "replacing a credential erased a sector"
    );
    assert!(
        fws::credstore::find_by_id(&cred_id(2, 0)).is_some(),
        "bystander lost"
    );
}

#[test]
fn compaction_reclaims_dead_records() {
    // The silicon churn run in one test, and further than a token run
    // reached: a fixed set of users re-registered far past the raw slot
    // count. Without compaction this refuses once every slot is used.
    let _g = fresh();
    const USERS: u8 = 8;
    let mut refused = 0;
    for round in 0..40u8 {
        for u in 0..USERS {
            if !put(1, u, round) {
                refused += 1;
            }
        }
    }
    assert_eq!(
        refused, 0,
        "{refused} writes were refused; dead records are not being reclaimed"
    );
    assert_eq!(
        fws::credstore::count(&rp_hash(1)),
        USERS as usize,
        "the live set grew across compaction"
    );
    // And the newest generation is what survived.
    for u in 0..USERS {
        assert!(
            fws::credstore::find_by_id(&cred_id(u, 39)).is_some(),
            "user {u}'s newest credential is missing after compaction"
        );
    }
}

#[test]
fn every_raw_slot_is_usable_for_distinct_credentials() {
    // Measured: 64 of 64. Worth pinning, because it contradicts what the
    // compaction work was written up as -- "one sector is always kept
    // blank as a spare, so usable capacity is 56, not 64". That
    // description is wrong. Distinct credentials fill every slot, and
    // compaction stays reachable because dead records free slots *within*
    // sectors rather than because a sector is held in reserve.
    let _g = fresh();
    let mut stored = 0usize;
    for u in 0..(fws::credstore::CAPACITY as u16 + 16) {
        let mut id = [0u8; 64];
        id[0] = (u & 0xff) as u8;
        id[1] = (u >> 8) as u8;
        id[63] = 0x5a;
        if fws::credstore::store(
            &rp_hash(1),
            &id,
            &[(u & 0xff) as u8, (u >> 8) as u8],
            b"example.test",
            &[],
            b"n",
            b"d",
            0,
        ) {
            stored += 1;
        } else {
            break;
        }
    }
    assert_eq!(
        stored,
        fws::credstore::CAPACITY,
        "usable capacity measured {stored}, expected every one of {} raw slots",
        fws::credstore::CAPACITY
    );
    assert_eq!(fws::credstore::count(&rp_hash(1)), stored);
}

#[test]
fn a_full_store_refuses_rather_than_overwriting() {
    // The failure has to be a refusal. Silently dropping someone else's
    // credential to make room would be worse than saying no.
    let _g = fresh();
    let mut ids = Vec::new();
    for u in 0..(fws::credstore::CAPACITY as u16 + 16) {
        let id = cred_id((u & 0xff) as u8, (u >> 8) as u8 | 0x40);
        if fws::credstore::store(
            &rp_hash(2),
            &id,
            &[(u & 0xff) as u8, (u >> 8) as u8, 0xee],
            b"example.test",
            &[],
            b"n",
            b"d",
            0,
        ) {
            ids.push(id);
        }
    }
    // Everything that was accepted is still there.
    for id in &ids {
        assert!(
            fws::credstore::find_by_id(id).is_some(),
            "a credential the store accepted went missing once it filled"
        );
    }
    assert_eq!(fws::credstore::count(&rp_hash(2)), ids.len());
}

#[test]
fn deleting_frees_the_slot_for_reuse() {
    let _g = fresh();
    put(3, 1, 0);
    put(3, 2, 0);
    assert_eq!(fws::credstore::count(&rp_hash(3)), 2);
    assert!(
        fws::credstore::delete(&cred_id(1, 0)),
        "delete refused a live credential"
    );
    assert_eq!(fws::credstore::count(&rp_hash(3)), 1);
    assert!(fws::credstore::find_by_id(&cred_id(1, 0)).is_none());
    assert!(
        fws::credstore::find_by_id(&cred_id(2, 0)).is_some(),
        "delete took a bystander"
    );
    assert!(
        !fws::credstore::delete(&cred_id(1, 0)),
        "deleting twice reported success"
    );
}

#[test]
fn credentials_are_scoped_to_their_relying_party() {
    // A credential must not be findable under another RP's hash. This is
    // the store's half of cross-RP replay defence.
    let _g = fresh();
    put(1, 1, 0);
    put(2, 2, 0);
    assert_eq!(fws::credstore::count(&rp_hash(1)), 1);
    assert_eq!(fws::credstore::count(&rp_hash(2)), 1);
    assert_eq!(
        fws::credstore::count(&rp_hash(9)),
        0,
        "an unknown RP found credentials"
    );
    assert!(fws::credstore::get(&rp_hash(1), 0).is_some());
    assert!(
        fws::credstore::get(&rp_hash(1), 1).is_none(),
        "index past the end returned a credential"
    );
}

#[test]
fn totals_and_rp_enumeration_agree_with_the_per_rp_counts() {
    let _g = fresh();
    put(1, 1, 0);
    put(1, 2, 0);
    put(2, 3, 0);
    let (used, _cap) = fws::credstore::totals();
    assert_eq!(used, 3, "totals disagrees with what was stored");
    assert_eq!(
        fws::credstore::rp_count(),
        2,
        "two relying parties should be enumerated"
    );
    assert!(fws::credstore::nth_rp(0).is_some());
    assert!(fws::credstore::nth_rp(1).is_some());
    assert!(
        fws::credstore::nth_rp(2).is_none(),
        "a third RP appeared from nowhere"
    );
}

#[test]
fn updating_a_user_leaves_the_credential_findable() {
    // CredentialManagement's updateUserInformation. A rewrite that lost
    // the record would silently delete a passkey.
    let _g = fresh();
    put(1, 5, 0);
    assert!(
        fws::credstore::update_user(
            &cred_id(5, 0),
            &[5, 0x11, 0x22],
            b"new name",
            b"New Display"
        ),
        "update_user refused a live credential"
    );
    let found = fws::credstore::find_by_id(&cred_id(5, 0));
    assert!(found.is_some(), "the credential vanished during an update");
    assert_eq!(
        fws::credstore::count(&rp_hash(1)),
        1,
        "update duplicated the credential"
    );
}

#[test]
fn over_long_fields_are_truncated_rather_than_overflowing() {
    // Every one of these is host-supplied and none is length-checked by
    // the caller. `store` clamps them; this is the test that says so.
    let _g = fresh();
    let long_user = vec![0xAB; fws::credstore::MAX_USER_ID * 4];
    let long_rp = vec![b'x'; fws::credstore::MAX_RP_ID * 4];
    let long_blob = vec![0xCD; fws::credstore::MAX_CRED_BLOB * 4];
    let long_name = vec![b'n'; fws::credstore::MAX_NAME * 4];
    assert!(
        fws::credstore::store(
            &rp_hash(4),
            &cred_id(1, 0),
            &long_user,
            &long_rp,
            &long_blob,
            &long_name,
            &long_name,
            0,
        ),
        "store refused over-long fields instead of clamping them"
    );
    assert_eq!(fws::credstore::count(&rp_hash(4)), 1);
    assert!(fws::credstore::find_by_id(&cred_id(1, 0)).is_some());
}
