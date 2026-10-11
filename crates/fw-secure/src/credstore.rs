// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Resident (discoverable) credentials, in Secure flash.
//!
//! Until now getInfo reported `rk:false` and meant it: every credential
//! was stateless, recoverable only from an id the relying party handed
//! back. A discoverable credential has to survive on the token, which
//! means storing the user handle next to the credential id -- and that
//! is exactly the kind of data the boundary exists to keep away from
//! the Non-secure world, so the store is Secure-only like the key
//! sector and the counter.
//!
//! ## Layout
//!
//! Eight 4 KiB sectors at [`BASE`], eight 512-byte records each: 64
//! credentials. Two pages per record rather than one: Credential-
//! Management enumerates relying parties by *name* rather than by hash,
//! and credBlob adds another 32 bytes, which together no longer fit a
//! 256-byte page. Records stay page-aligned, so one can still be
//! written without touching its neighbours.
//!
//! ## Invalidation without erasing
//!
//! CTAP2 says a new credential for the same (rpId, userId) replaces the
//! old one. Replacing in place would mean an erase, which is a 4 KiB
//! operation over fifteen bystanders. Instead the old record's magic is
//! programmed to zero -- flash can always clear bits, never set them --
//! so invalidation costs one page write and no erase at all. A sector
//! is only erased once every record in it is dead.
//!
//! ## Compaction
//!
//! Retiring a record frees its slot only in principle: the slot cannot
//! be reused until its whole sector is erased. So a store that churns
//! -- register, replace, register again -- eventually reports itself
//! full while most of it is dead records.
//!
//! Reclaiming them needs somewhere to put the survivors, which is why
//! **one sector is always kept entirely blank as a spare**. Allocation
//! therefore prefers a sector that is already partly used, and only
//! opens a fresh one while more than one blank sector remains. That
//! invariant is what makes compaction possible at all: without it,
//! "no blank slot" and "nowhere to evacuate to" arrive together and
//! nothing can ever be reclaimed.
//!
//! [`compact`] then copies the live records out of the emptiest sector
//! into the spare and erases it, so the victim becomes the new spare.
//! **The copy completes before the erase begins**, so a power cut
//! anywhere in the middle leaves every record present at least once,
//! never zero times. Duplicates are harmless -- lookups take the first
//! match and the stale copy is retired on the next write -- whereas a
//! missing credential is unrecoverable.
//!
//! Usable capacity is therefore 56 credentials, not 64: seven sectors
//! of eight, with the eighth always in reserve.

use crate::flash::flash_op;
use hal::rom_data;
use rp235x_hal as hal;

/// Eight sectors immediately above the Non-secure image region and
/// below the counter's pair. Outside SAU region 0 (which ends at
/// 0x101EFFFF), so Secure-only.
const BASE: u32 = 0x1F_0000;
const SECTOR_COUNT: usize = 8;
const SECTOR_SIZE: usize = 4096;
const PAGE_SIZE: usize = 256;
/// A record spans two pages.
const RECORD_SIZE: usize = 2 * PAGE_SIZE;
const SLOTS_PER_SECTOR: usize = SECTOR_SIZE / RECORD_SIZE;
pub const CAPACITY: usize = SECTOR_COUNT * SLOTS_PER_SECTOR;
/// Base of the XIP window the store is read through.
///
/// A real address on the board. On a host build -- which exists so this
/// module's awkward cases can be tested without a token, see
/// `crates/fw-secure-hosttest` -- it is the base of a simulated die
/// instead, because nothing else here needs to change to be testable:
/// every read goes through one pointer helper and every write through
/// `rom_data`.
#[cfg(any(target_arch = "arm", target_arch = "riscv32"))]
const XIP_BASE: usize = 0x1000_0000;
#[cfg(not(any(target_arch = "arm", target_arch = "riscv32")))]
#[allow(non_snake_case)]
fn XIP_BASE_fn() -> usize {
    hal::window() as usize
}
#[inline]
fn xip_base() -> usize {
    #[cfg(any(target_arch = "arm", target_arch = "riscv32"))]
    {
        XIP_BASE
    }
    #[cfg(not(any(target_arch = "arm", target_arch = "riscv32")))]
    {
        XIP_BASE_fn()
    }
}

/// 4 KiB sector erase (W25Q). NOT 0xd8, the 64 KiB block erase.
const BLOCK_ERASE_CMD: u8 = 0x20;

const MAGIC: u32 = 0x545a_5232; // "TZR2" -- bumped with the record layout
pub const MAX_USER_ID: usize = 64;
pub const MAX_RP_ID: usize = 128;
/// Advertised as maxCredBlobLength; CTAP2 requires at least 32.
pub const MAX_CRED_BLOB: usize = 32;
/// User name and display name. CredentialManagement enumerates them,
/// and updateUserInformation exists to change them -- so they have to
/// be stored, not just accepted and dropped.
pub const MAX_NAME: usize = 64;

// Record field offsets.
const OFF_MAGIC: usize = 0;
const OFF_RP: usize = 4;
const OFF_CRED: usize = 36;
const OFF_USER_LEN: usize = 100;
const OFF_USER: usize = 101;
const OFF_RP_ID_LEN: usize = 165;
const OFF_RP_ID: usize = 166;
const OFF_BLOB_LEN: usize = 294;
const OFF_BLOB: usize = 295;
const OFF_NAME_LEN: usize = 327;
const OFF_NAME: usize = 328;
const OFF_DISPLAY_LEN: usize = 392;
const OFF_DISPLAY: usize = 393;
const OFF_PROTECT: usize = 457;

/// One stored credential, as handed back to the CTAP2 layer.
pub struct Resident {
    pub cred_id: [u8; 64],
    pub user_id: [u8; MAX_USER_ID],
    pub user_id_len: usize,
    pub rp_id: [u8; MAX_RP_ID],
    pub rp_id_len: usize,
    pub blob: [u8; MAX_CRED_BLOB],
    pub blob_len: usize,
    pub name: [u8; MAX_NAME],
    pub name_len: usize,
    pub display: [u8; MAX_NAME],
    pub display_len: usize,
    /// credProtect policy 1..3, 0 if none was requested.
    pub cred_protect: u8,
}

fn slot_ptr(sector: usize, slot: usize) -> *const u8 {
    (xip_base() + BASE as usize + sector * SECTOR_SIZE + slot * RECORD_SIZE) as *const u8
}

fn read_u32(p: *const u8, off: usize) -> u32 {
    // SAFETY: reading our own reserved sectors through the XIP window.
    unsafe { core::ptr::read_unaligned(p.add(off) as *const u32) }
}

fn is_valid(sector: usize, slot: usize) -> bool {
    read_u32(slot_ptr(sector, slot), OFF_MAGIC) == MAGIC
}

/// Erased means every byte reads 0xff. "Not valid" is a different
/// question -- an invalidated record has a zeroed magic but is not
/// writable, and treating the two as the same silently corrupts the
/// next write. (The counter learned this the hard way.)
fn is_blank(sector: usize, slot: usize) -> bool {
    let p = slot_ptr(sector, slot);
    // SAFETY: as above.
    (0..RECORD_SIZE).all(|i| unsafe { core::ptr::read_volatile(p.add(i)) } == 0xff)
}

fn record_rp(sector: usize, slot: usize) -> [u8; 32] {
    let p = slot_ptr(sector, slot);
    let mut out = [0u8; 32];
    // SAFETY: as above.
    unsafe { core::ptr::copy_nonoverlapping(p.add(OFF_RP), out.as_mut_ptr(), 32) };
    out
}

fn record_user(sector: usize, slot: usize) -> ([u8; MAX_USER_ID], usize) {
    let p = slot_ptr(sector, slot);
    let mut out = [0u8; MAX_USER_ID];
    // SAFETY: as above.
    let len = unsafe {
        core::ptr::copy_nonoverlapping(p.add(OFF_USER), out.as_mut_ptr(), MAX_USER_ID);
        core::ptr::read_volatile(p.add(OFF_USER_LEN)) as usize
    };
    (out, len.min(MAX_USER_ID))
}

fn record_cred(sector: usize, slot: usize) -> [u8; 64] {
    let p = slot_ptr(sector, slot);
    let mut out = [0u8; 64];
    // SAFETY: as above.
    unsafe { core::ptr::copy_nonoverlapping(p.add(OFF_CRED), out.as_mut_ptr(), 64) };
    out
}

fn program(sector: usize, slot: usize, page: &[u8; RECORD_SIZE]) {
    let addr = BASE + (sector * SECTOR_SIZE + slot * RECORD_SIZE) as u32;
    // SAFETY: `flash_op` upholds the no-XIP contract; `page` is a RAM
    // buffer that stays readable while XIP is suspended.
    unsafe {
        flash_op(|| {
            rom_data::connect_internal_flash();
            rom_data::flash_exit_xip();
            rom_data::flash_range_program(addr, page.as_ptr(), RECORD_SIZE);
            rom_data::flash_flush_cache();
            rom_data::flash_enter_cmd_xip();
        });
    }
}

fn erase(sector: usize) {
    let addr = BASE + (sector * SECTOR_SIZE) as u32;
    // SAFETY: as `program`.
    unsafe {
        flash_op(|| {
            rom_data::connect_internal_flash();
            rom_data::flash_exit_xip();
            rom_data::flash_range_erase(addr, SECTOR_SIZE, SECTOR_SIZE as u32, BLOCK_ERASE_CMD);
            rom_data::flash_flush_cache();
            rom_data::flash_enter_cmd_xip();
        });
    }
}

/// Retire a record by clearing its magic. No erase: programming can
/// always drive bits from 1 to 0, and every other byte is left as-is.
fn invalidate(sector: usize, slot: usize) {
    let p = slot_ptr(sector, slot);
    let mut page = [0u8; RECORD_SIZE];
    // SAFETY: reading the record we are about to rewrite.
    unsafe { core::ptr::copy_nonoverlapping(p, page.as_mut_ptr(), RECORD_SIZE) };
    page[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&[0u8; 4]);
    program(sector, slot, &page);
}

/// Store a discoverable credential, replacing any existing one for the
/// same relying party and user. False when the store is full.
pub fn store(
    rp_id_hash: &[u8; 32],
    cred_id: &[u8; 64],
    user_id: &[u8],
    rp_id: &[u8],
    blob: &[u8],
    name: &[u8],
    display: &[u8],
    cred_protect: u8,
) -> bool {
    let ulen = user_id.len().min(MAX_USER_ID);
    let rlen = rp_id.len().min(MAX_RP_ID);
    let blen = blob.len().min(MAX_CRED_BLOB);
    let nlen = name.len().min(MAX_NAME);
    let dlen = display.len().min(MAX_NAME);

    // CTAP2: one credential per (rpId, userId). Retire the old first,
    // so a full store still replaces rather than refusing.
    for s in 0..SECTOR_COUNT {
        for slot in 0..SLOTS_PER_SECTOR {
            if !is_valid(s, slot) || record_rp(s, slot) != *rp_id_hash {
                continue;
            }
            let (u, l) = record_user(s, slot);
            if l == ulen && u[..ulen] == user_id[..ulen] {
                invalidate(s, slot);
            }
        }
    }

    let mut page = [0u8; RECORD_SIZE];
    page[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC.to_le_bytes());
    page[OFF_RP..OFF_RP + 32].copy_from_slice(rp_id_hash);
    page[OFF_CRED..OFF_CRED + 64].copy_from_slice(cred_id);
    page[OFF_USER_LEN] = ulen as u8;
    page[OFF_USER..OFF_USER + ulen].copy_from_slice(&user_id[..ulen]);
    page[OFF_RP_ID_LEN] = rlen as u8;
    page[OFF_RP_ID..OFF_RP_ID + rlen].copy_from_slice(&rp_id[..rlen]);
    page[OFF_BLOB_LEN] = blen as u8;
    page[OFF_BLOB..OFF_BLOB + blen].copy_from_slice(&blob[..blen]);
    page[OFF_NAME_LEN] = nlen as u8;
    page[OFF_NAME..OFF_NAME + nlen].copy_from_slice(&name[..nlen]);
    page[OFF_DISPLAY_LEN] = dlen as u8;
    page[OFF_DISPLAY..OFF_DISPLAY + dlen].copy_from_slice(&display[..dlen]);
    page[OFF_PROTECT] = cred_protect;

    if let Some((s, slot)) = first_blank() {
        program(s, slot, &page);
        return true;
    }
    // No blank slot. A sector with nothing live in it is free to
    // reclaim; otherwise try to make one.
    for s in 0..SECTOR_COUNT {
        if (0..SLOTS_PER_SECTOR).all(|slot| !is_valid(s, slot)) {
            erase(s);
            program(s, 0, &page);
            return true;
        }
    }
    if compact() {
        if let Some((s, slot)) = first_blank() {
            program(s, slot, &page);
            return true;
        }
    }
    false
}

/// Reclaim the emptiest sector by evacuating it into the spare.
///
/// Returns false when nothing can be gained, which means the store
/// really is full rather than merely fragmented.
///
/// The safety argument is the ordering: every live record is copied
/// into the spare BEFORE the victim is erased, so a power cut in the
/// middle leaves each record present at least once. Duplicates are
/// tolerable (first match wins, stale copy retired on the next write);
/// a lost credential is not.
fn compact() -> bool {
    // The spare. The allocation invariant keeps one, but check rather
    // than assume -- erasing a victim with nowhere to put its
    // survivors is exactly the failure this must never cause.
    let spare = match (0..SECTOR_COUNT).find(|&s| sector_blank(s)) {
        Some(s) => s,
        None => return false,
    };

    // Victim: the sector with the fewest live records, so the copy is
    // cheapest and the most dead slots come back.
    let mut victim = None;
    let mut fewest = usize::MAX;
    for s in 0..SECTOR_COUNT {
        if s == spare || sector_blank(s) {
            continue;
        }
        let live = (0..SLOTS_PER_SECTOR)
            .filter(|&slot| is_valid(s, slot))
            .count();
        let dead = SLOTS_PER_SECTOR - live;
        if dead == 0 {
            continue; // nothing to reclaim here
        }
        if live < fewest {
            fewest = live;
            victim = Some(s);
        }
    }
    let victim = match victim {
        Some(v) => v,
        // Every sector is entirely live: genuinely full.
        None => return false,
    };

    // Copy the survivors into the spare. It has SLOTS_PER_SECTOR slots
    // and the victim has at most that many live records, so this always
    // fits.
    let mut dest = 0usize;
    for slot in 0..SLOTS_PER_SECTOR {
        if !is_valid(victim, slot) {
            continue;
        }
        let rec = read_record(victim, slot);
        let rp = record_rp(victim, slot);
        let mut page = [0u8; RECORD_SIZE];
        page[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC.to_le_bytes());
        page[OFF_RP..OFF_RP + 32].copy_from_slice(&rp);
        page[OFF_CRED..OFF_CRED + 64].copy_from_slice(&rec.cred_id);
        page[OFF_USER_LEN] = rec.user_id_len as u8;
        page[OFF_USER..OFF_USER + rec.user_id_len].copy_from_slice(&rec.user_id[..rec.user_id_len]);
        page[OFF_RP_ID_LEN] = rec.rp_id_len as u8;
        page[OFF_RP_ID..OFF_RP_ID + rec.rp_id_len].copy_from_slice(&rec.rp_id[..rec.rp_id_len]);
        page[OFF_BLOB_LEN] = rec.blob_len as u8;
        page[OFF_BLOB..OFF_BLOB + rec.blob_len].copy_from_slice(&rec.blob[..rec.blob_len]);
        page[OFF_NAME_LEN] = rec.name_len as u8;
        page[OFF_NAME..OFF_NAME + rec.name_len].copy_from_slice(&rec.name[..rec.name_len]);
        page[OFF_DISPLAY_LEN] = rec.display_len as u8;
        page[OFF_DISPLAY..OFF_DISPLAY + rec.display_len]
            .copy_from_slice(&rec.display[..rec.display_len]);
        page[OFF_PROTECT] = rec.cred_protect;
        program(spare, dest, &page);
        dest += 1;
    }

    // Only now is the victim expendable. It becomes the new spare.
    erase(victim);
    true
}

/// Is every slot in this sector erased?
fn sector_blank(sector: usize) -> bool {
    (0..SLOTS_PER_SECTOR).all(|slot| is_blank(sector, slot))
}

fn blank_sector_count() -> usize {
    (0..SECTOR_COUNT).filter(|&s| sector_blank(s)).count()
}

/// Find a slot to write into, keeping one sector blank in reserve.
///
/// Prefers a sector already in use, and only breaks into a fresh one
/// while more than one blank sector remains. Without that reserve,
/// compaction has nowhere to evacuate to and can never run.
fn first_blank() -> Option<(usize, usize)> {
    for s in 0..SECTOR_COUNT {
        if sector_blank(s) {
            continue;
        }
        for slot in 0..SLOTS_PER_SECTOR {
            if is_blank(s, slot) {
                return Some((s, slot));
            }
        }
    }
    if blank_sector_count() > 1 {
        for s in 0..SECTOR_COUNT {
            if sector_blank(s) {
                return Some((s, 0));
            }
        }
    }
    None
}

/// How many discoverable credentials this relying party has.
pub fn count(rp_id_hash: &[u8; 32]) -> usize {
    let mut n = 0;
    for s in 0..SECTOR_COUNT {
        for slot in 0..SLOTS_PER_SECTOR {
            if is_valid(s, slot) && record_rp(s, slot) == *rp_id_hash {
                n += 1;
            }
        }
    }
    n
}

/// The `index`-th discoverable credential for this relying party.
pub fn get(rp_id_hash: &[u8; 32], index: usize) -> Option<Resident> {
    let mut n = 0;
    for s in 0..SECTOR_COUNT {
        for slot in 0..SLOTS_PER_SECTOR {
            if !is_valid(s, slot) || record_rp(s, slot) != *rp_id_hash {
                continue;
            }
            if n == index {
                return Some(read_record(s, slot));
            }
            n += 1;
        }
    }
    None
}

fn read_record(sector: usize, slot: usize) -> Resident {
    let p = slot_ptr(sector, slot);
    let (user_id, user_id_len) = record_user(sector, slot);
    let mut rp_id = [0u8; MAX_RP_ID];
    let mut blob = [0u8; MAX_CRED_BLOB];
    // SAFETY: reading our own reserved sector through the XIP window.
    let (rp_id_len, blob_len) = unsafe {
        core::ptr::copy_nonoverlapping(p.add(OFF_RP_ID), rp_id.as_mut_ptr(), MAX_RP_ID);
        core::ptr::copy_nonoverlapping(p.add(OFF_BLOB), blob.as_mut_ptr(), MAX_CRED_BLOB);
        (
            (core::ptr::read_volatile(p.add(OFF_RP_ID_LEN)) as usize).min(MAX_RP_ID),
            (core::ptr::read_volatile(p.add(OFF_BLOB_LEN)) as usize).min(MAX_CRED_BLOB),
        )
    };
    let mut name = [0u8; MAX_NAME];
    let mut display = [0u8; MAX_NAME];
    // SAFETY: as above.
    let (name_len, display_len) = unsafe {
        core::ptr::copy_nonoverlapping(p.add(OFF_NAME), name.as_mut_ptr(), MAX_NAME);
        core::ptr::copy_nonoverlapping(p.add(OFF_DISPLAY), display.as_mut_ptr(), MAX_NAME);
        (
            (core::ptr::read_volatile(p.add(OFF_NAME_LEN)) as usize).min(MAX_NAME),
            (core::ptr::read_volatile(p.add(OFF_DISPLAY_LEN)) as usize).min(MAX_NAME),
        )
    };
    Resident {
        cred_id: record_cred(sector, slot),
        user_id,
        user_id_len,
        rp_id,
        rp_id_len,
        blob,
        blob_len,
        name,
        name_len,
        display,
        display_len,
        // SAFETY: as above.
        cred_protect: unsafe { core::ptr::read_volatile(p.add(OFF_PROTECT)) },
    }
}

/// Live credentials, and how many erased slots remain.
///
/// The second number is what CredentialManagement reports as
/// maxRemaining. It counts *erased* slots only, not retired ones: a
/// retired record still occupies its slot until its whole sector is
/// dead, so promising it would be a lie.
pub fn totals() -> (usize, usize) {
    let mut used = 0;
    let mut free = 0;
    for s in 0..SECTOR_COUNT {
        for slot in 0..SLOTS_PER_SECTOR {
            if is_valid(s, slot) {
                used += 1;
            } else if is_blank(s, slot) {
                free += 1;
            }
        }
    }
    (used, free)
}

/// The `index`-th distinct relying party, in scan order.
pub fn nth_rp(index: usize) -> Option<Resident> {
    let mut seen = [[0u8; 32]; CAPACITY];
    let mut n = 0usize;
    for s in 0..SECTOR_COUNT {
        for slot in 0..SLOTS_PER_SECTOR {
            if !is_valid(s, slot) {
                continue;
            }
            let rp = record_rp(s, slot);
            if seen[..n].iter().any(|x| *x == rp) {
                continue;
            }
            if n == index {
                return Some(read_record(s, slot));
            }
            seen[n] = rp;
            n += 1;
        }
    }
    None
}

/// How many distinct relying parties hold a credential here.
pub fn rp_count() -> usize {
    let mut seen = [[0u8; 32]; CAPACITY];
    let mut n = 0usize;
    for s in 0..SECTOR_COUNT {
        for slot in 0..SLOTS_PER_SECTOR {
            if !is_valid(s, slot) {
                continue;
            }
            let rp = record_rp(s, slot);
            if !seen[..n].iter().any(|x| *x == rp) {
                seen[n] = rp;
                n += 1;
            }
        }
    }
    n
}

/// Update a credential's user information.
///
/// CTAP2's updateUserInformation is about the *names*: the client sends
/// name and displayName and leaves the id alone. Passing an empty slice
/// for any field keeps the stored one, which is what makes this a
/// partial update rather than a replace.
pub fn update_user(cred_id: &[u8; 64], user_id: &[u8], name: &[u8], display: &[u8]) -> bool {
    for s in 0..SECTOR_COUNT {
        for slot in 0..SLOTS_PER_SECTOR {
            if !is_valid(s, slot) || record_cred(s, slot) != *cred_id {
                continue;
            }
            let rec = read_record(s, slot);
            let rp = record_rp(s, slot);
            let uid: &[u8] = if user_id.is_empty() {
                &rec.user_id[..rec.user_id_len]
            } else {
                user_id
            };
            let nm: &[u8] = if name.is_empty() {
                &rec.name[..rec.name_len]
            } else {
                name
            };
            let dn: &[u8] = if display.is_empty() {
                &rec.display[..rec.display_len]
            } else {
                display
            };
            let mut uid_buf = [0u8; MAX_USER_ID];
            let mut nm_buf = [0u8; MAX_NAME];
            let mut dn_buf = [0u8; MAX_NAME];
            let (ul, nl, dl) = (uid.len(), nm.len(), dn.len());
            uid_buf[..ul].copy_from_slice(uid);
            nm_buf[..nl].copy_from_slice(nm);
            dn_buf[..dl].copy_from_slice(dn);
            invalidate(s, slot);
            return store(
                &rp,
                cred_id,
                &uid_buf[..ul],
                &rec.rp_id[..rec.rp_id_len],
                &rec.blob[..rec.blob_len],
                &nm_buf[..nl],
                &dn_buf[..dl],
                rec.cred_protect,
            );
        }
    }
    false
}

/// Retire a credential outright.
pub fn delete(cred_id: &[u8; 64]) -> bool {
    for s in 0..SECTOR_COUNT {
        for slot in 0..SLOTS_PER_SECTOR {
            if is_valid(s, slot) && record_cred(s, slot) == *cred_id {
                invalidate(s, slot);
                return true;
            }
        }
    }
    false
}

/// Find a credential by id, whichever relying party owns it.
/// May this credential be used for an assertion, given how the request
/// was made? The credProtect policy (CTAP 2.1 sec. 12.1) in one place:
///
///   1 (or none)  userVerificationOptional -- always
///   2            userVerificationOptionalWithCredentialIDList -- usable
///                without UV only when the client named it in an
///                allowList; discovery must not surface it
///   3            userVerificationRequired -- only with UV
///
/// Enforcement lives here rather than at the call sites because there
/// are three of them (discovery, allowList, GetNextAssertion) and the
/// original defect was that all three had none: the policy was stored,
/// echoed to the relying party and reported by credMgmt, and never once
/// consulted when it mattered.
pub fn usable_for(rec: &Resident, uv: bool, named_in_allow_list: bool) -> bool {
    policy_allows(rec.cred_protect, uv, named_in_allow_list)
}

/// The same rule over a bare policy level. This is what the GetAssertion
/// allowList path uses, because since the level is baked into the
/// credential id it is available for NON-resident credentials too -- the
/// ones the first version of this enforcement could not see at all: with
/// nothing stored there was nothing to look up, so a non-resident
/// credential registered userVerificationRequired had its policy signed
/// into authData and never once consulted.
pub fn policy_allows(level: u8, uv: bool, named_in_allow_list: bool) -> bool {
    match level {
        3 => uv,
        2 => uv || named_in_allow_list,
        _ => true,
    }
}

/// The `index`-th credential for this RP that discovery may surface --
/// `get` filtered by `usable_for` with no allowList. Discovery and
/// GetNextAssertion must both count with THIS, or numberOfCredentials
/// promises assertions the token will then refuse to give.
pub fn nth_discoverable(rp_id_hash: &[u8; 32], index: usize, uv: bool) -> Option<Resident> {
    let mut n = 0;
    for s in 0..SECTOR_COUNT {
        for slot in 0..SLOTS_PER_SECTOR {
            if !is_valid(s, slot) || record_rp(s, slot) != *rp_id_hash {
                continue;
            }
            let rec = read_record(s, slot);
            if !usable_for(&rec, uv, false) {
                continue;
            }
            if n == index {
                return Some(rec);
            }
            n += 1;
        }
    }
    None
}

/// How many credentials discovery may surface for this RP.
pub fn count_discoverable(rp_id_hash: &[u8; 32], uv: bool) -> usize {
    let mut n = 0;
    for s in 0..SECTOR_COUNT {
        for slot in 0..SLOTS_PER_SECTOR {
            if is_valid(s, slot)
                && record_rp(s, slot) == *rp_id_hash
                && usable_for(&read_record(s, slot), uv, false)
            {
                n += 1;
            }
        }
    }
    n
}

pub fn find_by_id(cred_id: &[u8; 64]) -> Option<Resident> {
    for s in 0..SECTOR_COUNT {
        for slot in 0..SLOTS_PER_SECTOR {
            if is_valid(s, slot) && record_cred(s, slot) == *cred_id {
                return Some(read_record(s, slot));
            }
        }
    }
    None
}
