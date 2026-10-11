// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! PIN state in Secure flash: the PIN hash and the retry counter.
//!
//! Both have to be Secure-only for different reasons. The hash is
//! obviously secret-adjacent. The **retry counter is the more delicate
//! of the two**: if the Non-secure world could roll it back, the
//! brute-force limit that makes a 4-digit PIN meaningful would simply
//! not exist.
//!
//! Same append-and-ping-pong shape as [`crate::counter`], and for the
//! same reason: records are appended so a sector fills and must be
//! erased, and a power cut during that erase must not lose the state.
//! The erase always targets the sector that is *not* live, so at every
//! instant one sector still holds the current record.
//!
//! Writes are rare -- setPIN, changePIN, a failed attempt, or a
//! successful one resetting the count -- so the amortised cost never
//! shows up anywhere.

use crate::flash::flash_op;
use hal::rom_data;
use rp235x_hal as hal;

/// Two sectors below the signature counter's pair, still above SAU
/// region 0 and below the 2 MiB die end.
const SECTORS: [u32; 2] = [0x1F_B000, 0x1F_C000];
/// Base of the XIP window this store is read through.
///
/// A real address on the board; on a host build, the base of a simulated
/// die instead, so the logic can be tested without a token. See
/// `crates/fw-secure-hosttest`.
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

const SECTOR_SIZE: usize = 4096;
const PAGE_SIZE: usize = 256;
const SLOTS: usize = SECTOR_SIZE / PAGE_SIZE;
/// 4 KiB sector erase (W25Q). NOT 0xd8, the 64 KiB block erase.
const BLOCK_ERASE_CMD: u8 = 0x20;

const MAGIC: u32 = 0x545a_5031; // "TZP1"
/// CTAP2 allows 8 attempts before the PIN is permanently blocked.
pub const MAX_RETRIES: u8 = 8;

/// Layout inside a record: magic(4) | seq(4) | set(1) | retries(1) |
/// pin_hash(16) | min_pin(1) | force_change(1) | rp_count(1) |
/// rp_hashes(4 x 32). Comfortably inside one 256-byte page.
const OFF_SEQ: usize = 4;
const OFF_SET: usize = 8;
const OFF_RETRIES: usize = 9;
const OFF_HASH: usize = 10;
const OFF_MIN_PIN: usize = 26;
const OFF_FORCE: usize = 27;
const OFF_RP_COUNT: usize = 28;
const OFF_RP: usize = 29;

/// Relying parties allowed to see minPinLength. CTAP2 sets no floor;
/// four is enough for any real deployment and keeps the record in one
/// page.
pub const MAX_MIN_PIN_RPS: usize = 4;
/// CTAP2 default minimum PIN length, in code points.
pub const DEFAULT_MIN_PIN: u8 = 4;

#[derive(Clone, Copy)]
pub struct PinState {
    pub is_set: bool,
    pub retries: u8,
    /// Left 16 bytes of SHA-256(pin), as CTAP2 specifies.
    pub hash: [u8; 16],
    /// Bumped by `put`, so `init` can pick the newest record out of the
    /// two sectors. Public only so callers can use struct-update
    /// syntax; `put` overwrites whatever they pass.
    pub seq: u32,
    pub min_pin_length: u8,
    pub force_change: bool,
    /// rpIdHashes allowed to receive the minPinLength extension.
    pub min_pin_rps: [[u8; 32]; MAX_MIN_PIN_RPS],
    pub min_pin_rp_count: u8,
}

impl PinState {
    const fn fresh() -> Self {
        Self {
            is_set: false,
            retries: MAX_RETRIES,
            hash: [0u8; 16],
            seq: 0,
            min_pin_length: DEFAULT_MIN_PIN,
            force_change: false,
            min_pin_rps: [[0u8; 32]; MAX_MIN_PIN_RPS],
            min_pin_rp_count: 0,
        }
    }
}

static mut STATE: PinState = PinState::fresh();
static mut ACTIVE: usize = 0;

fn slot_ptr(sector: u32, slot: usize) -> *const u8 {
    (xip_base() + sector as usize + slot * PAGE_SIZE) as *const u8
}

fn read_slot(sector: u32, slot: usize) -> Option<PinState> {
    let p = slot_ptr(sector, slot);
    // SAFETY: reading our own reserved sector through the XIP window.
    unsafe {
        if core::ptr::read_unaligned(p as *const u32) != MAGIC {
            return None;
        }
        let mut hash = [0u8; 16];
        core::ptr::copy_nonoverlapping(p.add(OFF_HASH), hash.as_mut_ptr(), 16);
        let mut rps = [[0u8; 32]; MAX_MIN_PIN_RPS];
        for (i, rp) in rps.iter_mut().enumerate() {
            core::ptr::copy_nonoverlapping(p.add(OFF_RP + i * 32), rp.as_mut_ptr(), 32);
        }
        let min_pin = core::ptr::read_volatile(p.add(OFF_MIN_PIN));
        Some(PinState {
            min_pin_length: if min_pin == 0 {
                DEFAULT_MIN_PIN
            } else {
                min_pin
            },
            force_change: core::ptr::read_volatile(p.add(OFF_FORCE)) != 0,
            min_pin_rps: rps,
            min_pin_rp_count: core::ptr::read_volatile(p.add(OFF_RP_COUNT))
                .min(MAX_MIN_PIN_RPS as u8),
            seq: core::ptr::read_unaligned(p.add(OFF_SEQ) as *const u32),
            is_set: core::ptr::read_volatile(p.add(OFF_SET)) != 0,
            retries: core::ptr::read_volatile(p.add(OFF_RETRIES)),
            hash,
        })
    }
}

/// Erased, not merely invalid -- see the same note in [`crate::counter`].
fn slot_blank(sector: u32, slot: usize) -> bool {
    let p = slot_ptr(sector, slot);
    // SAFETY: as above.
    (0..PAGE_SIZE).all(|i| unsafe { core::ptr::read_volatile(p.add(i)) } == 0xff)
}

fn free_slot(sector: u32) -> Option<usize> {
    (0..SLOTS).find(|&s| slot_blank(sector, s))
}

fn erase(sector: u32) {
    // SAFETY: `flash_op` upholds the no-XIP contract and parks core 1.
    unsafe {
        flash_op(|| {
            rom_data::connect_internal_flash();
            rom_data::flash_exit_xip();
            rom_data::flash_range_erase(sector, SECTOR_SIZE, SECTOR_SIZE as u32, BLOCK_ERASE_CMD);
            rom_data::flash_flush_cache();
            rom_data::flash_enter_cmd_xip();
        });
    }
}

fn commit(st: &PinState, active: usize) -> usize {
    let mut page = [0xffu8; PAGE_SIZE];
    page[..4].copy_from_slice(&MAGIC.to_le_bytes());
    page[OFF_SEQ..OFF_SEQ + 4].copy_from_slice(&st.seq.to_le_bytes());
    page[OFF_SET] = u8::from(st.is_set);
    page[OFF_RETRIES] = st.retries;
    page[OFF_HASH..OFF_HASH + 16].copy_from_slice(&st.hash);
    page[OFF_MIN_PIN] = st.min_pin_length;
    page[OFF_FORCE] = u8::from(st.force_change);
    page[OFF_RP_COUNT] = st.min_pin_rp_count;
    for (i, rp) in st.min_pin_rps.iter().enumerate() {
        page[OFF_RP + i * 32..OFF_RP + (i + 1) * 32].copy_from_slice(rp);
    }

    let (sector_idx, slot) = match free_slot(SECTORS[active]) {
        Some(s) => (active, s),
        None => {
            // The live sector still holds the current record while the
            // other is erased, so nothing is lost mid-operation.
            let other = 1 - active;
            erase(SECTORS[other]);
            (other, 0)
        }
    };
    let addr = SECTORS[sector_idx] + (slot * PAGE_SIZE) as u32;
    // SAFETY: as `erase`; `page` is a RAM buffer.
    unsafe {
        flash_op(|| {
            rom_data::connect_internal_flash();
            rom_data::flash_exit_xip();
            rom_data::flash_range_program(addr, page.as_ptr(), PAGE_SIZE);
            rom_data::flash_flush_cache();
            rom_data::flash_enter_cmd_xip();
        });
    }
    sector_idx
}

/// Load the newest record at boot. A blank pair means no PIN is set.
pub fn init() {
    let mut best: Option<(PinState, usize)> = None;
    for (i, &sector) in SECTORS.iter().enumerate() {
        for slot in 0..SLOTS {
            if let Some(st) = read_slot(sector, slot) {
                if best.map_or(true, |(b, _)| st.seq >= b.seq) {
                    best = Some((st, i));
                }
            }
        }
    }
    // SAFETY: single-threaded, before NS runs.
    unsafe {
        match best {
            Some((st, i)) => {
                STATE = st;
                ACTIVE = i;
            }
            None => STATE = PinState::fresh(),
        }
    }
}

pub fn get() -> PinState {
    // SAFETY: single-threaded read.
    unsafe { STATE }
}

/// Persist a new state, bumping the sequence so `init` picks it up.
pub fn put(mut st: PinState) {
    // SAFETY: single-threaded; Secure-only.
    unsafe {
        st.seq = STATE.seq.wrapping_add(1);
        STATE = st;
        ACTIVE = commit(&st, ACTIVE);
    }
}
