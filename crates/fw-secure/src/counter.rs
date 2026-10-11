// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Monotonic signature counter, in Secure flash.
//!
//! WebAuthn sec. 6.1.1: the counter a relying party sees must never go
//! backwards, or the RP is entitled to conclude the authenticator has
//! been cloned. Until now it lived in RAM and restarted at 1 every
//! boot, which is exactly that failure.
//!
//! ## Why it is not one flash write per signature
//!
//! Design point 4 flags the sign-counter commit as being on the latency
//! path, and notes the C port already paid for that. So this reserves a
//! block instead: on boot it records `current + BATCH` in flash, hands
//! out values from RAM, and only writes again when the block runs out.
//! After a reset the counter resumes from the reserved high-water, so
//! it may *skip* -- which WebAuthn permits, since it requires the value
//! to increase, not to be contiguous -- but it can never repeat.
//!
//! Cost: one 256-byte program per [`BATCH`] signatures, and one sector
//! erase per 16 of those.
//!
//! ## Why two sectors
//!
//! Records are appended, so a sector eventually fills and has to be
//! erased -- and a power cut during that erase would leave no record at
//! all, so the next boot would restart from zero and the counter would
//! go backwards. That is the one failure this design exists to prevent,
//! so it cannot be left to chance.
//!
//! Two sectors ping-pong. The live value is always the highest record
//! in either. When the active sector is full, the *other* is erased --
//! it only ever holds older values -- and the new record written there.
//! At every instant, including mid-erase and between erase and program,
//! the untouched sector still holds the current high-water.

use crate::flash::flash_op;
use hal::rom_data;
use rp235x_hal as hal;

/// The two counter sectors, as flash offsets. Both sit above SAU region
/// 0 (which ends at 0x101EFFFF) and below the 2 MiB die end, so they are
/// Secure-only, like the key sector immediately above them.
const SECTORS: [u32; 2] = [0x1F_D000, 0x1F_E000];
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

const SECTOR_SIZE: usize = 4096;
const PAGE_SIZE: usize = 256;
const SLOTS: usize = SECTOR_SIZE / PAGE_SIZE; // 16
/// 4 KiB sector erase (W25Q). NOT 0xd8 -- that is the 64 KiB block
/// erase and would take the key sector with it.
const BLOCK_ERASE_CMD: u8 = 0x20;

const MAGIC: u32 = 0x545a_4331; // "TZC1"
/// Values handed out per flash write. 64 keeps the amortised cost
/// invisible while bounding how far the counter jumps across a reset.
const BATCH: u32 = 64;

/// Next value to hand out, and the value at which we must reserve more.
static mut NEXT: u32 = 0;
static mut LIMIT: u32 = 0;

fn slot_ptr(sector: u32, slot: usize) -> *const u8 {
    (xip_base() + sector as usize + slot * PAGE_SIZE) as *const u8
}

/// Read one slot's value, if it holds a valid record.
fn read_slot(sector: u32, slot: usize) -> Option<u32> {
    let p = slot_ptr(sector, slot);
    // SAFETY: reading our own reserved sector through the XIP window.
    let (magic, value) = unsafe {
        (
            core::ptr::read_unaligned(p as *const u32),
            core::ptr::read_unaligned(p.add(4) as *const u32),
        )
    };
    if magic == MAGIC {
        Some(value)
    } else {
        None
    }
}

/// Highest recorded value, and which sector held it.
fn scan() -> (u32, usize) {
    let mut best = 0u32;
    let mut best_sector = 0usize;
    for (i, &sector) in SECTORS.iter().enumerate() {
        for slot in 0..SLOTS {
            if let Some(v) = read_slot(sector, slot) {
                if v >= best {
                    best = v;
                    best_sector = i;
                }
            }
        }
    }
    (best, best_sector)
}

/// Is this slot actually erased?
///
/// "Has no valid record" is NOT the same question, and assuming it was
/// cost a silent failure: flash programming can only clear bits, so
/// writing a record into a slot holding stale data produces neither the
/// old contents nor the new one. These sectors are not blank just
/// because this image never wrote them -- restoring a whole-flash
/// backup, or any earlier firmware, leaves data here.
fn slot_blank(sector: u32, slot: usize) -> bool {
    let p = slot_ptr(sector, slot);
    // SAFETY: reading our own reserved sector through the XIP window.
    (0..PAGE_SIZE).all(|i| unsafe { core::ptr::read_volatile(p.add(i)) } == 0xff)
}

/// First erased slot in a sector, if any.
fn free_slot(sector: u32) -> Option<usize> {
    (0..SLOTS).find(|&s| slot_blank(sector, s))
}

/// Write a record. Erases the inactive sector only when the active one
/// is full; see the module note on why that ordering is safe.
fn write_record(value: u32, active: usize) -> usize {
    let mut page = [0u8; PAGE_SIZE];
    page[..4].copy_from_slice(&MAGIC.to_le_bytes());
    page[4..8].copy_from_slice(&value.to_le_bytes());

    let (sector_idx, slot) = match free_slot(SECTORS[active]) {
        Some(s) => (active, s),
        None => {
            let other = 1 - active;
            // SAFETY: `flash_op` upholds the no-XIP contract. The active
            // sector still holds the current high-water throughout.
            unsafe {
                flash_op(|| {
                    rom_data::connect_internal_flash();
                    rom_data::flash_exit_xip();
                    rom_data::flash_range_erase(
                        SECTORS[other],
                        SECTOR_SIZE,
                        SECTOR_SIZE as u32,
                        BLOCK_ERASE_CMD,
                    );
                    rom_data::flash_flush_cache();
                    rom_data::flash_enter_cmd_xip();
                });
            }
            (other, 0)
        }
    };

    let addr = SECTORS[sector_idx] + (slot * PAGE_SIZE) as u32;
    // SAFETY: as above; `page` is a RAM buffer readable while XIP is off.
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

/// Which sector we are currently appending to.
static mut ACTIVE: usize = 0;

/// Resume the counter at boot.
///
/// Deliberately reserves NOTHING here. Reserving eagerly meant a boot
/// that never signed anything still burned a whole block, so a token
/// power-cycled a few times would hand a relying party a counter that
/// had leapt hundreds with no signatures behind it -- legal, but it
/// looks exactly like the cloning it is supposed to reveal. It also
/// cost a flash write on every boot.
///
/// Setting `LIMIT` equal to `NEXT` makes the first signature take the
/// reservation path, which writes the new high-water to flash BEFORE
/// handing the value out. So the skip is now only the unused tail of
/// the last batch, rather than a fresh block per boot.
///
/// Called once from `main`, before the NS world exists.
pub fn init() {
    let (high, active) = scan();
    // SAFETY: single-threaded, before NS runs.
    unsafe {
        NEXT = high;
        LIMIT = high;
        ACTIVE = active;
    }
}

/// Hand out the next counter value.
///
/// Crosses into flash only when the reserved block runs out, so the
/// common case costs nothing on the signing path.
pub fn next() -> u32 {
    // SAFETY: single-threaded; only ever called from a Secure veneer.
    unsafe {
        let n = &mut *(&raw mut NEXT);
        *n = n.wrapping_add(1);
        let value = *n;
        if value >= LIMIT {
            LIMIT = value + BATCH;
            ACTIVE = write_record(LIMIT, ACTIVE);
        }
        value
    }
}
