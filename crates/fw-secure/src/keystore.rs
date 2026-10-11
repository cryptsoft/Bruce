// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! M4d -- the Secure master key, persisted in Secure-only flash.
//!
//! Without this the master key is regenerated every boot and no
//! credential survives a reset, which makes the whole authenticator a
//! demo. The store is one 4 KiB sector at [`STORE_OFFSET`].
//!
//! **Why that address is Secure.** SAU region 0 ends at `0x101EFFFF`,
//! matching `memory-nonsecure.x`, so the sector at `0x101F0000` is
//! covered by no SAU region at all and is therefore Secure by default
//! (`SAU_CTRL.ALLNS = 0`). NS cannot read it, which is the only reason
//! it is safe to keep a bare key there. Widening region 0 back to
//! `0x101FFFFF` would silently publish the master key.
//!
//! It also has to sit below 2 MiB: the die on these boards really is
//! 2 MiB. The map in docs/TRUSTZONE.md used to say 4 MiB, which is the
//! same wrong assumption that cost a day on the DFU bootloader -- a
//! 2 MiB die addressed as 4 MiB aliases, and writes land on the
//! bootloader's vector table.

use crate::flash::flash_op;
use hal::rom_data;
use rp235x_hal as hal;

/// Flash offset (not an XIP address) of the key sector: the last 4 KiB
/// below 2 MiB (XIP `0x101FF000`), well above both the Non-secure image
/// region, which ends at `0x101F0000`, and SAU region 0, which ends at
/// `0x101EFFFF`.
const STORE_OFFSET: u32 = 0x1F_F000;
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
/// 4 KiB sector erase (W25Q), matching `SECTOR_SIZE`. NOT 0xd8: that is
/// the 64 KiB block erase, and at this offset it would run to the end of
/// the die and take 60 KiB of neighbouring flash with it.
const BLOCK_ERASE_CMD: u8 = 0x20;

/// Tags a written sector. Bumped if the layout ever changes.
const MAGIC: u32 = 0x545a_4b31; // "TZK1"

/// Read the stored master key, if this sector holds one.
///
/// Erased flash reads as all-ones, so a blank sector simply fails the
/// magic check. An all-zero or all-ones key is rejected too: those are
/// what a half-finished write or a failed erase leaves behind, and
/// silently adopting one would give every such board the same key.
pub fn load(out: &mut [u8; 32]) -> bool {
    let p = (xip_base() + STORE_OFFSET as usize) as *const u8;
    // SAFETY: reading our own reserved sector through the XIP window.
    let magic = unsafe { core::ptr::read_unaligned(p as *const u32) };
    if magic != MAGIC {
        return false;
    }
    // SAFETY: as above; 32 bytes inside the same sector.
    unsafe {
        core::ptr::copy_nonoverlapping(p.add(4), out.as_mut_ptr(), 32);
    }
    let all_zero = out.iter().all(|&b| b == 0);
    let all_ones = out.iter().all(|&b| b == 0xff);
    !(all_zero || all_ones)
}

/// Write the master key into the sector, erasing it first.
pub fn store(key: &[u8; 32]) {
    let mut page = [0u8; PAGE_SIZE];
    page[..4].copy_from_slice(&MAGIC.to_le_bytes());
    page[4..36].copy_from_slice(key);
    // SAFETY: `flash_op` upholds the no-XIP-access contract; `page` is
    // a stack (RAM) buffer that stays readable while XIP is suspended.
    unsafe {
        flash_op(|| {
            rom_data::connect_internal_flash();
            rom_data::flash_exit_xip();
            rom_data::flash_range_erase(
                STORE_OFFSET,
                SECTOR_SIZE,
                SECTOR_SIZE as u32,
                BLOCK_ERASE_CMD,
            );
            rom_data::flash_range_program(STORE_OFFSET, page.as_ptr(), PAGE_SIZE);
            rom_data::flash_flush_cache();
            rom_data::flash_enter_cmd_xip();
        });
    }
}
