// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Mixed-architecture (Arm core 0 + RISC-V core 1) ABI constants.
//!
//! The `core1_riscv` firmware feature embeds a standalone RISC-V
//! payload (the `pqf-core1-riscv` crate, compiled and objcopy'd by
//! the firmware's build.rs) and launches it on core 1 after flipping
//! that core's OTP ARCHSEL bit. The two link units rendezvous through
//! the fixed addresses below -- this module is the single normative
//! home for them; the two linker scripts that must agree
//! (`crates/firmware/memory_core1riscv.x` and
//! `crates/fw-core1-riscv/blob.x`) each carry a comment pointing
//! back here, and the firmware launcher asserts against these values
//! at build time via `include_bytes!` length checks where it can.
//!
//! Memory carve-up in the mixed build:
//!
//! ```text
//!   FLASH 0x1000_0000 .. 0x1018_0000   Arm firmware image (1.5 MiB)
//!         0x1018_0000 .. 0x1020_0000   RISC-V core-1 blob (512 KiB,
//!                                      executed by core 1 via XIP)
//!         0x103F_D000 .. 0x1040_0000   flash-store reserve (as ever)
//!   RAM   0x2000_0000 .. 0x2006_0000   Arm firmware (384 KiB)
//!         0x2006_0000 .. 0x2008_0000   blob RAM: .data/.bss/heap up,
//!                                      64 KiB stack down from the top
//! ```
//!
//! The mailbox itself needs NO fixed address: after the boot-ROM
//! launch handshake, core 0 pushes `&CORE1_SIGNER as u32` through the
//! inter-core SIO FIFO and the blob's startup reads it as its first
//! action -- the FIFO is empty at that point (the handshake echoes
//! have all been consumed).

/// Flash address the blob is linked at and stored at (via the Arm
/// image's `.core1_blob` section). Core 1 executes it from here
/// through XIP, sharing the QSPI bus with core 0's own fetches.
///
/// Kept BELOW the 2 MiB mark deliberately: boards whose FLASH_DEVINFO
/// OTP row is unprogrammed (e.g. Feitian RP2350 sample units) make
/// picotool assume a 2 MiB flash and refuse to load anything beyond
/// it -- and it also keeps mixed images loadable on genuinely-2 MiB
/// RP2350 boards.
/// A DFU build (`PQF_APP_OFFSET`) relocates the blob inside the
/// bootloader's app slot; the linker scripts are rewritten to match by
/// `crates/firmware/build.rs`. Standalone images keep 0x1018_0000.
/// Mirrors the C port's `PQF_BLOB_FLASH_ORIGIN`.
pub const BLOB_FLASH_ORIGIN: u32 = match option_env!("PQF_APP_OFFSET") {
    Some(_) => 0x100A_0000,
    None => 0x1018_0000,
};

/// Size of the flash window reserved for the blob. Ends exactly at
/// the 2 MiB mark (0x1020_0000), far below the three reserved
/// flash-store sectors at 0x103F_D000. The ML-DSA-87 payload is
/// ~90 KiB, so 512 KiB is ample.
pub const BLOB_FLASH_LEN: u32 = 0x0008_0000;

/// Base of the RAM window owned by the blob (`.data`, `.bss`, heap,
/// stack). The Arm firmware's RAM region is shortened to end here --
/// see `memory_core1riscv.x`.
pub const BLOB_RAM_ORIGIN: u32 = 0x2006_0000;

/// Size of the blob RAM window (128 KiB: 64 KiB stack + 32 KiB heap
/// + data/bss + slack).
pub const BLOB_RAM_LEN: u32 = 0x0002_0000;

/// Initial stack pointer handed to core 1 in the launch handshake:
/// top of the blob RAM window (16-byte aligned per the RISC-V psABI).
pub const BLOB_STACK_TOP: u32 = BLOB_RAM_ORIGIN + BLOB_RAM_LEN;

/// Offset of the blob's trap parking loop from `BLOB_FLASH_ORIGIN`.
/// Handed to core 1 as its MTVEC (direct mode) in the launch
/// handshake, so a fault in the blob spins in a `wfi` loop instead of
/// jumping wild. The blob's entry asm pins this layout -- see the
/// `.blob_entry` section in `crates/fw-core1-riscv/src/main.rs`.
pub const BLOB_TRAP_OFFSET: u32 = 0;

/// Offset of the blob's actual entry point from `BLOB_FLASH_ORIGIN`
/// (the trap loop above occupies the first 8 bytes).
pub const BLOB_ENTRY_OFFSET: u32 = 8;
