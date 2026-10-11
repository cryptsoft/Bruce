// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! pqf-signer-core -- the hybrid (ECDSA-P256 + ML-DSA) core-1 signing
//! worker, its cross-core shared-SRAM mailbox, and the tiny arch shim
//! they need. Extracted from the firmware crate so the exact same
//! worker compiles for either RP2350 instruction set:
//!
//!   * linked into the firmware (Arm or RISC-V build -- core 1 runs
//!     the same instruction set as core 0 there), and
//!   * linked into `pqf-core1-riscv`, the standalone RISC-V payload
//!     the mixed-architecture firmware build (`core1_riscv` feature)
//!     embeds and launches on core 1 while core 0 stays Arm.
//!
//! Nothing in here touches a HAL, PAC, or runtime -- the mailbox is a
//! `repr(C)` struct in shared SRAM synchronised with plain atomic
//! loads/stores (no atomic RMW, so no reliance on either core's
//! exclusive-monitor / AMO plumbing when the two cores run different
//! instruction sets), and the only asm is the `arch` module's
//! inline(always) shims.

#![no_std]

extern crate alloc;

pub mod arch;
pub mod mixed;
pub mod mldsa_alg;
pub mod signer;
