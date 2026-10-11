// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Architecture shim -- re-exported from `pqf-signer-core`.
//!
//! The nop / sev / wfe / interrupt-mask primitives moved to the
//! shared `pqf-signer-core` crate (`crates/signer-core/src/arch.rs`)
//! so the core-1 signing worker -- which is compiled separately for
//! riscv32 in the mixed-architecture build -- carries them along.
//! Firmware code keeps addressing them as `crate::arch::*`; see the
//! signer-core module for the full documentation (Hazard3 h3.block /
//! h3.unblock encodings, RAM-residency guarantees, PRIMASK vs
//! mstatus.MIE semantics).

pub use pqf_signer_core::arch::*;
