// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Core 1 signing worker -- firmware-side anchor.
//!
//! The worker itself (state machine, mailbox struct, hybrid
//! ECDSA-P256 + ML-DSA signing, the M1 flash-park spin) lives in the
//! shared `pqf-signer-core` crate (`crates/signer-core/src/signer.rs`)
//! so the identical code can also be cross-compiled into the
//! standalone RISC-V core-1 blob used by the mixed-architecture build
//! (`core1_riscv` feature: Arm core 0 + Hazard3 core 1). This module
//! re-exports its whole surface under the historical
//! `crate::core1_signer::*` paths and owns the two statics that must
//! live in the firmware image:
//!
//! * [`CORE1_SIGNER`] -- the shared-SRAM mailbox. On same-architecture
//!   builds both cores reach it as a normal static; on the mixed
//!   build core 0 pushes its address through the SIO FIFO right after
//!   launching the blob, which is the blob's only way to find it.
//! * [`CORE1_STACK`] -- core 1's stack, on builds where the Arm HAL's
//!   `multicore::spawn` does the launching (it wants its own `Stack`
//!   wrapper type). RISC-V firmware builds use `crate::core1_launch`'s
//!   private stack instead, and the mixed build's blob carves its
//!   stack out of the blob RAM window (`pqf_signer_core::mixed`).

pub use pqf_signer_core::signer::*;

/// The shared signer instance both cores reach via `&'static`.
pub static CORE1_SIGNER: Core1Signer = Core1Signer::new();

/// Core 1's stack for HAL-spawned (Arm, same-architecture) builds.
/// Lives in `.bss`, sized via [`CORE1_STACK_WORDS`].
#[cfg(all(
    target_arch = "arm",
    not(feature = "core1_riscv"),
    not(feature = "single_core")
))]
pub static CORE1_STACK: rp235x_hal::multicore::Stack<CORE1_STACK_WORDS> =
    rp235x_hal::multicore::Stack::new();
