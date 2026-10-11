// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! M4f -- the hybrid signing worker, anchored in the Secure world.
//!
//! The worker itself is `pqf-signer-core`, shared verbatim with the FIDO
//! firmware, so both worlds run identical signing code. What changes
//! here is *which side of the boundary it runs on*.
//!
//! Design point 3 called this the awkward one, and set out the choice:
//! either core 1 becomes Secure-only, or the signer stays Non-secure and
//! receives blinded inputs. The second is not available -- ML-DSA
//! signing needs the expanded private key, so a Non-secure signer would
//! have to be handed the seed, which is the thing being protected. So
//! core 1 becomes Secure-only, and both statics below live in Secure
//! RAM.
//!
//! The mailbox in particular carries the P-256 scalar and the ML-DSA
//! seed as *inputs*. Leaving it in shared Non-secure RAM would hand NS
//! every credential's private key, which is why the RAM split moved.

pub use pqf_signer_core::signer::*;

/// The shared mailbox. In Secure RAM (0x20000000..0x2006FFFF), outside
/// SAU region 1, so NS cannot address it at all.
pub static CORE1_SIGNER: Core1Signer = Core1Signer::new();

/// Core 1's stack, also Secure. 64 KiB, sized by the shared crate.
pub static CORE1_STACK: rp235x_hal::multicore::Stack<CORE1_STACK_WORDS> =
    rp235x_hal::multicore::Stack::new();
