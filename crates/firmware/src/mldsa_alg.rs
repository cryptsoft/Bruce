// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Compile-time ML-DSA variant selection -- firmware-side surface.
//!
//! The OpenSK PQC fork supports three ML-DSA security levels (44, 65,
//! 87) and this firmware labels its hybrid credentials with the
//! composite PQ/T COSE algorithm identifiers requested in
//! draft-ietf-jose-pq-composite-sigs-04. Picking a level is a
//! compile-time decision driven by mutually-exclusive cargo features:
//!
//!   - `mldsa44` -- security level 2, hybrid alg = `COSE_ALG_MLDSA44_ES256`
//!   - `mldsa65` -- security level 3, hybrid alg = `COSE_ALG_MLDSA65_ES256` (default)
//!   - `mldsa87` -- security level 5, hybrid alg = `COSE_ALG_MLDSA87_ES384`
//!
//! Those constants (-54 / -55 / -56 today, still provisional) and the
//! per-build `COSE_ALG_HYBRID_MLDSA` are defined once, in
//! `pqf_signer_core::mldsa_alg`, and re-exported here. The ids were
//! -51/-52/-53 before RFC 9864 assigned those numbers to other
//! algorithms, and -48/-49/-50 before that; only the label changed,
//! the signing construction did not.
//!
//! The crypto-level aliases (`MLDSA`, `MLDSA_PK_LEN`, `MLDSA_SIG_LEN`,
//! ...) moved to the shared `pqf-signer-core` crate -- the firmware
//! forwards its `mldsa*` feature there (see Cargo.toml), and this
//! module re-exports them under the historical paths plus the
//! display names that only the firmware cares about. The
//! feature-mutual-exclusion `compile_error!` guards also live in
//! signer-core now and fire for any consumer.

pub use pqf_signer_core::mldsa_alg::*;

/// Human-readable alg name. Currently unused at runtime (we only emit
/// the numeric COSE alg on the wire), but handy for future log
/// messages / panics / picotool `binary-info`.
#[allow(dead_code)]
#[cfg(feature = "mldsa44")]
pub const MLDSA_ALG_NAME: &str = "ML-DSA-44";
#[allow(dead_code)]
#[cfg(feature = "mldsa65")]
pub const MLDSA_ALG_NAME: &str = "ML-DSA-65";
#[allow(dead_code)]
#[cfg(feature = "mldsa87")]
pub const MLDSA_ALG_NAME: &str = "ML-DSA-87";
