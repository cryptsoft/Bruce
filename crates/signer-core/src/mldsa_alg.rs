// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Compile-time ML-DSA variant selection -- the crypto-level half.
//!
//! Wraps the bouncycastle-mldsa-lowmemory crate's three variant-
//! specific types and constants (`MLDSA44` / `MLDSA65` / `MLDSA87`,
//! `MLDSA44_PK_LEN`, etc.) behind a single set of unified names
//! (`MLDSA`, `MLDSA_PK_LEN`, `MLDSA_SIG_LEN`, ...) driven by the
//! mutually-exclusive `mldsa44` / `mldsa65` / `mldsa87` cargo
//! features. `MLDSA_SIG_LEN` sizes the mailbox signature buffer in
//! [`crate::signer`], which is shared-SRAM ABI in the mixed-
//! architecture build -- the firmware and the RISC-V core-1 blob MUST
//! be built with the same feature (both forward their selection to
//! this crate, so a mismatch is a build failure, not a runtime one).
//!
//! The composite PQ/T COSE algorithm identifiers also live here, at
//! the bottom of this file -- not because the worker needs them (it
//! never sees the wire encoding) but because this is the one crate
//! that the firmware, the TrustZone Secure image and both host-test
//! crates all link, so it is the single place a relabel has to touch.
//! The human-readable names stay in the firmware's `mldsa_alg` module.
//!
//! Mirrors the cfg-pattern in
//! `OpenSK/libraries/crypto/src/hybrid.rs:17-47` byte-for-byte.

// Mutual-exclusion guard. Lives at the top of the file so its
// `compile_error!` fires before the `pub use` redefinitions below
// would otherwise produce confusing E0252 / E0428 noise.
#[cfg(any(
    all(feature = "mldsa44", feature = "mldsa65"),
    all(feature = "mldsa44", feature = "mldsa87"),
    all(feature = "mldsa65", feature = "mldsa87"),
))]
compile_error!(
    "pqf-signer-core: pick exactly ONE of the `mldsa44`, `mldsa65`, `mldsa87` \
     cargo features. They're mutually exclusive."
);

#[cfg(not(any(feature = "mldsa44", feature = "mldsa65", feature = "mldsa87")))]
compile_error!(
    "pqf-signer-core: enable exactly ONE of the `mldsa44`, `mldsa65`, `mldsa87` \
     cargo features (the firmware defaults to `mldsa65`)."
);

#[cfg(feature = "mldsa44")]
pub use bouncycastle_mldsa_lowmemory::{
    MLDSA44PublicKey as MLDSAPublicKey, MLDSA44 as MLDSA, MLDSA44_PK_LEN as MLDSA_PK_LEN,
    MLDSA44_SIG_LEN as MLDSA_SIG_LEN,
};
#[cfg(feature = "mldsa65")]
pub use bouncycastle_mldsa_lowmemory::{
    MLDSA65PublicKey as MLDSAPublicKey, MLDSA65 as MLDSA, MLDSA65_PK_LEN as MLDSA_PK_LEN,
    MLDSA65_SIG_LEN as MLDSA_SIG_LEN,
};
#[cfg(feature = "mldsa87")]
pub use bouncycastle_mldsa_lowmemory::{
    MLDSA87PublicKey as MLDSAPublicKey, MLDSA87 as MLDSA, MLDSA87_PK_LEN as MLDSA_PK_LEN,
    MLDSA87_SIG_LEN as MLDSA_SIG_LEN,
};

// ---- Composite PQ/T COSE algorithm identifiers ----
//
// The ids requested for the ML-DSA + ECDSA composites in
// draft-ietf-jose-pq-composite-sigs-04 (10 September 2026). They are
// still provisional -- the draft says "TBD, request -54" and so on --
// so each level has exactly one named constant, and a future relabel
// is a one-line change per level here (plus the C port's hybrid.h and
// the host client's `ctap2::types`, which cannot link this crate).
//
// History: draft -02 requested -51/-52/-53; RFC 9864 (October 2025)
// then assigned -51 ESP384, -52 ESP512 and -53 Ed448, so those three
// numbers must never be read as a composite again. Before that the
// firmware emitted the pure ML-DSA ids -48/-49/-50 (RFC 9964) for the
// same construction. Only the label changed each time; the signing
// construction and message format did not.

/// ML-DSA-44 + ECDSA P-256 (`MLDSA44-ES256`).
pub const COSE_ALG_MLDSA44_ES256: i64 = -54;
/// ML-DSA-65 + ECDSA P-256 (`MLDSA65-ES256`).
pub const COSE_ALG_MLDSA65_ES256: i64 = -55;
/// ML-DSA-87 + ECDSA (`MLDSA87-ES384` in the draft). This firmware
/// pairs ML-DSA-87 with P-256, not P-384 -- see docs/PROTOCOL.md,
/// "Deviations from draft -04".
pub const COSE_ALG_MLDSA87_ES384: i64 = -56;

/// The composite id of *this* build's ML-DSA level: the only hybrid
/// id the firmware mints, reports in a COSE_Key or accepts in
/// `pubKeyCredParams`.
#[cfg(feature = "mldsa44")]
pub const COSE_ALG_HYBRID_MLDSA: i64 = COSE_ALG_MLDSA44_ES256;
#[cfg(feature = "mldsa65")]
pub const COSE_ALG_HYBRID_MLDSA: i64 = COSE_ALG_MLDSA65_ES256;
#[cfg(feature = "mldsa87")]
pub const COSE_ALG_HYBRID_MLDSA: i64 = COSE_ALG_MLDSA87_ES384;
