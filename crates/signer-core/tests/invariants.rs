// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Host tests for the parts of the signer that are not the silicon.
//!
//! This crate could not be compiled for the host at all until the
//! architecture shim grew a fallback arm and the two `.data.ramfunc`
//! attributes were made conditional -- `.data.ramfunc` is an ELF section
//! name and a host build links Mach-O. Everything the worker does that
//! is *not* cross-core handshaking is ordinary code, and this is where
//! it gets checked without a board.
//!
//! Run with the variant you care about, on the host:
//!
//! ```text
//! cargo test -p pqf-signer-core --features mldsa65 \
//!     --target "$(rustc -vV | awk '/^host:/{print $2}')"
//! ```

use pqf_signer_core::mldsa_alg::{MLDSA_PK_LEN, MLDSA_SIG_LEN};
use pqf_signer_core::signer::{Core1Signer, HYBRID_LABEL, MAX_MSG_LEN};

/// FIPS 204 Table 2. Hard-coded rather than derived, because deriving
/// them from the same constants under test would prove nothing.
const FIPS204: &[(&str, usize, usize)] = &[
    // (variant, public key bytes, signature bytes)
    ("mldsa44", 1312, 2420),
    ("mldsa65", 1952, 3309),
    ("mldsa87", 2592, 4627),
];

fn selected() -> &'static str {
    if cfg!(feature = "mldsa44") {
        "mldsa44"
    } else if cfg!(feature = "mldsa65") {
        "mldsa65"
    } else {
        "mldsa87"
    }
}

#[test]
fn the_selected_variant_has_the_sizes_fips_204_specifies() {
    // These size the mailbox buffers, which are shared SRAM in the
    // mixed-architecture build: the Arm firmware and the RISC-V core-1
    // blob lay out the same struct from the same constants. A wrong
    // value here is not a failed signature, it is one core writing past
    // where the other expects the buffer to end.
    let (_, pk, sig) = FIPS204
        .iter()
        .find(|(name, _, _)| *name == selected())
        .expect("exactly one variant feature must be enabled");
    assert_eq!(MLDSA_PK_LEN, *pk, "{} public key length", selected());
    assert_eq!(MLDSA_SIG_LEN, *sig, "{} signature length", selected());
}

#[test]
fn the_mailbox_is_laid_out_the_way_both_cores_expect() {
    // In the mixed-architecture build this struct IS the cross-core ABI:
    // the Arm firmware and the RISC-V core-1 blob each compile their own
    // copy from these same constants and meet in shared SRAM. The
    // signature buffer is sized to the *selected* variant, not to the
    // largest, so a build where the two sides disagreed about the level
    // would not fail to link -- one core would simply write past where
    // the other expects the buffer to end.
    //
    // Nothing here can catch that mismatch across two separate builds;
    // what it can catch is a field being added, removed or resized on
    // one side of a refactor, which changes the total.
    let buffers = 32          // ecdsa_scalar
        + 32                  // mldsa_seed
        + MAX_MSG_LEN         // msg
        + 80                  // ecdsa_der, worst-case P-256 DER
        + MLDSA_SIG_LEN; // mldsa_sig
    let total = core::mem::size_of::<Core1Signer>();
    assert!(
        total >= buffers,
        "Core1Signer is {total} bytes but its buffers alone need {buffers}"
    );
    // The atomics and any padding, generously bounded. A jump past this
    // means a field appeared that the other core does not know about.
    assert!(
        total <= buffers + 64,
        "Core1Signer is {total} bytes, {} more than its buffers need -- \
         a new field here has to be added to the blob too",
        total - buffers
    );
}

#[test]
fn a_credential_message_fits_the_mailbox() {
    // authenticatorData + clientDataHash for a credential with the
    // largest attested public key. If MAX_MSG_LEN ever drops below what
    // a real assertion carries, the failure is a refused signature at
    // ceremony time and nowhere else.
    let largest_pk = FIPS204.iter().map(|(_, p, _)| *p).max().unwrap();
    assert!(
        MAX_MSG_LEN > largest_pk + 512,
        "MAX_MSG_LEN {MAX_MSG_LEN} leaves no room for a {largest_pk}-byte key plus authData"
    );
}

#[test]
fn the_hybrid_label_is_the_openskin_constant_byte_for_byte() {
    // Wire compatibility with OpenSK-PQC-fork relying parties rests
    // entirely on this value: it is the domain separator hashed into
    // both halves of the composite. A single wrong byte produces
    // signatures that verify nowhere, and the only symptom is a relying
    // party rejecting every assertion.
    //
    // Written out again here rather than referenced, so that editing the
    // constant cannot silently edit its own test.
    const EXPECTED: [u8; 32] = [
        43, 253, 32, 250, 19, 51, 24, 237, 138, 49, 47, 182, 4, 194, 133, 183, 177, 218, 115, 58,
        92, 117, 45, 172, 156, 5, 214, 176, 248, 103, 55, 216,
    ];
    assert_eq!(HYBRID_LABEL, EXPECTED);
}

#[test]
fn the_hybrid_label_is_not_accidentally_trivial() {
    // Cheap guard against a constant that got zeroed or truncated by a
    // bad merge -- the kind of damage that still compiles.
    assert_ne!(HYBRID_LABEL, [0u8; 32]);
    assert!(
        HYBRID_LABEL
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            > 16,
        "label has suspiciously few distinct bytes"
    );
}

// ---- the architecture shim's host arms --------------------------------

#[test]
fn the_interrupt_shims_are_a_no_op_pair_off_target() {
    // On the host there is no PRIMASK and no mstatus. The point of the
    // fallback arms is that this crate compiles and can be tested at
    // all; the contract they have to keep is that saving and restoring
    // is inert rather than pretending to have masked something.
    let saved = pqf_signer_core::arch::irq_save_disable();
    assert_eq!(saved, 0, "the host arm must report nothing was masked");
    pqf_signer_core::arch::irq_restore(saved);
    // Nested use is what the flash-blackout callers actually do.
    let a = pqf_signer_core::arch::irq_save_disable();
    let b = pqf_signer_core::arch::irq_save_disable();
    pqf_signer_core::arch::irq_restore(b);
    pqf_signer_core::arch::irq_restore(a);
}

#[test]
fn the_event_shims_do_not_block_off_target() {
    // `wfe` parks a core until the other one sends an event. With no
    // second core it must return rather than hang, or every host test
    // that touches the worker would deadlock instead of failing.
    pqf_signer_core::arch::nop();
    pqf_signer_core::arch::sev();
    pqf_signer_core::arch::wfe();
}

/// The single-core build's entry point: one sign, synchronously, on the
/// calling core, parked where `take_result` looks. This is the path the
/// timer-driven KEEPALIVE build takes instead of `submit` + worker, so
/// it gets the check the worker gets on silicon -- the shape of the
/// result -- plus two the worker never had: the ECDSA half verifies
/// under the public key, and the ML-DSA half is deterministic.
#[test]
fn sign_here_runs_to_completion_and_the_result_verifies() {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

    static SIGNER: Core1Signer = Core1Signer::new();
    let mut scalar = [0x11u8; 32];
    scalar[31] = 0x27;
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
    let msg: Vec<u8> = (0..200u32).map(|i| (i * 7) as u8).collect();

    assert!(!SIGNER.is_done(), "fresh signer already done");
    SIGNER
        .sign_here(&scalar, &seed, &msg)
        .expect("message fits");
    assert!(
        SIGNER.is_done(),
        "sign_here returned without parking a result"
    );
    assert!(!SIGNER.errored(), "sign_here reported an error");

    let mut out = Vec::new();
    SIGNER.take_result(&mut out);
    assert!(
        out.len() > MLDSA_SIG_LEN,
        "no ECDSA prefix in front of the ML-DSA half"
    );
    let der_len = out.len() - MLDSA_SIG_LEN;
    assert!(
        (70..=72).contains(&der_len),
        "DER ECDSA length {der_len} is not P-256's"
    );

    // ECDSA half: verify over SHA-256(LABEL || msg) with the key the
    // scalar defines.
    let vk = VerifyingKey::from(&SigningKey::from_bytes((&scalar).into()).unwrap());
    let prehash = {
        use bouncycastle_core_interface::traits::Hash;
        let mut h = bouncycastle_sha2::SHA256::default();
        h.do_update(&HYBRID_LABEL);
        h.do_update(&msg);
        let mut o = [0u8; 32];
        h.do_final_out(&mut o);
        o
    };
    let sig = Signature::from_der(&out[..der_len]).expect("DER parses");
    vk.verify_prehash(&prehash, &sig)
        .expect("ECDSA half does not verify");

    // ML-DSA half: deterministic (rnd = 0^32, RFC 6979 ECDSA in front),
    // so a second run is byte-identical. `take_result` returned the
    // signer to IDLE, which is also what lets the second call proceed.
    SIGNER.sign_here(&scalar, &seed, &msg).expect("second sign");
    let mut again = Vec::new();
    SIGNER.take_result(&mut again);
    assert_eq!(out, again, "the inline sign is not deterministic");

    // Oversized message: refused up front, state untouched.
    let big = vec![0u8; MAX_MSG_LEN + 1];
    assert!(SIGNER.sign_here(&scalar, &seed, &big).is_err());
    assert!(!SIGNER.is_done(), "a refused request left a result behind");
}
