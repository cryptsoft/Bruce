// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Host-side checks of a hybrid (ECDSA-P256 + ML-DSA) signature.
//!
//! What this module verifies, and what it does not:
//!
//! - The **ECDSA-P256 half is verified in full** against the P-256 point
//!   in the credential's COSE_Key, over the message the firmware signs
//!   (`SHA-256(LABEL || msg)` for a hybrid credential, `SHA-256(msg)`
//!   for a classical one; see `docs/PROTOCOL.md`, "Hybrid signature
//!   wire format").
//! - The **ML-DSA half is checked for shape only**: the length FIPS 204
//!   fixes for the level, and that it is not all zero. Verifying it
//!   needs an ML-DSA implementation this crate deliberately does not
//!   depend on; in a deployment that is the relying party's job, and
//!   the firmware's own host tests cover the signer. A caller must say
//!   so when it reports a result from here.
//!
//! The helpers are what the `pqc_roundtrip` example reports with; the
//! `bench` example carries its own copies so that its offline self-test
//! exercises exactly the parser its live path uses.

use crate::ctap2::types::{ALG_HYBRID_MLDSA44, ALG_HYBRID_MLDSA65, ALG_HYBRID_MLDSA87};
use crate::Value;

/// The 32-byte domain-separation label the firmware prefixes to the
/// message before the ECDSA half signs it. Byte-identical to
/// `pqf_signer_core::HYBRID_LABEL` and the C port's `PQF_HYBRID_LABEL`
/// (an OpenSK constant; see `THIRD_PARTY.md`).
pub const HYBRID_LABEL: [u8; 32] = [
    43, 253, 32, 250, 19, 51, 24, 237, 138, 49, 47, 182, 4, 194, 133, 183, 177, 218, 115, 58, 92,
    117, 45, 172, 156, 5, 214, 176, 248, 103, 55, 216,
];

/// ML-DSA name, signature size and public-key size for a hybrid COSE
/// algorithm (FIPS 204 sec. 4, Table 2); `None` for a classical one.
pub fn mldsa_sizes(alg: i64) -> Option<(&'static str, usize, usize)> {
    match alg {
        ALG_HYBRID_MLDSA44 => Some(("ML-DSA-44", 2420, 1312)),
        ALG_HYBRID_MLDSA65 => Some(("ML-DSA-65", 3309, 1952)),
        ALG_HYBRID_MLDSA87 => Some(("ML-DSA-87", 4627, 2592)),
        _ => None,
    }
}

/// The parts of a credential's COSE_Key these checks need.
#[derive(Debug, Clone)]
pub struct CoseKey {
    /// COSE algorithm id (label 3).
    pub alg: i64,
    /// P-256 x coordinate (label -2), 32 bytes.
    pub x: Vec<u8>,
    /// P-256 y coordinate (label -3), 32 bytes.
    pub y: Vec<u8>,
    /// ML-DSA public key (label -4) when the algorithm is hybrid.
    pub mldsa_pub: Option<Vec<u8>>,
}

impl CoseKey {
    /// Parse the CBOR COSE_Key from an attested credential and check
    /// that its shape matches its algorithm.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let v = crate::decode(bytes).map_err(|e| format!("COSE_Key CBOR: {e:?}"))?;
        let m = match v {
            Value::Map(m) => m,
            _ => return Err("COSE_Key is not a CBOR map".to_string()),
        };
        let get = |k: i64| -> Option<&Value> {
            m.iter()
                .find(|(kk, _)| match kk {
                    Value::Uint(u) => k >= 0 && *u == k as u64,
                    Value::Nint(n) => *n == k,
                    _ => false,
                })
                .map(|(_, v)| v)
        };
        let as_int = |v: &Value| -> Option<i64> {
            match v {
                Value::Uint(u) => i64::try_from(*u).ok(),
                Value::Nint(n) => Some(*n),
                _ => None,
            }
        };
        let as_bytes = |v: &Value| -> Option<Vec<u8>> {
            match v {
                Value::Bytes(b) => Some(b.clone()),
                _ => None,
            }
        };

        let alg = get(3)
            .and_then(as_int)
            .ok_or("COSE_Key has no integer alg (label 3)")?;
        let x = get(-2)
            .and_then(as_bytes)
            .ok_or("COSE_Key has no x coordinate (label -2)")?;
        let y = get(-3)
            .and_then(as_bytes)
            .ok_or("COSE_Key has no y coordinate (label -3)")?;
        if x.len() != 32 || y.len() != 32 {
            return Err(format!(
                "COSE_Key P-256 point has wrong size: x={}B y={}B (want 32/32)",
                x.len(),
                y.len()
            ));
        }
        let mldsa_pub = get(-4).and_then(as_bytes);
        match mldsa_sizes(alg) {
            Some((name, _, want_pk)) => {
                let pk = mldsa_pub.as_ref().ok_or_else(|| {
                    format!("alg {alg} is hybrid but COSE_Key has no -4 ({name} public key)")
                })?;
                if pk.len() != want_pk {
                    return Err(format!(
                        "{name} public key is {}B, expected {want_pk}B",
                        pk.len()
                    ));
                }
            }
            None if mldsa_pub.is_some() => {
                return Err(format!(
                    "alg {alg} is not hybrid but COSE_Key carries a -4 entry"
                ));
            }
            None => {}
        }
        Ok(CoseKey {
            alg,
            x,
            y,
            mldsa_pub,
        })
    }
}

/// Split `ecdsa_der || mldsa_raw` at the DER boundary. The ECDSA
/// signature is a definite-length SEQUENCE whose length fits one byte,
/// so the split is at `sig[1] + 2` (`docs/PROTOCOL.md`).
pub fn split_hybrid_sig(sig: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if sig.len() < 8 {
        return Err(format!("hybrid signature is only {}B", sig.len()));
    }
    if sig[0] != 0x30 {
        return Err(format!(
            "hybrid signature does not start with a DER SEQUENCE tag (got 0x{:02x})",
            sig[0]
        ));
    }
    if sig[1] & 0x80 != 0 {
        return Err("ECDSA DER uses a long-form length -- not expected for P-256".to_string());
    }
    let der_len = sig[1] as usize + 2;
    if der_len > sig.len() {
        return Err(format!(
            "ECDSA DER claims {der_len}B but the signature is only {}B",
            sig.len()
        ));
    }
    Ok(sig.split_at(der_len))
}

/// Strict DER reader for `SEQUENCE { INTEGER r, INTEGER s }`,
/// returning both scalars as 32 big-endian bytes.
///
/// The parsing is the RustCrypto `ecdsa` crate's own
/// (`Signature::from_der`): minimal lengths, minimal positive
/// INTEGERs, no trailing bytes, and both scalars in `[1, n)`. An
/// earlier hand-rolled reader here read a negative INTEGER (high bit
/// set, no `0x00` pad) as the unsigned scalar with the same bytes, so a
/// malformed signature still verified -- not a forgery, but this is
/// the check that is meant to catch malformed firmware output.
pub fn parse_ecdsa_der(der: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let sig = p256::ecdsa::Signature::from_der(der)
        .map_err(|e| format!("ECDSA signature is not strict DER: {e}"))?;
    let (r, s) = sig.split_bytes();
    Ok((r.into(), s.into()))
}

/// Verify a DER ECDSA-P256 signature over `msg` (SHA-256 applied
/// internally) against the COSE_Key's public point.
pub fn verify_ecdsa_der(der: &[u8], cose: &CoseKey, msg: &[u8], what: &str) -> Result<(), String> {
    use p256::ecdsa::signature::Verifier;

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&cose.x);
    sec1.extend_from_slice(&cose.y);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| format!("{what}: COSE_Key is not a valid P-256 point: {e}"))?;

    let sig = p256::ecdsa::Signature::from_der(der)
        .map_err(|e| format!("{what}: ECDSA signature is not strict DER: {e}"))?;

    vk.verify(msg, &sig)
        .map_err(|_| format!("{what}: ECDSA-P256 signature does NOT verify"))
}

/// Check a credential signature over `msg`: a classical credential's
/// one ECDSA signature, or a hybrid credential's ECDSA half (verified
/// in full over `LABEL || msg`) plus the ML-DSA half's shape. Returns
/// one line per check that passed, so a caller prints exactly what was
/// established; the first failure is the error.
pub fn verify_credential_sig(
    alg: i64,
    sig: &[u8],
    cose: &CoseKey,
    msg: &[u8],
    what: &str,
) -> Result<Vec<String>, String> {
    match mldsa_sizes(alg) {
        None => {
            verify_ecdsa_der(sig, cose, msg, what)?;
            Ok(vec![format!("{what}: ES256 verifies")])
        }
        Some((name, want_sig, _)) => {
            let (der, mldsa) = split_hybrid_sig(sig)?;
            let mut labelled = HYBRID_LABEL.to_vec();
            labelled.extend_from_slice(msg);
            verify_ecdsa_der(der, cose, &labelled, what)?;
            if mldsa.len() != want_sig {
                return Err(format!(
                    "{what}: {name} half is {}B, expected {want_sig}B",
                    mldsa.len()
                ));
            }
            if mldsa.iter().all(|&b| b == 0) {
                return Err(format!("{what}: {name} half is all zero"));
            }
            Ok(vec![
                format!(
                    "{what}: ECDSA-P256 half verifies on the host (DER {}B, over LABEL || message)",
                    der.len()
                ),
                format!(
                    "{what}: {name} half has the right size ({}B) and is not degenerate -- \
                     not verified here (no ML-DSA verifier in this crate; a relying party does that)",
                    mldsa.len()
                ),
            ])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    fn key() -> (SigningKey, CoseKey) {
        let sk = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let cose = CoseKey {
            alg: -7,
            x: point.x().unwrap().to_vec(),
            y: point.y().unwrap().to_vec(),
            mldsa_pub: None,
        };
        (sk, cose)
    }

    /// A signature over `prefix || msg-<n>` whose DER pads `r` with a
    /// `0x00` (r's top bit set), with the `msg-<n>` it signs.
    fn padded_signature(sk: &SigningKey, prefix: &[u8]) -> (Vec<u8>, Vec<u8>) {
        for n in 0u32.. {
            let msg = format!("msg-{n}").into_bytes();
            let mut signed = prefix.to_vec();
            signed.extend_from_slice(&msg);
            let sig: Signature = sk.sign(&signed);
            let der = sig.to_der().as_bytes().to_vec();
            // 30 len 02 rlen [00 ...]
            if der[3] == 33 && der[4] == 0x00 {
                return (der, msg);
            }
        }
        unreachable!()
    }

    #[test]
    fn a_canonical_signature_verifies() {
        let (sk, cose) = key();
        let (der, msg) = padded_signature(&sk, &[]);
        assert!(verify_ecdsa_der(&der, &cose, &msg, "t").is_ok());
        let (r, s) = parse_ecdsa_der(&der).unwrap();
        let sig = Signature::from_der(&der).unwrap();
        assert_eq!(Signature::from_scalars(r, s).unwrap(), sig);
    }

    #[test]
    fn a_negative_integer_is_refused() {
        // The reviewer's case: drop r's 0x00 pad and fix both lengths.
        // r's first byte now has its top bit set -- a negative INTEGER
        // in DER -- yet the same 32 bytes; the old reader accepted it
        // and the signature verified.
        let (sk, cose) = key();
        let (der, msg) = padded_signature(&sk, &[]);
        let mut bad = vec![0x30, der[1] - 1, 0x02, 32];
        bad.extend_from_slice(&der[5..]);
        assert!(bad[4] & 0x80 != 0);
        assert!(Signature::from_der(&bad).is_err());
        assert!(parse_ecdsa_der(&bad).is_err());
        let e = verify_ecdsa_der(&bad, &cose, &msg, "t").unwrap_err();
        assert!(e.contains("not strict DER"), "{e}");
    }

    #[test]
    fn a_non_minimal_integer_is_refused() {
        // An extra 0x00 in front of an already-padded r.
        let (sk, cose) = key();
        let (der, msg) = padded_signature(&sk, &[]);
        let mut bad = vec![0x30, der[1] + 1, 0x02, 34, 0x00];
        bad.extend_from_slice(&der[4..]);
        assert!(parse_ecdsa_der(&bad).is_err());
        assert!(verify_ecdsa_der(&bad, &cose, &msg, "t").is_err());
    }

    #[test]
    fn trailing_bytes_and_truncation_are_refused() {
        let (sk, cose) = key();
        let (der, msg) = padded_signature(&sk, &[]);
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(verify_ecdsa_der(&trailing, &cose, &msg, "t").is_err());
        assert!(verify_ecdsa_der(&der[..der.len() - 1], &cose, &msg, "t").is_err());
    }

    #[test]
    fn a_hybrid_signature_with_a_negative_ecdsa_half_is_refused() {
        let (sk, mut cose) = key();
        cose.alg = ALG_HYBRID_MLDSA65;
        cose.mldsa_pub = Some(vec![7; 1952]);
        let (der, msg) = padded_signature(&sk, &HYBRID_LABEL);
        let mut good = der.clone();
        good.extend_from_slice(&[0xa5; 3309]);
        assert!(verify_credential_sig(ALG_HYBRID_MLDSA65, &good, &cose, &msg, "t").is_ok());
        let mut bad = vec![0x30, der[1] - 1, 0x02, 32];
        bad.extend_from_slice(&der[5..]);
        bad.extend_from_slice(&[0xa5; 3309]);
        assert!(verify_credential_sig(ALG_HYBRID_MLDSA65, &bad, &cose, &msg, "t").is_err());
    }
}
