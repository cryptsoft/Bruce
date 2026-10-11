// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// Register AND authenticate against whichever hybrid PQC algorithm the
// attached build actually implements, check the assertion signature,
// then report which algorithm was used.
//
// Why this exists: the external conformance suite hard-codes
// MLDSA65-ES256 for its hybrid case, so on an ML-DSA-44 or ML-DSA-87 build the device
// answers CTAP2_ERR_UNSUPPORTED_ALGORITHM and every hybrid check is
// skipped. That is easy to misread as "the matrix passed" when what
// actually ran was the ES256 path and the post-quantum code -- the entire
// point of the firmware -- was never executed. This example instead sends
// the client's default pubKeyCredParams (-56, -55, -54, -7 in that
// order) and lets the authenticator's own picker choose, so it exercises
// the real PQC path on any build.
//
// Registration alone is not enough either: at ML-DSA-87 the attestation
// is ES256-only (the CTAPHID message-size ceiling), so MakeCredential
// only proves ML-DSA *key generation*. The GetAssertion below is what
// drives an actual ML-DSA signature.
//
// What is checked on the host, and what is not: the ECDSA-P256 half of
// the assertion signature is verified in full against the credential's
// public key; the ML-DSA half is checked for the size and shape FIPS
// 204 fixes, not verified -- this crate carries no ML-DSA verifier, and
// in a deployment that is the relying party's job (`pqf_ctaphid::hybrid`
// says so in detail). The output names which is which.
//
// Run:
//   ./client.sh pqc_roundtrip
// or
//   cargo run -p pqf-ctaphid --example pqc_roundtrip \
//       --target $(rustc -vV | awk '/host/{print $2}')

use pqf_ctaphid::ctap2::types::{
    CredentialDescriptor, RelyingParty, User, ALG_ES256, ALG_HYBRID_MLDSA44, ALG_HYBRID_MLDSA65,
    ALG_HYBRID_MLDSA87,
};
use pqf_ctaphid::hybrid::{self, CoseKey};
use pqf_ctaphid::session::{
    authenticate, register, AuthenticateRequest, PinSource, RegisterRequest,
};
use pqf_ctaphid::{ctap2, hid};
use sha2::{Digest, Sha256};

/// COSE algorithm ids this firmware can mint, for reporting.
fn alg_name(alg: i64) -> &'static str {
    match alg {
        ALG_HYBRID_MLDSA87 => "MLDSA87-ES384 (hybrid PQC)",
        ALG_HYBRID_MLDSA65 => "MLDSA65-ES256 (hybrid PQC)",
        ALG_HYBRID_MLDSA44 => "MLDSA44-ES256 (hybrid PQC)",
        ALG_ES256 => "ES256 (classical only)",
        _ => "unknown",
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let infos = hid::enumerate()?;
    let info = infos.first().ok_or("no FIDO HID device plugged in")?;
    let dev = hid::Device::open(info)?;
    println!("Opened {:?}", info.product);

    let rp_id = "pqc-roundtrip.local";
    let origin = "https://pqc-roundtrip.local";
    let pin = std::env::var("BRUCE_PIN").ok();
    let mut pin_source: Box<PinSource> =
        Box::new(move || Ok(pin.as_ref().map(|s| s.as_bytes().to_vec())));

    // ---- register -------------------------------------------------
    // pub_key_cred_params: None => the client's default list, which
    // offers all three composite ids before ES256, so the device picks
    // the strongest it implements.
    let req = RegisterRequest {
        rp: RelyingParty {
            id: rp_id.to_string(),
            name: Some("pqc round trip".to_string()),
        },
        user: User {
            id: vec![0x5au8; 16],
            name: Some("pqc".to_string()),
            display_name: Some("PQC Test".to_string()),
        },
        challenge: b"pqc-roundtrip-challenge-32-bytes!!",
        origin,
        pub_key_cred_params: None,
        exclude_list: None,
        options: Default::default(),
    };

    println!("\nRegistering: touch the button now if this board has one (10 s)...");
    let resp = match register(&dev, &req, &mut pin_source) {
        Ok(r) => r,
        Err(ctap2::Error::Ctap(ctap2::Status::PuatRequired)) => {
            eprintln!("Device has a PIN set -- set BRUCE_PIN=... and rerun, or wipe it.");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let attested = resp
        .auth_data
        .attested_credential
        .as_ref()
        .ok_or("MakeCredential returned no attested credential")?;
    let cred_id = attested.credential_id.clone();
    let cose = CoseKey::parse(&attested.credential_public_key_cose)?;
    let alg = cose.alg;
    println!("\n== MakeCredential ==");
    println!("  negotiated alg : {} ({})", alg, alg_name(alg));
    println!("  credential id  : {} bytes", cred_id.len());
    println!("  attestation fmt: {}", resp.raw.fmt);
    if alg == -7 {
        eprintln!(
            "\n  WARNING: the device fell back to ES256, so NO post-quantum code ran. \
             That is what a build advertising a composite alg it cannot mint looks like."
        );
    }

    // ---- authenticate ---------------------------------------------
    // This is the step that makes the device produce an ML-DSA
    // signature; registration at level 87 attests with ES256 only.
    let auth_req = AuthenticateRequest {
        rp_id: rp_id.to_string(),
        challenge: b"pqc-roundtrip-assertion-challenge!",
        origin,
        allow_list: Some(vec![CredentialDescriptor {
            id: cred_id.clone(),
            transports: None,
        }]),
        options: Default::default(),
    };

    println!("\nSigning: touch the button again if this board has one (10 s)...");
    let auth = authenticate(&dev, &auth_req, &mut pin_source)?;
    println!("\n== GetAssertion ==");
    println!("  signature      : {} bytes", auth.raw.signature.len());
    println!("  signCount      : {}", auth.auth_data.sign_count);
    println!("  flags          : 0x{:02x}", auth.auth_data.flags);

    // ---- check the signature --------------------------------------
    // An assertion signs authData || SHA-256(clientDataJSON), with the
    // credential's own key; the session returns the exact JSON it sent.
    let mut signed = auth.raw.auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(auth.client_data_json.as_bytes()));
    println!("\n== Signature check (host) ==");
    let lines =
        hybrid::verify_credential_sig(alg, &auth.raw.signature, &cose, &signed, "assertion")?;
    for l in &lines {
        println!("  ok {l}");
    }

    match hybrid::mldsa_sizes(alg) {
        Some((name, _, _)) => println!(
            "\nPQC round trip OK -- registered and signed with {}.\n\
             The ECDSA-P256 half was verified on this host; the {name} half was checked \
             for size and shape only (verifying it is a relying party's job).",
            alg_name(alg)
        ),
        None => println!(
            "\nRound trip OK -- registered and signed with {}, verified on this host.",
            alg_name(alg)
        ),
    }
    Ok(())
}
