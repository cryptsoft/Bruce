// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// Register and authenticate against ONE explicitly-named COSE algorithm.
//
// `pqc_roundtrip` sends the client's default pubKeyCredParams and lets
// the authenticator pick, which is right for proving the PQC path runs
// but cannot target an algorithm the default list omits. Optional
// firmware features add exactly those: `ed25519` advertises EdDSA (-8),
// which no default list and no conformance suite (composites only)
// will ever request.
//
//   cargo run -p pqf-ctaphid --example alg_roundtrip \
//       --target $(rustc -vV | awk '/host/{print $2}') -- -8
use pqf_ctaphid::ctap2::types::{CredentialDescriptor, PubKeyCredParam, RelyingParty, User};
use pqf_ctaphid::hid;
use pqf_ctaphid::session::{
    authenticate, register, AuthenticateRequest, PinSource, RegisterRequest,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alg: i64 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(-8);
    let infos = hid::enumerate()?;
    let info = infos.first().ok_or("no FIDO HID device")?;
    let dev = hid::Device::open(info)?;
    println!("Opened {:?}, requesting ONLY alg {}", info.product, alg);

    let rp_id = "alg-roundtrip.local";
    // Same PIN handling as the other examples: BRUCE_PIN in the
    // environment, none if unset (a token with a PIN then answers
    // PuatRequired).
    let pin = std::env::var("BRUCE_PIN").ok();
    let mut pin_source: Box<PinSource> =
        Box::new(move || Ok(pin.as_ref().map(|s| s.as_bytes().to_vec())));
    let req = RegisterRequest {
        rp: RelyingParty {
            id: rp_id.to_string(),
            name: Some("alg roundtrip".into()),
        },
        user: User {
            id: vec![0x7au8; 16],
            name: Some("alg".into()),
            display_name: Some("Alg".into()),
        },
        challenge: b"alg-roundtrip-challenge-32-bytes!",
        origin: "https://alg-roundtrip.local",
        pub_key_cred_params: Some(vec![PubKeyCredParam::new(alg)]),
        exclude_list: None,
        options: Default::default(),
    };
    println!("Registering: touch the button now if this board has one (10 s)...");
    let resp = register(&dev, &req, &mut pin_source)?;
    let att = resp
        .auth_data
        .attested_credential
        .as_ref()
        .ok_or("no attested credential")?;
    println!(
        "  MakeCredential OK: credId {} bytes, fmt {}",
        att.credential_id.len(),
        resp.raw.fmt
    );

    println!("Signing: touch the button again if this board has one (10 s)...");
    let auth = authenticate(
        &dev,
        &AuthenticateRequest {
            rp_id: rp_id.to_string(),
            challenge: b"alg-roundtrip-assertion-challenge",
            origin: "https://alg-roundtrip.local",
            allow_list: Some(vec![CredentialDescriptor {
                id: att.credential_id.clone(),
                transports: None,
            }]),
            options: Default::default(),
        },
        &mut pin_source,
    )?;
    println!(
        "  GetAssertion OK: signature {} bytes",
        auth.raw.signature.len()
    );
    println!("round trip OK with alg {}", alg);
    Ok(())
}
