// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// End-to-end register flow against an attached authenticator.
//
//   1. Open the first FIDO HID device.
//   2. Call session::register() with a synthetic challenge.
//   3. Print the credentialID, alg, and authData flags.
//
// On a device with a PIN set, the example reads the PIN from the
// BRUCE_PIN env var (no interactive prompt -- keeps it usable
// from CI). Skip the PIN gate by wiping the device first if you
// don't want to deal with it.
//
// Run:
//   cargo run -p pqf-ctaphid --example register \
//       --target $(rustc -vV | awk '/host/{print $2}')

use pqf_ctaphid::ctap2::types::{RelyingParty, User};
use pqf_ctaphid::session::{register, PinSource, RegisterRequest};
use pqf_ctaphid::{ctap2, hid};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let infos = hid::enumerate()?;
    let info = infos.first().ok_or("no FIDO HID device plugged in")?;
    let dev = hid::Device::open(info)?;
    println!("Opened {:?}", info.product);

    let req = RegisterRequest {
        rp: RelyingParty {
            id: "test.local".to_string(),
            name: Some("pqf-ctaphid smoke test".to_string()),
        },
        user: User {
            id: vec![0xa5u8; 16],
            name: Some("alice".to_string()),
            display_name: Some("Alice".to_string()),
        },
        challenge: b"some-server-supplied-32-byte-challenge!",
        origin: "https://test.local",
        pub_key_cred_params: None,
        exclude_list: None,
        options: Default::default(),
    };

    let pin = std::env::var("BRUCE_PIN").ok();
    let mut pin_source: Box<PinSource> =
        Box::new(move || Ok(pin.as_ref().map(|s| s.as_bytes().to_vec())));

    println!("\nRegistering: touch the button now if this board has one (10 s)...");
    let resp = match register(&dev, &req, &mut pin_source) {
        Ok(r) => r,
        Err(ctap2::Error::Ctap(ctap2::Status::PuatRequired)) => {
            eprintln!(
                "Device has a PIN set. Set BRUCE_PIN=... in the environment and rerun, \
                 or wipe the device to test the no-PIN path."
            );
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    println!("\nclientDataJSON: {}", resp.client_data_json);
    println!("attestation fmt: {}", resp.raw.fmt);

    let ad = &resp.auth_data;
    println!("authData:");
    println!(
        "  rpIdHash:   {}",
        ad.rp_id_hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!(
        "  flags:      0x{:02x} (UP={} UV={})",
        ad.flags,
        ad.user_present(),
        ad.user_verified()
    );
    println!("  signCount:  {}", ad.sign_count);
    if let Some(attested) = &ad.attested_credential {
        println!(
            "  aaguid:     {}",
            attested
                .aaguid
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        println!("  cred id:    {} bytes", attested.credential_id.len());
        println!(
            "  COSE_Key:   {} bytes (decoded:",
            attested.credential_public_key_cose.len()
        );
        let cose = pqf_cbor::decode(&attested.credential_public_key_cose)
            .map_err(|e| format!("COSE_Key decode: {e:?}"))?;
        if let pqf_cbor::Value::Map(m) = cose {
            for (k, v) in m {
                println!("                {:?} -> {:?}", k, summarise(&v));
            }
        }
        println!("              )");
    }
    Ok(())
}

/// Truncate a `Value` for printing -- byte strings get rendered as
/// "<N bytes>" so the output stays scannable.
fn summarise(v: &pqf_cbor::Value) -> String {
    match v {
        pqf_cbor::Value::Bytes(b) => format!("<{} bytes>", b.len()),
        other => format!("{other:?}"),
    }
}
