// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// Count the CTAPHID KEEPALIVE frames a token sends while it signs.
//
// The host's transport layer swallows KEEPALIVE (0xBB) frames so callers
// only ever see the real response; it counts them on the way through
// (`Device::stats().keepalives`). That count is the one thing a host can
// observe about how a token keeps the channel alive during a ~1 s hybrid
// signature, which makes it the witness for the single-core builds: there
// the frames come from a timer interrupt (Rust) or from yield hooks in
// the crypto (C) rather than from a second core pumping USB.
//
//   1. Open the first FIDO HID device and print its product string
//      (single-core images append " 1CORE").
//   2. Register, then authenticate against the new credential.
//   3. For each: wall time, KEEPALIVE frames, the mean period between
//      them, and the longest silence the host saw between two frames
//      (`Stats::max_gap`, the number a client watchdog acts on). A
//      dual-core image pumps at ~50 ms; the single-core builds at ~25 ms.
//      Zero frames on a slow operation means the host's watchdog was on
//      its own. A denied operation (presence-gated build, nobody pressed)
//      still gets its row, so the cadence during the presence wait is
//      visible too; the exit code is then 3.
//
// PIN: read from BRUCE_PIN like the register example. Both operations
// need user presence; the test builds confirm it automatically.
//
// Run:
//   cargo run -p pqf-ctaphid --example keepalives \
//       --target $(rustc -vV | awk '/host/{print $2}')

use std::time::Instant;

use pqf_ctaphid::ctap2::types::{CredentialDescriptor, RelyingParty, User};
use pqf_ctaphid::session::{
    authenticate, register, AuthenticateRequest, PinSource, RegisterRequest,
};
use pqf_ctaphid::{ctap2, hid};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let infos = hid::enumerate()?;
    let info = infos.first().ok_or("no FIDO HID device plugged in")?;
    let dev = hid::Device::open(info)?;
    let product = info.product.clone().unwrap_or_default();
    println!("device: {product:?}");

    let pin = std::env::var("BRUCE_PIN").ok();
    let mut pin_source: Box<PinSource> =
        Box::new(move || Ok(pin.as_ref().map(|s| s.as_bytes().to_vec())));

    let rp_id = "keepalive.test";
    let origin = "https://keepalive.test";
    let challenge = [0x5au8; 32];

    let reg = RegisterRequest {
        rp: RelyingParty {
            id: rp_id.to_string(),
            name: Some("keepalive witness".to_string()),
        },
        user: User {
            id: vec![0x3cu8; 16],
            name: Some("witness".to_string()),
            display_name: Some("Witness".to_string()),
        },
        challenge: &challenge,
        origin,
        pub_key_cred_params: None,
        exclude_list: None,
        options: Default::default(),
    };

    // The PIN handshake (getInfo, clientPin) happens inside register()
    // too; it is quick and sends no keepalives, so it does not distort
    // the count. Stats are reset right before each operation.
    // Stats are reset right before each operation. A failed operation
    // still gets its row: a presence-gated build that nobody touched
    // answers OperationDenied after its 10 s wait, and how the token kept
    // the channel alive during that wait is exactly what this is for.
    let mut rows: Vec<(&str, f64, pqf_ctaphid::hid::Stats, String)> = Vec::new();
    let mut worst = 0;

    dev.reset_stats();
    let t0 = Instant::now();
    let reg_res = register(&dev, &reg, &mut pin_source);
    let reg_ms = t0.elapsed().as_secs_f64() * 1e3;
    let (reg_status, reg_code) = describe(&reg_res);
    rows.push(("makeCredential", reg_ms, dev.stats(), reg_status));
    worst = worst.max(reg_code);

    if let Ok(resp) = &reg_res {
        let cred_id = resp
            .auth_data
            .attested_credential
            .as_ref()
            .ok_or("makeCredential returned no attested credential")?
            .credential_id
            .clone();
        let auth = AuthenticateRequest {
            rp_id: rp_id.to_string(),
            challenge: &challenge,
            origin,
            allow_list: Some(vec![CredentialDescriptor {
                id: cred_id,
                transports: None,
            }]),
            options: Default::default(),
        };
        dev.reset_stats();
        let t1 = Instant::now();
        let auth_res = authenticate(&dev, &auth, &mut pin_source);
        let auth_ms = t1.elapsed().as_secs_f64() * 1e3;
        let (auth_status, auth_code) = describe(&auth_res);
        rows.push(("getAssertion", auth_ms, dev.stats(), auth_status));
        worst = worst.max(auth_code);
    }

    println!(
        "{:<16} {:>9} {:>11} {:>12} {:>11}  {}",
        "operation", "wall ms", "keepalives", "mean gap ms", "max gap ms", "result"
    );
    for (name, ms, st, status) in &rows {
        let gap = if st.keepalives > 0 {
            format!("{:.1}", ms / st.keepalives as f64)
        } else {
            "-".to_string()
        };
        let max_gap = st.max_gap.as_secs_f64() * 1e3;
        println!(
            "{name:<16} {ms:>9.0} {:>11} {gap:>12} {max_gap:>11.1}  {status}",
            st.keepalives
        );
    }
    if worst != 0 {
        std::process::exit(worst);
    }
    Ok(())
}

/// The result column, and the process exit code it maps to: 0 ok,
/// 3 presence denied, 2 PIN required, 1 anything else.
fn describe<T>(r: &Result<T, ctap2::Error>) -> (String, i32) {
    match r {
        Ok(_) => ("ok".to_string(), 0),
        Err(ctap2::Error::Ctap(ctap2::Status::OperationDenied)) => {
            ("denied (no presence)".to_string(), 3)
        }
        Err(ctap2::Error::Ctap(ctap2::Status::PuatRequired)) => {
            ("PIN required (set BRUCE_PIN)".to_string(), 2)
        }
        Err(e) => (format!("error: {e:?}"), 1),
    }
}
