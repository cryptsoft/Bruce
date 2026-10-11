// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// TrustZone image test suite, driven entirely by the in-tree client.
//
// The device is opened ONCE, and that one handle serves both the CTAP2
// commands and the dev-only vendor commands the TrustZone build
// exposes (`hid::Device::vendor`).
//
// Vendor commands (dev builds only):
//   0x42  presence: empty = one simulated touch, 0x01 latch on,
//                   0x02 latch off
//   0x43  raw button state, no gesture logic
//   0x44  register probe: CTRL readback | QSPI_CSN bit
//
//   cargo run -p pqf-ctaphid --example tz_test \
//       --target $(rustc -vV | awk '/host/{print $2}') -- \
//       [--press] [--pin] [--latch on|off] [--churn] [--count] [device-path]
//
//     --churn  fill the resident store and replace repeatedly, to
//              force compaction and prove nothing is lost
//     --count  one signature, print the counter, and exit
//     --latch  set the dev presence latch and exit. The conformance suite
//              cannot press a button, so it needs presence latched on for the
//              whole run; without it every UP-gated command times out
//              and the entire suite cascades into failure.
//     --press  wait for a REAL finger instead of injecting one
//     --pin    exercise ClientPIN too
//
// With no device path, the FIDO HID device whose product string
// contains "TZ-NS" is used.
//
// ClientPIN is behind a flag because those checks LEAVE A PIN SET, and
// the conformance suite manages its own -- run them together in that
// order and every PIN verification in the suite fails and cascades through the whole suite.
// Learned the hard way; it looked exactly like a firmware regression.

use std::io::Write;

use pqf_cbor::Value;
use pqf_ctaphid::ctap2::client_pin::{self, permission, PinUvAuth};
use pqf_ctaphid::ctap2::get_assertion::{self, GetAssertionRequest, GetAssertionResponse};
use pqf_ctaphid::ctap2::get_info::{self, GetInfo};
use pqf_ctaphid::ctap2::make_credential::{self, MakeCredentialRequest};
use pqf_ctaphid::ctap2::pin_protocol::Protocol;
use pqf_ctaphid::ctap2::types::{
    AuthOptions, CredentialDescriptor, PubKeyCredParam, RelyingParty, User, ALG_ES256,
};
use pqf_ctaphid::ctap2::{self, credential_management, get_next_assertion, Error, Status};
use pqf_ctaphid::hid;
use pqf_ctaphid::session::AuthData;

const VENDOR_PRESENCE: u8 = 0x42;
const VENDOR_PROBE: u8 = 0x44;
const VENDOR_LAST_CBOR: u8 = 0x45;

/// The suite's shared state: the one device handle, the failure count,
/// and whether a real finger is doing the touching.
struct Tz {
    dev: hid::Device,
    failures: u32,
    real_press: bool,
}

impl Tz {
    fn ok(&mut self, what: &str, cond: bool) {
        println!("  [{}] {what}", if cond { "PASS" } else { "FAIL" });
        if !cond {
            self.failures += 1;
        }
    }

    /// One simulated touch, unless --press asked for a real one.
    fn touch(&self) {
        if self.real_press {
            println!("    >>> PRESS AND RELEASE THE BUTTON <<<");
            let _ = std::io::stdout().flush();
            return;
        }
        if let Err(e) = self.dev.vendor(VENDOR_PRESENCE, &[0]) {
            println!("    (touch injection failed: {e})");
        }
    }

    fn presence_latch(&self, on: bool) {
        if self.real_press {
            return;
        }
        let mode = if on { 0x01 } else { 0x02 };
        if let Err(e) = self.dev.vendor(VENDOR_PRESENCE, &[mode]) {
            println!("    (presence latch failed: {e})");
        }
    }
}

fn fill_random(b: &mut [u8]) {
    rand::Rng::fill(&mut rand::rngs::OsRng, b);
}

fn random_u16() -> u16 {
    rand::Rng::gen(&mut rand::rngs::OsRng)
}

/// A getInfo option as the C client reported it: 1 true, 0 false,
/// -1 absent.
fn tri(o: Option<bool>) -> i32 {
    match o {
        Some(true) => 1,
        Some(false) => 0,
        None => -1,
    }
}

/// COSE alg (label 3) of an attested credential's public key.
fn cose_alg(cose: &[u8]) -> i64 {
    match pqf_cbor::decode(cose) {
        Ok(Value::Map(m)) => m
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Uint(3), Value::Nint(n)) => Some(*n),
                (Value::Uint(3), Value::Uint(u)) => Some(*u as i64),
                _ => None,
            })
            .unwrap_or(0),
        _ => 0,
    }
}

fn is_status<T>(r: &Result<T, Error>, s: Status) -> bool {
    matches!(r, Err(Error::Ctap(got)) if *got == s)
}

/// (rc, status byte) as the C harness printed them: rc 0 on success
/// and -1 on any failure; the CTAP status byte, or 0x00 when the
/// failure was not a CTAP one.
fn rc_status<T>(r: &Result<T, Error>) -> (i32, u8) {
    match r {
        Ok(_) => (0, 0x00),
        Err(Error::Ctap(s)) => (-1, *s as u8),
        Err(_) => (-1, 0x00),
    }
}

/// Prefer PIN protocol 2, as the rest of the crate does; fall back to
/// 1 only on a device that advertises nothing else.
fn pin_protocol(info: Option<&GetInfo>) -> Protocol {
    match info.and_then(|i| i.pin_uv_auth_protocols.as_ref()) {
        Some(p) if !p.contains(&2) && p.contains(&1) => Protocol::V1,
        _ => Protocol::V2,
    }
}

fn mint_token(
    dev: &hid::Device,
    proto: Protocol,
    pin: &[u8],
    permissions: u8,
    rp_id: Option<&str>,
) -> Result<PinUvAuth, Error> {
    let session = client_pin::establish_session(dev, proto)?;
    client_pin::get_pin_uv_auth_token_using_pin(dev, session, pin, permissions, rp_id)
}

/// A fresh MakeCredential request: random clientDataHash, ES256 only,
/// user name "u", nothing optional.
fn mc_request(rp_id: &str, user_id: &[u8]) -> MakeCredentialRequest {
    let mut cdh = [0u8; 32];
    fill_random(&mut cdh);
    MakeCredentialRequest {
        client_data_hash: cdh,
        rp: RelyingParty {
            id: rp_id.to_string(),
            name: None,
        },
        user: User {
            id: user_id.to_vec(),
            name: Some("u".to_string()),
            display_name: None,
        },
        pub_key_cred_params: vec![PubKeyCredParam::new(ALG_ES256)],
        exclude_list: None,
        extensions: None,
        options: None,
        pin_uv_auth_param: None,
        pin_uv_auth_protocol: None,
        enterprise_attestation: None,
    }
}

/// A fresh GetAssertion request with a random clientDataHash and no
/// allowList (discoverable).
fn ga_request(rp_id: &str) -> GetAssertionRequest {
    let mut cdh = [0u8; 32];
    fill_random(&mut cdh);
    GetAssertionRequest {
        rp_id: rp_id.to_string(),
        client_data_hash: cdh,
        allow_list: None,
        extensions: None,
        options: None,
        pin_uv_auth_param: None,
        pin_uv_auth_protocol: None,
    }
}

/// MakeCredential with the authData parsed, which is what the C client
/// handed back: flags, signCount and credentialId all live there.
fn make_cred(dev: &hid::Device, mc: &MakeCredentialRequest) -> Result<AuthData, Error> {
    let r = make_credential::make_credential(dev, mc)?;
    AuthData::parse(&r.auth_data)
}

/// GetAssertion with the authData parsed alongside the response.
fn get_assert(
    dev: &hid::Device,
    ga: &GetAssertionRequest,
) -> Result<(GetAssertionResponse, AuthData), Error> {
    let r = get_assertion::get_assertion(dev, ga)?;
    let ad = AuthData::parse(&r.auth_data)?;
    Ok((r, ad))
}

fn get_next(dev: &hid::Device) -> Result<(GetAssertionResponse, AuthData), Error> {
    let r = get_next_assertion::get_next_assertion(dev)?;
    let ad = AuthData::parse(&r.auth_data)?;
    Ok((r, ad))
}

fn main() {
    let mut real_press = false;
    let mut do_pin = false;
    let mut do_churn = false;
    let mut do_count = false;
    let mut latch_mode: Option<bool> = None;
    let mut path: Option<String> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--press" => real_press = true,
            "--pin" => do_pin = true,
            "--churn" => do_churn = true,
            "--count" => do_count = true,
            "--latch" if i + 1 < args.len() => {
                i += 1;
                latch_mode = Some(args[i] == "on");
            }
            other => path = Some(other.to_string()),
        }
        i += 1;
    }

    let info = match path {
        Some(path) => hid::DeviceInfo {
            path,
            vendor_id: 0,
            product_id: 0,
            manufacturer: None,
            product: None,
            serial_number: None,
        },
        None => {
            let infos = match hid::enumerate() {
                Ok(v) if !v.is_empty() => v,
                _ => {
                    println!("no FIDO devices found");
                    std::process::exit(1);
                }
            };
            let tz = infos
                .into_iter()
                .filter(|d| d.product.as_deref().map_or(false, |p| p.contains("TZ-NS")))
                .last();
            match tz {
                Some(d) => d,
                None => {
                    println!("no TZ-NS device found");
                    std::process::exit(1);
                }
            }
        }
    };
    let dev = match hid::Device::open(&info) {
        Ok(d) => d,
        Err(_) => {
            println!("open failed");
            std::process::exit(1);
        }
    };

    if let Some(on) = latch_mode {
        // The firmware acknowledges this command with a byte of its
        // own; `vendor` reads that reply rather than leaving it on the
        // channel for the next command to trip over.
        let rc = dev.vendor(VENDOR_PRESENCE, &[if on { 0x01 } else { 0x02 }]);
        println!(
            "presence latch {}: {}",
            if on { "on" } else { "off" },
            if rc.is_ok() { "ok" } else { "FAILED" }
        );
        drop(dev);
        std::process::exit(if rc.is_ok() { 0 } else { 1 });
    }

    let mut tz = Tz {
        dev,
        failures: 0,
        real_press,
    };

    // ---- counter probe: one signature, print the count ----
    if do_count {
        tz.presence_latch(true);
        let mut user_id = [0u8; 16];
        fill_random(&mut user_id);
        let mc = mc_request("count.example", &user_id);
        let count = make_cred(&tz.dev, &mc).map(|ad| ad.sign_count).unwrap_or(0);
        println!("signCount={count}");
        tz.presence_latch(false);
        drop(tz);
        std::process::exit(0);
    }

    // ---- getInfo ----
    let info = get_info::get_info(&tz.dev);
    tz.ok("getInfo succeeds", info.is_ok());
    let info: Option<GetInfo> = info.ok();
    let option = |name: &str| info.as_ref().and_then(|i| i.option(name));
    println!(
        "    rk={} up={} clientPin={}",
        tri(option("rk")),
        tri(option("up")),
        tri(option("clientPin"))
    );
    let pin_was_set = option("clientPin") == Some(true);
    let proto = pin_protocol(info.as_ref());

    // ---- the presence gate refuses without a gesture ----
    tz.presence_latch(false);
    let mut user_id = [0u8; 16];
    fill_random(&mut user_id);
    let mut mc = mc_request("tz.example", &user_id);
    let rc = make_cred(&tz.dev, &mc);
    tz.ok(
        "no gesture -> MakeCredential refused",
        is_status(&rc, Status::OperationDenied),
    );

    // ---- ...and succeeds with one ----
    tz.touch();
    fill_random(&mut mc.client_data_hash);
    let rc = make_cred(&tz.dev, &mc);
    tz.ok("gesture -> MakeCredential succeeds", rc.is_ok());
    let mut cred_id: Vec<u8> = Vec::new();
    let mut first_count: u32 = 0;
    if let Ok(ad) = &rc {
        tz.ok("UP flag set in authData", ad.flags & 0x01 != 0);
        tz.ok("attested credential data present", ad.flags & 0x40 != 0);
        let mut alg = 0;
        if let Some(att) = &ad.attested_credential {
            cred_id = att.credential_id.clone();
            alg = cose_alg(&att.credential_public_key_cose);
        }
        first_count = ad.sign_count;
        println!(
            "    alg={alg} credIdLen={} signCount={}",
            cred_id.len(),
            ad.sign_count
        );
    }

    // ---- one touch authorises exactly one operation ----
    let mut ga = ga_request("tz.example");
    if !cred_id.is_empty() {
        ga.allow_list = Some(vec![CredentialDescriptor {
            id: cred_id.clone(),
            transports: None,
        }]);
        let rc = get_assert(&tz.dev, &ga);
        tz.ok(
            "one touch authorises ONE operation",
            is_status(&rc, Status::OperationDenied),
        );
    }

    // ---- signature counter strictly increases ----
    if !cred_id.is_empty() {
        let mut prev = first_count;
        let mut monotonic = true;
        for _ in 0..8 {
            tz.touch();
            fill_random(&mut ga.client_data_hash);
            match get_assert(&tz.dev, &ga) {
                Ok((_, ad)) if ad.sign_count > prev => prev = ad.sign_count,
                _ => {
                    monotonic = false;
                    break;
                }
            }
        }
        tz.ok(
            "signature counter strictly increasing over 8 assertions",
            monotonic,
        );
        println!("    {first_count} -> {prev}");
    }

    // ---- resident credentials ----
    tz.presence_latch(true);
    {
        let rp = format!("res-{:04x}.example", random_u16());
        // rk requested; up and uv left out of the map.
        mc.rp.id = rp.clone();
        mc.options = Some(AuthOptions {
            rk: Some(true),
            up: None,
            uv: None,
        });
        tz.touch();
        fill_random(&mut mc.client_data_hash);
        let rc = make_cred(&tz.dev, &mc);
        tz.ok("resident MakeCredential succeeds", rc.is_ok());

        // discoverable: no allowList at all
        let mut ga = ga_request(&rp);
        tz.touch();
        let rc = get_assert(&tz.dev, &ga);
        tz.ok(
            "no allowList -> discoverable assertion succeeds",
            rc.is_ok(),
        );
        if let Ok((resp, _)) = &rc {
            tz.ok(
                "user handle returned",
                resp.user
                    .as_ref()
                    .map_or(false, |u| u.id.len() == user_id.len()),
            );
        }

        // a second user makes the count 2 and GetNextAssertion reachable
        let mut uid2 = [0u8; 16];
        fill_random(&mut uid2);
        mc.user.id = uid2.to_vec();
        tz.touch();
        fill_random(&mut mc.client_data_hash);
        let _ = make_cred(&tz.dev, &mc);
        tz.touch();
        fill_random(&mut ga.client_data_hash);
        let rc = get_assert(&tz.dev, &ga);
        tz.ok(
            "two credentials reported",
            matches!(&rc, Ok((r, _)) if r.number_of_credentials == Some(2)),
        );
        let rc = get_next(&tz.dev);
        tz.ok("GetNextAssertion reaches the second credential", rc.is_ok());
        mc.user.id = user_id.to_vec();
        mc.options = None;
    }

    // ---- resident-store churn: force compaction ----
    if do_churn {
        // Compaction is about reclaiming DEAD records, so the test
        // has to generate dead records without growing the live set.
        //
        // A fixed set of users, re-registered over and over: each
        // replacement retires the old record and consumes a fresh
        // slot, while the live count stays at USERS. Without
        // compaction the store wedges after 64 writes no matter how
        // few credentials are actually live. With it, this runs
        // indefinitely.
        //
        // Registering distinct users instead would only have measured
        // capacity -- 56 live is 56 live however well compaction
        // works -- which is what the first version of this test got
        // wrong.
        const USERS: usize = 8;
        const ROUNDS: usize = 30;
        let rp3 = format!("churn-{:04x}.example", random_u16());
        mc.rp.id = rp3.clone();
        mc.options = Some(AuthOptions {
            rk: Some(true),
            up: None,
            uv: None,
        });
        tz.presence_latch(true);
        let (mut ok_count, mut fail_count) = (0usize, 0usize);
        for _ in 0..ROUNDS {
            for n in 0..USERS {
                let mut uid = [0u8; 16];
                uid[0] = n as u8;
                mc.user.id = uid.to_vec();
                fill_random(&mut mc.client_data_hash);
                if make_cred(&tz.dev, &mc).is_ok() {
                    ok_count += 1;
                } else {
                    fail_count += 1;
                }
            }
        }
        println!(
            "    churn: {ok_count} accepted, {fail_count} refused over {} writes of {USERS} users",
            ROUNDS * USERS
        );
        tz.ok(
            "dead records are reclaimed (writes exceed the 64 raw slots)",
            ok_count > 64 && fail_count == 0,
        );

        // And the survivors must still be usable and not duplicated.
        let ga = ga_request(&rp3);
        tz.touch();
        let rc = get_assert(&tz.dev, &ga);
        tz.ok(
            "a credential survives compaction and still asserts",
            rc.is_ok(),
        );
        let n = rc
            .as_ref()
            .ok()
            .and_then(|(r, _)| r.number_of_credentials)
            .unwrap_or(0);
        println!("    numberOfCredentials after churn: {n} (expected {USERS})");
        tz.ok("live set did not grow across compaction", n == USERS as u64);
        tz.presence_latch(false);
    }

    // ---- ClientPIN ----
    let retries = client_pin::get_pin_retries(&tz.dev);
    tz.ok("getPinRetries succeeds", retries.is_ok());
    println!(
        "    retries={}{}",
        retries.as_ref().map(|r| r.retries).unwrap_or(0),
        if do_pin {
            ""
        } else {
            "  (PIN checks skipped; pass --pin)"
        }
    );
    if do_pin && !pin_was_set {
        let rc = client_pin::establish_session(&tz.dev, proto)
            .and_then(|s| client_pin::set_pin(&tz.dev, &s, b"1234"));
        tz.ok("setPin succeeds", rc.is_ok());
        let rc = mint_token(
            &tz.dev,
            proto,
            b"1234",
            permission::MAKE_CREDENTIAL,
            Some("tz.example"),
        );
        tz.ok("getPinUvAuthToken succeeds", rc.is_ok());
        let rc = mint_token(
            &tz.dev,
            proto,
            b"9999",
            permission::MAKE_CREDENTIAL,
            Some("tz.example"),
        );
        tz.ok("wrong PIN rejected", is_status(&rc, Status::PinInvalid));
        let rc = client_pin::establish_session(&tz.dev, proto)
            .and_then(|s| client_pin::change_pin(&tz.dev, &s, b"1234", b"5678"));
        tz.ok("changePin succeeds", rc.is_ok());
    }

    // ---- raw button probe (dev builds) ----
    if let Ok(v) = tz.dev.vendor(VENDOR_PROBE, &[]) {
        if v.len() >= 4 {
            let raw = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            println!(
                "    OEOVER={} (2=DISABLE) CSN={} (1=released)",
                (raw & 0xffff) >> 14,
                (raw >> 16) & 1
            );
            tz.ok("chip-select override lands", (raw & 0xffff) >> 14 == 2);
        }
    }

    // ---- CredentialManagement probe (needs a token) ----
    if do_pin {
        let token = mint_token(
            &tz.dev,
            proto,
            b"5678",
            permission::CREDENTIAL_MANAGEMENT | permission::MAKE_CREDENTIAL,
            None,
        );
        let (rc, st) = rc_status(&token);
        println!("    token for credMgmt: rc={rc} status=0x{st:02x}");
        let meta = match &token {
            Ok(auth) => credential_management::get_creds_metadata(&tz.dev, auth).map(|_| ()),
            // No token to sign with: send the bare subcommand anyway and
            // let the device say what it makes of it. The point of this
            // probe is the status byte, not the metadata.
            Err(_) => ctap2::cbor_call(
                &tz.dev,
                ctap2::CMD_CREDENTIAL_MANAGEMENT,
                Some(&Value::Map(vec![(Value::Uint(0x01), Value::Uint(0x01))])),
            )
            .map(|_| ()),
        };
        let (rc, st) = rc_status(&meta);
        println!("    getCredsMetadata: rc={rc} status=0x{st:02x}");
        if let Ok(echo) = tz.dev.vendor(VENDOR_LAST_CBOR, &[]) {
            let hex: String = echo.iter().take(32).map(|b| format!(" {b:02x}")).collect();
            println!("    last CBOR ({} bytes):{hex}", echo.len());
        }
        tz.ok("getCredsMetadata succeeds", meta.is_ok());
    }

    tz.presence_latch(false);
    let failures = tz.failures;
    drop(tz);
    println!(
        "{}: {failures} failure(s)",
        if failures != 0 { "FAIL" } else { "PASS" }
    );
    std::process::exit(if failures != 0 { 1 } else { 0 });
}
