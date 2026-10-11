// tz_cm -- credentialManagement enumeration against the TrustZone
// build, printing the CTAP status byte for every step.
//
// The conformance suite reports only pass/fail for enumerateCredentialsGetNext, and
// on 2026-09-02 that failed on the hybrid credential while the ES256
// one before it enumerated fine. The host tests pass. This exists to
// ask the device what it actually answered.
//
//   cargo run -p pqf-ctaphid --example tz_cm \
//       --target $(rustc -vV | awk '/host/{print $2}') -- \
//       [--pin S] [--wipe] [--cp3] [device-path]
//
//   --pin S  the PIN to mint the credMgmt token with (default: the
//            conformance suite's 123456)
//
//   --cp3    credProtect level 3 on a NON-resident credential: register
//            one at level 3 and one at level 1, then assert with an
//            allowList and no PIN token (expect the level-3 one refused,
//            the level-1 one chosen when both are listed), then with a
//            token (expect the level-3 one served). This is the case no
//            conformance run reaches and the one the credential-id
//            format was changed for.
//
//   --wipe   delete every resident credential, then confirm the store
//            is empty. The TrustZone port has no authenticatorReset, so
//            this is how a bench board is returned to the state the
//            conformance suite assumes. Its credential store survives reflashing -- it is
//            a Secure-only flash sector -- and an interrupted conformance
//            run leaves its two credentials behind, which the next run
//            then counts (2026-09-02: 60/5/4 that was entirely this).
//
// With no device path, the FIDO HID device whose product string
// contains "TZ-NS" is used.
//
// SPDX-License-Identifier: Apache-2.0

use pqf_cbor::Value;
use pqf_ctaphid::ctap2::client_pin::{self, permission, PinUvAuth};
use pqf_ctaphid::ctap2::credential_management as cm;
use pqf_ctaphid::ctap2::get_assertion::{self, GetAssertionRequest, GetAssertionResponse};
use pqf_ctaphid::ctap2::get_info;
use pqf_ctaphid::ctap2::make_credential::{self, MakeCredentialRequest};
use pqf_ctaphid::ctap2::pin_protocol::Protocol;
use pqf_ctaphid::ctap2::types::{
    AuthOptions, CredentialDescriptor, PubKeyCredParam, RelyingParty, User, ALG_ES256,
};
use pqf_ctaphid::ctap2::{Error, Status};
use pqf_ctaphid::hid;
use pqf_ctaphid::session::AuthData;

/// (rc, status byte, status name) as the C harness printed them: rc 0
/// on success and -1 on any failure; the CTAP status byte, or 0x00
/// when the failure was not a CTAP one, in which case the name is the
/// error itself.
fn outcome<T>(r: &Result<T, Error>) -> (i32, u8, String) {
    match r {
        Ok(_) => (0, 0x00, format!("{:?}", Status::Ok)),
        Err(Error::Ctap(s)) => (-1, *s as u8, format!("{s:?}")),
        Err(e) => (-1, 0x00, e.to_string()),
    }
}

fn show<T>(what: &str, r: &Result<T, Error>) {
    let (rc, st, name) = outcome(r);
    println!("  {what:<44} rc={rc:<3} status=0x{st:02x} ({name})");
}

/// Prefer PIN protocol 2, as the rest of the crate does; fall back to
/// 1 only on a device that advertises nothing else.
fn pin_protocol(dev: &hid::Device) -> Protocol {
    match get_info::get_info(dev)
        .ok()
        .and_then(|i| i.pin_uv_auth_protocols)
    {
        Some(p) if !p.contains(&2) && p.contains(&1) => Protocol::V1,
        _ => Protocol::V2,
    }
}

fn mint_token(
    dev: &hid::Device,
    pin: &str,
    permissions: u8,
    rp_id: Option<&str>,
) -> Result<PinUvAuth, Error> {
    let session = client_pin::establish_session(dev, pin_protocol(dev))?;
    client_pin::get_pin_uv_auth_token_using_pin(dev, session, pin.as_bytes(), permissions, rp_id)
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

/// Whether the authData carried a credProtect extension output, and
/// the policy it echoed: (1, policy) or (0, 0).
fn cred_protect_echo(ad: &AuthData) -> (i32, u64) {
    let ext = match ad.extensions_cbor.as_deref().map(pqf_cbor::decode) {
        Some(Ok(Value::Map(m))) => m,
        _ => return (0, 0),
    };
    ext.iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(s), Value::Uint(p)) if s == "credProtect" => Some((1, *p)),
            _ => None,
        })
        .unwrap_or((0, 0))
}

/// Encoded size of a COSE key, as the C client reported it.
fn cose_len(v: &Value) -> usize {
    let mut buf = Vec::new();
    pqf_cbor::encode(v, &mut buf);
    buf.len()
}

fn cred_protect(c: &cm::CredentialEntry) -> i64 {
    c.cred_protect.map(|p| p as i64).unwrap_or(-1)
}

fn descriptor(id: &[u8]) -> CredentialDescriptor {
    CredentialDescriptor {
        id: id.to_vec(),
        transports: None,
    }
}

/// credProtect level 3 on a NON-resident credential. Returns the exit
/// code.
fn cp3_probe(dev: &hid::Device, pin: &str) -> i32 {
    const RP: &str = "cp3.example";
    let cdh = [0x5cu8; 32];
    let mut uid = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut id3: Vec<u8> = Vec::new();
    let mut id1: Vec<u8> = Vec::new();
    let mut fails = 0;

    for level in [3u64, 1] {
        uid[0] = level as u8;
        let req = MakeCredentialRequest {
            client_data_hash: cdh,
            rp: RelyingParty {
                id: RP.to_string(),
                name: None,
            },
            user: User {
                id: uid.to_vec(),
                name: None,
                display_name: None,
            },
            pub_key_cred_params: vec![PubKeyCredParam::new(ALG_ES256)],
            exclude_list: None,
            // The request carries extensions as a raw CBOR map.
            extensions: Some(Value::Map(vec![(
                Value::Text("credProtect".to_string()),
                Value::Uint(level),
            )])),
            // rk=false; up and uv left out of the map.
            options: Some(AuthOptions {
                rk: Some(false),
                up: None,
                uv: None,
            }),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
            enterprise_attestation: None,
        };
        let rc =
            make_credential::make_credential(dev, &req).and_then(|r| AuthData::parse(&r.auth_data));
        let (rcv, st, _) = outcome(&rc);
        println!(
            "  MakeCredential rk=0 credProtect={level}              rc={rcv:<3} status=0x{st:02x}"
        );
        match &rc {
            Ok(ad) => {
                let id = ad
                    .attested_credential
                    .as_ref()
                    .map(|a| a.credential_id.clone())
                    .unwrap_or_default();
                if level == 3 {
                    id3 = id;
                } else {
                    id1 = id;
                }
                let (has, policy) = cred_protect_echo(ad);
                println!("    credProtect echoed: {has} (policy {policy})");
            }
            Err(_) => fails += 1,
        }
    }

    if !id3.is_empty() && !id1.is_empty() {
        let one = vec![descriptor(&id3)];
        let two = vec![descriptor(&id3), descriptor(&id1)];
        let ga = |allow: &[CredentialDescriptor]| GetAssertionRequest {
            rp_id: RP.to_string(),
            client_data_hash: cdh,
            allow_list: Some(allow.to_vec()),
            extensions: None,
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };

        // 1. level 3 alone, no token -> must be refused
        let rc = get_assert(dev, &ga(&one));
        let (rcv, st, _) = outcome(&rc);
        let refused = st == Status::NoCredentials as u8;
        println!(
            "  GA allowList=[cp3] no token                     rc={rcv:<3} status=0x{st:02x}  {}",
            if refused {
                "REFUSED (NO_CREDENTIALS) -- correct"
            } else {
                "!! SERVED a level-3 credential without UV"
            }
        );
        if !refused {
            fails += 1;
        }

        // 2. level 3 first, level 1 second, no token -> the level-1 one
        let rc = get_assert(dev, &ga(&two));
        let (rcv, st, _) = outcome(&rc);
        let is1 = matches!(&rc, Ok((r, _)) if r.credential.as_ref().map_or(false, |c| c.id == id1));
        println!(
            "  GA allowList=[cp3,cp1] no token                 rc={rcv:<3} status=0x{st:02x}  {}",
            if is1 {
                "served the level-1 one -- correct (second candidate)"
            } else {
                "!! did not fall back to the usable credential"
            }
        );
        if !is1 {
            fails += 1;
        }

        // 3. with a token: UV, so the level-3 one is usable and stays first
        let tok = mint_token(
            dev,
            pin,
            permission::MAKE_CREDENTIAL | permission::GET_ASSERTION,
            Some(RP),
        );
        let (rcv, st, _) = outcome(&tok);
        println!("  getPinUvAuthToken (mc|ga, scoped)              rc={rcv:<3} status=0x{st:02x}");
        let mut req = ga(&two);
        req.options = Some(AuthOptions {
            rk: None,
            up: None,
            uv: Some(true),
        });
        if let Ok(auth) = &tok {
            req.pin_uv_auth_param = auth.sign(&cdh).ok();
            req.pin_uv_auth_protocol = Some(auth.protocol.as_byte() as u64);
        }
        let rc = get_assert(dev, &req);
        let (rcv, st, _) = outcome(&rc);
        let flags = rc.as_ref().map(|(_, ad)| ad.flags).unwrap_or(0);
        let is3 = matches!(&rc, Ok((r, ad))
            if r.credential.as_ref().map_or(false, |c| c.id == id3) && ad.flags & 0x04 != 0);
        println!(
            "  GA allowList=[cp3,cp1] WITH token (uv)          rc={rcv:<3} status=0x{st:02x} flags=0x{flags:02x}  {}",
            if is3 {
                "served the level-3 one with UV -- correct"
            } else {
                "!! wrong credential or UV flag clear"
            }
        );
        if !is3 {
            fails += 1;
        }
    } else {
        fails += 1;
    }

    println!(
        "{}: credProtect-3 non-resident probe, {fails} failure(s)",
        if fails != 0 { "FAIL" } else { "PASS" }
    );
    if fails != 0 {
        1
    } else {
        0
    }
}

/// Enumerate (or, with `wipe`, delete) the resident store. Returns the
/// exit code.
fn enumerate(dev: &hid::Device, pin: &str, wipe: bool) -> i32 {
    let tok = mint_token(dev, pin, permission::CREDENTIAL_MANAGEMENT, None);
    show("getPinUvAuthToken (credMgmt)", &tok);
    let auth = match tok {
        Ok(a) => a,
        Err(_) => return 1,
    };

    let first = cm::enumerate_rps_begin(dev, &auth);
    show("enumerateRPsBegin", &first);
    let rp = match first {
        Ok(rp) => rp,
        Err(e) => {
            if matches!(e, Error::Ctap(Status::NoCredentials)) {
                println!("    store is EMPTY (NO_CREDENTIALS)");
            }
            return if wipe { 0 } else { 1 };
        }
    };
    let total_rps = rp.total_rps.unwrap_or(0);
    println!("    totalRPs={total_rps} first={}", rp.rp.id);

    if wipe {
        // Collect every credential id FIRST, then delete. A delete is
        // "another command" and abandons the enumeration in progress
        // (CTAP 2.1 sec. 6.8), so interleaving them would walk off a dead
        // cursor after the first one.
        let mut rps = vec![rp];
        while (rps.len() as u64) < total_rps {
            match cm::enumerate_rps_next(dev) {
                Ok(r) => rps.push(r),
                Err(_) => break,
            }
        }
        let mut ids: Vec<Vec<u8>> = Vec::new();
        for r in &rps {
            let c = match cm::enumerate_credentials_begin(dev, &auth, &r.rp_id_hash) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let tc = c.total_credentials.unwrap_or(0);
            if tc >= 1 {
                ids.push(c.credential.id);
            }
            for _ in 1..tc {
                match cm::enumerate_credentials_next(dev) {
                    Ok(c) => ids.push(c.credential.id),
                    Err(_) => break,
                }
            }
        }
        println!(
            "  wiping {} credential(s) across {} RP(s)",
            ids.len(),
            rps.len()
        );
        for id in &ids {
            let rc = cm::delete_credential(dev, &auth, id);
            show("  deleteCredential", &rc);
        }
        let again = cm::enumerate_rps_begin(dev, &auth);
        let (rcv, st, _) = outcome(&again);
        println!(
            "  after wipe: enumerateRPsBegin rc={rcv} status=0x{st:02x} ({})",
            if st == Status::NoCredentials as u8 {
                "store EMPTY"
            } else {
                "still has credentials"
            }
        );
        return 0;
    }

    // The RPs Begin above consumed its enumeration context; this starts
    // a fresh one, under the same token.
    let first = cm::enumerate_credentials_begin(dev, &auth, &rp.rp_id_hash);
    show("enumerateCredentialsBegin", &first);
    if let Ok(c) = first {
        let total = c.total_credentials.unwrap_or(0);
        println!(
            "    totalCreds={total}  cred[0]: credId {} B, COSE key {} B, credProtect={}",
            c.credential.id.len(),
            cose_len(&c.public_key_cose),
            cred_protect(&c)
        );
        for i in 1..total {
            let rc = cm::enumerate_credentials_next(dev);
            show("enumerateCredentialsGetNext", &rc);
            if let Ok(c) = rc {
                println!(
                    "    cred[{i}]: credId {} B, COSE key {} B, credProtect={}",
                    c.credential.id.len(),
                    cose_len(&c.public_key_cose),
                    cred_protect(&c)
                );
            }
        }
    }
    0
}

fn main() {
    let mut pin = "123456".to_string();
    let mut wipe = false;
    let mut cp3 = false;
    let mut path: Option<String> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pin" if i + 1 < args.len() => {
                i += 1;
                pin = args[i].clone();
            }
            "--wipe" => wipe = true,
            "--cp3" => cp3 = true,
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
                    println!("no FIDO devices");
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
                    println!("no TZ-NS device");
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

    let code = if cp3 {
        cp3_probe(&dev, &pin)
    } else {
        enumerate(&dev, &pin, wipe)
    };
    drop(dev);
    std::process::exit(code);
}
