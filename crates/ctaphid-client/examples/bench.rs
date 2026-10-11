// Wall-clock benchmark for hybrid MakeCredential / GetAssertion
// against an attached authenticator.
//
// Times the full host-visible round trip of each operation, reports
// the response size and the KEEPALIVE count, verifies the signature
// the device returned, and summarises min / median / max over N
// repetitions. This is the only timing path the project has: the
// firmware carries no cycle counter and prints no timing over CDC,
// so the number produced here -- host USB stack included -- is the
// measurement of record.
//
//   MakeCredential : 5530B in 1.16s (keepalives=4)
//   GetAssertion   : 3617B in 0.87s (keepalives=3)
//
// ---------------------------------------------------------------
// PREREQUISITE: USER PRESENCE MUST NOT BLOCK
//
// On a board with a button, every MakeCredential and GetAssertion
// waits up to 10 s for a fresh press-and-release before it will
// sign. Unattended, the run fails with CTAP2_ERR_OPERATION_DENIED
// (0x27); attended, the number measured is a human reaction time
// with a signature somewhere inside it.
//
//   C port    build the firmware with -DPQF_TEST_NO_USER_BUTTON=ON.
//   Rust port build with the `test_no_user_button` feature. Add
//             `reboot_no_up` and the token can be reflashed between
//             levels without a finger either; tools/silicon-sweep.sh
//             builds exactly that pair.
//
// Both auto-confirm user presence outright --
// exactly the gesture that stops a web page from silently exercising
// a credential. A build carrying it is a development build: never
// ship it, and never leave it on a key holding real credentials.
// (It replaced PQF_BENCH_AUTO_UP, deleted in 0bd96fb.)
// ---------------------------------------------------------------
//
// Run:
//   cargo run --release -p pqf-ctaphid --example bench \
//       --target $(rustc -vV | awk '/host/{print $2}') -- -n 10
//
// Build --release. A debug build spends enough time in ECDSA
// verification to blur the numbers it is meant to be measuring.
//
// Offline self-test (no hardware, no device touched):
//   cargo run -p pqf-ctaphid --example bench \
//       --target $(rustc -vV | awk '/host/{print $2}') -- --self-test
//
// If the device has a PIN set, put it in BRUCE_PIN -- same
// convention as the `register` example.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use pqf_ctaphid::ctap2::client_pin::{self, permission, PinUvAuth};
use pqf_ctaphid::ctap2::get_assertion::{self, GetAssertionRequest};
use pqf_ctaphid::ctap2::make_credential::{self, MakeCredentialRequest};
use pqf_ctaphid::ctap2::pin_protocol::Protocol;
use pqf_ctaphid::ctap2::types::{
    AuthOptions, CredentialDescriptor, PubKeyCredParam, RelyingParty, User, ALG_ES256,
    ALG_HYBRID_MLDSA44, ALG_HYBRID_MLDSA65, ALG_HYBRID_MLDSA87,
};
use pqf_ctaphid::ctap2::{get_info, Error as Ctap2Error, Status};
use pqf_ctaphid::session::{client_data_hash, AuthData, WebAuthnType};
use pqf_ctaphid::{hid, Value};

// ---------- Hybrid construction constants ----------

/// The 32-byte domain-separation prefix both firmware ports apply to
/// a hybrid signature.
///
/// Reproduced from the OpenSK PQC fork
/// (`libraries/crypto/src/hybrid.rs::LABEL`) -- Copyright (c) 2019-2023
/// Google LLC, SPDX-License-Identifier: Apache-2.0 -- full text in
/// `LICENSE-APACHE-OPENSK` at the repository root, provenance in
/// `THIRD_PARTY.md`. Must stay byte-identical to `PQF_HYBRID_LABEL`
/// (`c/firmware/src/hybrid.c`) and the Rust firmware's
/// `core1_signer::LABEL`, or nothing here verifies.
const HYBRID_LABEL: [u8; 32] = [
    43, 253, 32, 250, 19, 51, 24, 237, 138, 49, 47, 182, 4, 194, 133, 183, 177, 218, 115, 58, 92,
    117, 45, 172, 156, 5, 214, 176, 248, 103, 55, 216,
];

/// ML-DSA signature and public-key sizes, FIPS 204 sec. 4 Table 2.
/// Indexed by hybrid COSE alg.
fn mldsa_sizes(alg: i64) -> Option<(&'static str, usize, usize)> {
    match alg {
        //                     name         sig    pubkey
        ALG_HYBRID_MLDSA44 => Some(("ML-DSA-44", 2420, 1312)),
        ALG_HYBRID_MLDSA65 => Some(("ML-DSA-65", 3309, 1952)),
        ALG_HYBRID_MLDSA87 => Some(("ML-DSA-87", 4627, 2592)),
        _ => None,
    }
}

// ---------- Argument parsing ----------

struct Args {
    iterations: usize,
    rp_id: String,
    origin: String,
    alg: Option<i64>,
    device: Option<String>,
    list: bool,
    self_test: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            iterations: 5,
            // Matches the rp.id the published baseline was taken
            // against; keep it unless you are deliberately measuring
            // something else.
            rp_id: "bruce.example".to_string(),
            origin: "https://bruce.example".to_string(),
            alg: None,
            device: None,
            list: false,
            self_test: false,
        }
    }
}

const USAGE: &str = "\
bench -- wall-clock timing for hybrid MakeCredential / GetAssertion

USAGE:
    cargo run --release -p pqf-ctaphid --example bench -- [OPTIONS]

OPTIONS:
    -n, --iterations N   Repetitions to time (default 5). Reported as
                         min / median / max; one sample is noise.
        --rp-id ID       Relying-party id (default bruce.example)
        --origin URL     clientData.origin (default https://bruce.example)
        --alg NAME       Algorithm to request: 44, 65, 87, es256, or
                         'any' (default: offer all four, device picks)
        --device MATCH   Substring of the product string or hidapi
                         path, when more than one key is attached
    -l, --list           List attached FIDO HID devices and exit
        --self-test      Run the offline checks (CBOR shapes, DER
                         parser, hybrid split, statistics) and exit.
                         Touches no hardware.
    -h, --help           This text

PREREQUISITE: user presence must not block. C port: build with
-DPQF_TEST_NO_USER_BUTTON=ON. Rust port: use a board with no button.
Otherwise each operation waits on a physical press and the timings
measure a human, not the device. PQF_TEST_NO_USER_BUTTON auto-confirms
user presence -- development builds only, never ship it.

If a PIN is set, supply it in the BRUCE_PIN environment variable.
";

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut need = |what: &str| -> Result<String, String> {
            it.next()
                .ok_or_else(|| format!("{a}: missing {what} argument"))
        };
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "-l" | "--list" => args.list = true,
            "--self-test" => args.self_test = true,
            "-n" | "--iterations" => {
                let v = need("count")?;
                args.iterations = v
                    .parse()
                    .map_err(|_| format!("--iterations: not a number: {v}"))?;
                if args.iterations == 0 {
                    return Err("--iterations must be at least 1".into());
                }
            }
            "--rp-id" => args.rp_id = need("id")?,
            "--origin" => args.origin = need("url")?,
            "--device" => args.device = Some(need("match")?),
            "--alg" => {
                let v = need("name")?;
                args.alg = match v.as_str() {
                    "44" => Some(ALG_HYBRID_MLDSA44),
                    "65" => Some(ALG_HYBRID_MLDSA65),
                    "87" => Some(ALG_HYBRID_MLDSA87),
                    "es256" | "-7" => Some(ALG_ES256),
                    "any" | "auto" => None,
                    other => {
                        return Err(format!(
                            "--alg: expected 44, 65, 87, es256 or any; got {other}"
                        ))
                    }
                };
            }
            other => return Err(format!("unrecognised argument: {other}")),
        }
    }
    Ok(Some(args))
}

// ---------- Entry point ----------

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(Some(a)) => a,
        // --help printed the usage text.
        Ok(None) => return ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bench: {e}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    if args.self_test {
        return match self_test() {
            Ok(n) => {
                println!("\nSELF-TEST PASS ({n} checks)");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("\nSELF-TEST FAIL: {e}");
                ExitCode::FAILURE
            }
        };
    }

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\nbench: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    // ---- Enumerate ----
    let infos = hid::enumerate().map_err(|e| format!("enumerating HID devices: {e}"))?;

    if args.list {
        if infos.is_empty() {
            println!("No FIDO HID devices attached.");
        } else {
            println!("Attached FIDO HID devices:");
            for (i, d) in infos.iter().enumerate() {
                println!(
                    "  [{i}] {:04x}:{:04x} {:?}  {}",
                    d.vendor_id,
                    d.product_id,
                    d.product.as_deref().unwrap_or("<no product string>"),
                    d.path
                );
            }
        }
        return Ok(());
    }

    if infos.is_empty() {
        return Err(concat!(
            "no FIDO HID device attached.\n\n",
            "  Plug in the authenticator and try again. If it is plugged in:\n",
            "    - confirm it enumerates:  cargo run -p pqf-ctaphid --example bench -- --list\n",
            "    - both ports advertise cafe:f1d0; the product string is\n",
            "      \"Bruce (C port)\" for the C port and \"<board> PQC\" for Rust\n",
            "    - enumeration filters on the FIDO usage page (0xf1d0 / usage 0x01);\n",
            "      on Linux a udev rule may be needed for a non-root user\n",
            "    - a device sitting in BOOTSEL exposes mass storage, not HID"
        )
        .to_string());
    }

    let info = match &args.device {
        None => &infos[0],
        Some(m) => infos
            .iter()
            .find(|d| {
                d.path.contains(m.as_str())
                    || d.product.as_deref().is_some_and(|p| p.contains(m.as_str()))
            })
            .ok_or_else(|| {
                format!(
                    "--device {m:?} matched none of the {} attached device(s)",
                    infos.len()
                )
            })?,
    };
    if infos.len() > 1 && args.device.is_none() {
        eprintln!(
            "note: {} FIDO devices attached, benchmarking the first. Use --device to pick.",
            infos.len()
        );
    }

    // ---- Open + INIT ----
    let dev = hid::Device::open(info).map_err(|e| {
        format!(
            "opening {:?} ({}): {e}",
            info.product.as_deref().unwrap_or("device"),
            info.path
        )
    })?;

    println!(
        "Device   : {:04x}:{:04x} {:?}",
        info.vendor_id,
        info.product_id,
        info.product.as_deref().unwrap_or("<no product string>")
    );
    let (maj, min, bld) = dev.firmware_version();
    let caps = dev.capabilities();
    println!(
        "CID      : {:08x}  (CTAPHID v{}, device v{maj}.{min}.{bld})",
        dev.cid(),
        dev.ctaphid_version()
    );
    println!(
        "Caps     : 0x{:02x} (cbor={} wink={} nmsg={})",
        caps.0,
        caps.cbor(),
        caps.wink(),
        caps.nmsg()
    );
    if !caps.cbor() {
        return Err(
            "device does not advertise the CBOR capability -- not a CTAP2 authenticator"
                .to_string(),
        );
    }

    // ---- getInfo ----
    let gi = get_info::get_info(&dev).map_err(|e| format!("authenticatorGetInfo: {e}"))?;
    println!(
        "AAGUID   : {}",
        gi.aaguid
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!("Versions : {}", gi.versions.join(", "));
    if let Some(ref algs) = gi.algorithms {
        let list: Vec<String> = algs.iter().map(|a| a.alg.to_string()).collect();
        println!("Algs     : {}", list.join(", "));
    }
    if let Some(mms) = gi.max_msg_size {
        println!("maxMsgSize: {mms}");
    }

    // ---- PIN, if the device has one set ----
    let pin_set = gi.options.iter().any(|(k, v)| k == "clientPin" && *v);
    let mut pin_auth: Option<PinUvAuth> = None;
    if pin_set {
        let pin = std::env::var("BRUCE_PIN").map_err(|_| {
            concat!(
                "device has a PIN set but BRUCE_PIN is not in the environment.\n",
                "  Either export BRUCE_PIN=... or reset the device first:\n",
                "    fido2-token -R <uri>"
            )
            .to_string()
        })?;
        // Prefer v2 where offered -- matches session::register().
        let proto = match gi.pin_uv_auth_protocols {
            Some(ref p) if p.contains(&2) => Protocol::V2,
            _ => Protocol::V1,
        };
        let sess = client_pin::establish_session(&dev, proto)
            .map_err(|e| format!("PIN protocol key agreement: {e}"))?;
        let tok = client_pin::get_pin_uv_auth_token_using_pin(
            &dev,
            sess,
            pin.as_bytes(),
            permission::MAKE_CREDENTIAL | permission::GET_ASSERTION,
            Some(&args.rp_id),
        )
        .map_err(|e| format!("minting pinUvAuthToken: {e}"))?;
        println!("PIN      : token minted (protocol v{})", proto.as_byte());
        pin_auth = Some(tok);
    }

    let cred_params: Vec<PubKeyCredParam> = match args.alg {
        Some(a) => vec![PubKeyCredParam::new(a)],
        // Strongest first -- the firmware's picker takes the first
        // entry it implements, so this lets the device choose.
        None => vec![
            PubKeyCredParam::new(ALG_HYBRID_MLDSA87),
            PubKeyCredParam::new(ALG_HYBRID_MLDSA65),
            PubKeyCredParam::new(ALG_HYBRID_MLDSA44),
            PubKeyCredParam::new(ALG_ES256),
        ],
    };

    println!(
        "\nRP       : {} ({})\nRounds   : {}\n",
        args.rp_id, args.origin, args.iterations
    );

    // ---- The measured loop ----
    let mut mc_times: Vec<Duration> = Vec::with_capacity(args.iterations);
    let mut ga_times: Vec<Duration> = Vec::with_capacity(args.iterations);
    let mut failures = 0usize;

    for round in 1..=args.iterations {
        if args.iterations > 1 {
            println!("--- round {round}/{} ---", args.iterations);
        }
        match one_round(&dev, args, &cred_params, pin_auth.as_ref()) {
            Ok((mc, ga)) => {
                mc_times.push(mc);
                ga_times.push(ga);
            }
            Err(e) => {
                failures += 1;
                eprintln!("  round {round} FAILED: {e}");
            }
        }
    }

    // ---- Summary ----
    if !mc_times.is_empty() && args.iterations > 1 {
        println!("\nSummary over {} successful round(s):", mc_times.len());
        print_summary("MakeCredential", &mc_times);
        print_summary("GetAssertion  ", &ga_times);
    }

    if failures > 0 {
        return Err(format!("{failures} of {} round(s) failed", args.iterations));
    }
    println!("\nALL ROUNDS PASS");
    Ok(())
}

/// One MakeCredential + GetAssertion pair: timed, measured, and
/// cryptographically checked. Returns the two wall times.
fn one_round(
    dev: &hid::Device,
    args: &Args,
    cred_params: &[PubKeyCredParam],
    pin_auth: Option<&PinUvAuth>,
) -> Result<(Duration, Duration), String> {
    // A fresh challenge per round: a constant one would let a
    // (hypothetical) response cache flatter the numbers, and the
    // signature check would not notice.
    let mut challenge = [0u8; 32];
    rand::Rng::fill(&mut rand::rngs::OsRng, &mut challenge[..]);
    let cdh = client_data_hash(WebAuthnType::Create, &challenge, &args.origin);

    let (mc_param, mc_proto) = match pin_auth {
        Some(t) => (
            Some(t.sign(&cdh).map_err(|e| format!("pinUvAuthParam: {e}"))?),
            Some(t.protocol.as_byte() as u64),
        ),
        None => (None, None),
    };

    let req = MakeCredentialRequest {
        client_data_hash: cdh,
        rp: RelyingParty {
            id: args.rp_id.clone(),
            name: Some("Bruce benchmark".to_string()),
        },
        user: User {
            id: vec![0xa5; 16],
            name: Some("bench".to_string()),
            display_name: Some("Bench".to_string()),
        },
        pub_key_cred_params: cred_params.to_vec(),
        exclude_list: None,
        extensions: None,
        // rk deliberately unset: a resident credential per round
        // would fill the device's finite slot table over a long run
        // and start evicting, which is a different measurement.
        options: None,
        pin_uv_auth_param: mc_param,
        pin_uv_auth_protocol: mc_proto,
        enterprise_attestation: None,
    };

    dev.reset_stats();
    let t0 = Instant::now();
    let resp = make_credential::make_credential(dev, &req).map_err(describe_ctap_error)?;
    let mc_elapsed = t0.elapsed();
    let mc_stats = dev.stats();

    println!(
        "  MakeCredential : {}B in {:.2}s (keepalives={})",
        mc_stats.rx_bytes,
        mc_elapsed.as_secs_f64(),
        mc_stats.keepalives
    );

    // ---- Verify the attestation ----
    let ad = AuthData::parse(&resp.auth_data).map_err(|e| format!("authData parse: {e}"))?;
    let attested = ad
        .attested_credential
        .as_ref()
        .ok_or("MakeCredential authData has no attestedCredentialData (AT flag clear)")?;
    let cose = CoseKey::parse(&attested.credential_public_key_cose)?;

    println!(
        "  credentialId: {} bytes, alg {}{}",
        attested.credential_id.len(),
        cose.alg,
        match mldsa_sizes(cose.alg) {
            Some((n, _, pk)) => format!(" (ECDSA-P256 + {n}, pubkey {pk}B)"),
            None => String::new(),
        }
    );

    // The signed message is authData || clientDataHash, for both
    // MakeCredential and GetAssertion (PROTOCOL.md, "hybrid signing").
    let mut signed = resp.auth_data.clone();
    signed.extend_from_slice(&cdh);

    let (att_alg, att_sig) = att_stmt_fields(&resp.att_stmt)?;
    report(&verify_attestation(att_alg, &att_sig, &cose, &signed)?);

    // ---- GetAssertion for the credential we just made ----
    let mut ga_challenge = [0u8; 32];
    rand::Rng::fill(&mut rand::rngs::OsRng, &mut ga_challenge[..]);
    let ga_cdh = client_data_hash(WebAuthnType::Get, &ga_challenge, &args.origin);
    let (ga_param, ga_proto) = match pin_auth {
        Some(t) => (
            Some(
                t.sign(&ga_cdh)
                    .map_err(|e| format!("pinUvAuthParam: {e}"))?,
            ),
            Some(t.protocol.as_byte() as u64),
        ),
        None => (None, None),
    };

    let ga_req = GetAssertionRequest {
        rp_id: args.rp_id.clone(),
        client_data_hash: ga_cdh,
        allow_list: Some(vec![CredentialDescriptor {
            id: attested.credential_id.clone(),
            transports: None,
        }]),
        extensions: None,
        options: Some(AuthOptions {
            rk: None,
            up: Some(true),
            uv: None,
        }),
        pin_uv_auth_param: ga_param,
        pin_uv_auth_protocol: ga_proto,
    };

    dev.reset_stats();
    let t0 = Instant::now();
    let ga = get_assertion::get_assertion(dev, &ga_req).map_err(describe_ctap_error)?;
    let ga_elapsed = t0.elapsed();
    let ga_stats = dev.stats();

    println!(
        "  GetAssertion   : {}B in {:.2}s (keepalives={})",
        ga_stats.rx_bytes,
        ga_elapsed.as_secs_f64(),
        ga_stats.keepalives
    );

    // ---- Verify the assertion ----
    let ga_ad = AuthData::parse(&ga.auth_data).map_err(|e| format!("assertion authData: {e}"))?;
    if ga_ad.rp_id_hash != ad.rp_id_hash {
        return Err("assertion rpIdHash does not match the registration".to_string());
    }
    if !ga_ad.user_present() {
        return Err(concat!(
            "assertion has the UP flag clear -- the device did not register a user-presence ",
            "gesture. Expected on a -DPQF_TEST_NO_USER_BUTTON=ON build."
        )
        .to_string());
    }
    let mut ga_signed = ga.auth_data.clone();
    ga_signed.extend_from_slice(&ga_cdh);

    // An assertion is always signed with the credential's own
    // algorithm -- the ES256 attestation fallback at level 87 applies
    // to the attStmt only, never here.
    report(&verify_credential_sig(
        cose.alg,
        &ga.signature,
        &cose,
        &ga_signed,
        "GetAssert",
    )?);

    Ok((mc_elapsed, ga_elapsed))
}

/// Turn a CTAP2 error into a message that says what to do about it.
fn describe_ctap_error(e: Ctap2Error) -> String {
    match e {
        Ctap2Error::Ctap(Status::UserActionTimeout) => concat!(
            "CTAP2_ERR_OPERATION_DENIED (0x27) -- the device waited for a button press ",
            "and gave up.\n  Build the firmware with -DPQF_TEST_NO_USER_BUTTON=ON for ",
            "unattended benchmarking (development builds only), or tap the button when the ",
            "LED indicates it."
        )
        .to_string(),
        Ctap2Error::Ctap(Status::PuatRequired) => concat!(
            "CTAP2_ERR_PUAT_REQUIRED (0x36) -- a PIN is set on this device.\n  ",
            "Export BRUCE_PIN=... or reset the device with: fido2-token -R <uri>"
        )
        .to_string(),
        other => format!("{other}"),
    }
}

// ---------- Attestation / assertion verification ----------

/// The COSE_Key fields the hybrid construction needs. Layout per
/// docs/PROTOCOL.md "COSE_Key": `1` kty, `3` alg, `-1` crv,
/// `-2` x, `-3` y, and `-4` for the ML-DSA public key on a hybrid
/// credential.
struct CoseKey {
    alg: i64,
    x: Vec<u8>,
    y: Vec<u8>,
    mldsa_pub: Option<Vec<u8>>,
}

impl CoseKey {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let v = pqf_ctaphid::decode(bytes).map_err(|e| format!("COSE_Key CBOR: {e:?}"))?;
        let m = match v {
            Value::Map(m) => m,
            _ => return Err("COSE_Key is not a CBOR map".to_string()),
        };
        // `pqf_cbor` stores a negative integer already decoded
        // (COSE alg -55 is `Nint(-55)`), so labels compare directly.
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

        // A hybrid alg must carry -4, and at the right length; a
        // classical alg must not.
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

/// Pull `alg` and `sig` out of a packed attestation statement.
fn att_stmt_fields(att: &Value) -> Result<(i64, Vec<u8>), String> {
    let m = match att {
        Value::Map(m) => m,
        _ => return Err("attStmt is not a CBOR map".to_string()),
    };
    let find = |name: &str| -> Option<&Value> {
        m.iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
            .map(|(_, v)| v)
    };
    let alg = match find("alg") {
        Some(Value::Uint(u)) => i64::try_from(*u).map_err(|_| "attStmt alg out of range")?,
        Some(Value::Nint(n)) => *n,
        _ => return Err("attStmt has no integer \"alg\"".to_string()),
    };
    let sig = match find("sig") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("attStmt has no byte-string \"sig\"".to_string()),
    };
    Ok((alg, sig))
}

/// Check the MakeCredential attestation statement.
///
/// Two shapes are legitimate, and which one arrives is decided by the
/// build's ML-DSA level (commit 8e1f37e):
///
///   - `att_alg == cose.alg` (hybrid, levels 44 and 65) -- the full
///     dual signature over `LABEL || msg`, same construction as an
///     assertion.
///   - `att_alg == -7` on a hybrid credential (level 87 only) -- the
///     dual attStmt would be 7617 B against a 7609 B CTAPHID ceiling,
///     so the attestation alone downgrades to plain packed ES256.
///     That signature is over `msg` with **no** LABEL prefix; the
///     hybrid ECDSA half is not reusable for it.
fn verify_attestation(
    att_alg: i64,
    sig: &[u8],
    cose: &CoseKey,
    signed: &[u8],
) -> Result<Vec<String>, String> {
    if att_alg == cose.alg {
        return verify_credential_sig(cose.alg, sig, cose, signed, "MakeCred attestation");
    }
    if att_alg == ALG_ES256 && mldsa_sizes(cose.alg).is_some() {
        if cose.alg != ALG_HYBRID_MLDSA87 {
            return Err(format!(
                "attStmt downgraded to ES256 on an alg-{} credential. Only ML-DSA-87 has a \
                 size justification for that; at 44/65 the dual attestation fits and a \
                 conformant verifier will reject this.",
                cose.alg
            ));
        }
        // Plain packed ES256: no LABEL.
        verify_ecdsa_der(sig, cose, signed, "MakeCred attestation")?;
        return Ok(vec![
            "MakeCred attestation: ES256 verifies (ML-DSA-87 size fallback, no PQC half)"
                .to_string(),
        ]);
    }
    Err(format!(
        "attStmt alg {att_alg} matches neither the credential alg ({}) nor the ES256 fallback",
        cose.alg
    ))
}

/// Verify a signature produced with the credential's own algorithm --
/// the assertion path always, and the attestation path at 44/65.
///
/// Returns the lines describing what passed. Reporting is left to the
/// caller so a deliberately-failing check cannot print a reassuring
/// "ok" for the half that verified before the half that did not.
fn verify_credential_sig(
    alg: i64,
    sig: &[u8],
    cose: &CoseKey,
    msg: &[u8],
    what: &str,
) -> Result<Vec<String>, String> {
    match mldsa_sizes(alg) {
        // Classical credential: the whole blob is one ECDSA DER sig
        // over msg, no LABEL.
        None => {
            verify_ecdsa_der(sig, cose, msg, what)?;
            Ok(vec![format!("{what}: ES256 verifies")])
        }
        Some((name, want_sig, _)) => {
            let (der, mldsa) = split_hybrid_sig(sig)?;
            // ECDSA half signs SHA-256(LABEL || msg); the verifier
            // hashes internally, so hand it LABEL || msg.
            let mut labelled = HYBRID_LABEL.to_vec();
            labelled.extend_from_slice(msg);
            verify_ecdsa_der(der, cose, &labelled, what)?;

            // The ML-DSA half is checked structurally only. Full
            // verification needs an ML-DSA implementation this crate
            // deliberately does not depend on -- in a real deployment
            // the relying party does it. Length plus non-degeneracy
            // still catches a truncated or all-zero sign, which is
            // the failure a memory or cache optimisation would
            // plausibly introduce.
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
                    "{what}: ECDSA-P256 verifies (DER {}B + {name} {}B)",
                    der.len(),
                    mldsa.len()
                ),
                format!("{what}: {name} sig length / non-zero OK"),
            ])
        }
    }
}

/// Print the lines a verify helper produced, in the documented shape.
fn report(lines: &[String]) {
    for l in lines {
        println!("  ok {l}");
    }
}

/// Split `ecdsa_der || mldsa_raw` at the DER boundary. The ECDSA
/// signature is always a definite-length SEQUENCE whose length fits
/// one byte, so the total is `sig[1] + 2` (docs/PROTOCOL.md).
fn split_hybrid_sig(sig: &[u8]) -> Result<(&[u8], &[u8]), String> {
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

/// Verify a DER ECDSA-P256 signature over `msg` (SHA-256 applied
/// internally) against the COSE_Key's public point.
fn verify_ecdsa_der(der: &[u8], cose: &CoseKey, msg: &[u8], what: &str) -> Result<(), String> {
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

/// Strict DER reader for `SEQUENCE { INTEGER r, INTEGER s }`,
/// returning both scalars as 32 big-endian bytes: the RustCrypto
/// `ecdsa` crate's own parser (`Signature::from_der` -- minimal
/// lengths, minimal positive INTEGERs, no trailing bytes, scalars in
/// `[1, n)`), the same as `pqf_ctaphid::hybrid::parse_ecdsa_der`. A
/// hand-rolled reader here used to read a negative INTEGER as the
/// unsigned scalar with the same bytes and let the signature verify.
fn parse_ecdsa_der(der: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let sig = p256::ecdsa::Signature::from_der(der)
        .map_err(|e| format!("ECDSA signature is not strict DER: {e}"))?;
    let (r, s) = sig.split_bytes();
    Ok((r.into(), s.into()))
}

// ---------- Statistics ----------

fn print_summary(label: &str, times: &[Duration]) {
    if times.is_empty() {
        return;
    }
    let (lo, med, hi) = min_median_max(times);
    println!(
        "  {label} : min {:.2}s  median {:.2}s  max {:.2}s   (n={})",
        lo.as_secs_f64(),
        med.as_secs_f64(),
        hi.as_secs_f64(),
        times.len()
    );
}

/// Min, median and max of a sample. The median of an even-sized
/// sample is the mean of the two central values.
fn min_median_max(times: &[Duration]) -> (Duration, Duration, Duration) {
    let mut v = times.to_vec();
    v.sort_unstable();
    let n = v.len();
    let median = if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2
    };
    (v[0], median, v[n - 1])
}

// ---------- Offline self-test ----------

/// Everything that can be checked without a device: the DER reader,
/// the hybrid split, the COSE_Key reader, the request CBOR shapes,
/// the statistics, and a real ECDSA verification against a key we
/// generate here. Returns the number of checks that passed.
///
/// This is what lets the script be developed and regression-tested
/// on a machine with no token attached. It does NOT substitute for a
/// run against real hardware -- nothing here exercises the transport,
/// the keepalive counting, or the firmware.
fn self_test() -> Result<usize, String> {
    use p256::ecdsa::signature::{Signer, Verifier};
    let mut n = 0usize;
    macro_rules! check {
        ($cond:expr, $($msg:tt)*) => {
            if !($cond) { return Err(format!($($msg)*)); }
            n += 1;
        };
    }

    println!("Offline self-test (no device is opened)");

    // --- Constants ---
    check!(
        HYBRID_LABEL.len() == 32 && HYBRID_LABEL[0] == 43 && HYBRID_LABEL[31] == 216,
        "HYBRID_LABEL does not match the firmware constant"
    );
    check!(
        mldsa_sizes(ALG_HYBRID_MLDSA44) == Some(("ML-DSA-44", 2420, 1312))
            && mldsa_sizes(ALG_HYBRID_MLDSA65) == Some(("ML-DSA-65", 3309, 1952))
            && mldsa_sizes(ALG_HYBRID_MLDSA87) == Some(("ML-DSA-87", 4627, 2592))
            && mldsa_sizes(ALG_ES256).is_none(),
        "FIPS 204 size table is wrong"
    );
    println!("  ok constants: LABEL + FIPS 204 Table 2 sizes");

    // --- A real P-256 key, and a real signature over a labelled
    //     message, verified through the same path the live code uses.
    let sk = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let vk = p256::ecdsa::VerifyingKey::from(&sk);
    let point = vk.to_encoded_point(false);
    let cose = CoseKey {
        alg: ALG_HYBRID_MLDSA65,
        x: point.x().ok_or("no x")?.to_vec(),
        y: point.y().ok_or("no y")?.to_vec(),
        mldsa_pub: Some(vec![7u8; 1952]),
    };
    let msg = b"authData||clientDataHash stand-in";
    let mut labelled = HYBRID_LABEL.to_vec();
    labelled.extend_from_slice(msg);
    let sig: p256::ecdsa::Signature = sk.sign(&labelled);
    check!(
        vk.verify(&labelled, &sig).is_ok(),
        "sanity: fresh signature does not verify"
    );

    // --- DER round trip through our hand-rolled reader ---
    let der = sig.to_der();
    let der_bytes = der.as_bytes();
    let (r, s) = parse_ecdsa_der(der_bytes)?;
    let rebuilt = p256::ecdsa::Signature::from_scalars(r, s)
        .map_err(|e| format!("from_scalars rejected our own parse: {e}"))?;
    check!(rebuilt == sig, "DER parse round trip changed the signature");
    println!(
        "  ok DER reader: {}B SEQUENCE round-trips to the same (r,s)",
        der_bytes.len()
    );

    // Malformed DER must be rejected, not silently mis-parsed.
    check!(parse_ecdsa_der(&[]).is_err(), "empty DER accepted");
    check!(parse_ecdsa_der(&[0x31; 16]).is_err(), "wrong tag accepted");
    let mut trunc = der_bytes.to_vec();
    trunc.pop();
    check!(parse_ecdsa_der(&trunc).is_err(), "truncated DER accepted");
    let mut trailing = der_bytes.to_vec();
    trailing.push(0xff);
    check!(
        parse_ecdsa_der(&trailing).is_err(),
        "DER with trailing byte accepted"
    );
    println!("  ok DER reader rejects empty / mis-tagged / truncated / trailing input");

    // A negative INTEGER -- a padded r with its 0x00 dropped -- carries
    // the same 32 bytes and must still be refused, by the reader and by
    // the full check. Signatures are deterministic, so search for a
    // message whose r needs the pad.
    let (padded, padded_msg) = (0u32..)
        .find_map(|n| {
            let m = format!("negative-r {n}").into_bytes();
            let mut l = HYBRID_LABEL.to_vec();
            l.extend_from_slice(&m);
            let s: p256::ecdsa::Signature = sk.sign(&l);
            let d = s.to_der().as_bytes().to_vec();
            (d[3] == 33 && d[4] == 0x00).then_some((d, m))
        })
        .ok_or("no padded signature found")?;
    let mut negative = vec![0x30, padded[1] - 1, 0x02, 32];
    negative.extend_from_slice(&padded[5..]);
    check!(
        parse_ecdsa_der(&negative).is_err(),
        "DER with a negative INTEGER accepted"
    );
    let mut padded_hybrid = padded.clone();
    padded_hybrid.extend_from_slice(&vec![0xa5u8; 3309]);
    let mut negative_hybrid = negative.clone();
    negative_hybrid.extend_from_slice(&vec![0xa5u8; 3309]);
    check!(
        verify_credential_sig(
            ALG_HYBRID_MLDSA65,
            &padded_hybrid,
            &cose,
            &padded_msg,
            "self-test"
        )
        .is_ok(),
        "the padded signature does not verify"
    );
    check!(
        verify_credential_sig(
            ALG_HYBRID_MLDSA65,
            &negative_hybrid,
            &cose,
            &padded_msg,
            "self-test"
        )
        .is_err(),
        "a hybrid signature with a negative ECDSA INTEGER verified"
    );
    println!("  ok DER reader rejects a negative INTEGER that carries the right scalar");

    // --- Hybrid split, against a synthetic ML-DSA-65 tail ---
    let mut hybrid = der_bytes.to_vec();
    hybrid.extend_from_slice(&vec![0xa5u8; 3309]);
    let (got_der, got_mldsa) = split_hybrid_sig(&hybrid)?;
    check!(
        got_der == der_bytes,
        "hybrid split returned the wrong DER half"
    );
    check!(
        got_mldsa.len() == 3309,
        "hybrid split returned the wrong ML-DSA half"
    );
    check!(
        split_hybrid_sig(&[0u8; 4]).is_err(),
        "runt hybrid signature accepted"
    );
    println!(
        "  ok hybrid split: {}B DER + 3309B ML-DSA-65",
        got_der.len()
    );

    // --- End-to-end verification of a hybrid-shaped signature ---
    report(&verify_credential_sig(
        ALG_HYBRID_MLDSA65,
        &hybrid,
        &cose,
        msg,
        "hybrid verify",
    )?);
    n += 1;

    // A tampered message must fail.
    check!(
        verify_credential_sig(
            ALG_HYBRID_MLDSA65,
            &hybrid,
            &cose,
            b"different",
            "self-test"
        )
        .is_err(),
        "verification accepted a signature over the wrong message"
    );
    // An all-zero ML-DSA half must fail.
    let mut zeroed = der_bytes.to_vec();
    zeroed.extend_from_slice(&vec![0u8; 3309]);
    check!(
        verify_credential_sig(ALG_HYBRID_MLDSA65, &zeroed, &cose, msg, "self-test").is_err(),
        "verification accepted an all-zero ML-DSA half"
    );
    // A short ML-DSA half must fail.
    let mut short = der_bytes.to_vec();
    short.extend_from_slice(&vec![0xa5u8; 3308]);
    check!(
        verify_credential_sig(ALG_HYBRID_MLDSA65, &short, &cose, msg, "self-test").is_err(),
        "verification accepted a truncated ML-DSA half"
    );
    println!("  ok tamper rejection: wrong message / zero ML-DSA / short ML-DSA");

    // --- Attestation policy: the ES256 fallback is 87-only ---
    let es256_over_msg: p256::ecdsa::Signature = sk.sign(msg);
    let es256_der = es256_over_msg.to_der();
    check!(
        verify_attestation(ALG_ES256, es256_der.as_bytes(), &cose, msg).is_err(),
        "ES256 attestation fallback wrongly accepted on an ML-DSA-65 credential"
    );
    let cose87 = CoseKey {
        alg: ALG_HYBRID_MLDSA87,
        x: cose.x.clone(),
        y: cose.y.clone(),
        mldsa_pub: Some(vec![7u8; 2592]),
    };
    report(&verify_attestation(
        ALG_ES256,
        es256_der.as_bytes(),
        &cose87,
        msg,
    )?);
    n += 1;
    check!(
        verify_attestation(ALG_ES256, der_bytes, &cose87, msg).is_err(),
        "ES256 fallback accepted a signature computed over LABEL || msg"
    );
    println!("  ok attestation policy: ES256 fallback accepted at 87, refused at 65");

    // --- COSE_Key reader, including the size guards ---
    // Labels per docs/PROTOCOL.md: 1 kty, 3 alg, -1 crv, -2 x,
    // -3 y, -4 ML-DSA public key.
    let key_cbor = |alg: i64, pk_len: Option<usize>| -> Vec<u8> {
        let mut entries = vec![
            (Value::Uint(1), Value::Uint(2)),
            (Value::int(-1), Value::Uint(1)),
            (Value::int(-2), Value::Bytes(cose.x.clone())),
            (Value::int(-3), Value::Bytes(cose.y.clone())),
            (Value::Uint(3), Value::int(alg)),
        ];
        if let Some(l) = pk_len {
            entries.push((Value::int(-4), Value::Bytes(vec![0x5a; l])));
        }
        let mut out = Vec::new();
        pqf_ctaphid::encode(&Value::Map(entries), &mut out);
        out
    };
    let parsed = CoseKey::parse(&key_cbor(ALG_HYBRID_MLDSA65, Some(1952)))?;
    check!(
        parsed.alg == ALG_HYBRID_MLDSA65 && parsed.mldsa_pub.as_ref().unwrap().len() == 1952,
        "COSE_Key reader lost fields on a valid hybrid key"
    );
    let es = CoseKey::parse(&key_cbor(ALG_ES256, None))?;
    check!(
        es.alg == ALG_ES256 && es.mldsa_pub.is_none(),
        "COSE_Key reader mishandled ES256"
    );
    check!(
        CoseKey::parse(&key_cbor(ALG_HYBRID_MLDSA65, None)).is_err(),
        "COSE_Key reader accepted a hybrid alg with no -4 public key"
    );
    check!(
        CoseKey::parse(&key_cbor(ALG_HYBRID_MLDSA65, Some(1312))).is_err(),
        "COSE_Key reader accepted an ML-DSA-65 key of the wrong length"
    );
    check!(
        CoseKey::parse(&key_cbor(ALG_ES256, Some(1952))).is_err(),
        "COSE_Key reader accepted a -4 entry on a classical key"
    );
    println!("  ok COSE_Key reader: hybrid + ES256, with the -4 size guards");

    // --- attStmt field extraction ---
    let att = Value::Map(vec![
        (Value::Text("alg".into()), Value::int(ALG_HYBRID_MLDSA65)),
        (Value::Text("sig".into()), Value::Bytes(vec![1, 2, 3])),
    ]);
    let (a, s2) = att_stmt_fields(&att)?;
    check!(
        a == ALG_HYBRID_MLDSA65 && s2 == vec![1, 2, 3],
        "attStmt reader returned wrong fields"
    );
    check!(
        att_stmt_fields(&Value::Uint(1)).is_err(),
        "attStmt reader accepted a non-map"
    );
    println!("  ok attStmt reader: negative alg decoded as {a}");

    // --- Request CBOR shapes actually encode + decode ---
    let cdh = client_data_hash(WebAuthnType::Create, b"challenge", "https://bruce.example");
    let mc = MakeCredentialRequest {
        client_data_hash: cdh,
        rp: RelyingParty {
            id: "bruce.example".into(),
            name: None,
        },
        user: User {
            id: vec![0xa5; 16],
            name: None,
            display_name: None,
        },
        pub_key_cred_params: vec![PubKeyCredParam::new(ALG_HYBRID_MLDSA65)],
        exclude_list: None,
        extensions: None,
        options: None,
        pin_uv_auth_param: None,
        pin_uv_auth_protocol: None,
        enterprise_attestation: None,
    };
    let mut buf = Vec::new();
    pqf_ctaphid::encode(&mc.to_cbor(), &mut buf);
    let back = pqf_ctaphid::decode(&buf).map_err(|e| format!("MakeCredential CBOR: {e:?}"))?;
    let entries = match back {
        Value::Map(m) => m,
        _ => return Err("MakeCredential request did not encode to a map".to_string()),
    };
    // clientDataHash, rp, user, pubKeyCredParams -- and nothing else,
    // since every optional field is None.
    check!(
        entries.len() == 4,
        "MakeCredential request has {} entries, expected 4",
        entries.len()
    );
    let has = |k: u64| {
        entries
            .iter()
            .any(|(kk, _)| matches!(kk, Value::Uint(u) if *u == k))
    };
    check!(
        has(1) && has(2) && has(3) && has(4),
        "MakeCredential request is missing a required key"
    );
    println!("  ok MakeCredential request: 4 canonical entries (0x01-0x04)");

    let ga = GetAssertionRequest {
        rp_id: "bruce.example".into(),
        client_data_hash: cdh,
        allow_list: Some(vec![CredentialDescriptor {
            id: vec![0x11; 161],
            transports: None,
        }]),
        extensions: None,
        options: Some(AuthOptions {
            rk: None,
            up: Some(true),
            uv: None,
        }),
        pin_uv_auth_param: None,
        pin_uv_auth_protocol: None,
    };
    let mut buf2 = Vec::new();
    pqf_ctaphid::encode(&ga.to_cbor(), &mut buf2);
    let back2 = pqf_ctaphid::decode(&buf2).map_err(|e| format!("GetAssertion CBOR: {e:?}"))?;
    let e2 = match back2 {
        Value::Map(m) => m,
        _ => return Err("GetAssertion request did not encode to a map".to_string()),
    };
    check!(
        e2.len() == 4,
        "GetAssertion request has {} entries, expected 4",
        e2.len()
    );
    println!("  ok GetAssertion request: 4 canonical entries, 161B credentialId in allowList");

    // --- Statistics ---
    let d = |ms| Duration::from_millis(ms);
    let (lo, med, hi) = min_median_max(&[d(300), d(100), d(200)]);
    check!(
        lo == d(100) && med == d(200) && hi == d(300),
        "min/median/max wrong on an odd-sized sample"
    );
    let (lo, med, hi) = min_median_max(&[d(400), d(100), d(300), d(200)]);
    check!(
        lo == d(100) && med == d(250) && hi == d(400),
        "min/median/max wrong on an even-sized sample"
    );
    let (lo, med, hi) = min_median_max(&[d(42)]);
    check!(
        lo == d(42) && med == d(42) && hi == d(42),
        "min/median/max wrong on n=1"
    );
    println!("  ok statistics: odd, even and single-sample medians");

    Ok(n)
}
