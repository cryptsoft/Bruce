// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The Rust firmware's hardware-free modules, compiled for the host.
//!
//! Nothing is reimplemented: the files pulled in here are the ones that
//! ship. What is substituted is the single hardware dependency,
//! `crate::trng`, whose only job in these paths is to produce bytes.

extern crate alloc;

/// Stands in for `crate::trng`.
///
/// The real one drives the RP2350's ring-oscillator source and checks its
/// on-die health bits. Neither exists here, and neither is what these
/// tests are about -- they are about what the credential-id format does
/// with the bytes. Deterministic, so a test can say what IV a credential
/// will carry and get the same answer twice; and settable, so two
/// credentials can be forced to share an IV to see whether that alone
/// leaks anything.
/// A CTAP platform, for tests that need an authenticated session.
///
/// Anything past ClientPIN -- credential management, largeBlobs,
/// authenticatorConfig -- is gated behind a `pinUvAuthToken`, so a test
/// for those has to run the whole PIN dance first. This is that dance,
/// in one place.
///
/// The ECDH is the platform's own (`p256`); key derivation goes through
/// the firmware's `SharedSecret`, which `tests/client_pin.rs` pins
/// against an independent computation. The `pinUvAuthParam` over a
/// command is computed here with a plain HMAC rather than through the
/// firmware, so a mistake in the firmware's own tag construction is
/// still visible.
pub mod testclient {
    use crate::client_pin::{PinSession, SharedSecret, PIN_PROTOCOL_V1};
    use crate::ctap2::{self, CredStore, HostOp, CTAP2_CLIENT_PIN, CTAP2_OK};
    use crate::trng::Trng;
    use pqf_cbor::Value;

    pub const SUB_SET_PIN: u64 = 0x03;
    pub const SUB_GET_KEY_AGREEMENT: u64 = 0x02;
    pub const SUB_GET_TOKEN_PERMS: u64 = 0x09;

    pub fn encode(v: &Value) -> Vec<u8> {
        let mut o = Vec::new();
        pqf_cbor::encode(v, &mut o);
        o
    }

    /// The 64-byte zero-padded PIN CTAP encrypts on the wire.
    pub fn padded_pin(pin: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 64];
        p[..pin.len()].copy_from_slice(pin);
        p
    }

    /// The platform's ECDH key.
    pub struct Platform {
        sk: p256::SecretKey,
    }

    impl Platform {
        pub fn new() -> Self {
            let mut b = [0x11u8; 32];
            b[31] = 0x27;
            Platform {
                sk: p256::SecretKey::from_slice(&b).expect("a valid P-256 scalar"),
            }
        }

        pub fn cose_pub(&self) -> Value {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let ep = self.sk.public_key().to_encoded_point(false);
            let b = ep.as_bytes();
            Value::Map(vec![
                (Value::Uint(1), Value::Uint(2)),
                (Value::Nint(-1), Value::Uint(1)),
                (Value::Nint(-2), Value::Bytes(b[1..33].to_vec())),
                (Value::Nint(-3), Value::Bytes(b[33..65].to_vec())),
            ])
        }

        pub fn shared(&self, x: &[u8; 32], y: &[u8; 32]) -> SharedSecret {
            use p256::elliptic_curve::sec1::FromEncodedPoint;
            let ep = p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
            let pk =
                p256::PublicKey::from_encoded_point(&ep).expect("authenticator key is on-curve");
            let s = p256::ecdh::diffie_hellman(self.sk.to_nonzero_scalar(), pk.as_affine());
            let mut h = [0u8; 32];
            h.copy_from_slice(s.raw_secret_bytes());
            SharedSecret::from_handshake(h, PIN_PROTOCOL_V1).expect("v1 is a known protocol")
        }
    }

    fn send(
        trng: &mut Trng,
        session: &mut PinSession,
        store: &mut CredStore,
        cmd: u8,
        params: &[(u64, Value)],
    ) -> Vec<u8> {
        let mut m: Vec<(Value, Value)> = params
            .iter()
            .map(|(k, v)| (Value::Uint(*k), v.clone()))
            .collect();
        m.sort_by_key(|(k, _)| if let Value::Uint(n) = k { *n } else { 0 });
        let mut msg = vec![cmd];
        msg.extend_from_slice(&encode(&Value::Map(m)));
        let mut host = |_op: HostOp| true;
        ctap2::handle_cbor(&msg, trng, session, store, &mut host, 0, [0, 0, 0, 1]).to_vec()
    }

    fn resp_key(resp: &[u8], want: u64) -> Option<Value> {
        match pqf_cbor::decode(&resp[1..]).ok()? {
            Value::Map(m) => m.iter().find_map(|(k, v)| match k {
                Value::Uint(n) if *n == want => Some(v.clone()),
                _ => None,
            }),
            _ => None,
        }
    }

    fn handshake(
        p: &Platform,
        trng: &mut Trng,
        session: &mut PinSession,
        store: &mut CredStore,
    ) -> SharedSecret {
        let r = send(
            trng,
            session,
            store,
            CTAP2_CLIENT_PIN,
            &[
                (1, Value::Uint(PIN_PROTOCOL_V1)),
                (2, Value::Uint(SUB_GET_KEY_AGREEMENT)),
            ],
        );
        assert_eq!(r[0], CTAP2_OK, "getKeyAgreement failed");
        let cose = match resp_key(&r, 1).expect("no keyAgreement") {
            Value::Map(m) => m,
            other => panic!("keyAgreement is {other:?}"),
        };
        let coord = |k: i64| -> [u8; 32] {
            match cose
                .iter()
                .find_map(|(kk, vv)| match kk {
                    Value::Nint(n) if *n == k => Some(vv.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no coordinate {k}"))
            {
                Value::Bytes(b) if b.len() == 32 => b.try_into().unwrap(),
                other => panic!("coordinate {k} is {other:?}"),
            }
        };
        p.shared(&coord(-2), &coord(-3))
    }

    /// Set `pin`, then mint a token carrying `perms`, optionally scoped
    /// to `rp`. Returns the plaintext `pinUvAuthToken` the platform
    /// would hold.
    pub fn authenticate(
        trng: &mut Trng,
        session: &mut PinSession,
        store: &mut CredStore,
        pin: &[u8],
        perms: u64,
        rp: Option<&str>,
    ) -> Vec<u8> {
        let p = Platform::new();

        let s = handshake(&p, trng, session, store);
        let new_pin_enc = s.encrypt(trng, &padded_pin(pin)).to_vec();
        let auth = s.authenticate(&new_pin_enc).to_vec();
        let r = send(
            trng,
            session,
            store,
            CTAP2_CLIENT_PIN,
            &[
                (1, Value::Uint(PIN_PROTOCOL_V1)),
                (2, Value::Uint(SUB_SET_PIN)),
                (3, p.cose_pub()),
                (4, Value::Bytes(auth)),
                (5, Value::Bytes(new_pin_enc)),
            ],
        );
        assert_eq!(r[0], CTAP2_OK, "setPIN failed with {:#04x}", r[0]);

        mint_token(trng, session, store, pin, perms, rp)
    }

    /// Mint a token on a device that already has `pin` set.
    pub fn mint_token(
        trng: &mut Trng,
        session: &mut PinSession,
        store: &mut CredStore,
        pin: &[u8],
        perms: u64,
        rp: Option<&str>,
    ) -> Vec<u8> {
        let p = Platform::new();
        let s = handshake(&p, trng, session, store);
        let pin_hash_enc = s
            .encrypt(trng, &crate::bc_crypto::sha256(pin)[..16])
            .to_vec();
        let mut params: Vec<(u64, Value)> = vec![
            (1, Value::Uint(PIN_PROTOCOL_V1)),
            (2, Value::Uint(SUB_GET_TOKEN_PERMS)),
            (3, p.cose_pub()),
            (6, Value::Bytes(pin_hash_enc)),
            (9, Value::Uint(perms)),
        ];
        if let Some(r) = rp {
            params.push((0x0A, Value::Text(r.into())));
        }
        let r = send(trng, session, store, CTAP2_CLIENT_PIN, &params);
        assert_eq!(r[0], CTAP2_OK, "token request failed with {:#04x}", r[0]);
        let enc = match resp_key(&r, 2).expect("no token in the response") {
            Value::Bytes(b) => b,
            other => panic!("the token is {other:?}"),
        };
        s.decrypt(&enc).expect("the token did not decrypt").to_vec()
    }

    /// A device plus the platform state needed to talk to it: the
    /// serial guard, a simulated blank die, and (optionally) a PIN and a
    /// minted `pinUvAuthToken`.
    pub struct Device {
        _guard: crate::testlock::Guard,
        pub trng: Trng,
        pub session: PinSession,
        pub store: CredStore,
        /// The plaintext token, empty when the device has no PIN.
        pub token: Vec<u8>,
        /// The PIN currently set, empty when there is none. Kept so
        /// `mint` can re-authenticate without every caller passing it.
        pub pin: Vec<u8>,
    }

    /// The PIN every authenticated test device is given.
    pub const TEST_PIN: &[u8] = b"1234";

    impl Device {
        /// A blank device with no PIN and no token.
        pub fn bare() -> Self {
            let guard = crate::testlock::acquire();
            rp235x_hal::reset();
            rp235x_hal::reset_counts();
            crate::core1_signer::CORE1_SIGNER.reset_for_test();
            let mut trng = Trng::new_for_test();
            let store = CredStore::load(&mut trng);
            let session = PinSession::new(&mut trng);
            let mut d = Device {
                _guard: guard,
                trng,
                session,
                store,
                token: Vec::new(),
                pin: Vec::new(),
            };
            d.clear_boot_lifetime_state();
            d
        }

        /// Clear the state a real power cycle would clear but a
        /// simulated die reset does not.
        ///
        /// largeBlobs assembles a write across several transactions in a
        /// process-global staging buffer. `rp235x_hal::reset()` wipes the
        /// flash; it does not touch that. So without this, a test that
        /// left a write half-assembled hands the next one a device with
        /// something already in flight -- and a test asserting "nothing
        /// is in flight" passes or fails on the order the harness
        /// happened to run in.
        ///
        /// Done over the wire rather than with a test hook in the
        /// firmware: a write declaring a total below the legal minimum
        /// resets the buffer on its way to refusing. The error is the
        /// point, so it is discarded.
        fn clear_boot_lifetime_state(&mut self) {
            let body = Value::Map(vec![
                (Value::Uint(0x02), Value::Bytes(vec![0x80])), // set
                (Value::Uint(0x03), Value::Uint(0)),           // offset
                (Value::Uint(0x04), Value::Uint(0)),           // length: illegal
            ]);
            let _ = self.send(ctap2::CTAP2_LARGE_BLOBS, &body);
        }

        /// A blank device with `TEST_PIN` set and a token carrying
        /// `perms`, optionally scoped to `rp`.
        pub fn authenticated(perms: u64, rp: Option<&str>) -> Self {
            let mut d = Device::bare();
            d.pin = TEST_PIN.to_vec();
            d.token = authenticate(
                &mut d.trng,
                &mut d.session,
                &mut d.store,
                TEST_PIN,
                perms,
                rp,
            );
            d
        }

        /// Send one CTAP2 command, presence always confirmed.
        pub fn send(&mut self, cmd: u8, body: &Value) -> Vec<u8> {
            let mut m = vec![cmd];
            m.extend_from_slice(&encode(body));
            let mut host = |_op: HostOp| true;
            ctap2::handle_cbor(
                &m,
                &mut self.trng,
                &mut self.session,
                &mut self.store,
                &mut host,
                0,
                [0, 0, 0, 1],
            )
            .to_vec()
        }

        /// One entry of a response map, by integer key.
        pub fn field(resp: &[u8], key: u64) -> Option<Value> {
            resp_key(resp, key)
        }

        /// A subcommand of credentialManagement (0x0A) or
        /// authenticatorConfig (0x0D), framed as CTAP 2.1 numbers them:
        /// `pinUvAuthProtocol` at 0x03 (unsigned), `pinUvAuthParam` at
        /// 0x04 (byte string).
        ///
        /// The signed message differs by command: credentialManagement
        /// signs `subCommand || params` bare, authenticatorConfig
        /// prefixes 32 bytes of 0xff and the command byte 0x0d.
        pub fn subcommand(&mut self, cmd: u8, sub: u64, params: Option<Value>) -> Vec<u8> {
            let pcbor = params.as_ref().map(|p| encode(p)).unwrap_or_default();
            let mut msg = Vec::new();
            if cmd == ctap2::CTAP2_CONFIG {
                msg.extend_from_slice(&[0xffu8; 32]);
                msg.push(0x0d);
            }
            msg.push(sub as u8);
            msg.extend_from_slice(&pcbor);
            let ap = auth_param(&self.token, &msg);
            let mut e = vec![(Value::Uint(1), Value::Uint(sub))];
            if let Some(p) = params {
                e.push((Value::Uint(2), p));
            }
            e.push((Value::Uint(3), Value::Uint(1)));
            e.push((Value::Uint(4), Value::Bytes(ap)));
            self.send(cmd, &Value::Map(e))
        }

        /// Ask for a fresh `pinUvAuthToken`, keeping the raw response so
        /// a caller can assert a refusal. On success the new token
        /// replaces the stored one.
        pub fn mint(&mut self, perms: u64, rp: Option<&str>) -> Vec<u8> {
            let p = Platform::new();
            let s = handshake(&p, &mut self.trng, &mut self.session, &mut self.store);
            let pin_hash_enc = s
                .encrypt(&mut self.trng, &crate::bc_crypto::sha256(&self.pin)[..16])
                .to_vec();
            let mut params: Vec<(Value, Value)> = vec![
                (Value::Uint(1), Value::Uint(PIN_PROTOCOL_V1)),
                (Value::Uint(2), Value::Uint(SUB_GET_TOKEN_PERMS)),
                (Value::Uint(3), p.cose_pub()),
                (Value::Uint(6), Value::Bytes(pin_hash_enc)),
                (Value::Uint(9), Value::Uint(perms)),
            ];
            if let Some(r) = rp {
                params.push((Value::Uint(0x0A), Value::Text(r.into())));
            }
            params.sort_by_key(|(k, _)| if let Value::Uint(n) = k { *n } else { 0 });
            let r = self.send(CTAP2_CLIENT_PIN, &Value::Map(params));
            if r[0] == CTAP2_OK {
                if let Some(Value::Bytes(enc)) = resp_key(&r, 2) {
                    self.token = s.decrypt(&enc).expect("the token did not decrypt").to_vec();
                }
            }
            r
        }

        /// setPIN alone, no token minted. Returns the raw response so a
        /// caller can assert the refusal; on success `pin` is recorded.
        pub fn set_pin(&mut self, pin: &[u8]) -> Vec<u8> {
            let p = Platform::new();
            let s = handshake(&p, &mut self.trng, &mut self.session, &mut self.store);
            let new_pin_enc = s.encrypt(&mut self.trng, &padded_pin(pin)).to_vec();
            let auth = s.authenticate(&new_pin_enc).to_vec();
            let r = send(
                &mut self.trng,
                &mut self.session,
                &mut self.store,
                CTAP2_CLIENT_PIN,
                &[
                    (1, Value::Uint(PIN_PROTOCOL_V1)),
                    (2, Value::Uint(SUB_SET_PIN)),
                    (3, p.cose_pub()),
                    (4, Value::Bytes(auth)),
                    (5, Value::Bytes(new_pin_enc)),
                ],
            );
            if r[0] == CTAP2_OK {
                self.pin = pin.to_vec();
            }
            r
        }

        /// Change the device PIN, authenticated with the current one.
        /// Returns the raw response so a caller can assert the refusal.
        pub fn change_pin(&mut self, old: &[u8], new: &[u8]) -> Vec<u8> {
            let p = Platform::new();
            let s = handshake(&p, &mut self.trng, &mut self.session, &mut self.store);
            let new_pin_enc = s.encrypt(&mut self.trng, &padded_pin(new)).to_vec();
            let pin_hash_enc = s
                .encrypt(&mut self.trng, &crate::bc_crypto::sha256(old)[..16])
                .to_vec();
            let mut combined = new_pin_enc.clone();
            combined.extend_from_slice(&pin_hash_enc);
            let auth = s.authenticate(&combined).to_vec();
            let r = self.send(
                CTAP2_CLIENT_PIN,
                &Value::Map(vec![
                    (Value::Uint(1), Value::Uint(PIN_PROTOCOL_V1)),
                    (Value::Uint(2), Value::Uint(0x04)),
                    (Value::Uint(3), p.cose_pub()),
                    (Value::Uint(4), Value::Bytes(auth)),
                    (Value::Uint(5), Value::Bytes(new_pin_enc)),
                    (Value::Uint(6), Value::Bytes(pin_hash_enc)),
                ]),
            );
            if r[0] == CTAP2_OK {
                self.pin = new.to_vec();
            }
            r
        }

        /// Register a discoverable credential for `rp`, authenticated
        /// with the current token (required once a PIN is set).
        pub fn register(&mut self, rp: &str, user_id: u8, name: &str) -> Vec<u8> {
            let txt = |s: &str| Value::Text(s.into());
            let mut e = vec![
                (Value::Uint(1), Value::Bytes(vec![0x11; 32])),
                (Value::Uint(2), Value::Map(vec![(txt("id"), txt(rp))])),
                (
                    Value::Uint(3),
                    Value::Map(vec![
                        (txt("id"), Value::Bytes(vec![user_id; 4])),
                        (txt("name"), txt(name)),
                        (txt("displayName"), txt(name)),
                    ]),
                ),
                (
                    Value::Uint(4),
                    Value::Array(vec![Value::Map(vec![
                        (txt("alg"), Value::Nint(-7)),
                        (txt("type"), txt("public-key")),
                    ])]),
                ),
                (
                    Value::Uint(7),
                    Value::Map(vec![(txt("rk"), Value::Bool(true))]),
                ),
            ];
            if !self.token.is_empty() {
                e.push((
                    Value::Uint(8),
                    Value::Bytes(auth_param(&self.token, &[0x11u8; 32])),
                ));
                e.push((Value::Uint(9), Value::Uint(1)));
            }
            e.sort_by_key(|(k, _)| if let Value::Uint(n) = k { *n } else { 0 });
            let r = self.send(ctap2::CTAP2_MAKE_CREDENTIAL, &Value::Map(e));
            assert_eq!(r[0], CTAP2_OK, "registering at {rp} failed: {:#04x}", r[0]);
            // The credential id, out of authData.
            let ad = match resp_key(&r, 2).expect("no authData") {
                Value::Bytes(b) => b,
                other => panic!("authData is {other:?}"),
            };
            let len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
            ad[55..55 + len].to_vec()
        }
    }

    /// The v1 `pinUvAuthParam` over a message: LEFT(HMAC-SHA-256, 16).
    /// Computed here rather than through the firmware, so an error in
    /// its own tag construction still shows.
    pub fn auth_param(token: &[u8], message: &[u8]) -> Vec<u8> {
        let mut k = [0u8; 32];
        k.copy_from_slice(token);
        crate::bc_crypto::hmac_sha256(&k, message)[..16].to_vec()
    }
}

/// Serialising the tests, and naming the one mistake that looks like a
/// hang.
///
/// Every module under test owns process-global state -- a simulated
/// flash die, a boot-lifetime gate, a signer mailbox -- so tests take a
/// device lock for their whole body and `cargo test` runs them in
/// parallel around it. Blocking is therefore correct and normal.
///
/// The exception is a second `acquire()` on a thread that already holds
/// the guard, which cannot ever resolve. That is a test bug, not
/// contention, and it used to stop the suite dead with no output. So the
/// holder is recorded and the self-deadlock reports itself: only this
/// thread can have set its own id, so the check needs no synchronisation
/// beyond the flag itself.
pub mod testlock {
    use std::sync::{Mutex, MutexGuard};
    use std::thread::ThreadId;

    static LOCK: Mutex<()> = Mutex::new(());
    static OWNER: Mutex<Option<ThreadId>> = Mutex::new(None);

    fn owner() -> Option<ThreadId> {
        *OWNER.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn set_owner(v: Option<ThreadId>) {
        *OWNER.lock().unwrap_or_else(|e| e.into_inner()) = v;
    }

    pub struct Guard {
        _inner: MutexGuard<'static, ()>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            set_owner(None);
        }
    }

    /// Take the device lock, blocking until other tests are done.
    pub fn acquire() -> Guard {
        let me = std::thread::current().id();
        assert!(
            owner() != Some(me),
            "this thread already holds the device lock -- an earlier test \
             device is still alive in this scope. Drop it before making \
             another; two at once can never both be served."
        );
        let inner = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_owner(Some(me));
        Guard { _inner: inner }
    }
}

/// The **real** TRNG driver, against a simulated peripheral.
///
/// Distinct from the `trng` stub below, which every other suite uses as
/// a deterministic byte source. This one is the firmware's own
/// `trng.rs` driving `halsim`'s scriptable noise source, so the paths
/// hardware almost never takes can actually be run: a health-test
/// failure, a source that never asserts EHR_VALID, and the decision to
/// refuse to operate rather than hand back weak keys.
#[allow(dead_code)]
/// The USB DFU runtime interface and the FIDO HID class. Both are
/// self-contained usb-device `UsbClass` impls -- no `crate::`, no cfg
/// gates -- so they come in by path like everything else here and run
/// against the mock bus in `tests/usbmock.rs`.
/// The GDB stub, for the sake of the debug-unit registers behind its
/// `mmio` seam -- the FPB comparators and DEMCR, none of which existed
/// off silicon before. The protocol itself is gdbstub-core's.
#[allow(dead_code)]
#[path = "../../firmware/src/gdbstub.rs"]
pub mod gdbstub;

#[allow(dead_code)]
#[path = "../../firmware/src/dfu_runtime.rs"]
pub mod dfu_runtime;

#[allow(dead_code)]
#[path = "../../firmware/src/fido_hid.rs"]
pub mod fido_hid;

/// The Non-secure world's HID class. Textually a subset of the firmware
/// one, but the subset relation holds between the two CLASSES, not the
/// two IMAGES: the firmware drains its ring every main-loop iteration,
/// while the Non-secure image polls USB for up to ten seconds inside
/// `await_user_presence` without draining. Same ring, same depth,
/// different driver -- and the driver decides whether it ever fills.
#[allow(dead_code)]
#[path = "../../fw-nonsecure/src/fido_hid.rs"]
pub mod ns_fido_hid;

/// The Non-secure CBOR reader, for differential fuzzing against
/// `pqf_cbor`. Two independent decoders of one format: where they
/// disagree about the same bytes, one of them is wrong.
#[allow(dead_code)]
#[path = "../../fw-nonsecure/src/cborr.rs"]
pub mod ns_cborr;

#[path = "../../firmware/src/trng.rs"]
pub mod real_trng;

/// The picker that puts the QRNG ahead of the TRNG -- over the stub
/// `trng` below, whose deterministic stream is what makes "the TRNG was
/// not consulted" a checkable statement.
#[path = "../../firmware/src/entropy.rs"]
pub mod entropy;
/// The QRNG driver, exactly as shipped. Its protocol logic is
/// written against `qrng::Bus`, so the host scripts the bus; the RP2350
/// transport (`qrng::hw`) is cfg'd to the two firmware targets and is not
/// compiled here.
#[path = "../../firmware/src/qrng.rs"]
pub mod qrng;

pub mod trng {
    pub struct Trng {
        next: u8,
        step: u8,
    }

    impl Trng {
        pub fn new_for_test() -> Self {
            Self { next: 1, step: 1 }
        }

        /// A TRNG stuck on one value. Not a realistic failure, but it is
        /// the cheapest way to ask "does anything here depend on the IV
        /// being unique?" and get an answer rather than an assumption.
        pub fn stuck(value: u8) -> Self {
            Self {
                next: value,
                step: 0,
            }
        }

        pub fn fill(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                *b = self.next;
                self.next = self.next.wrapping_add(self.step);
            }
        }
    }

    /// `p256` asks for `CryptoRngCore` on the key-generation path, and
    /// the real `Trng` satisfies it the same way. Deterministic here,
    /// which is the point: a test that generates a key twice gets the
    /// same key.
    impl rand_core::RngCore for Trng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.fill(dest);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for Trng {}
}

/// The COSE algorithm ids, selected by the same feature the firmware
/// uses. Level-independent for the credential-id format -- the ML-DSA
/// seed is 32 bytes at every level -- but the id itself is not.
#[allow(dead_code)]
#[path = "../../firmware/src/mldsa_alg.rs"]
pub mod mldsa_alg;

/// SHA-256, HMAC, HKDF and the constant-time compare, straight from the
/// firmware. No hardware in it.
#[allow(dead_code)]
#[path = "../../firmware/src/bc_crypto.rs"]
pub mod bc_crypto;

/// Stands in for `crate::arch`.
///
/// The firmware's spin loops call `nop()` while waiting on core 1. It is
/// emitted in place on the board so it can run with the XIP window down;
/// here there is nothing to wait for and nothing to keep out of flash.
pub mod arch {
    pub fn nop() {}
    pub fn sev() {}

    /// Interrupt masking, simulated. `flash_op_locked` saves the mask,
    /// disables, runs the flash op, then restores -- so a caller that
    /// already had interrupts masked stays masked. That is a real
    /// property and it is checkable here.
    static MASKED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    pub fn irq_save_disable() -> u32 {
        let was = MASKED.swap(true, core::sync::atomic::Ordering::SeqCst);
        if was {
            1
        } else {
            0
        }
    }
    pub fn irq_restore(saved: u32) {
        MASKED.store(saved != 0, core::sync::atomic::Ordering::SeqCst);
    }

    /// Test helpers.
    pub fn irqs_masked() -> bool {
        MASKED.load(core::sync::atomic::Ordering::SeqCst)
    }
    pub fn set_irqs_masked(v: bool) {
        MASKED.store(v, core::sync::atomic::Ordering::SeqCst);
    }
}

/// Stands in for `crate::core1_signer`.
///
/// On the board this is the cross-core mailbox: core 0 hands over the
/// scalar, the seed and the message, then spins pumping USB keepalives
/// while the Hazard3 core produces a hybrid signature. Here it produces
/// a signature of the right *shape* and nothing else.
///
/// **What that means for anything tested through it.** These tests cover
/// what the token says -- dispatch, CBOR shaping, request parsing,
/// policy -- and not what it signs. The signature itself, the cross-core
/// handshake, the keepalive cadence and the spin backstop are silicon
/// concerns and stay covered there: `pqc_roundtrip` on all six
/// port x ISA configurations, and the conformance suite verifying the
/// attestation against the credential's own public key.
///
/// The failure this could hide is a signature that is well formed and
/// wrong. So the shape is all that is asserted here -- a DER prefix plus
/// exactly `MLDSA_SIG_LEN` -- and validity is never claimed.
pub mod core1_signer {
    use core::cell::RefCell;
    use pqf_signer_core::mldsa_alg::MLDSA_SIG_LEN;

    pub struct Core1Signer {
        state: RefCell<State>,
        /// The park handshake `ramfunc::flash_op_locked` drives. There
        /// is no second core here, so a cooperative one is simulated:
        /// reading `park_ack` mirrors whatever `park_request` last said.
        /// Without that the firmware's spin loop would never terminate,
        /// which is itself the point -- on silicon a core 1 that never
        /// acks hangs core 0 forever.
        pub park_request: core::sync::atomic::AtomicBool,
        pub park_ack: SimulatedAck,
    }

    /// Core 1's side of the park handshake, simulated.
    ///
    /// `load` returns whatever `park_request` currently holds, so the
    /// firmware's two spin loops (wait for ack, then wait for it to
    /// clear) both terminate. Every transition is recorded so a test can
    /// check the *order* the handshake ran in, which is the part that
    /// matters: XIP must not be suspended until core 1 has acknowledged.
    pub struct SimulatedAck;

    impl SimulatedAck {
        pub fn load(&self, _o: core::sync::atomic::Ordering) -> bool {
            let v = CORE1_SIGNER
                .park_request
                .load(core::sync::atomic::Ordering::Acquire);
            trace_push(if v {
                Ev::AckObservedSet
            } else {
                Ev::AckObservedClear
            });
            v
        }
    }

    /// What happened, in order, during a `flash_op_locked` call.
    #[derive(Clone, Copy, PartialEq, Debug)]
    pub enum Ev {
        ParkRequested,
        ParkReleased,
        AckObservedSet,
        AckObservedClear,
        OpRan,
    }

    static TRACE: std::sync::Mutex<Vec<Ev>> = std::sync::Mutex::new(Vec::new());

    pub fn trace_push(e: Ev) {
        TRACE.lock().unwrap_or_else(|x| x.into_inner()).push(e);
    }
    pub fn trace() -> Vec<Ev> {
        TRACE.lock().unwrap_or_else(|x| x.into_inner()).clone()
    }
    pub fn trace_clear() {
        TRACE.lock().unwrap_or_else(|x| x.into_inner()).clear();
    }

    struct State {
        pending: Option<alloc::vec::Vec<u8>>,
        fail_next: bool,
        errored: bool,
        submits: u32,
        /// Polls of `is_done` still to answer "not yet" while a result
        /// is pending. See `hold_next_result`.
        busy_polls: u32,
    }

    /// Worst-case DER for a P-256 signature, matching the real mailbox.
    const DER_MAX: usize = 72;

    // SAFETY: the tests are single-threaded and take a lock around any
    // module that owns process-global state; there is no second core
    // here for the RefCell to race with.
    unsafe impl Sync for Core1Signer {}

    impl Core1Signer {
        const fn new() -> Self {
            Self {
                state: RefCell::new(State {
                    pending: None,
                    fail_next: false,
                    errored: false,
                    submits: 0,
                    busy_polls: 0,
                }),
                park_request: core::sync::atomic::AtomicBool::new(false),
                park_ack: SimulatedAck,
            }
        }

        pub fn submit(
            &self,
            ecdsa_scalar: &[u8; 32],
            mldsa_seed: &[u8; 32],
            msg: &[u8],
        ) -> Result<(), &'static str> {
            let mut st = self.state.borrow_mut();
            st.submits += 1;
            if st.fail_next {
                st.fail_next = false;
                st.errored = true;
                st.pending = Some(alloc::vec::Vec::new());
                return Ok(());
            }
            st.errored = false;
            // Shape only, but derived from the inputs so two different
            // credentials do not produce the same bytes -- a test that
            // wanted to tell two signatures apart should be able to.
            let mut sig = alloc::vec::Vec::with_capacity(DER_MAX + MLDSA_SIG_LEN);
            sig.push(0x30);
            sig.push((DER_MAX - 2) as u8);
            for i in 0..(DER_MAX - 2) {
                sig.push(ecdsa_scalar[i % 32] ^ (i as u8));
            }
            for i in 0..MLDSA_SIG_LEN {
                sig.push(mldsa_seed[i % 32] ^ msg.get(i % msg.len().max(1)).copied().unwrap_or(0));
            }
            st.pending = Some(sig);
            Ok(())
        }

        /// Immediate: there is no second core to wait for, so a caller's
        /// spin loop runs exactly once -- unless `hold_next_result` asked
        /// for it to run longer.
        pub fn is_done(&self) -> bool {
            let mut st = self.state.borrow_mut();
            if st.pending.is_none() {
                return false;
            }
            if st.busy_polls > 0 {
                st.busy_polls -= 1;
                return false;
            }
            true
        }

        pub fn errored(&self) -> bool {
            self.state.borrow().errored
        }

        pub fn take_result(&self, out: &mut alloc::vec::Vec<u8>) {
            let mut st = self.state.borrow_mut();
            out.clear();
            if let Some(sig) = st.pending.take() {
                out.extend_from_slice(&sig);
            }
        }

        /// Test hook: make the next signature fail, so the caller's error
        /// path can be reached. On the board this is core 1 panicking or
        /// the shared heap running out.
        pub fn fail_next_submit(&self) {
            self.state.borrow_mut().fail_next = true;
        }

        /// Test hook: report the next result as not ready for `polls`
        /// checks. A result that is ready at once means the caller's wait
        /// loop never pumps the host, and the pump is where a
        /// CTAPHID_CANCEL is noticed -- so without this a cancelled sign
        /// cannot be reached here at all. On the board this is simply
        /// core 1 taking its one to two seconds.
        pub fn hold_next_result(&self, polls: u32) {
            self.state.borrow_mut().busy_polls = polls;
        }

        /// How many signatures have been asked for. Lets a test say "this
        /// command signed once" rather than inferring it from the output.
        pub fn submits(&self) -> u32 {
            self.state.borrow().submits
        }

        pub fn reset_for_test(&self) {
            let mut st = self.state.borrow_mut();
            st.pending = None;
            st.fail_next = false;
            st.errored = false;
            st.submits = 0;
            st.busy_polls = 0;
            drop(st);
            self.park_request
                .store(false, core::sync::atomic::Ordering::Release);
            trace_clear();
        }
    }

    pub static CORE1_SIGNER: Core1Signer = Core1Signer::new();
}

/// The **real** `ramfunc`, against simulated QMI and a cooperative
/// core 1.
///
/// Distinct from the `ramfunc` stub below, which other suites use. This
/// one is the firmware's own, so the QMI save/restore can be checked --
/// the guard that turned a 13-second ML-DSA-65 signature back into 1.3
/// seconds.
#[allow(dead_code)]
#[path = "../../firmware/src/ramfunc.rs"]
pub mod real_ramfunc;

/// Stands in for `crate::ramfunc`.
///
/// On the board this is RAM-resident code that masks interrupts and
/// parks the other core before the XIP window goes down, because a flash
/// fetch during that window returns garbage. There is no XIP window here
/// and no second core; the parking is exercised on silicon and by
/// `pqf-signer-core`'s own tests.
pub mod ramfunc {
    pub fn flash_op_locked<R>(f: impl FnOnce() -> R) -> R {
        f()
    }
}

/// The flash-backed credential and key store, against a simulated die.
#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../firmware/src/flash_store.rs"]
pub mod flash_store;

/// The CTAP2 command surface: dispatch, request parsing, CBOR shaping
/// and policy. The signing underneath it is stubbed -- see
/// [`core1_signer`].
#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../firmware/src/ctap2.rs"]
pub mod ctap2;

/// The CTAP2 PIN protocol.
#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../firmware/src/client_pin.rs"]
pub mod client_pin;

/// CredentialManagement.
#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../firmware/src/credential_management.rs"]
pub mod credential_management;

/// LargeBlobs.
#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../firmware/src/large_blobs.rs"]
pub mod large_blobs;

/// AuthenticatorConfig.
#[allow(dead_code)]
#[allow(static_mut_refs)]
#[path = "../../firmware/src/authenticator_config.rs"]
pub mod authenticator_config;

/// CTAPHID framing: channel allocation, message reassembly, the error
/// replies. No imports at all -- it is pure protocol.
#[allow(dead_code)]
#[path = "../../firmware/src/ctaphid.rs"]
pub mod ctaphid;

/// Whether `CTAPHID_CMD_REBOOT` waits for a touch: a pure `const fn`,
/// which is the point. On the sealed Feitian USB-C token that reboot is
/// the only way back into the bootloader, so a wrong answer is a token
/// that can never be reflashed -- its truth table is checked here, not
/// discovered on the token.
#[path = "../../firmware/src/reboot_policy.rs"]
pub mod reboot_policy;

/// The sealed credential id.
#[allow(dead_code)]
#[path = "../../firmware/src/credential_id.rs"]
pub mod credential_id;

/// Ed25519 (-8), behind the same feature gate the firmware uses.
///
/// The one algorithm path in this firmware that can be verified for
/// real on the host: `ed25519_dalek` is the actual implementation, not
/// a stub, so a signature made here can be checked rather than merely
/// measured for length. Everything ML-DSA is shape-only.
#[cfg(feature = "ed25519")]
#[allow(dead_code)]
#[path = "../../firmware/src/ed25519_alg.rs"]
pub mod ed25519_alg;

/// The CTAP1/U2F back-compat surface, behind the same feature gate the
/// firmware uses. It was structurally unreachable once already -- the
/// dispatch refused CMD_MSG while getInfo advertised NMSG
/// unconditionally, so the feature only linked a hardcoded key -- which
/// is reason enough to test what it does when it *is* built in.
#[cfg(feature = "u2f")]
#[allow(dead_code)]
#[path = "../../firmware/src/u2f.rs"]
pub mod u2f;
