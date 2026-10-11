// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAP 2.1 PIN/UV-auth protocols v1 and v2 (sec. 6.5.6 / sec. 6.5.7).
//!
//! The PIN protocol's job is to let the host and authenticator
//! derive a shared secret (via ECDH on P-256) and then use that
//! secret to authenticate / encrypt the PIN-protocol payloads of
//! `authenticatorClientPin` subcommands and the `pinUvAuthParam`
//! field on `authenticatorMakeCredential` /
//! `authenticatorGetAssertion`.
//!
//! Both protocols share the same outer shape -- ECDH key exchange ->
//! shared secret -> wrap subsequent payloads -- but differ in how
//! the shared secret is used:
//!
//! - **Protocol v1** (sec. 6.5.6.1): AES-256-CBC with a fixed all-zero
//!   IV, HMAC-SHA-256 of the ciphertext truncated to the first 16
//!   bytes for `pinUvAuthParam`.
//!
//! - **Protocol v2** (sec. 6.5.6.2): AES-256-CBC with a fresh 16-byte
//!   random IV prepended to the ciphertext, HMAC-SHA-256 full
//!   32-byte tag. The shared secret is fed through HKDF-SHA-256
//!   (RFC 5869) to derive separate 32-byte AES and HMAC keys
//!   ("CTAP2 HMAC key" + "CTAP2 AES key" info strings).
//!
//! Each protocol is implemented as a value type ([`V1`], [`V2`])
//! that owns the host's ephemeral ECDH key pair, applies the ECDH
//! step against the device's public key (from
//! [`crate::ctap2::client_pin::get_key_agreement`]), and exposes
//! `encrypt` / `decrypt` / `authenticate` methods.

use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::{generic_array::GenericArray, sec1::ToEncodedPoint},
    PublicKey,
};
use pqf_cbor::Value;
use rand::rngs::OsRng;
use sha2::Sha256;

use super::Error;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Length of the truncated `pinUvAuthParam` under protocol v1.
const V1_HMAC_TRUNC_LEN: usize = 16;
/// Length of the IV used by protocol v2.
const V2_IV_LEN: usize = 16;

/// Protocol selector. Determines which crypto suite a [`Session`]
/// uses. CTAP 2.1 sec. 6.5.5.7 mandates the host pick a single
/// protocol per `pinUvAuthToken`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    /// Protocol version 1 -- fixed-IV AES-CBC, 16-byte truncated HMAC.
    V1 = 1,
    /// Protocol version 2 -- random-IV AES-CBC with HKDF-derived
    /// keys, full 32-byte HMAC tag.
    V2 = 2,
}

impl Protocol {
    /// The on-wire byte used in the `pinUvAuthProtocol` field of
    /// CTAP requests.
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Inverse of [`Self::as_byte`]. Returns an error for any byte
    /// other than 1 or 2.
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            1 => Ok(Protocol::V1),
            2 => Ok(Protocol::V2),
            other => Err(Error::Decode(format!(
                "unknown PIN protocol byte {other:?}"
            ))),
        }
    }
}

/// A live PIN protocol session -- host's ephemeral ECDH key pair
/// plus the shared secret derived from the device's
/// `keyAgreement` public key.
///
/// Builder pattern:
///
///   1. Call [`Session::initiate`] to generate the host key pair.
///      You get back a [`Session`] in "no shared secret yet" state.
///   2. Send `clientPin.getKeyAgreement` to the device (subcommand
///      0x02), which returns its `keyAgreement` COSE_Key.
///   3. Call [`Session::complete`] with the device's COSE_Key. The
///      session now has the shared secret and can encrypt /
///      authenticate.
///
/// All subsequent PIN-protocol payloads are wrapped via
/// [`Session::encrypt`] / [`Session::decrypt`] /
/// [`Session::authenticate`].
pub struct Session {
    proto: Protocol,
    sk: EphemeralSecret,
    shared: Option<SharedSecret>,
}

/// Cached derived material -- for protocol v1, the raw 32-byte
/// shared-secret point; for protocol v2, the two 32-byte HKDF
/// outputs split into AES and HMAC sub-keys.
enum SharedSecret {
    V1 {
        secret: [u8; 32],
    },
    V2 {
        hmac_key: [u8; 32],
        aes_key: [u8; 32],
    },
}

impl Session {
    /// Generate the host's ephemeral ECDH key pair and return a
    /// session ready to be completed via [`Self::complete`].
    pub fn initiate(proto: Protocol) -> Self {
        let sk = EphemeralSecret::random(&mut OsRng);
        Self {
            proto,
            sk,
            shared: None,
        }
    }

    /// The protocol this session was initiated with.
    pub fn protocol(&self) -> Protocol {
        self.proto
    }

    /// The host's `keyAgreement` public key, in the CBOR COSE_Key
    /// shape the device expects in subcommands 0x03 / 0x04 / 0x05
    /// / 0x06 / 0x09 of `authenticatorClientPin` (CTAP 2.1
    /// sec. 6.5.5.7).
    pub fn public_key_cbor(&self) -> Value {
        let pub_key = self.sk.public_key();
        let encoded = pub_key.to_encoded_point(false);
        let bytes = encoded.as_bytes();
        // SEC1 uncompressed: 0x04 || X (32 bytes) || Y (32 bytes).
        debug_assert_eq!(bytes.len(), 65);
        let x = bytes[1..33].to_vec();
        let y = bytes[33..65].to_vec();
        // COSE_Key per CTAP 2.1 sec. 6.5.5.7.1:
        //   1: kty = 2 (EC2)
        //   3: alg = -25 (ECDH-ES + HKDF-256) for both v1 and v2
        //   -1: crv = 1 (P-256)
        //   -2: x   (32-byte big-endian)
        //   -3: y   (32-byte big-endian)
        Value::Map(vec![
            (Value::Uint(1), Value::Uint(2)),
            (Value::Uint(3), Value::Nint(-25)),
            (Value::Nint(-1), Value::Uint(1)),
            (Value::Nint(-2), Value::Bytes(x)),
            (Value::Nint(-3), Value::Bytes(y)),
        ])
    }

    /// Complete the ECDH and derive the protocol-specific key
    /// material from the device's `keyAgreement` COSE_Key.
    pub fn complete(&mut self, device_key_cose: &Value) -> Result<(), Error> {
        let dev_pub = decode_cose_p256(device_key_cose)?;
        let shared_point = self.sk.diffie_hellman(&dev_pub);

        // Per CTAP 2.1 sec. 6.5.6.1 / sec. 6.5.6.2 the shared input to the
        // KDF / SHA is the X coordinate only (32 bytes), not the
        // full SEC1 point.
        let raw: [u8; 32] = (*shared_point.raw_secret_bytes()).into();

        self.shared = Some(match self.proto {
            Protocol::V1 => {
                // sec. 6.5.6.1: shared secret = SHA-256(ECDH-X).
                let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
                sha2::Digest::update(&mut hasher, raw);
                let secret_bytes = sha2::Digest::finalize(hasher);
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&secret_bytes);
                SharedSecret::V1 { secret }
            }
            Protocol::V2 => {
                // sec. 6.5.6.2 derives two keys via HKDF-SHA-256 with a
                // 32-byte salt of zeros and the info strings
                // "CTAP2 HMAC key" + "CTAP2 AES key".
                let salt = [0u8; 32];
                let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), &raw);
                let mut hmac_key = [0u8; 32];
                hk.expand(b"CTAP2 HMAC key", &mut hmac_key).map_err(|e| {
                    Error::Decode(format!("HKDF(CTAP2 HMAC key) expand failed: {e}"))
                })?;
                let mut aes_key = [0u8; 32];
                hk.expand(b"CTAP2 AES key", &mut aes_key).map_err(|e| {
                    Error::Decode(format!("HKDF(CTAP2 AES key) expand failed: {e}"))
                })?;
                SharedSecret::V2 { hmac_key, aes_key }
            }
        });
        Ok(())
    }

    /// Encrypt `plaintext` under the shared secret. Plaintext
    /// length must be a multiple of 16 (AES-CBC, no padding --
    /// CTAP 2.1 sec. 6.5.6).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if plaintext.len() % 16 != 0 {
            return Err(Error::Decode(format!(
                "encrypt: plaintext length {} not a multiple of 16",
                plaintext.len()
            )));
        }
        let shared = self
            .shared
            .as_ref()
            .ok_or_else(|| Error::Decode("encrypt before session.complete()".into()))?;
        match shared {
            SharedSecret::V1 { secret } => {
                let cipher = Aes256CbcEnc::new(
                    GenericArray::from_slice(secret),
                    GenericArray::from_slice(&[0u8; 16]),
                );
                let mut out = plaintext.to_vec();
                let n = out.len();
                cipher
                    .encrypt_padded_mut::<NoPadding>(&mut out, n)
                    .map_err(|e| Error::Decode(format!("AES-CBC encrypt: {e}")))?;
                Ok(out)
            }
            SharedSecret::V2 { aes_key, .. } => {
                let mut iv = [0u8; V2_IV_LEN];
                rand::Rng::fill(&mut OsRng, &mut iv[..]);
                let cipher = Aes256CbcEnc::new(
                    GenericArray::from_slice(aes_key),
                    GenericArray::from_slice(&iv),
                );
                let mut buf = plaintext.to_vec();
                let n = buf.len();
                cipher
                    .encrypt_padded_mut::<NoPadding>(&mut buf, n)
                    .map_err(|e| Error::Decode(format!("AES-CBC encrypt: {e}")))?;
                let mut out = Vec::with_capacity(V2_IV_LEN + buf.len());
                out.extend_from_slice(&iv);
                out.extend_from_slice(&buf);
                Ok(out)
            }
        }
    }

    /// Decrypt `ciphertext` under the shared secret. For v2 the
    /// first 16 bytes are the IV; the remaining bytes are the
    /// AES-CBC ciphertext.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let shared = self
            .shared
            .as_ref()
            .ok_or_else(|| Error::Decode("decrypt before session.complete()".into()))?;
        match shared {
            SharedSecret::V1 { secret } => {
                if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
                    return Err(Error::Decode(format!(
                        "v1 decrypt: ciphertext length {} not a positive multiple of 16",
                        ciphertext.len()
                    )));
                }
                let cipher = Aes256CbcDec::new(
                    GenericArray::from_slice(secret),
                    GenericArray::from_slice(&[0u8; 16]),
                );
                let mut buf = ciphertext.to_vec();
                let plain = cipher
                    .decrypt_padded_mut::<NoPadding>(&mut buf)
                    .map_err(|e| Error::Decode(format!("AES-CBC decrypt: {e}")))?;
                Ok(plain.to_vec())
            }
            SharedSecret::V2 { aes_key, .. } => {
                if ciphertext.len() < V2_IV_LEN || (ciphertext.len() - V2_IV_LEN) % 16 != 0 {
                    return Err(Error::Decode(format!(
                        "v2 decrypt: ciphertext length {} not IV (16) + multiple-of-16",
                        ciphertext.len()
                    )));
                }
                let iv = &ciphertext[..V2_IV_LEN];
                let ct = &ciphertext[V2_IV_LEN..];
                let cipher = Aes256CbcDec::new(
                    GenericArray::from_slice(aes_key),
                    GenericArray::from_slice(iv),
                );
                let mut buf = ct.to_vec();
                let plain = cipher
                    .decrypt_padded_mut::<NoPadding>(&mut buf)
                    .map_err(|e| Error::Decode(format!("AES-CBC decrypt: {e}")))?;
                Ok(plain.to_vec())
            }
        }
    }

    /// Compute the `pinUvAuthParam` tag for `payload`. For v1 the
    /// HMAC-SHA-256 output is truncated to the first 16 bytes;
    /// for v2 the full 32-byte tag is returned.
    pub fn authenticate(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let shared = self
            .shared
            .as_ref()
            .ok_or_else(|| Error::Decode("authenticate before session.complete()".into()))?;
        match shared {
            SharedSecret::V1 { secret } => {
                let mut mac = HmacSha256::new_from_slice(secret)
                    .map_err(|e| Error::Decode(format!("HMAC init: {e}")))?;
                mac.update(payload);
                let tag = mac.finalize().into_bytes();
                Ok(tag[..V1_HMAC_TRUNC_LEN].to_vec())
            }
            SharedSecret::V2 { hmac_key, .. } => {
                let mut mac = HmacSha256::new_from_slice(hmac_key)
                    .map_err(|e| Error::Decode(format!("HMAC init: {e}")))?;
                mac.update(payload);
                Ok(mac.finalize().into_bytes().to_vec())
            }
        }
    }
}

/// Read a COSE header-parameter value as a small signed integer.
/// COSE encodes these as either an unsigned (`Uint`) or negative
/// (`Nint`) CBOR integer; anything else yields `None`.
fn cose_int(v: &Value) -> Option<i64> {
    match v {
        Value::Uint(u) => Some(*u as i64),
        Value::Nint(n) => Some(*n),
        _ => None,
    }
}

/// Decode a CBOR COSE_Key (P-256) into a `p256::PublicKey`. The
/// device's `keyAgreement` field uses this shape per CTAP 2.1
/// sec. 6.5.5.7.1, which fixes the COSE header parameters: `kty` (label
/// 1) = 2 (EC2), `alg` (label 3) = -25 (ECDH-ES + HKDF-256), and
/// `crv` (label -1) = 1 (P-256). We assert each before trusting the
/// (x, y) coordinates so a malformed or mismatched key is rejected
/// rather than silently reinterpreted as a P-256 point.
fn decode_cose_p256(v: &Value) -> Result<PublicKey, Error> {
    // COSE_Key labels (RFC 9052 sec. 7) and the values sec. 6.5.5.7.1 fixes.
    const COSE_KTY: i64 = 1;
    const COSE_ALG: i64 = 3;
    const COSE_CRV: i64 = -1;
    const KTY_EC2: i64 = 2;
    const ALG_ECDH_ES_HKDF_256: i64 = -25;
    const CRV_P256: i64 = 1;

    let map = match v {
        Value::Map(m) => m,
        _ => return Err(Error::Decode("keyAgreement was not a map".into())),
    };
    let mut kty: Option<i64> = None;
    let mut alg: Option<i64> = None;
    let mut crv: Option<i64> = None;
    let mut x: Option<&[u8]> = None;
    let mut y: Option<&[u8]> = None;
    for (k, val) in map {
        // COSE positive labels arrive as `Uint`, negative ones as
        // `Nint`; the value of each header parameter is a small int.
        let label = match k {
            Value::Uint(u) => *u as i64,
            Value::Nint(n) => *n,
            _ => continue,
        };
        match label {
            COSE_KTY => kty = cose_int(val),
            COSE_ALG => alg = cose_int(val),
            COSE_CRV => crv = cose_int(val),
            -2 => {
                if let Value::Bytes(b) = val {
                    x = Some(b);
                }
            }
            -3 => {
                if let Value::Bytes(b) = val {
                    y = Some(b);
                }
            }
            _ => {}
        }
    }
    // Reject a key whose header parameters don't match the EC2 /
    // ECDH-ES+HKDF-256 / P-256 profile mandated for `keyAgreement`.
    match kty {
        Some(KTY_EC2) => {}
        other => {
            return Err(Error::Decode(format!(
                "keyAgreement kty != 2 (EC2): {other:?}"
            )))
        }
    }
    // `alg` is optional in a bare COSE_Key, but when the device sends
    // it the value must be the one CTAP fixes for `keyAgreement`.
    if let Some(a) = alg {
        if a != ALG_ECDH_ES_HKDF_256 {
            return Err(Error::Decode(format!(
                "keyAgreement alg != -25 (ECDH-ES+HKDF-256): {a}"
            )));
        }
    }
    match crv {
        Some(CRV_P256) => {}
        other => {
            return Err(Error::Decode(format!(
                "keyAgreement crv != 1 (P-256): {other:?}"
            )))
        }
    }
    let x = x.ok_or_else(|| Error::Decode("keyAgreement missing x".into()))?;
    let y = y.ok_or_else(|| Error::Decode("keyAgreement missing y".into()))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::Decode(format!(
            "keyAgreement x/y not 32 bytes (x={}, y={})",
            x.len(),
            y.len()
        )));
    }
    // SEC1 uncompressed: 0x04 || X || Y.
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(x);
    sec1[33..65].copy_from_slice(y);
    PublicKey::from_sec1_bytes(&sec1)
        .map_err(|e| Error::Decode(format!("keyAgreement not a valid P-256 point: {e}")))
}

/// LEFT(SHA-256(PIN), 16) -- the "PIN hash" the device uses to
/// verify the user's PIN. Caller wraps the result via
/// [`Session::encrypt`] before sending in `pinHashEnc`.
pub fn pin_hash(pin: &[u8]) -> [u8; 16] {
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut hasher, pin);
    let h = sha2::Digest::finalize(hasher);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}

/// Pad a new PIN to 64 bytes with trailing zeroes -- the format
/// the device expects in `newPinEnc` (CTAP 2.1 sec. 6.5.5.4.1).
pub fn pad_new_pin(pin: &[u8]) -> Result<[u8; 64], Error> {
    if pin.is_empty() || pin.len() > 63 {
        return Err(Error::Decode(format!(
            "pad_new_pin: PIN length {} not in 1..=63",
            pin.len()
        )));
    }
    let mut out = [0u8; 64];
    out[..pin.len()].copy_from_slice(pin);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_new_pin_length_bounds() {
        assert!(pad_new_pin(&[]).is_err());
        let pad4 = pad_new_pin(b"1234").unwrap();
        assert_eq!(&pad4[..4], b"1234");
        assert!(pad4[4..].iter().all(|&b| b == 0));
        // Maximum acceptable length is 63 (1..=63 inclusive).
        let pad63 = pad_new_pin(&[b'x'; 63]).unwrap();
        assert_eq!(pad63[62], b'x');
        assert_eq!(pad63[63], 0);
        // 64 should fail -- would leave no room for the trailing 0.
        assert!(pad_new_pin(&[b'x'; 64]).is_err());
    }

    #[test]
    fn pin_hash_first_sixteen_bytes_of_sha256() {
        // Hand-verified: SHA-256("1234").
        // 03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
        let h = pin_hash(b"1234");
        assert_eq!(
            h,
            [
                0x03, 0xac, 0x67, 0x42, 0x16, 0xf3, 0xe1, 0x5c, 0x76, 0x1e, 0xe1, 0xa5, 0xe2, 0x55,
                0xf0, 0x67,
            ]
        );
    }

    #[test]
    fn protocol_byte_round_trip() {
        assert_eq!(Protocol::from_byte(1).unwrap(), Protocol::V1);
        assert_eq!(Protocol::from_byte(2).unwrap(), Protocol::V2);
        assert!(Protocol::from_byte(0).is_err());
        assert!(Protocol::from_byte(3).is_err());
        assert_eq!(Protocol::V1.as_byte(), 1);
        assert_eq!(Protocol::V2.as_byte(), 2);
    }

    #[test]
    fn ecdh_round_trip() {
        // Two sessions complete each other's ECDH and verify the
        // derived shared secret is symmetric.
        let mut a = Session::initiate(Protocol::V2);
        let mut b = Session::initiate(Protocol::V2);
        let a_pub = a.public_key_cbor();
        let b_pub = b.public_key_cbor();
        a.complete(&b_pub).unwrap();
        b.complete(&a_pub).unwrap();
        // Encrypt-then-decrypt across the two sessions.
        let plain = vec![0xa5u8; 32];
        let ct = a.encrypt(&plain).unwrap();
        let pt = b.decrypt(&ct).unwrap();
        assert_eq!(pt, plain);
        // Authentication tag should match too.
        let payload = b"hello CTAP world";
        let tag_a = a.authenticate(payload).unwrap();
        let tag_b = b.authenticate(payload).unwrap();
        assert_eq!(tag_a, tag_b);
        assert_eq!(tag_a.len(), 32); // v2 full 32-byte HMAC.
    }

    #[test]
    fn v1_truncates_hmac_to_16_bytes() {
        let mut a = Session::initiate(Protocol::V1);
        let mut b = Session::initiate(Protocol::V1);
        let b_pub = b.public_key_cbor();
        let a_pub = a.public_key_cbor();
        a.complete(&b_pub).unwrap();
        b.complete(&a_pub).unwrap();
        let tag = a.authenticate(b"hello").unwrap();
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn decode_cose_p256_rejects_wrong_header_params() {
        // Start from a well-formed keyAgreement COSE_Key the device
        // would send, then mutate one header parameter at a time and
        // confirm each violation is rejected (CTAP 2.1 sec. 6.5.5.7.1
        // fixes kty=2, alg=-25, crv=1).
        let good = Session::initiate(Protocol::V2).public_key_cbor();
        assert!(decode_cose_p256(&good).is_ok());

        let mutate = |label: Value, value: Value| -> Value {
            let mut map = match good.clone() {
                Value::Map(m) => m,
                _ => unreachable!(),
            };
            for entry in map.iter_mut() {
                if entry.0 == label {
                    entry.1 = value.clone();
                }
            }
            Value::Map(map)
        };

        // Wrong kty (OKP=1 instead of EC2=2).
        assert!(decode_cose_p256(&mutate(Value::Uint(1), Value::Uint(1))).is_err());
        // Wrong alg (ES256=-7 instead of ECDH-ES+HKDF-256=-25).
        assert!(decode_cose_p256(&mutate(Value::Uint(3), Value::Nint(-7))).is_err());
        // Wrong crv (P-384=2 instead of P-256=1).
        assert!(decode_cose_p256(&mutate(Value::Nint(-1), Value::Uint(2))).is_err());
    }
}
