// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAP2 command dispatch.
//!
//! Day 2 covers `authenticatorGetInfo`, `authenticatorMakeCredential`,
//! and `authenticatorGetAssertion`, all with ECDSA-P256 (COSE alg -7).
//! Credentials are stored in RAM only (lost across resets); Day 3
//! adds QSPI flash persistence and the hybrid ML-DSA path.

extern crate alloc;

use alloc::vec::Vec as AllocVec;
// Low-memory ML-DSA -- unmodified upstream. We pull in the trait so its
// associated methods (`keygen_from_seed`, `sign_mu_deterministic_out`,
// `compute_mu_from_sk`) are callable on the `MLDSA` type alias (which
// resolves to `MLDSA44`/`MLDSA65`/`MLDSA87` at compile time).
// We only need the lowmem-crate types here for hybrid PK derivation
// during MakeCredential. All hybrid signing happens on core 1, so the
// signing-side types (`MuBuilder`, `MLDSAPrivateKeyTrait`,
// `MLDSA_SIG_LEN`, `PrehashSigner`) live in `core1_signer.rs`.
//
// `MLDSA` is the cfg-aliased type from `mldsa_alg`: ML-DSA-44 / -65 /
// -87 depending on which cargo feature is active.
use bouncycastle_core_interface::key_material::{KeyMaterial, KeyType};
// `encode()` on the ML-DSA public key comes from the generic
// `SignaturePublicKey` trait now, not from an ML-DSA-specific one.
use crate::bc_crypto::{HmacCtx, Sha256Ctx};
use crate::mldsa_alg::{
    COSE_ALG_HYBRID_MLDSA, COSE_ALG_MLDSA44_ES256, COSE_ALG_MLDSA65_ES256, COSE_ALG_MLDSA87_ES384,
    MLDSA,
};
use bouncycastle_core_interface::traits::SignaturePublicKey;
use bouncycastle_mldsa_lowmemory::MLDSATrait;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use pqf_cbor::{cbor_array, cbor_bool, cbor_int, cbor_map, cbor_text, Value};

use crate::client_pin::{self, PinPersistent, PinSession};
use crate::credential_id::{
    decrypt_credential_id, encrypt_to_credential_id, CredentialSource, CRED_ID_LEN,
};
use crate::flash_store::{
    self, StoredCredential, StoredImage, MAX_SLOTS, MAX_USER_DISPLAY_NAME_LEN, MAX_USER_ID_LEN,
    MAX_USER_NAME_LEN, OVERFLOW_SLOTS, RESIDENT_EXTRA_SECTORS, STATE_ACTIVE, STATE_EMPTY,
    TOTAL_SLOTS,
};
use rand_core::CryptoRngCore;

/// CTAP2 command codes (CTAP 2.1 sec. 6).
pub const CTAP2_MAKE_CREDENTIAL: u8 = 0x01;
pub const CTAP2_GET_ASSERTION: u8 = 0x02;
pub const CTAP2_GET_INFO: u8 = 0x04;
pub const CTAP2_CLIENT_PIN: u8 = 0x06;
pub const CTAP2_GET_NEXT_ASSERTION: u8 = 0x08;
pub const CTAP2_RESET_CMD: u8 = 0x07;
pub const CTAP2_CREDENTIAL_MANAGEMENT: u8 = 0x0A;
pub const CTAP2_SELECTION: u8 = 0x0B;
pub const CTAP2_LARGE_BLOBS: u8 = 0x0C;
pub const CTAP2_CONFIG: u8 = 0x0D;

/// Status codes.
pub const CTAP2_OK: u8 = 0x00;
pub const CTAP2_ERR_INVALID_COMMAND: u8 = 0x01;
pub const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
pub const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;
pub const CTAP2_ERR_NOT_IMPLEMENTED: u8 = 0x10;
pub const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
/// A credential in MakeCredential's excludeList is already bound to this
/// authenticator for the requested RP (WebAuthn excludeCredentials).
pub const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
/// (M15) All discoverable-credential slots are in use and the request
/// asked to create another resident credential (CTAP 2.1 sec. 6.1).
pub const CTAP2_ERR_KEY_STORE_FULL: u8 = 0x28;
/// (L1) The request supplied a valid `options` key the authenticator
/// cannot satisfy in the requested configuration (CTAP 2.1 sec. 6.1/sec. 6.2).
pub const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2B;
/// A parameter present with the wrong CBOR major type (CTAP 2.1 sec. 8.2).
pub const CTAP2_ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
/// (L1) The request supplied an `options` value that is invalid for the
/// command (e.g. `up=false` on MakeCredential) (CTAP 2.1 sec. 6.1/sec. 6.2).
pub const CTAP2_ERR_INVALID_OPTION: u8 = 0x2C;
/// CTAP 2.1 sec. 6.1 -- returned when a command requires user presence
/// and the device couldn't confirm a button press within the per-
/// command timeout (10 s for MakeCred / GetAssert per OpenSK).
/// CTAP2_ERR_OPERATION_DENIED. What a failed test of user presence
/// answers, in this port, the C port and the TrustZone one: CTAP 2.1
/// sec. 6.1.2 step 14 / sec. 6.2.2 step 15 name this code for "the user did not
/// consent", and a gesture that never came is that. The spec also
/// defines CTAP2_ERR_OPERATION_DENIED (0x2F); no port here uses it,
/// and this constant used to carry that name while holding this value.
pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
/// The outstanding transaction was cancelled by a CTAPHID_CANCEL on the
/// active channel (CTAP 2.1 sec. 11.2.9.1.4 / L15).
pub const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;

/// Operations the embedding firmware exposes to the CTAP2 dispatcher.
///
/// Until Phase 7 we just had a `tick()` closure that pumped CTAP HID
/// `KEEPALIVE` frames during slow crypto. Phase 7 also needs the
/// dispatcher to *gate* MakeCred / GetAssert on a fresh button press
/// (CTAP 2.1's "user presence" -- currently always claimed). Rather
/// than pass two mutually-aliasing `&mut dyn FnMut()` closures (which
/// Rust won't let coexist because they'd both borrow the same USB +
/// LED + button state on the embedding side), we route both
/// operations through a single closure that takes a `HostOp` variant.
///
/// The embedding side is `main.rs::host_op` -- it owns the references
/// to `fido` / `usb_dev` / `timer` / `touch_button` / LEDs, and runs
/// the right code path per variant.
#[derive(Clone, Copy, Debug)]
pub enum HostOp {
    /// Push the standard KEEPALIVE-processing burst over CTAP HID +
    /// poll USB. Used between slow crypto phases to keep Chrome's
    /// watchdog (~100 ms cadence) happy. Returns `true` to continue and
    /// `false` if a CTAPHID_CANCEL for the active channel was observed
    /// while pumping -- the caller must then abort the operation and
    /// reply [`CTAP2_ERR_KEEPALIVE_CANCEL`] (L15).
    Pump,
    /// Block until the user presses the on-board button (GP23) **or**
    /// `timeout_us` microseconds elapse, whichever comes first. While
    /// waiting, the embedding side keeps pumping KEEPALIVE frames and
    /// flashes the green LED so the user knows we're waiting for them.
    /// Returns `true` on a fresh press, `false` on timeout (caller
    /// should respond with [`CTAP2_ERR_OPERATION_DENIED`]).
    WaitForUp { timeout_us: u64 },
}

/// 16-byte AAGUID identifying the model of authenticator. Default is
/// this project's own id, ef80634d-5f41-4a62-b14f-5a6944096a0b: a
/// random version-4 UUID allocated for the Rust port of Bruce (the
/// C port and the TrustZone Secure image each carry their own, so a
/// relying party can tell the three apart).
///
/// Vendors shipping their own firmware should override at build time
/// with the `BRUCE_AAGUID` env var, set to a 32-hex-character
/// string with no separators:
///   BRUCE_AAGUID=ef80634d5f414a62b14f5a6944096a0b cargo build ...
///
/// Before the public release the default was the OpenSK sample id
/// (664d9f67-84a2-412a-9ff7-b4f7d8ee6d05), which a relying party that
/// only trusts the OpenSK PQC reference list recognises. That id is one
/// override away:
///   BRUCE_AAGUID=664d9f6784a2412a9ff7b4f7d8ee6d05 cargo build ...
///
/// Parsing happens at compile time via `option_env!` + a const-fn
/// hex decoder so we don't pay a runtime cost. A malformed override
/// (wrong length / non-hex) is a compile error.
pub const AAGUID: [u8; 16] = parse_aaguid_env();

const fn parse_aaguid_env() -> [u8; 16] {
    const FALLBACK: [u8; 16] = [
        0xef, 0x80, 0x63, 0x4d, 0x5f, 0x41, 0x4a, 0x62, 0xb1, 0x4f, 0x5a, 0x69, 0x44, 0x09, 0x6a,
        0x0b,
    ];
    match option_env!("BRUCE_AAGUID") {
        Some(s) => decode_hex16(s),
        None => FALLBACK,
    }
}

const fn decode_hex16(s: &str) -> [u8; 16] {
    let bytes = s.as_bytes();
    assert!(
        bytes.len() == 32,
        "BRUCE_AAGUID must be exactly 32 hex characters",
    );
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = (hex_nibble(bytes[i * 2]) << 4) | hex_nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("BRUCE_AAGUID contains a non-hex character"),
    }
}

/// COSE_Algorithm identifiers.
const COSE_ALG_ES256: i64 = -7;
/// Ed25519 / EdDSA (RFC 8152 sec. 8.2). Only used when the `ed25519`
/// cargo feature is enabled -- Phase 11c. The constant is defined
/// unconditionally so the picker / advertiser code can reference it
/// without `#[cfg]` gating; the feature gate controls whether it
/// actually appears in `getInfo.algorithms` and whether the MakeCred
/// path will accept it.
const COSE_ALG_ED25519: i64 = -8;
// OpenSK PQC fork: hybrid ECDSA-P256 + ML-DSA. COSE_ALG_HYBRID_MLDSA
// is `crate::mldsa_alg::COSE_ALG_HYBRID_MLDSA`, imported above: this
// build's composite id, one of COSE_ALG_MLDSA44_ES256 /
// COSE_ALG_MLDSA65_ES256 / COSE_ALG_MLDSA87_ES384 by feature. Those
// three are defined once, in pqf_signer_core::mldsa_alg.

// The 32-byte LABEL constant for the OpenSK hybrid scheme (domain
// separation for ECDSA + ML-DSA, source `OpenSK/libraries/crypto/src
// /hybrid.rs::LABEL`) lives in `core1_signer.rs` since that's the
// only place we actually sign with it. If you ever need it here for
// pubkey derivation, pull it in as
// `crate::core1_signer::HYBRID_LABEL`.

/// Authenticator data flag bits (WebAuthn sec. 6.1).
const AUTHDATA_FLAG_UP: u8 = 0x01;
const AUTHDATA_FLAG_UV: u8 = 0x04; // user verified (PIN/UV)
const AUTHDATA_FLAG_AT: u8 = 0x40; // attested credential data included
const AUTHDATA_FLAG_ED: u8 = 0x80; // extension data included (CTAP 2.1 sec. 6.1)

/// On-wire credential ID size -- the 161-byte encrypted blob (see
/// [`crate::credential_id::CRED_ID_LEN`]). Replaces the 32-byte random
/// handle from v4.
pub const CREDENTIAL_ID_LEN: usize = CRED_ID_LEN;
/// Use the same slot count as the on-flash store so we don't have to
/// reconcile two different capacities: the main sector's [`MAX_SLOTS`]
/// plus every overflow sector's (`PQF_RESIDENT_EXTRA_SECTORS`, none by
/// default, so 6).
const MAX_CREDENTIALS: usize = TOTAL_SLOTS;

/// `MAX_CREDENTIALS` empty slots on the heap, built there directly
/// rather than on the stack and moved.
fn empty_slots() -> alloc::boxed::Box<[StoredCredential]> {
    alloc::vec![StoredCredential::empty(); MAX_CREDENTIALS].into_boxed_slice()
}

/// Domain label for the overflow sectors' key tag. See
/// [`overflow_key_tag`].
const DOMAIN_RK_OVERFLOW: &[u8] = b"pqf-rk-overflow";

/// The tag every overflow sector carries: the first four bytes of
/// `HMAC(key_handle_hmac_key, "pqf-rk-overflow")`, little-endian.
///
/// Binds an overflow sector to the master keys it was written under.
/// authenticatorReset rotates the keys and erases the overflow sectors,
/// but a build with fewer overflow sectors cannot erase the ones it
/// does not know about; when a larger build is flashed again later,
/// those sectors' tags no longer match and they read as empty instead
/// of resurrecting passkeys that can no longer decrypt. Computed only
/// when there are overflow sectors, so the default build's boot does
/// no extra work.
fn overflow_key_tag(hmac_key: &[u8; 32]) -> u32 {
    if RESIDENT_EXTRA_SECTORS == 0 {
        return 0;
    }
    let mut mac = HmacCtx::new(hmac_key);
    mac.update(DOMAIN_RK_OVERFLOW);
    let t = mac.finalize();
    u32::from_le_bytes([t[0], t[1], t[2], t[3]])
}

pub type CtapResponse = AllocVec<u8>;

/// In-flight `authenticatorGetNextAssertion` iterator. Populated by
/// `emit_get_assertion` when more than one credential matches a
/// no-allowList request, and only once that GetAssertion's own assertion
/// has been signed; popped one credential at a time by
/// `emit_get_next_assertion`. 30-second timeout matches OpenSK's
/// `STATEFUL_COMMAND_TIMEOUT_DURATION` and the CM iterators.
#[derive(Clone, Debug)]
pub struct AssertionIterState {
    /// Slot indices remaining to be returned, in spec-defined
    /// "most recent first" order (descending `creation_order`).
    pub remaining_slot_idxs: AllocVec<usize>,
    /// Original `clientDataHash` from the GetAssertion -- we use the
    /// same one for each subsequent GetNextAssertion sign.
    pub client_data_hash: [u8; 32],
    /// Original RP id hash.
    pub rp_id_hash: [u8; 32],
    /// `uv_present` snapshot from the originating GetAssertion (the
    /// follow-up GetNextAssertion(s) don't re-auth): true only when its
    /// pinUvAuthParam verified.
    pub uv_present: bool,
    /// Whether the originating GetAssertion's presence test ran and
    /// passed -- never merely whether one was asked for. A
    /// silent (`up: false`) GetAssertion clears the UP flag in its own
    /// authData per CTAP 2.1 sec. 6.2; the GetNextAssertions that continue
    /// it sign the same ceremony and must say the same thing. This port
    /// hard-coded UP on every GetNextAssertion, so after a silent
    /// GetAssertion the second credential's assertion claimed a presence
    /// test that never happened. The C port has carried `up_flag` in its
    /// iterator all along.
    pub up_present: bool,
    /// Total number of credentials matched at GetAssertion time --
    /// used to set the `numberOfCredentials` response field on the
    /// first reply (CTAP 2.1 sec. 6.2.3 response key 0x05).
    pub total: u32,
    /// Deadline after which the iterator is dropped.
    pub deadline_us: u64,
    pub _cid: [u8; 4],
}

/// In-RAM view of a stored credential used during dispatch. v5 onwards
/// this carries only "metadata" -- the actual keys live encrypted in
/// `credential_id`. Recover them with
/// `crate::credential_id::decrypt_credential_id` at sign time.
#[derive(Clone)]
struct Credential {
    credential_id: [u8; CREDENTIAL_ID_LEN],
    rp_id_hash: [u8; 32],
    counter: u32,
    /// WebAuthn user.id (from MakeCredential 0x03.id). Bytes
    /// [0..user_id_len] are the actual handle; the rest is zero
    /// padding. Returned in GetAssertion's 0x04 user field.
    user_id_len: u8,
    user_id: [u8; MAX_USER_ID_LEN],
    /// `credProtect` policy (1/2/3) requested at MakeCred time;
    /// 0 = unset / default. See CTAP 2.1 sec. 12.1.1.
    cred_protect: u8,
    /// `credBlob` payload: bytes [0..cred_blob_len] are valid. 0 means
    /// no blob was set.
    cred_blob_len: u8,
    cred_blob: [u8; flash_store::MAX_CRED_BLOB_LEN],
    /// WebAuthn user.name (UTF-8). `user_name_len` is the number of
    /// valid bytes; the rest is zero. Mutable via
    /// `authenticatorCredentialManagement::updateUserInformation`.
    user_name_len: u8,
    user_name: [u8; MAX_USER_NAME_LEN],
    /// WebAuthn user.displayName (UTF-8). Same shape as `user_name`.
    user_display_name_len: u8,
    user_display_name: [u8; MAX_USER_DISPLAY_NAME_LEN],
    /// Per-credential monotonic timestamp, max(existing)+1 at insert,
    /// kept so CM enumeration has a stable order to give clients. Part
    /// of the persisted slot layout; the firmware writes it and never
    /// reads it back, which is why the lint is silenced here.
    #[allow(dead_code)]
    creation_order: u32,
    /// (F4) WebAuthn rp.id text (UTF-8). `rp_id_len` is the number of
    /// valid bytes; the rest is zero. Stored so `enumerateRPs` can
    /// return the real RP id string.
    rp_id_len: u8,
    rp_id: [u8; flash_store::MAX_RP_ID_LEN],
    /// (L11) Whether this credential was minted with the `largeBlobKey`
    /// extension. GetAssertion only returns the per-credential
    /// `0x07 largeBlobKey` when this is set (CTAP 2.1 sec. 12.3).
    large_blob_key: bool,
}

/// Credential database, RAM-resident with flash persistence.
///
/// Layout: a fixed-size array of `MAX_CREDENTIALS` slots, each
/// reflecting one flash slot: indices `0..MAX_SLOTS` are the main
/// sector's, then `OVERFLOW_SLOTS` per overflow sector in order. On
/// boot we populate the RAM image from flash; on every modification we
/// rewrite the one sector holding the changed slot (PIN / config
/// changes rewrite the main sector). Phase 2
/// adds two device-wide master keys (`key_handle_aes_key`,
/// `key_handle_hmac_key`) that wrap every credentialId -- see
/// `credential_id.rs`. They live in the flash header alongside the
/// PIN state and have the same factory-reset lifecycle.
pub struct CredStore {
    /// `MAX_CREDENTIALS` slots, on the heap: 580 B each, so held inline
    /// they would sit on core 0's stack inside `main`'s frame, and a
    /// by-value `CredStore` is moved more than once on its way there --
    /// with overflow sectors configured that multiplied the stack cost
    /// several times over. Allocated once at boot and never freed, so
    /// it costs exactly its size in heap and cannot fragment it.
    slots: alloc::boxed::Box<[StoredCredential]>,
    /// Overflow-sector key tag under the current master keys (see
    /// [`overflow_key_tag`]); 0 when there are no overflow sectors.
    overflow_tag: u32,
    pub pin: PinPersistent,
    /// AES-256 master key for credentialId wrapping. Set once on first
    /// boot (see [`CredStore::load`]) and never rotated until reset.
    pub key_handle_aes_key: [u8; 32],
    /// HMAC-SHA-256 master key for credentialId outer authentication.
    pub key_handle_hmac_key: [u8; 32],
    /// AuthenticatorConfig persistent state (Phase 9).
    pub always_uv: bool,
    pub enterprise_attestation: bool,
    /// 0 = "use the default of 4 bytes"; nonzero = enforced override.
    pub min_pin_length: u8,
    pub min_pin_length_rpid_count: u8,
    pub min_pin_length_rpid_hashes: [[u8; 32]; flash_store::MAX_MIN_PIN_LEN_RPIDS],
    /// (X13) `forcePINChange`: when true the device wants the host to
    /// run an old-PIN-authenticated `changePIN` before further use.
    /// Persisted in the sector header; surfaced in `getInfo` as the
    /// `0x0C forcePINChange` member. Set by AuthenticatorConfig
    /// `setMinPINLength`'s `forceChangePin` (CTAP 2.1 sec. 6.11.4); the PIN
    /// stays active so this does NOT remove PIN protection.
    pub force_pin_change: bool,
    /// Diagnostic: the `pubKeyCredParams` alg list from the most-
    /// recent `authenticatorMakeCredential` request, captured before
    /// the picker chooses one. Lets the LCD-equipped boards show
    /// what the browser is actually forwarding to the device -- useful
    /// for confirming whether Firefox / Chrome / libfido2 is stripping
    /// the PQC algorithms.
    ///
    /// RAM-only (not persisted across boots). Cap at 8 entries -- more
    /// than enough for real-world `pubKeyCredParams` lists (which
    /// typically have 1-4 entries).
    pub last_make_cred_algs: [i64; 8],
    pub last_make_cred_alg_count: u8,
}

impl CredStore {
    /// Load the on-flash image into RAM.
    ///
    /// H1: the master keys are read from their OWN sector, independent
    /// of the main PIN/config/credential sector:
    ///   - Key sector absent/invalid  -> fresh device: generate both
    ///     master keys from TRNG and write the key sector once.
    ///   - Main sector absent/invalid -> start empty (PIN unset, no
    ///     credentials), but the master keys are STILL intact from
    ///     their own sector, so non-resident credentials survive a
    ///     torn main-sector write. If a PIN had been set under those
    ///     keys (the key sector's PIN-armed word), start PIN-blocked
    ///     instead of PIN-less: the surviving keys must not be usable
    ///     behind a PIN anyone could now set.
    /// A schema bump or factory reset of only the main sector therefore
    /// resets PIN/config/resident-credentials but never the keys; only
    /// a key-sector-invalid (truly fresh / post-reset) device
    /// regenerates them.
    pub fn load(trng: &mut impl CryptoRngCore) -> Self {
        // Master keys first -- their lifecycle is independent of the
        // routinely-rewritten main sector.
        let (key_handle_aes_key, key_handle_hmac_key) = match flash_store::read_key_sector() {
            Some((aes, hmac)) => (aes, hmac),
            None => {
                // Fresh device (or just-reset): mint both keys and
                // persist them once to their dedicated sector. From
                // here on, routine writes never touch this sector.
                let mut aes = [0u8; 32];
                let mut hmac = [0u8; 32];
                trng.fill_bytes(&mut aes);
                trng.fill_bytes(&mut hmac);
                flash_store::write_key_sector(&aes, &hmac);
                (aes, hmac)
            }
        };

        let overflow_tag = overflow_key_tag(&key_handle_hmac_key);
        let mut store = Self::load_main(key_handle_aes_key, key_handle_hmac_key, overflow_tag);
        // Overflow sectors are independent of the main sector: a torn
        // or version-bumped main sector does not discard them, and an
        // absent / foreign one reads as empty (not written until a
        // credential lands in it) -- which is also what enlarging the
        // capacity over an existing default-layout store looks like.
        for k in 0..RESIDENT_EXTRA_SECTORS {
            if let Some(creds) = flash_store::read_overflow_sector(k, overflow_tag) {
                let base = MAX_SLOTS + k * OVERFLOW_SLOTS;
                store.slots[base..base + OVERFLOW_SLOTS].copy_from_slice(&creds);
            }
        }
        // The PIN-armed word in the key sector (`flash_store::arm_pin`)
        // says a PIN was set under these master keys. A main sector
        // with no PIN while it is set lost the PIN to a torn or corrupt
        // write; come up PIN-blocked rather than PIN-less, so neither a
        // new PIN nor user verification is available until
        // authenticatorReset rotates the keys. A PIN with no armed word
        // was set by a build without the word, or its arming was cut
        // short: arm it now.
        if store.pin.pin_set != 0 {
            flash_store::arm_pin();
        } else if flash_store::pin_armed() {
            store.pin = PinPersistent {
                pin_hash: [0; client_pin::PIN_HASH_LEN],
                pin_set: 1,
                retries_left: 0,
            };
        }
        store
    }

    /// The main-sector half of [`CredStore::load`]: PIN, config and the
    /// first `MAX_SLOTS` slots; the rest start empty.
    fn load_main(
        key_handle_aes_key: [u8; 32],
        key_handle_hmac_key: [u8; 32],
        overflow_tag: u32,
    ) -> Self {
        match flash_store::read_sector() {
            Some(img) => Self {
                slots: {
                    let mut slots = empty_slots();
                    slots[..MAX_SLOTS].copy_from_slice(&img.creds);
                    slots
                },
                overflow_tag,
                pin: PinPersistent {
                    pin_hash: img.pin_hash,
                    pin_set: img.pin_set,
                    // A persisted 0 is the BLOCKED state and MUST survive a
                    // reboot: the retry counter is the only brute-force
                    // defence (no time lockout), so resetting it to the max
                    // would let an attacker power-cycle past the limit. Only
                    // an out-of-range (corrupt) value falls back to the max;
                    // an erased / never-set sector takes the `None` cold-boot
                    // path below, where retries start at PIN_MAX_RETRIES.
                    retries_left: if img.retries_left > 8 {
                        client_pin::PIN_MAX_RETRIES
                    } else {
                        img.retries_left
                    },
                },
                key_handle_aes_key,
                key_handle_hmac_key,
                always_uv: img.always_uv != 0,
                enterprise_attestation: img.enterprise_attestation != 0,
                min_pin_length: img.min_pin_length,
                min_pin_length_rpid_count: img.min_pin_length_rpid_count,
                min_pin_length_rpid_hashes: img.min_pin_length_rpid_hashes,
                force_pin_change: img.force_pin_change != 0,
                last_make_cred_algs: [0i64; 8],
                last_make_cred_alg_count: 0,
            },
            None => {
                // Main sector empty/invalid (cold boot, schema bump, or
                // torn routine write). Start with empty PIN/config/creds
                // -- but the master keys above are intact, so non-resident
                // credentials minted by this device still decrypt.
                Self {
                    slots: empty_slots(),
                    overflow_tag,
                    pin: PinPersistent::empty(),
                    key_handle_aes_key,
                    key_handle_hmac_key,
                    always_uv: false,
                    enterprise_attestation: false,
                    min_pin_length: 0,
                    min_pin_length_rpid_count: 0,
                    min_pin_length_rpid_hashes: [[0u8; 32]; flash_store::MAX_MIN_PIN_LEN_RPIDS],
                    force_pin_change: false,
                    last_make_cred_algs: [0i64; 8],
                    last_make_cred_alg_count: 0,
                }
                // NOTE: we intentionally do NOT eagerly persist an empty
                // main sector here. The keys are already safe in their
                // own sector, and a routine write will materialise the
                // main sector on the first real mutation.
            }
        }
    }

    /// Persist the main sector (PIN + config + credential index).
    ///
    /// H1: this is a ROUTINE write -- it never touches the master-key
    /// sector. The keys are written only by [`CredStore::load`]
    /// first-boot provisioning and by [`CredStore::wipe_all`] (Reset),
    /// so a power loss during any `persist()` cannot lose them.
    pub fn persist(&self) {
        let mut creds = [StoredCredential::empty(); MAX_SLOTS];
        creds.copy_from_slice(&self.slots[..MAX_SLOTS]);
        flash_store::write_sector(&StoredImage {
            pin_hash: self.pin.pin_hash,
            pin_set: self.pin.pin_set,
            retries_left: self.pin.retries_left,
            always_uv: if self.always_uv { 1 } else { 0 },
            enterprise_attestation: if self.enterprise_attestation { 1 } else { 0 },
            min_pin_length: self.min_pin_length,
            min_pin_length_rpid_count: self.min_pin_length_rpid_count,
            min_pin_length_rpid_hashes: self.min_pin_length_rpid_hashes,
            force_pin_change: if self.force_pin_change { 1 } else { 0 },
            creds,
        });
    }

    /// Persist the one sector holding slot `idx`: the main sector (via
    /// [`CredStore::persist`]) for `idx < MAX_SLOTS`, else that slot's
    /// overflow sector alone. Credential mutations go through here so a
    /// counter bump in an overflow slot never rewrites the main sector
    /// (the PIN state) or any other overflow sector.
    fn persist_slot(&self, idx: usize) {
        if idx < MAX_SLOTS {
            self.persist();
        } else {
            self.persist_overflow((idx - MAX_SLOTS) / OVERFLOW_SLOTS);
        }
    }

    /// Write overflow sector `k` from its slots in RAM.
    fn persist_overflow(&self, k: usize) {
        let base = MAX_SLOTS + k * OVERFLOW_SLOTS;
        flash_store::write_overflow_sector(
            k,
            self.overflow_tag,
            &self.slots[base..base + OVERFLOW_SLOTS],
        );
    }

    /// Replace the PIN state and persist. A set PIN also arms the
    /// key sector's PIN-armed word (once; see `flash_store::arm_pin`),
    /// after the main sector holds the PIN, so a power loss in between
    /// leaves a PIN that the next boot arms.
    pub fn persist_pin(&mut self, pin: &PinPersistent) {
        self.pin = *pin;
        self.persist();
        if pin.pin_set != 0 {
            flash_store::arm_pin();
        }
    }

    /// Insert a discoverable (resident) credential. Returns
    /// `Err(())` when every slot is occupied and the credential
    /// doesn't overwrite an existing one -- the caller maps that to
    /// `CTAP2_ERR_KEY_STORE_FULL` (M15). Non-resident (rk=false)
    /// MakeCredentials don't call this at all, so they never consume a
    /// slot.
    fn insert(&mut self, c: Credential) -> Result<(), ()> {
        // Re-registration overwrites the matching slot: dedupe by
        // (rp_id_hash, user.id) per CTAP 2.1 sec. 6.1 step 8, so registering
        // the same account twice updates in place rather than filling a
        // second slot (and never reports KEY_STORE_FULL for an update).
        let dup_idx = self.slots.iter().position(|s| {
            s.state == STATE_ACTIVE
                && s.rp_id_hash == c.rp_id_hash
                && s.user_id_len == c.user_id_len
                && s.user_id[..s.user_id_len as usize] == c.user_id[..c.user_id_len as usize]
        });
        // Otherwise take the first empty/tombstoned slot. When none is
        // free we DON'T FIFO-evict a still-valid credential (that would
        // silently destroy another account's passkey); instead the
        // caller surfaces KEY_STORE_FULL.
        let slot_idx =
            match dup_idx.or_else(|| self.slots.iter().position(|s| s.state != STATE_ACTIVE)) {
                Some(idx) => idx,
                None => return Err(()),
            };
        // CM enumeration needs a stable order -- use max(existing)+1
        // as this credential's creation_order. Cheap to compute since
        // MAX_CREDENTIALS is small (<= 62). Resets to 1 on factory wipe.
        let creation_order = self
            .slots
            .iter()
            .filter(|s| s.state == STATE_ACTIVE)
            .map(|s| s.creation_order)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        self.slots[slot_idx] = StoredCredential {
            state: STATE_ACTIVE,
            credential_id: c.credential_id,
            _pad1: [0; 3],
            rp_id_hash: c.rp_id_hash,
            counter: c.counter,
            user_id_len: c.user_id_len,
            _pad2: [0; 3],
            user_id: c.user_id,
            cred_protect: c.cred_protect,
            cred_blob_len: c.cred_blob_len,
            _pad3: [0; 2],
            cred_blob: c.cred_blob,
            user_name_len: c.user_name_len,
            _pad4: [0; 3],
            user_name: c.user_name,
            user_display_name_len: c.user_display_name_len,
            _pad5: [0; 3],
            user_display_name: c.user_display_name,
            creation_order,
            rp_id_len: c.rp_id_len,
            large_blob_key: if c.large_blob_key { 1 } else { 0 },
            _pad6: [0; 2],
            rp_id: c.rp_id,
        };
        self.persist_slot(slot_idx);
        Ok(())
    }

    fn find_by_id_idx(&self, id: &[u8]) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.state == STATE_ACTIVE && s.credential_id[..] == *id)
    }

    fn read(&self, idx: usize) -> Credential {
        let s = &self.slots[idx];
        Credential {
            credential_id: s.credential_id,
            rp_id_hash: s.rp_id_hash,
            counter: s.counter,
            user_id_len: s.user_id_len,
            user_id: s.user_id,
            cred_protect: s.cred_protect,
            cred_blob_len: s.cred_blob_len,
            cred_blob: s.cred_blob,
            user_name_len: s.user_name_len,
            user_name: s.user_name,
            user_display_name_len: s.user_display_name_len,
            user_display_name: s.user_display_name,
            creation_order: s.creation_order,
            rp_id_len: s.rp_id_len,
            rp_id: s.rp_id,
            large_blob_key: s.large_blob_key != 0,
        }
    }

    /// Bump the signature counter for slot `idx` and persist.
    fn bump_counter(&mut self, idx: usize, new_counter: u32) {
        self.slots[idx].counter = new_counter;
        self.persist_slot(idx);
    }

    // -----------------------------------------------------------------
    // CredentialManagement (Phase 8 / CTAP 2.1 sec. 6.8) accessors.
    // -----------------------------------------------------------------

    /// Total number of active resident credentials.
    pub fn active_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state == STATE_ACTIVE)
            .count()
    }

    /// Iterate active slots in `creation_order` ascending, yielding
    /// `(slot_idx, &StoredCredential)`. Stable ordering is what
    /// `enumerateRPs` and `enumerateCredentials` rely on.
    pub fn iter_active_by_creation(&self) -> impl Iterator<Item = (usize, &StoredCredential)> {
        // Collect indices then sort -- MAX_CREDENTIALS is tiny so the small
        // allocation is fine. We can't easily build a sorted iterator
        // without alloc here; the caller is already in an alloc
        // context (CTAP2 dispatch on core 0).
        let mut entries: AllocVec<(usize, &StoredCredential)> = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.state == STATE_ACTIVE)
            .collect();
        entries.sort_by_key(|(_, s)| s.creation_order);
        entries.into_iter()
    }

    /// Tombstone the slot at `idx` and persist. Used by
    /// `authenticatorCredentialManagement::deleteCredential` (0x06).
    pub fn delete_slot(&mut self, idx: usize) {
        if idx < self.slots.len() {
            self.slots[idx].state = STATE_EMPTY;
            self.persist_slot(idx);
        }
    }

    /// Replace the user.name / user.displayName fields of an existing
    /// slot. Used by `updateUserInformation` (0x07). `name` and
    /// `display_name` are passed as `Option<&[u8]>` so the caller
    /// can leave individual fields untouched.
    pub fn update_user_info(
        &mut self,
        idx: usize,
        new_name: Option<&[u8]>,
        new_display_name: Option<&[u8]>,
    ) {
        if idx >= self.slots.len() {
            return;
        }
        let s = &mut self.slots[idx];
        if let Some(n) = new_name {
            let len = n.len().min(flash_store::MAX_USER_NAME_LEN);
            s.user_name = [0; flash_store::MAX_USER_NAME_LEN];
            s.user_name[..len].copy_from_slice(&n[..len]);
            s.user_name_len = len as u8;
        }
        if let Some(d) = new_display_name {
            let len = d.len().min(flash_store::MAX_USER_DISPLAY_NAME_LEN);
            s.user_display_name = [0; flash_store::MAX_USER_DISPLAY_NAME_LEN];
            s.user_display_name[..len].copy_from_slice(&d[..len]);
            s.user_display_name_len = len as u8;
        }
        self.persist_slot(idx);
    }

    /// Borrow the read-only flash slot at `idx` (CM enumeration uses
    /// this to format the response without copying into a new
    /// `Credential` value).
    pub fn slot(&self, idx: usize) -> &StoredCredential {
        &self.slots[idx]
    }

    /// Maximum number of resident credentials the device can hold.
    pub fn max_slots(&self) -> usize {
        self.slots.len()
    }

    /// Erase every credential slot in flash. Used by CTAP2 Reset.
    pub fn wipe_all(&mut self, trng: &mut impl CryptoRngCore) {
        for s in self.slots.iter_mut() {
            *s = StoredCredential::empty();
        }
        // Rotate the credentialId master keys on factory reset so any
        // credentialId the host might still have cached becomes
        // un-decryptable (defence-in-depth -- re-registration is
        // already required for the user since slots are wiped).
        trng.fill_bytes(&mut self.key_handle_aes_key);
        trng.fill_bytes(&mut self.key_handle_hmac_key);
        // H1: Reset is one of only two writers of the dedicated
        // master-key sector (the other is first-boot provisioning).
        // Persist the freshly-rotated keys there so the old keys are
        // gone for good.
        flash_store::write_key_sector(&self.key_handle_aes_key, &self.key_handle_hmac_key);
        // Every overflow sector goes too. The new keys are already on
        // flash, so a power loss part-way through leaves any sector not
        // yet erased tagged under the old keys -- read as empty either
        // way.
        self.overflow_tag = overflow_key_tag(&self.key_handle_hmac_key);
        for k in 0..RESIDENT_EXTRA_SECTORS {
            flash_store::erase_overflow_sector(k);
        }
        // Phase 9: also clear AuthenticatorConfig state so the device
        // boots back to factory defaults (no alwaysUv, no minPin
        // override, no RP allowlist).
        self.always_uv = false;
        self.enterprise_attestation = false;
        self.min_pin_length = 0;
        self.min_pin_length_rpid_count = 0;
        self.min_pin_length_rpid_hashes = [[0u8; 32]; flash_store::MAX_MIN_PIN_LEN_RPIDS];
        // X13: a factory reset clears any pending forcePINChange.
        self.force_pin_change = false;
        self.persist();
    }
}

/// Parsed `hmac-secret` extension input on GetAssertion (CTAP 2.1
/// sec. 12.5.4). All four fields are required by the spec; we accept
/// pinProtocol omitted as "v1".
struct HmacSecretInput {
    /// Host's ephemeral ECDH public key X coordinate (COSE_Key -2).
    key_agreement_x: [u8; 32],
    /// Host's ephemeral ECDH public key Y coordinate (COSE_Key -3).
    key_agreement_y: [u8; 32],
    /// AES-CBC-encrypted salt(s) -- 32 or 64 bytes after decryption.
    salt_enc: AllocVec<u8>,
    /// HMAC-SHA-256(shared_secret, salt_enc)[..16] supplied by host
    /// -- checked before decrypting to authenticate the request.
    salt_auth: AllocVec<u8>,
    /// PIN protocol number (currently must be 1; Phase 5 adds 2).
    pin_protocol: u64,
}

fn parse_hmac_secret_input(map: &[(Value, Value)]) -> Option<HmacSecretInput> {
    let mut key_agreement_x: Option<[u8; 32]> = None;
    let mut key_agreement_y: Option<[u8; 32]> = None;
    let mut salt_enc: Option<AllocVec<u8>> = None;
    let mut salt_auth: Option<AllocVec<u8>> = None;
    let mut pin_protocol: u64 = 1;
    for (k, v) in map {
        let key = match k {
            Value::Uint(u) => *u as i64,
            Value::Nint(n) => *n,
            _ => continue,
        };
        match (key, v) {
            // 1: keyAgreement (COSE_Key)
            (1, Value::Map(ka)) => {
                for (kk, vv) in ka {
                    let kk = match kk {
                        Value::Uint(u) => *u as i64,
                        Value::Nint(n) => *n,
                        _ => continue,
                    };
                    match (kk, vv) {
                        (-2, Value::Bytes(b)) if b.len() == 32 => {
                            let mut x = [0u8; 32];
                            x.copy_from_slice(b);
                            key_agreement_x = Some(x);
                        }
                        (-3, Value::Bytes(b)) if b.len() == 32 => {
                            let mut y = [0u8; 32];
                            y.copy_from_slice(b);
                            key_agreement_y = Some(y);
                        }
                        _ => {}
                    }
                }
            }
            (2, Value::Bytes(b)) => salt_enc = Some(b.clone()),
            (3, Value::Bytes(b)) => salt_auth = Some(b.clone()),
            (4, Value::Uint(u)) => pin_protocol = *u,
            _ => {}
        }
    }
    Some(HmacSecretInput {
        key_agreement_x: key_agreement_x?,
        key_agreement_y: key_agreement_y?,
        salt_enc: salt_enc?,
        salt_auth: salt_auth?,
        pin_protocol,
    })
}

/// Run the hmac-secret protocol for one GetAssertion request and
/// produce the ciphertext that goes into the extension output map.
/// Returns `None` on any structural / cryptographic failure (caller
/// then emits no hmac-secret output, which browsers tolerate).
///
/// Steps per CTAP 2.1 sec. 12.5.5 (PIN-protocol-aware -- v1 AND v2):
///   1. ECDH(our_session_sk, host_pk) -> shared secret (SHA-256(x) for
///      v1, HKDF AES+HMAC keys for v2 -- `SharedSecret::from_handshake`)
///   2. Verify saltAuth == authenticate(shared, saltEnc)
///      (left-16 for v1, full-32 for v2)
///   3. decrypt saltEnc -> salts (32 or 64 B; v2 strips the leading IV)
///   4. cred_random = derive_cred_random(hmac_key, credential_id, uv)
///   5. output_i = HMAC(cred_random, salt_i)
///   6. encrypt outputs (zero IV for v1, fresh random IV for v2)
fn hmac_secret_compute_output(
    session: &PinSession,
    trng: &mut impl CryptoRngCore,
    hmac_key: &[u8; 32],
    credential_id: &[u8],
    uv_present: bool,
    input: &HmacSecretInput,
) -> Option<AllocVec<u8>> {
    // Protocol-aware shared secret (v1 or v2). Returns None for any
    // unsupported protocol value or invalid peer point.
    let shared = session.shared_secret_for_protocol(
        &input.key_agreement_x,
        &input.key_agreement_y,
        input.pin_protocol,
    )?;
    // saltAuth is computed over saltEnc; verify() applies the
    // protocol's truncation (v1 left-16, v2 full-32) and length check.
    if !shared.verify(&input.salt_enc, &input.salt_auth) {
        return None;
    }
    // Decrypt (v2 strips the 16-byte IV); the recovered salts must be
    // exactly one or two 32-byte salts.
    let salts = shared.decrypt(&input.salt_enc)?;
    if salts.len() != 32 && salts.len() != 64 {
        return None;
    }
    let cred_random = crate::credential_id::derive_cred_random(hmac_key, credential_id, uv_present);

    // Compute HMAC outputs over each 32 B salt.
    let mut outputs = AllocVec::with_capacity(salts.len());
    for salt in salts.chunks_exact(32) {
        let mut mac = HmacCtx::new(&cred_random);
        mac.update(salt);
        outputs.extend_from_slice(&mac.finalize());
    }
    Some(shared.encrypt(trng, &outputs))
}

/// Produce an OpenSK-style hybrid signature over `msg`. Returns
/// `ecdsa_der || mldsa_raw_sig` (no length prefix; the receiver
/// parses the DER length from the DER itself).
///
/// Layered as in `OpenSK/libraries/crypto/src/hybrid.rs::sign_rfc6979`:
///   - ECDSA signs SHA256(LABEL || msg) with RFC 6979 deterministic k
///   - ML-DSA's mu is computed over (LABEL || msg || ecdsa_der) under
///     the tr derived from the ML-DSA public key
///   - ML-DSA's signing randomness rnd = SHA256(LABEL || msg || ecdsa_der)
///
/// **Execution model (Phase 1b)**: this function only orchestrates.
/// The heavy crypto runs on core 1 via `crate::core1_signer`. Core 0
/// (us) ships the inputs over, then spins in a loop calling `tick()`
/// -- which pumps CTAP HID KEEPALIVE frames + USB polls -- until core 1
/// reports DONE. The low-memory ML-DSA-65 crate is ~3x slower than
/// the stock crate, but the user-visible signing time is unchanged
/// because we never go silent on the host's CTAP HID endpoint.
fn opensk_hybrid_sign(
    ecdsa_scalar: &[u8; 32],
    mldsa_seed: &[u8; 32],
    msg: &[u8],
    host: &mut dyn FnMut(HostOp) -> bool,
    // Set true iff the host sent CTAPHID_CANCEL during the sign (L15);
    // the returned signature is empty in that case and the caller must
    // answer CTAP2_ERR_KEEPALIVE_CANCEL.
    cancelled: &mut bool,
) -> AllocVec<u8> {
    let signer = &crate::core1_signer::CORE1_SIGNER;
    // Single-core builds run the sign right here on core 0; the KEEPALIVE
    // cadence comes from the timer interrupt (`keepalive_timer.rs`), and
    // the wait loop below then finds the result already parked.
    #[cfg(feature = "single_core")]
    let submitted = signer.sign_here(ecdsa_scalar, mldsa_seed, msg);
    #[cfg(not(feature = "single_core"))]
    let submitted = signer.submit(ecdsa_scalar, mldsa_seed, msg);
    if submitted.is_err() {
        // submit() only errors when msg exceeds the signer's MAX_MSG_LEN.
        // Return an empty signature (treated as a failed sign by the RP,
        // like the errored() path below) instead of panic-aborting the
        // transport core.
        return AllocVec::new();
    }
    // Spin until core 1 finishes, pumping CTAP HID KEEPALIVE frames
    // every iteration so Chrome's per-channel watchdog doesn't fire.
    //
    // Note (regression fix): we **busy-wait** here instead of using
    // `cortex_m::asm::wfe()`. The WFE-based park only wakes on a
    // cross-core event, which our `core1_signer` worker emits *only
    // when signing completes* (a single `sev()` at the end). USB
    // interrupts are not enabled in this firmware (we drive the
    // device via polling from the main loop), so there's nothing
    // else to wake WFE for. With WFE, core 0 went silent for the
    // full ~1.5-2 s ML-DSA-87 sign time after the first keepalive
    // burst -- which Chrome's macOS CTAP HID transport interprets as
    // a dead device and aborts the transaction with NotAllowedError
    // (looks like "the operation timed out" in the WebAuthn UI).
    //
    // Busy-waiting costs a few hundred mW of core-0 idle time across
    // the sign window. The trade is correct keepalive cadence (every
    // call to `host(HostOp::Pump)` ships up to 3 keepalive frames
    // through the USB IN endpoint), which is what Chrome needs to
    // keep the prompt alive. Power isn't an issue on bus-powered
    // RP2350 USB authenticators. This mirrors the same fix we
    // already use in `main.rs`'s `WaitForUp` loop (replaced its
    // initial `wfe()` with `nop()` for the same reason).
    // Bounded backstop: core 1 normally reports DONE/ERROR within the
    // ML-DSA-87 worst case (~2 s). If it ever wedges (a panic that halts
    // only core 1, or an allocator failure on the shared heap), don't
    // spin forever and hang the transport core. SPIN_CAP is orders of
    // magnitude above a legitimate sign's iteration count, so it can only
    // trip on a true hang; on expiry we return an empty signature,
    // handled exactly like the errored() path below.
    let mut spins: u64 = 0;
    const SPIN_CAP: u64 = 4_000_000_000;
    while !signer.is_done() {
        // `Pump` ships the KEEPALIVE burst AND reports whether the host
        // sent a CTAPHID_CANCEL on this channel (L15). On cancel we stop
        // pumping (the host has abandoned the request), but core 1 can't
        // be interrupted mid-sign, so we fall through to a bounded drain
        // that lets it finish and discards the result -- keeping the
        // signer's IDLE invariant for the next op.
        if !host(HostOp::Pump) {
            *cancelled = true;
            break;
        }
        crate::arch::nop();
        spins += 1;
        if spins >= SPIN_CAP {
            return AllocVec::new();
        }
    }
    if *cancelled {
        let mut dspins: u64 = 0;
        while !signer.is_done() {
            crate::arch::nop();
            dspins += 1;
            if dspins >= SPIN_CAP {
                // Core 1 wedged: leave the signer as-is (next submit()
                // will observe the non-IDLE state) and bail.
                return AllocVec::new();
            }
        }
        let mut discard = AllocVec::new();
        signer.take_result(&mut discard); // drains, returns signer to IDLE
        return AllocVec::new();
    }
    let mut out = AllocVec::new();
    let errored = signer.errored();
    signer.take_result(&mut out); // always returns the signer to IDLE
    if errored {
        // The crypto path on core 1 returned Err -- could be a malformed
        // ECDSA scalar, an ML-DSA keygen failure, etc. We have no good
        // way to surface that up the response chain from here (the
        // caller is committed to an OK packed-attestation response by
        // the time this runs), so return an empty signature. The RP
        // will reject the credential as unverifiable, which is the
        // correct user-facing outcome.
        out.clear();
    }
    out
}

/// Re-derive the ES256 COSE_Key for a stored credential's public key,
/// for the CredentialManagement enumerateCredentials `publicKey` field
/// (0x08, CTAP 2.1 sec. 6.8.3). Hybrid credentials emit only the ES256
/// (classical) half -- re-deriving the ML-DSA public key from its seed
/// would be expensive. An Ed25519 credential (alg -8) stores a seed,
/// not a P-256 scalar, so it is omitted rather than misrepresented.
pub fn es256_cose_public_key(alg: i64, ecdsa_scalar: &[u8; 32]) -> Option<Value> {
    if alg == -8 {
        return None;
    }
    let sk = SigningKey::from_bytes(ecdsa_scalar.into()).ok()?;
    let pt = sk.verifying_key().to_encoded_point(false);
    let xy = pt.as_bytes();
    if xy.len() < 65 {
        return None;
    }
    Some(cbor_map! {
        cbor_int!(1) => cbor_int!(2),
        cbor_int!(3) => cbor_int!(COSE_ALG_ES256),
        cbor_int!(-1) => cbor_int!(1),
        cbor_int!(-2) => Value::Bytes(xy[1..33].to_vec()),
        cbor_int!(-3) => Value::Bytes(xy[33..65].to_vec()),
    })
}

/// Entry: raw CBOR-command bytes, returns status + CBOR response.
pub fn handle_cbor(
    input: &[u8],
    trng: &mut impl CryptoRngCore,
    session: &mut PinSession,
    store: &mut CredStore,
    host: &mut dyn FnMut(HostOp) -> bool,
    now_us: u64,
    cid: [u8; 4],
) -> CtapResponse {
    let mut out = CtapResponse::new();
    if input.is_empty() {
        let _ = out.push(CTAP2_ERR_INVALID_COMMAND);
        return out;
    }
    let cmd = input[0];
    let params = &input[1..];

    // The GetNextAssertion iterator is valid only as the immediate
    // successor of the GetAssertion that armed it (CTAP 2.1 sec. 6.3). It
    // used to survive anything that was not a GetAssertion -- a
    // credentialManagement delete between the two, say, after which the
    // iterator's slot indices pointed at a store that had changed under
    // it. The C port has reset its iterator on every other command since
    // it was written; this does the same.
    if cmd != CTAP2_GET_NEXT_ASSERTION {
        session.assertion_iter = None;
    }

    match cmd {
        CTAP2_GET_INFO => emit_get_info_with_pin(
            &mut out,
            store.pin.pin_set != 0,
            store.always_uv,
            if store.min_pin_length == 0 {
                client_pin::PIN_MIN_LENGTH_BYTES as u8
            } else {
                store.min_pin_length
            },
            store.force_pin_change,
            // 0x14 remainingDiscoverableCredentials: free resident slots
            // = total slots minus active resident credentials.
            store.max_slots().saturating_sub(store.active_count()) as i64,
        ),
        CTAP2_MAKE_CREDENTIAL => emit_make_credential(params, trng, session, store, host, &mut out),
        CTAP2_GET_ASSERTION => {
            emit_get_assertion(params, trng, session, store, host, now_us, cid, &mut out)
        }
        CTAP2_GET_NEXT_ASSERTION => {
            emit_get_next_assertion(session, store, host, now_us, cid, &mut out)
        }
        CTAP2_RESET_CMD => emit_reset(trng, session, store, host, &mut out),
        CTAP2_CLIENT_PIN => emit_client_pin(params, trng, session, store, &mut out),
        CTAP2_CREDENTIAL_MANAGEMENT => {
            crate::credential_management::handle(params, session, store, now_us, cid, &mut out)
        }
        CTAP2_LARGE_BLOBS => crate::large_blobs::handle(params, session, store, &mut out),
        CTAP2_CONFIG => crate::authenticator_config::handle(params, session, store, &mut out),
        CTAP2_SELECTION => {
            // CTAP 2.1 sec. 6.9 -- `authenticatorSelection` IS the
            // touch-to-choose gesture: when more than one authenticator
            // could satisfy a ceremony, the platform sends this to every
            // connected one and the device the user *touches* is the one
            // selected. It MUST wait for a real user-presence touch and
            // return CTAP2_OK only then, or CTAP2_ERR_OPERATION_DENIED
            // on timeout -- exactly like the MakeCredential / GetAssertion
            // UP gates.
            //
            // A previous revision ACK'd immediately (rationalised as "we
            // gate UP elsewhere"). That was wrong and user-visible: an
            // instant OK makes us *always win* the selection race the
            // moment we're plugged in, so the browser never offers the
            // user another authenticator and never prompts for a press --
            // the device "hijacks" every registration. (A YubiKey waits
            // for its touch here, which is why it doesn't.) The auto-ACK
            // dated from when no board had a readable button; now that
            // user presence is real (BOOTSEL / GP0) the gesture must be
            // collected.
            if host(HostOp::WaitForUp {
                timeout_us: 10_000_000,
            }) {
                let _ = out.push(CTAP2_OK);
            } else {
                let _ = out.push(CTAP2_ERR_OPERATION_DENIED);
            }
        }
        _ => {
            let _ = out.push(CTAP2_ERR_NOT_IMPLEMENTED);
        }
    }
    out
}

/// `authenticatorReset` (CTAP 2.1 sec. 6.6). Spec wants this gated on
/// power-on + user-presence within 10 s; we relax the time gate
/// (no real-time clock in this build) but still require a fresh
/// CMD_CBOR call. Wipes every credential slot in flash and returns
/// CTAP2_OK.
fn emit_reset(
    trng: &mut impl CryptoRngCore,
    session: &mut PinSession,
    store: &mut CredStore,
    host: &mut dyn FnMut(HostOp) -> bool,
    out: &mut CtapResponse,
) {
    // CTAP 2.1 sec. 6.6: reset requires a test of user presence. It destroys
    // every credential and the PIN, and takes no PIN and no token, so the
    // touch is the only thing between a plugged-in authenticator and an
    // empty one. This wiped on request from any software. Collected
    // BEFORE anything is erased, so a timeout leaves the device as it was.
    if !host(HostOp::WaitForUp {
        timeout_us: 10_000_000,
    }) {
        let _ = out.push(CTAP2_ERR_OPERATION_DENIED);
        return;
    }
    store.wipe_all(trng);
    store.persist_pin(&PinPersistent::empty());
    // CTAP 2.1 sec. 6.6: reset destroys all device data -- including the
    // large-blob array, which lives in its own sector untouched by
    // wipe_all. Erase it back to the spec-initial value.
    crate::flash_store::reset_large_blob_sector();
    // ...and abandon any half-assembled write. The sector erase above
    // does not touch the staging buffer, so a fragmented write begun
    // before the reset would complete afterwards and be committed --
    // authenticated by a token the reset just destroyed.
    crate::large_blobs::abandon_write();
    // Also invalidate all PIN/UV session state (token + permissions,
    // key-agreement key, and every stateful iterator) so a reset can't
    // leave a live token or a stale GetNextAssertion / CM iterator
    // behind (CTAP 2.1 sec. 6.6).
    session.reset(trng);
    let _ = out.push(CTAP2_OK);
}

/// `authenticatorGetNextAssertion` (CTAP 2.1 sec. 6.3). Pops the next
/// pre-staged credential from `session.assertion_iter` and signs
/// against the same `clientDataHash` + `rp_id_hash` the
/// originating GetAssertion captured. Returns `ERR_NOT_ALLOWED`
/// (0x30) if no iterator is active or it's timed out.
fn emit_get_next_assertion(
    session: &mut PinSession,
    store: &mut CredStore,
    host: &mut dyn FnMut(HostOp) -> bool,
    now_us: u64,
    cid: [u8; 4],
    out: &mut CtapResponse,
) {
    // Snapshot the state. #12: PEEK the next index here -- do NOT pop it
    // and do NOT drop a drained iterator yet. The cancellable hybrid sign
    // below can return KEEPALIVE_CANCEL, and a state mutation before that
    // point would lose the cancelled credential (and, if it was the last,
    // drop the whole picker) from a subsequent GetNextAssertion. The
    // index is consumed only after the `sign_cancelled` guard passes,
    // mirroring the commit-after-cancel ordering of GetAssertion/MakeCred.
    let (next_idx, client_data_hash, rp_id_hash, uv_present, up_present) = {
        // #8: the iterator is bound to the HID channel that began the
        // ceremony (its `_cid`, captured at GetAssertion time). A
        // GetNextAssertion from any other channel is refused and the
        // iterator dropped -- a second host process can't drive or read
        // another channel's in-flight assertion picker. Mirrors the
        // credentialManagement enumeration cid-binding.
        let iter = match session.assertion_iter.as_mut() {
            Some(i) if now_us < i.deadline_us && i._cid == cid => i,
            _ => {
                session.assertion_iter = None;
                let _ = out.push(0x30); // ERR_NOT_ALLOWED
                return;
            }
        };
        if iter.remaining_slot_idxs.is_empty() {
            session.assertion_iter = None;
            let _ = out.push(0x30);
            return;
        }
        let idx = iter.remaining_slot_idxs[0];
        iter.deadline_us = now_us.saturating_add(30_000_000);
        (
            idx,
            iter.client_data_hash,
            iter.rp_id_hash,
            iter.uv_present,
            iter.up_present,
        )
    };

    // Re-derive the credential we're about to sign with.
    let credential_id_bytes = store.slots[next_idx].credential_id.to_vec();
    let source = match decrypt_credential_id(
        &store.key_handle_aes_key,
        &store.key_handle_hmac_key,
        &credential_id_bytes,
        &rp_id_hash,
    ) {
        Ok(s) => s,
        Err(_) => {
            let _ = out.push(CTAP2_ERR_NO_CREDENTIALS);
            return;
        }
    };
    let mut cred = store.read(next_idx);
    cred.counter = cred.counter.wrapping_add(1);
    let counter = cred.counter;
    let user_id_len = cred.user_id_len;
    let user_id = cred.user_id;
    let user_name_len = cred.user_name_len;
    let user_name = cred.user_name;
    let user_display_name_len = cred.user_display_name_len;
    let user_display_name = cred.user_display_name;

    // authData (same shape MakeCred/GetAssert build). UP is whatever
    // the originating GetAssertion asserted -- see `up_present`.
    let mut auth_data = AllocVec::with_capacity(37);
    auth_data.extend_from_slice(&rp_id_hash);
    let mut flags = if up_present { AUTHDATA_FLAG_UP } else { 0 };
    if uv_present {
        flags |= AUTHDATA_FLAG_UV;
    }
    auth_data.push(flags);
    auth_data.extend_from_slice(&counter.to_be_bytes());

    let mut to_sign = AllocVec::with_capacity(auth_data.len() + 32);
    to_sign.extend_from_slice(&auth_data);
    to_sign.extend_from_slice(&client_data_hash);

    let mut sign_cancelled = false;
    let final_sig: AllocVec<u8> = if source.alg == COSE_ALG_HYBRID_MLDSA {
        opensk_hybrid_sign(
            &source.ecdsa_scalar,
            &source.mldsa_seed,
            &to_sign,
            host,
            &mut sign_cancelled,
        )
    } else if source.alg == COSE_ALG_ED25519 {
        #[cfg(feature = "ed25519")]
        {
            // v2 credentialID: the `ecdsa_scalar` slot actually holds
            // the Ed25519 seed.
            crate::ed25519_alg::sign_with_seed(&source.ecdsa_scalar, &to_sign).to_vec()
        }
        #[cfg(not(feature = "ed25519"))]
        {
            // Can't happen -- decrypt_credential_id rejects v2 blobs
            // when the feature is off, so source.alg can never be -8
            // here. Belt-and-braces for the type checker.
            let _ = out.push(CTAP2_ERR_NO_CREDENTIALS);
            return;
        }
    } else {
        let signing_key = match SigningKey::from_bytes((&source.ecdsa_scalar).into()) {
            Ok(k) => k,
            Err(_) => {
                let _ = out.push(CTAP2_ERR_NO_CREDENTIALS);
                return;
            }
        };
        let ecdsa_sig: Signature = signing_key.sign(&to_sign);
        ecdsa_sig.to_der().as_bytes().to_vec()
    };
    // L15: the host dismissed the prompt (CTAPHID_CANCEL) during the
    // hybrid sign -- abandon the ceremony with KEEPALIVE_CANCEL rather
    // than committing a credential it no longer wants. #12: because we
    // only PEEKED the index above, the iterator is still intact here, so
    // a later GetNextAssertion can re-fetch this same credential.
    if sign_cancelled {
        let _ = out.push(CTAP2_ERR_KEEPALIVE_CANCEL);
        return;
    }
    // #12: the sign completed (not cancelled), so now consume the index
    // from the iterator and drop it if drained. Re-validate the iterator
    // and channel binding -- the cancellable sign pumps the host callback,
    // which could in principle have mutated session state.
    match session.assertion_iter.as_mut() {
        Some(i) if i._cid == cid && i.remaining_slot_idxs.first() == Some(&next_idx) => {
            i.remaining_slot_idxs.remove(0);
            if i.remaining_slot_idxs.is_empty() {
                // Drained -- drop the iterator so the next GetNext returns
                // ERR_NOT_ALLOWED instead of recycling.
                session.assertion_iter = None;
            }
        }
        _ => {
            // Iterator vanished or changed under us during the sign; the
            // signature we computed is still valid for `next_idx`, so emit
            // it, but don't recycle a stale iterator.
            session.assertion_iter = None;
        }
    }
    store.bump_counter(next_idx, counter);

    let mut resp: AllocVec<(Value, Value)> = AllocVec::new();
    resp.push((
        cbor_int!(0x01),
        cbor_map! {
            cbor_text!("type") => cbor_text!("public-key"),
            cbor_text!("id") => Value::Bytes(credential_id_bytes),
        },
    ));
    resp.push((cbor_int!(0x02), Value::Bytes(auth_data)));
    resp.push((cbor_int!(0x03), Value::Bytes(final_sig)));
    if user_id_len > 0 {
        // GetNextAssertion is only invoked after a multi-credential
        // GetAssertion stashed extras in `assertion_iter`, so PII
        // release (name + displayName) is always warranted here --
        // the host's UI is necessarily picking between candidates.
        // See CTAP 2.1 sec. 6.3 step 4 + sec. 6.2.2 step 12.
        let uid = user_id[..user_id_len as usize].to_vec();
        let mut user_map: AllocVec<(Value, Value)> = AllocVec::new();
        user_map.push((cbor_text!("id"), Value::Bytes(uid)));
        if user_name_len > 0 {
            if let Ok(s) = core::str::from_utf8(&user_name[..user_name_len as usize]) {
                user_map.push((cbor_text!("name"), cbor_text!(s)));
            }
        }
        if user_display_name_len > 0 {
            if let Ok(s) =
                core::str::from_utf8(&user_display_name[..user_display_name_len as usize])
            {
                user_map.push((cbor_text!("displayName"), cbor_text!(s)));
            }
        }
        resp.push((cbor_int!(0x04), Value::Map(user_map)));
    }
    let mut buf = AllocVec::with_capacity(256);
    pqf_cbor::encode(&Value::Map(resp), &mut buf);
    let _ = out.push(CTAP2_OK);
    let _ = out.extend_from_slice(&buf);
}

/// `authenticatorClientPin` (CTAP 2.1 sec. 6.5). Delegates to the
/// `client_pin` module which mirrors OpenSK's PIN Protocol v1.
fn emit_client_pin(
    params: &[u8],
    trng: &mut impl CryptoRngCore,
    session: &mut PinSession,
    store: &mut CredStore,
    out: &mut CtapResponse,
) {
    // Effective minimum PIN length: the AuthenticatorConfig
    // setMinPINLength override, else the built-in floor. Read BEFORE
    // the persist closure borrows `store` mutably. setPIN / changePIN
    // enforce this so a host-raised minimum actually rejects short
    // PINs (CTAP 2.1 sec. 6.5.5.7 / sec. 6.11.4).
    let min_pin_length = if store.min_pin_length == 0 {
        client_pin::PIN_MIN_LENGTH_BYTES
    } else {
        store.min_pin_length as usize
    };
    // We need an &mut to a PinPersistent that's also shared with the
    // store. Clone, run the protocol against the clone, persist on
    // mutation via a callback that goes through the store.
    let mut pin = store.pin;
    // Snapshot before `persist_cb` borrows `store` mutably (#13).
    let force_pin_change = store.force_pin_change;
    let mut persist_cb = |new: &PinPersistent| {
        // We can't capture `store` mutably AND `pin` at the same time
        // through the callback, so the cb just commits via the SHARED
        // store passed in.
        store.persist_pin(new);
    };
    let mut pin_changed = false;
    let resp = client_pin::handle_client_pin(
        params,
        trng,
        session,
        &mut pin,
        min_pin_length,
        &mut persist_cb,
        &mut pin_changed,
        force_pin_change,
    );
    // Make sure any in-place updates that didn't go through the cb
    // are committed.
    if store.pin.pin_set != pin.pin_set
        || store.pin.retries_left != pin.retries_left
        || store.pin.pin_hash != pin.pin_hash
    {
        store.persist_pin(&pin);
    }
    // X13: a successful changePIN satisfies a forced-change demand, so
    // drop the persistent flag (getInfo `0x0C forcePINChange` clears).
    if pin_changed && store.force_pin_change {
        store.force_pin_change = false;
        store.persist();
    }
    out.extend_from_slice(&resp);
}

fn emit_get_info_with_pin(
    out: &mut CtapResponse,
    pin_set: bool,
    always_uv: bool,
    min_pin_length: u8,
    force_pin_change: bool,
    remaining_discoverable: i64,
) {
    // `clientPin`: present + true = a PIN is set; present + false =
    // PIN supported but unset; absent = no PIN support. We support
    // PIN, so always present and reflect set-state.
    let info = cbor_map! {
        // Advertise BOTH FIDO_2_0 and FIDO_2_1. We implement the 2.1
        // feature surface a platform relies on -- pinUvAuthToken with
        // per-command permissions (ClientPIN 0x09), full
        // credentialManagement, authenticatorConfig, largeBlobs,
        // setMinPINLength, makeCredUvNotRqd, and the authenticatorSelection
        // (0x0B) touch-to-choose command -- so the 2.1 claim is honest.
        // (Optional 2.1 features we omit -- bioEnrollment, enterprise
        // attestation -- are not required to advertise the version; the
        // YubiKey Security Key, same feature scope, advertises 2.1 too.)
        //
        // This is load-bearing for passkeys: Chrome/macOS route
        // discoverable-credential (resident-key) ceremonies through the
        // modern FIDO 2.1 path for 2.1 authenticators, but through a
        // legacy security-key path for 2.0-only devices. The legacy path
        // is the forceful "engage this key / set a PIN now" flow that
        // reads as the token "hijacking" the ceremony instead of letting
        // the platform offer the normal chooser -- the exact YubiKey-vs-us
        // divergence a getInfo diff surfaced. Was FIDO_2_0-only on the
        // stated worry that 2.1 is "a contract for features we don't
        // implement"; that predates the 0x0B + makeCredUvNotRqd work and
        // is no longer true.
        0x01 => cbor_array![cbor_text!("FIDO_2_0"), cbor_text!("FIDO_2_1")],
        // 0x02 extensions: advertised list, sorted lexicographically
        // as CTAP 2.1 sec. 6.4 requires for canonical CBOR. Phase 4 ships
        // `credBlob`, `credProtect`, `hmac-secret`; Phase 9 adds
        // `minPinLength`. `largeBlobKey` is the per-credential key
        // extension (WebAuthn L3 sec. 10.1.4 / CTAP 2.1 sec. 12.3); it is
        // implemented end-to-end (see emit_make_credential /
        // emit_get_assertion) and advertised here so L3 clients that
        // key discovery off the extension list -- rather than the
        // `largeBlobs` option in 0x04 -- request it.
        0x02 => cbor_array![
            cbor_text!("credBlob"),
            cbor_text!("credProtect"),
            cbor_text!("hmac-secret"),
            cbor_text!("largeBlobKey"),
            cbor_text!("minPinLength"),
        ],
        0x03 => Value::Bytes(AAGUID.to_vec()),
        0x04 => cbor_map! {
            cbor_text!("plat") => cbor_bool!(false),       // roaming
            cbor_text!("rk")   => cbor_bool!(true),
            cbor_text!("up")   => cbor_bool!(true),
            // `makeCredUvNotRqd` (CTAP 2.1 sec. 6.4): a non-discoverable
            // credential may be created without user verification even
            // when a PIN is configured (UV via touch-only). Advertising
            // this -- and honouring it in emit_make_credential -- is what
            // lets a platform register a second-factor credential on a
            // touch alone once a PIN is set, exactly like a YubiKey,
            // instead of us forcing the PIN/UV flow on every ceremony.
            cbor_text!("makeCredUvNotRqd") => cbor_bool!(true),
            cbor_text!("clientPin") => cbor_bool!(pin_set),
            // Phase 9 AuthenticatorConfig options.
            cbor_text!("alwaysUv") => cbor_bool!(always_uv),
            cbor_text!("credMgmt") => cbor_bool!(true),
            cbor_text!("authnrCfg") => cbor_bool!(true),
            // `pinUvAuthToken` (CTAP 2.1 sec. 6.4) -- we implement
            // getPinUvAuthTokenUsingPinWithPermissions (ClientPIN 0x09)
            // with per-command permission scoping, so advertise it; a
            // spec-strict platform keys off this to use the
            // permissions-based token flow rather than the legacy
            // getPinToken (0x05).
            cbor_text!("pinUvAuthToken") => cbor_bool!(true),
            // `setMinPINLength` (CTAP 2.1 sec. 6.4) -- discovery signal for
            // AuthenticatorConfig setMinPINLength (0x03), which we
            // implement (newMinPINLength + minPinLengthRPIDs).
            cbor_text!("setMinPINLength") => cbor_bool!(true),
            // Phase 10 LargeBlobs option.
            cbor_text!("largeBlobs") => cbor_bool!(true),
        },
        // 0x05 maxMsgSize. Must accommodate the worst-case hybrid
        // MakeCredential response which, for ML-DSA-87 builds, is
        // dominated by the 2592 B PQ pubkey embedded in the COSE_Key
        // and the 4627 B ML-DSA-87 attestation signature (~7600 B
        // total). The CTAP HID transport caps a single command at
        // 57 + 0x80 * 59 = 7609 bytes, so we advertise that as the
        // ceiling. ML-DSA-65 / ML-DSA-44 fit well under this; the
        // RP just sees a generous max.
        0x05 => cbor_int!(7609i64),
        // 0x06 pinUvAuthProtocols -- we support v1 and v2. v1 is what
        // Chrome on macOS uses; v2 is offered by some Linux browsers
        // and required by FIDO Alliance L1 certification.
        0x06 => cbor_array![cbor_int!(1), cbor_int!(2)],
        0x07 => cbor_int!(8),
        0x08 => cbor_int!(CREDENTIAL_ID_LEN as i64),
        0x09 => cbor_array![cbor_text!("usb")],
        // 0x0a algorithms -- advertise ALL three OpenSK-fork PQC
        // hybrid variants (COSE_ALG_MLDSA87_ES384, _MLDSA65_ES256,
        // _MLDSA44_ES256) plus ES256 (-7) as the universal fallback,
        // regardless of which one this firmware is actually compiled
        // against. This build's hybrid alg goes first (so RPs that
        // pass our list back unchanged see it as our preference).
        //
        // Why advertise more than we implement: Chrome's
        // `MakeCredentialRequestHandler::IsCandidateAuthenticatorPostTouch`
        // computes the intersection of the RP's `pubKeyCredParams`
        // with this advertised list. If the intersection is empty,
        // Chrome short-circuits with `kNoCommonAlgorithms` and
        // returns `NotAllowedError` to the page **without ever
        // sending a CTAP frame** -- the user sees "the operation
        // timed out or was not allowed" and no PIN dialog ever
        // appears. Firefox / libfido2 skip this pre-check, which is
        // why Firefox works against PQC-only RPs while Chrome
        // doesn't.
        //
        // What happens at MakeCredential time: the picker further
        // down walks the RP's `pubKeyCredParams` in their preference
        // order and selects the first entry whose `alg` matches
        // *this build's* `COSE_ALG_HYBRID_MLDSA` (our actual hybrid
        // implementation) or `COSE_ALG_ES256`. If the RP only asked
        // for a hybrid variant we don't have (e.g. RP wants the
        // ML-DSA-65 composite but this is an ML-DSA-87 build), the picker falls through to
        // ES256 -- which sane RPs include as fallback. Worst case the
        // RP rejects ES256 and we return ERR_UNSUPPORTED_ALGORITHM;
        // that's a known-failure mode that the user can see in
        // device-log, vs. the silent kNoCommonAlgorithms failure
        // which gives no signal at all.
        0x0a => {
            // Algorithms advertised in getInfo. ML-DSA-87 / -65 / -44
            // hybrid variants are listed unconditionally so Chrome's
            // intersection check passes for any OpenSK-fork RP -- the
            // MakeCredential picker falls back to ES256 if the RP only
            // asked for a hybrid variant this build doesn't actually
            // implement. ES256 is the universal floor. Ed25519 (-8)
            // is appended only when the `ed25519` cargo feature is
            // enabled (Phase 11c, off by default -- costs ~30 KiB of
            // flash from the curve25519-dalek backend).
            let mut algs: AllocVec<Value> = AllocVec::new();
            algs.push(cbor_map! {
                cbor_text!("alg")  => cbor_int!(COSE_ALG_MLDSA87_ES384),
                cbor_text!("type") => cbor_text!("public-key"),
            });
            algs.push(cbor_map! {
                cbor_text!("alg")  => cbor_int!(COSE_ALG_MLDSA65_ES256),
                cbor_text!("type") => cbor_text!("public-key"),
            });
            algs.push(cbor_map! {
                cbor_text!("alg")  => cbor_int!(COSE_ALG_MLDSA44_ES256),
                cbor_text!("type") => cbor_text!("public-key"),
            });
            #[cfg(feature = "ed25519")]
            algs.push(cbor_map! {
                cbor_text!("alg")  => cbor_int!(COSE_ALG_ED25519),
                cbor_text!("type") => cbor_text!("public-key"),
            });
            algs.push(cbor_map! {
                cbor_text!("alg")  => cbor_int!(COSE_ALG_ES256),
                cbor_text!("type") => cbor_text!("public-key"),
            });
            Value::Array(algs)
        },
        // 0x0b maxSerializedLargeBlobArray (Phase 10) -- the
        // largeBlobs array ceiling. CTAP 2.1 sec. 6.4. Mirrors
        // `flash_store::MAX_LARGE_BLOB_LEN`.
        0x0b => cbor_int!(flash_store::MAX_LARGE_BLOB_LEN as i64),
        // 0x0c forcePINChange (X13) -- true if the device wants the host
        // to run authenticatorClientPin.changePIN (old-PIN-authenticated)
        // before any further use. Set by AuthenticatorConfig
        // setMinPINLength's forceChangePin (CTAP 2.1 sec. 6.11.4); the PIN
        // stays active so this signals "must change", not "PIN removed".
        // Cleared by a successful changePIN (see the clientPin dispatch).
        0x0c => cbor_bool!(force_pin_change),
        // 0x0d minPINLength -- the floor we enforce in setPIN. Phase
        // 9 lets AuthenticatorConfig 0x03 override the default 4
        // bytes; we surface the effective value here so the host
        // can warn the user before the PIN gets rejected.
        0x0d => cbor_int!(min_pin_length as i64),
        // 0x0e firmwareVersion -- a vendor-defined monotonic version
        // number for *this* firmware build. Bumped on every release.
        // CTAP 2.1 sec. 6.4; libfido2 surfaces it as `fwversion`.
        0x0e => cbor_int!(1),
        // 0x0f maxCredBlobLength -- the per-credential blob ceiling
        // we honour at MakeCred time (Phase 4). Matches
        // `flash_store::MAX_CRED_BLOB_LEN`.
        0x0f => cbor_int!(flash_store::MAX_CRED_BLOB_LEN as i64),
        // 0x10 maxRPIDsForSetMinPINLength (CTAP 2.1 sec. 6.4) -- how many RP
        // ids setMinPINLength accepts in its minPinLengthRPIDs list, so a
        // host can't over-send and have entries silently dropped.
        0x10 => cbor_int!(flash_store::MAX_MIN_PIN_LEN_RPIDS as i64),
        // 0x14 remainingDiscoverableCredentials (CTAP 2.1 sec. 6.4) -- the
        // estimated number of additional discoverable (resident)
        // credentials that can still be created. Lets passkey-manager
        // UIs show remaining capacity without an authenticated credMgmt
        // getCredsMetadata round-trip. Same quantity that
        // getCredsMetadata reports as `remaining`.
        0x14 => cbor_int!(remaining_discoverable),
    };
    let mut bytes = AllocVec::with_capacity(256);
    pqf_cbor::encode(&info, &mut bytes);
    let _ = out.push(CTAP2_OK);
    let _ = out.extend_from_slice(&bytes);
}

/// Parse a CBOR-encoded value out of a slice. Returns the value.
fn parse_cbor(input: &[u8]) -> Option<Value> {
    pqf_cbor::decode(input).ok()
}

/// Find a value in a CBOR map by integer key. `pqf-cbor` stores
/// `Value::Nint(n)` with `n` already being the signed integer
/// (e.g. -7), not the CBOR-on-the-wire `(-1 - n)` form.
fn map_get<'a>(map: &'a [(Value, Value)], key: i64) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| match k {
            Value::Uint(u) => *u as i64 == key,
            Value::Nint(n) => *n == key,
            _ => false,
        })
        .map(|(_, v)| v)
}

/// Find a value in a CBOR map by text-string key.
fn map_get_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
        .map(|(_, v)| v)
}

/// `authenticatorMakeCredential` (CTAP 2.1 sec. 6.1).
fn emit_make_credential(
    params: &[u8],
    trng: &mut impl CryptoRngCore,
    session: &mut PinSession,
    store: &mut CredStore,
    host: &mut dyn FnMut(HostOp) -> bool,
    out: &mut CtapResponse,
) {
    let value = match parse_cbor(params) {
        Some(v) => v,
        None => {
            let _ = out.push(CTAP2_ERR_INVALID_CBOR);
            return;
        }
    };
    let map = match value {
        Value::Map(m) => m,
        _ => {
            let _ = out.push(CTAP2_ERR_INVALID_CBOR);
            return;
        }
    };

    // 0x01 clientDataHash (bstr, 32 bytes)
    let client_data_hash = match map_get(&map, 0x01) {
        Some(Value::Bytes(b)) if b.len() == 32 => b.clone(),
        _ => {
            let _ = out.push(CTAP2_ERR_MISSING_PARAMETER);
            return;
        }
    };

    // 0x02 rp.id (text). Hoisted up here (out of the natural map-key
    // order) so the PIN/UV-permission check below has the
    // `rp_id_hash` it needs to enforce token RP-scope.
    let rp_id = match map_get(&map, 0x02) {
        Some(Value::Map(rp_map)) => match map_get_str(rp_map, "id") {
            Some(Value::Text(s)) => s.clone(),
            _ => {
                let _ = out.push(CTAP2_ERR_MISSING_PARAMETER);
                return;
            }
        },
        _ => {
            let _ = out.push(CTAP2_ERR_MISSING_PARAMETER);
            return;
        }
    };
    let rp_id_hash: [u8; 32] = {
        let mut h = Sha256Ctx::new();
        h.update(rp_id.as_bytes());
        h.finalize()
    };

    // 0x08 pinUvAuthParam, 0x09 pinUvAuthProtocol
    let pin_uv_auth_param = match map_get(&map, 0x08) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };
    let pin_uv_auth_protocol = match map_get(&map, 0x09) {
        Some(Value::Uint(u)) => Some(*u),
        _ => None,
    };
    // Set true ONLY after a successful PIN/UV verification below -- never
    // from mere field presence (see the alwaysUv comment further down).
    let mut uv_happened = false;
    if store.pin.pin_set != 0 {
        // We advertise `makeCredUvNotRqd: true` (getInfo), so having a
        // PIN set does NOT by itself force user verification: a
        // non-discoverable credential may be created on user-presence
        // (touch) alone, exactly like a YubiKey in a "security-key"
        // (second-factor, userVerification=discouraged) registration.
        // The cases that DO still require UV are enforced by dedicated
        // gates below -- `rk` (discoverable), an explicit `uv=true`
        // option, and `alwaysUv` -- each returning PUAT_REQUIRED when UV
        // didn't happen. So here we only VERIFY a supplied token; we do
        // NOT refuse when one is absent. (Previously an absent
        // pinUvAuthParam returned PUAT_REQUIRED unconditionally once a
        // PIN existed, which forced UV on every registration and made
        // Chrome drive our token differently from a YubiKey -- the
        // "hijacking" symptom.)
        //
        // Error-code discipline when a token IS supplied (CTAP 2.1
        // sec. 6.1): a present-but-invalid pinUvAuthParam -> PIN_AUTH_INVALID
        // (0x33), never PUAT_REQUIRED. Chrome's silent discovery probe
        // sends `pinUvAuthParam: h''` (present, empty) and keys its
        // picker decision off getting 0x33 here; the `if let Some`
        // below still lands that probe in the verification-failure path,
        // so it keeps surfacing us in the WebAuthn UI.
        if let Some(auth_param) = &pin_uv_auth_param {
            let proto = match pin_uv_auth_protocol {
                Some(p) if p == client_pin::PIN_PROTOCOL_V1 || p == client_pin::PIN_PROTOCOL_V2 => {
                    p
                }
                _ => {
                    let _ = out.push(client_pin::ERR_PIN_AUTH_INVALID);
                    return;
                }
            };
            // Token must be active, hold the `mc` permission bit, and
            // have a matching RP-scope (or no scope).
            if client_pin::check_token_permission(
                session,
                client_pin::PERM_MAKE_CREDENTIAL,
                &rp_id_hash,
            )
            .is_err()
            {
                let _ = out.push(client_pin::ERR_PIN_AUTH_INVALID);
                return;
            }
            // The `pinUvAuthParam` HMAC over clientDataHash must verify
            // under the session token.
            if !client_pin::verify_pin_uv_auth_param(
                session.pin_uv_auth_token(),
                &client_data_hash,
                auth_param,
                proto,
            ) {
                let _ = out.push(client_pin::ERR_PIN_AUTH_INVALID);
                return;
            }
            // PIN/UV verification succeeded -- UV genuinely happened.
            uv_happened = true;
        }
    }

    // 0x03 user (PublicKeyCredentialUserEntity). We persist
    // `user.id` (the opaque userHandle), and as of Phase 8 also the
    // optional UTF-8 `user.name` and `user.displayName` so that
    // `authenticatorCredentialManagement::enumerateCredentialsGetNextCredential`
    // (CTAP 2.1 sec. 6.8.4) can return them. CTAP 2.1 sec. 6.5.3.2 lets
    // these "personally identifiable information" fields be
    // released to the host without UV -- they came from the RP at
    // MakeCred time and only the same user can see them back via
    // CM (which requires a PIN-authenticated `cm`-scoped token).
    let mut user_id_buf = [0u8; MAX_USER_ID_LEN];
    let mut user_name_buf = [0u8; MAX_USER_NAME_LEN];
    let mut user_display_name_buf = [0u8; MAX_USER_DISPLAY_NAME_LEN];
    let mut user_name_len: u8 = 0;
    let mut user_display_name_len: u8 = 0;
    let user_id_len: u8 = match map_get(&map, 0x03) {
        Some(Value::Map(u_map)) => {
            // user.id (required)
            let id_len = match map_get_str(u_map, "id") {
                Some(Value::Bytes(b)) if !b.is_empty() && b.len() <= MAX_USER_ID_LEN => {
                    user_id_buf[..b.len()].copy_from_slice(b);
                    b.len() as u8
                }
                _ => 0,
            };
            // user.name (optional)
            if let Some(Value::Text(s)) = map_get_str(u_map, "name") {
                let n = s.as_bytes().len().min(MAX_USER_NAME_LEN);
                user_name_buf[..n].copy_from_slice(&s.as_bytes()[..n]);
                user_name_len = n as u8;
            }
            // user.displayName (optional)
            if let Some(Value::Text(s)) = map_get_str(u_map, "displayName") {
                let n = s.as_bytes().len().min(MAX_USER_DISPLAY_NAME_LEN);
                user_display_name_buf[..n].copy_from_slice(&s.as_bytes()[..n]);
                user_display_name_len = n as u8;
            }
            id_len
        }
        _ => 0,
    };
    if user_id_len == 0 {
        // CTAP 2.1 / WebAuthn require a PublicKeyCredentialUserEntity with
        // a 1..64-byte id. Missing / empty / over-long (the parse above
        // yields 0 for all of these) -> MISSING_PARAMETER, rather than
        // silently minting a credential with no user handle that can't be
        // bound to an account on GetAssertion.
        let _ = out.push(CTAP2_ERR_MISSING_PARAMETER);
        return;
    }

    // 0x07 options (CTAP 2.1 sec. 6.1) -- `rk` / `up` / `uv`. Defaults:
    // rk = false, up = true, uv = false. We parse them here (L1/F3) so:
    //   - `rk = true` requests a discoverable (resident) credential
    //     that consumes a flash slot; `rk` absent/false does NOT
    //     consume a slot (M15).
    //   - `up = false` is invalid for MakeCredential -- there is no
    //     "silent registration" -- so reject with INVALID_OPTION.
    //   - `uv = true` is only satisfiable here when UV actually
    //     happened (a PIN/UV token verified above). On this hardware
    //     UV is only available via a PIN, so an explicit `uv = true`
    //     that didn't authenticate fails rather than silently
    //     downgrading the ceremony (UNSUPPORTED_OPTION when no PIN is
    //     set, otherwise PUAT_REQUIRED via the alwaysUv-style gate
    //     below).
    let mut rk_requested = false;
    let mut uv_option = false;
    if let Some(Value::Map(opts)) = map_get(&map, 0x07) {
        if let Some(Value::Bool(b)) = map_get_str(opts, "rk") {
            rk_requested = *b;
        }
        if let Some(Value::Bool(false)) = map_get_str(opts, "up") {
            let _ = out.push(CTAP2_ERR_INVALID_OPTION);
            return;
        }
        if let Some(Value::Bool(b)) = map_get_str(opts, "uv") {
            uv_option = *b;
        }
    }
    if uv_option && !uv_happened {
        // Explicit uv=true the device can't satisfy. If no PIN is set
        // there is no UV method at all -> UNSUPPORTED_OPTION; if a PIN
        // is set the host must obtain a token first -> PUAT_REQUIRED.
        let code = if store.pin.pin_set == 0 {
            CTAP2_ERR_UNSUPPORTED_OPTION
        } else {
            client_pin::ERR_PUAT_REQUIRED
        };
        let _ = out.push(code);
        return;
    }
    // `makeCredUvNotRqd` exempts only NON-discoverable credentials from
    // the UV requirement. A discoverable (resident / `rk=true`) credential
    // can be asserted with no allowList, so presence-only creation would
    // let anyone holding the device use it silently -- therefore a
    // discoverable credential still requires UV once a PIN is configured.
    // (With no PIN there is no UV method, and resident creds remain
    // up-only as before -- unchanged behaviour.) This matches a YubiKey:
    // second-factor registrations go through on a touch, passkeys demand
    // the PIN.
    if rk_requested && store.pin.pin_set != 0 && !uv_happened {
        let _ = out.push(client_pin::ERR_PUAT_REQUIRED);
        return;
    }

    // 0x06 extensions input (CTAP 2.1 sec. 11). We support:
    //   - "hmac-secret": bool -- RP wants per-credential HMAC secrets
    //     for server-side blob encryption. cred_random is *derived*
    //     deterministically from HMAC(hmac_key, credentialId || domain)
    //     in `derive_cred_random`, so we just remember whether to
    //     advertise support in the extensions output map. Stored as
    //     a transient `hmac_secret_requested` flag -- no flash field.
    //   - "credProtect": uint 1..=3 -- gates credential use without UV.
    //     Stored in the per-credential flash slot.
    //   - "credBlob": bstr <=32 B -- RP-supplied opaque payload to
    //     persist with the credential and echo back at GetAssertion
    //     time. Stored in the flash slot.
    let mut hmac_secret_requested = false;
    let mut cred_protect_policy: u8 = 0;
    let mut cred_blob_len_in: u8 = 0;
    let mut cred_blob_in = [0u8; flash_store::MAX_CRED_BLOB_LEN];
    let mut cred_blob_too_long = false;
    let mut min_pin_length_requested = false;
    let mut large_blob_key_requested = false;
    if let Some(Value::Map(ext_map)) = map_get(&map, 0x06) {
        if let Some(Value::Bool(true)) = map_get_str(ext_map, "hmac-secret") {
            hmac_secret_requested = true;
        }
        match map_get_str(ext_map, "credProtect") {
            Some(Value::Uint(u)) if (1..=3).contains(u) => {
                cred_protect_policy = *u as u8;
            }
            _ => {}
        }
        if let Some(Value::Bytes(b)) = map_get_str(ext_map, "credBlob") {
            if b.len() > flash_store::MAX_CRED_BLOB_LEN {
                cred_blob_too_long = true;
            } else {
                cred_blob_in[..b.len()].copy_from_slice(b);
                cred_blob_len_in = b.len() as u8;
            }
        }
        // minPinLength: bool -- when true, and the RP is in the
        // AuthenticatorConfig allowlist, we echo the device's
        // configured minPinLength in the extensions output (CTAP 2.1
        // sec. 11.3).
        if let Some(Value::Bool(true)) = map_get_str(ext_map, "minPinLength") {
            min_pin_length_requested = true;
        }
        // largeBlobKey: bool -- when true, the device generates a
        // 32-byte per-credential symmetric key (via
        // `derive_large_blob_key`) and returns it in the response's
        // top-level `0x07 largeBlobKey` field for the RP to use as
        // an AEAD key on subsequent `authenticatorLargeBlobs` writes.
        if let Some(Value::Bool(true)) = map_get_str(ext_map, "largeBlobKey") {
            large_blob_key_requested = true;
        }
    }
    // #14/#20: the "minted with largeBlobKey" bit is baked into the
    // credentialId plaintext (byte [97], see `credential_id::CredentialSource`)
    // AND, for resident creds, into the flash slot. So the flag round-trips
    // for BOTH resident and non-resident (allowList) credentials: a
    // non-resident cred presented later via an allowList recovers the bit
    // from its decrypted credentialId, and GetAssertion's 0x07 gate fires
    // correctly. No clamp needed -- registration and assertion stay consistent
    // whether or not `rk` was requested.
    // Determine whether the requesting RP is in the
    // `minPinLengthRPIDs` allowlist (set via AuthenticatorConfig
    // subcmd 0x03). Computed up-front so it's available to the
    // extension-output emitter below.
    let min_pin_length_rp_allowed = min_pin_length_requested
        && store
            .min_pin_length_rpid_hashes
            .iter()
            .take(store.min_pin_length_rpid_count as usize)
            .any(|h| h == &rp_id_hash);
    // Per CTAP 2.1 sec. 12.4 the RP gets a structured signal of "blob
    // accepted" via the extension output. We don't fail the whole
    // MakeCredential just because the blob was too long -- we just
    // refuse to store it and emit `credBlob: false` on the way out.
    let cred_blob_accepted = cred_blob_len_in > 0 && !cred_blob_too_long;

    // 0x04 pubKeyCredParams -- strict two-pass alg picker over the
    // entries the RP / browser forwarded, in the RP's preference
    // order:
    //
    //   1. Pass 1 -- prefer post-quantum. Pick the first entry whose
    //      alg matches this build's `COSE_ALG_HYBRID_MLDSA` (one
    //      composite id, by cargo feature), or `COSE_ALG_ED25519` (-8)
    //      when the `ed25519` feature is enabled.
    //
    //   2. Pass 2 -- fall back to ES256 (`-7`).
    //
    // The picker never overrides the browser's choice -- every
    // emitted credential's alg is one of the entries the request
    // actually carried. This is intentional: any RP that
    // requested ES256 (with or without PQC) will accept the
    // resulting credential, which is the only way to keep the
    // device working across the widest set of RPs (PQC-aware,
    // legacy ES256-only, and everything in between).
    //
    // Firefox interaction: Firefox's WebAuthn stack (via libfido2)
    // strips entries whose COSE alg id it doesn't itself know how
    // to verify before forwarding the request to the device.
    // libfido2 currently doesn't recognise the ML-DSA ids, so an
    // RP that lists `[-56, -55, -54, -7]` arrives at the device
    // looking like `[-7]` under Firefox. Pass 1 finds nothing,
    // Pass 2 picks `-7`, and Firefox users get an ES256 credential.
    // PQC on this device is effectively Chrome-only until libfido2
    // ships ML-DSA support upstream -- outside our control. We
    // briefly tried a Pass 3 that forced `COSE_ALG_HYBRID_MLDSA`
    // even on `[-7]`-only requests, but that broke legacy ES256-
    // only RPs (which look identical on the wire to Firefox-
    // stripped requests), so we reverted.
    //
    // Each entry parses as either `Value::Nint(n)` (the COSE algs
    // we care about -- all negative) or `Value::Uint(u)` (an alg
    // the RP listed that we'll never match, e.g. -257 / RS256 = a
    // Uint after sign-flip; included for robustness).
    let alg_from_param = |v: &Value| -> Option<i64> {
        let Value::Map(m) = v else { return None };
        match map_get_str(m, "alg")? {
            Value::Nint(n) => Some(*n),
            // `as i64` wraps: a Uint above i64::MAX came out negative and
            // could equal -7 or the composite id, minting a credential for
            // an algorithm the relying party never named. The mirror of
            // the C port's `(int)` cast, fixed there yesterday. Anything
            // outside i64 is nobody's algorithm.
            Value::Uint(u) => i64::try_from(*u).ok(),
            _ => None,
        }
    };
    let is_pqc = |alg: i64| -> bool {
        if alg == COSE_ALG_HYBRID_MLDSA {
            return true;
        }
        #[cfg(feature = "ed25519")]
        if alg == COSE_ALG_ED25519 {
            return true;
        }
        false
    };
    // Diagnostic capture -- record the alg list we just received from
    // the browser so the LCD-equipped boards can show what's being
    // forwarded. Useful for proving whether Firefox / libfido2 is
    // stripping the PQC algs before they reach the device. Reset on
    // every MakeCredential, even if no algs are listed.
    store.last_make_cred_alg_count = 0;
    if let Some(Value::Array(arr)) = map_get(&map, 0x04) {
        for v in arr.iter() {
            if let Some(alg) = alg_from_param(v) {
                let slot = store.last_make_cred_alg_count as usize;
                if slot < store.last_make_cred_algs.len() {
                    store.last_make_cred_algs[slot] = alg;
                    store.last_make_cred_alg_count += 1;
                }
            }
        }
    }

    let chosen_alg = match map_get(&map, 0x04) {
        Some(Value::Array(arr)) => {
            // Pass 1: PQC reordering -- pick a hybrid PQC (or Ed25519)
            // entry from the RP's list if one is there, regardless
            // of its position. Lets the device prefer hybrid over
            // ES256 when both are offered.
            arr.iter()
                .filter_map(alg_from_param)
                .find(|alg| is_pqc(*alg))
                // Pass 2: ES256 from the RP's list. Picked when the
                // RP didn't offer hybrid (or the browser stripped
                // it). NO override -- if neither Pass finds anything
                // matching, we return None and the dispatch above
                // emits `CTAP2_ERR_UNSUPPORTED_ALGORITHM`. Firefox
                // sending `[-7]` lands here naturally.
                .or_else(|| {
                    arr.iter()
                        .filter_map(alg_from_param)
                        .find(|alg| *alg == COSE_ALG_ES256)
                })
        }
        _ => None,
    };
    let chosen_alg = match chosen_alg {
        Some(a) => a,
        None => {
            // CTAP 2.1 sec. 6.1: distinguish a missing required parameter
            // (no pubKeyCredParams at all -> 0x14) from a present list
            // with no algorithm we support (-> 0x26).
            let code = if map_get(&map, 0x04).is_none() {
                CTAP2_ERR_MISSING_PARAMETER
            } else {
                CTAP2_ERR_UNSUPPORTED_ALGORITHM
            };
            let _ = out.push(code);
            return;
        }
    };
    let is_hybrid = chosen_alg == COSE_ALG_HYBRID_MLDSA;
    #[cfg(feature = "ed25519")]
    let is_ed25519 = chosen_alg == COSE_ALG_ED25519;
    #[cfg(not(feature = "ed25519"))]
    let is_ed25519 = false;

    // `alwaysUv` enforcement (CTAP 2.1 sec. 6.11.4) -- when the device has
    // been configured for always-require-UV, MakeCred refuses unless UV
    // actually happened. `uv_happened` is set true ONLY inside the
    // verification path above; deriving it from field presence let a
    // PIN-less device be coaxed into asserting UV with a junk param.
    if store.always_uv && !uv_happened {
        let _ = out.push(client_pin::ERR_PUAT_REQUIRED);
        return;
    }

    // excludeList (0x05): if any listed credentialId was minted by THIS
    // device for THIS rp, registering again would duplicate-enroll the
    // authenticator -- WebAuthn's excludeCredentials guarantee. We can
    // decrypt our own credentialIds, so a successful decrypt under the
    // request's rp_id_hash is a match. Per CTAP 2.1 sec. 6.1.2 we still take
    // user presence first (below), then refuse with CREDENTIAL_EXCLUDED.
    let excluded = match map_get(&map, 0x05) {
        Some(Value::Array(arr)) => arr.iter().any(|v| match v {
            Value::Map(m) => match map_get_str(m, "id") {
                Some(Value::Bytes(id)) => {
                    id.len() == CREDENTIAL_ID_LEN
                        && decrypt_credential_id(
                            &store.key_handle_aes_key,
                            &store.key_handle_hmac_key,
                            id,
                            &rp_id_hash,
                        )
                        .is_ok()
                }
                _ => false,
            },
            _ => false,
        }),
        _ => false,
    };

    // User-presence gate (CTAP 2.1 sec. 6.1.2). PIN/UV (if any) was
    // already checked above; now we need a fresh button press on
    // GP23 within 10 s. `HostOp::WaitForUp` blocks while pumping
    // KEEPALIVE frames and flashing the green LED so the user
    // knows we're waiting. Timeout returns `CTAP2_ERR_OPERATION_DENIED`
    // (0x27) per spec.
    if !host(HostOp::WaitForUp {
        timeout_us: 10_000_000,
    }) {
        let _ = out.push(CTAP2_ERR_OPERATION_DENIED);
        return;
    }
    // After UP: a matched excludeList entry refuses the registration.
    if excluded {
        let _ = out.push(CTAP2_ERR_CREDENTIAL_EXCLUDED);
        return;
    }

    // Key generation. Three paths now:
    //   - Ed25519 (feature `ed25519`, alg -8): 32-byte seed, OKP shape.
    //   - ES256 / hybrid: always generate a fresh ECDSA-P256 keypair.
    //     Hybrid additionally derives an ML-DSA seed + pubkey.
    //
    // For Ed25519, `signing_key_bytes` holds the seed (NOT an ECDSA
    // scalar), and `x` / `y` are unused -- we emit an OKP-shaped COSE_Key
    // below that has just `-2: pub_bytes`. The ECDSA SigningKey is still
    // allocated even on the Ed25519 path because it's used by the
    // CredentialSource layout (which puts the 32-byte seed in the
    // `ecdsa_scalar` slot of the v2 plaintext); we never SIGN with it.
    let signing_key = SigningKey::random(trng);
    // `mut` only matters on the Ed25519 path, which overwrites this with
    // the Ed25519 seed; without that feature nothing reassigns it.
    #[cfg_attr(not(feature = "ed25519"), allow(unused_mut))]
    let mut signing_key_bytes: [u8; 32] = signing_key.to_bytes().into();
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let xy = encoded_point.as_bytes();
    let x: [u8; 32] = xy[1..33].try_into().unwrap();
    let y: [u8; 32] = xy[33..65].try_into().unwrap();

    // Ed25519 path: overwrite `signing_key_bytes` with a fresh
    // Ed25519 seed and compute the 32-byte raw public key. The
    // ECDSA-P256 key generated above is dropped (it was only ever
    // used as scaffolding for the layout).
    #[cfg(feature = "ed25519")]
    let ed25519_pub_bytes: [u8; 32] = if is_ed25519 {
        let seed = crate::ed25519_alg::gen_seed(trng);
        signing_key_bytes = seed;
        crate::ed25519_alg::derive_public_bytes(&seed)
    } else {
        [0u8; 32]
    };
    #[cfg(not(feature = "ed25519"))]
    // Only read from the `cfg(feature = "ed25519")` COSE branch below,
    // which does not exist in this build -- hence the underscore rather
    // than a blanket allow.
    let _ed25519_pub_bytes: [u8; 32] = {
        let _ = is_ed25519;
        [0u8; 32]
    };

    // Hybrid path: pick a fresh 32-byte seed; derive the ML-DSA-65
    // public key from it via the low-memory crate's `keygen_from_seed`.
    // (The lowmem crate dropped the convenience `pk_encode_from_seed_bytes`
    // helper that the stock crate exposed; `keygen_from_seed` returns
    // a typed PK whose `pk_encode()` gives us the same byte layout.)
    let mut mldsa_seed = [0u8; 32];
    let mldsa_pk_bytes: AllocVec<u8> = if is_hybrid {
        trng.fill_bytes(&mut mldsa_seed);
        let seed_km = KeyMaterial::<32>::from_bytes_as_type(&mldsa_seed, KeyType::Seed)
            .expect("ML-DSA-65 seed KeyMaterial");
        let (pk, _sk) = MLDSA::keygen_from_seed(&seed_km).expect("ML-DSA keygen_from_seed");
        pk.encode().to_vec()
    } else {
        AllocVec::new()
    };

    // (rp_id_hash was already computed at the top of this function
    // so the PIN/UV-permission check could reference it.)

    // The credentialId is the 161-byte encrypted blob carrying *all*
    // the key material plus the rp_id_hash and
    // (later) extensions. The device-wide master keys living on
    // `store.key_handle_{aes,hmac}_key` were either freshly generated
    // on first boot or rotated by the last authenticatorReset; we
    // never display them to the host.
    let source = CredentialSource {
        alg: chosen_alg,
        ecdsa_scalar: signing_key_bytes,
        mldsa_seed,
        rp_id_hash,
        // Bake the credProtect policy into the credentialId so it's
        // enforceable even on a non-resident / evicted credential.
        cred_protect: cred_protect_policy,
        // #14/#20: carry the largeBlobKey "minted-with" bit in the
        // credentialId so it round-trips for non-resident creds too.
        large_blob_key: large_blob_key_requested,
    };
    let credential_id = encrypt_to_credential_id(
        &store.key_handle_aes_key,
        &store.key_handle_hmac_key,
        trng,
        &source,
    );

    // (F4) Stash the UTF-8 rp.id string on the slot so
    // `enumerateRPs` (CTAP 2.1 sec. 6.8.2) can return the real RP id
    // instead of "". Truncate to MAX_RP_ID_LEN at a UTF-8 char
    // boundary -- the authoritative binding remains `rp_id_hash`, which
    // is computed over the full untruncated string above.
    let mut rp_id_buf = [0u8; flash_store::MAX_RP_ID_LEN];
    let rp_id_bytes = rp_id.as_bytes();
    let mut rp_id_len_stored = rp_id_bytes.len().min(flash_store::MAX_RP_ID_LEN);
    while rp_id_len_stored > 0 && !rp_id.is_char_boundary(rp_id_len_stored) {
        rp_id_len_stored -= 1;
    }
    rp_id_buf[..rp_id_len_stored].copy_from_slice(&rp_id_bytes[..rp_id_len_stored]);

    // NOTE (#2/#6/#9): the resident-credential commit (`store.insert`)
    // is deliberately DEFERRED until after the cancellable hybrid sign
    // below. Persisting here -- before the multi-second ML-DSA sign that
    // watches for CTAPHID_CANCEL -- would leave an active discoverable
    // credential in flash if the host cancels mid-sign (and, on the
    // (rp_id_hash, user.id) dedup-overwrite path, would have already
    // destroyed the user's prior passkey). All the buffers feeding the
    // `Credential` (credential_id, user_id_buf, rp_id_buf, cred_blob_in,
    // ...) are fixed-size `[u8; N]` arrays (Copy), so they remain valid
    // for the insert performed after the `sign_cancelled` guard. This
    // mirrors GetAssertion, which bumps its counter only after the
    // cancel check. KEY_STORE_FULL may now be reported post-sign, which
    // is acceptable: no signature is returned on that error.

    // authData: rpIdHash | flags(UP|AT[|UV]) | counter | AAGUID | credIdLen | credId | COSE_Key
    let mut auth_data = AllocVec::with_capacity(if is_hybrid { 2200 } else { 150 });
    auth_data.extend_from_slice(&rp_id_hash);
    // UV only when the PIN/UV check above actually passed (`uv_happened`),
    // exactly as GetAssertion reports `uv_present`. Leaving it out made a
    // registration made with the PIN look unverified, so a relying party
    // that requires user verification refused every one of them.
    let mut flags = AUTHDATA_FLAG_UP | AUTHDATA_FLAG_AT;
    if uv_happened {
        flags |= AUTHDATA_FLAG_UV;
    }
    auth_data.push(flags);
    // signCount. A discoverable credential gets a flash slot whose
    // counter starts at 1 (the `Credential { counter: 1, .. }` below),
    // and GetAssertion bumps it from there. A non-discoverable one has
    // no slot and so no counter: GetAssertion signs it with 0. The
    // registration has to say the same thing -- a 1 here followed by 0
    // at every login reads, to a relying party, as a counter that went
    // backwards, which is WebAuthn's signal for a cloned key (L3 sec.
    // 7.2, the signature-counter step), and a strict RP refuses the
    // login. 0 from registration on means "this credential keeps no
    // counter", which the same step accepts.
    let reg_counter: u32 = if rk_requested { 1 } else { 0 };
    auth_data.extend_from_slice(&reg_counter.to_be_bytes());
    auth_data.extend_from_slice(&AAGUID);
    auth_data.extend_from_slice(&(CREDENTIAL_ID_LEN as u16).to_be_bytes());
    auth_data.extend_from_slice(&credential_id);

    // COSE_Key (RFC 8152 sec. 8.2).
    //   ES256:   { 1: 2, 3: -7,  -1: 1, -2: X,        -3: Y                    }   kty = 2 (EC2)
    //   Hybrid:  { 1: 2, 3: -56, -1: 1, -2: X,        -3: Y, -4: ML-DSA-87 pk  }   kty = 2 (EC2)
    //   Ed25519: { 1: 1, 3: -8,  -1: 6, -2: pub_bytes                          }   kty = 1 (OKP)
    //
    // The Ed25519 path uses Octet Key Pair (`kty = 1`) per RFC 8152 sec. 13,
    // not EC2 -- Ed25519 is not a Weierstrass curve. Browsers and
    // libfido2 / webauthn-rs all check `kty` against the alg's
    // expected family, so getting this wrong rejects the credential
    // outright.
    let cose_key = if is_hybrid {
        cbor_map! {
            cbor_int!(1) => cbor_int!(2),
            cbor_int!(3) => cbor_int!(COSE_ALG_HYBRID_MLDSA),
            cbor_int!(-1) => cbor_int!(1),
            cbor_int!(-2) => Value::Bytes(x.to_vec()),
            cbor_int!(-3) => Value::Bytes(y.to_vec()),
            cbor_int!(-4) => Value::Bytes(mldsa_pk_bytes.clone()),
        }
    } else if is_ed25519 {
        #[cfg(feature = "ed25519")]
        {
            crate::ed25519_alg::cose_key(&ed25519_pub_bytes)
        }
        #[cfg(not(feature = "ed25519"))]
        {
            unreachable!("is_ed25519 only set when feature enabled");
        }
    } else {
        cbor_map! {
            cbor_int!(1) => cbor_int!(2),
            cbor_int!(3) => cbor_int!(COSE_ALG_ES256),
            cbor_int!(-1) => cbor_int!(1),
            cbor_int!(-2) => Value::Bytes(x.to_vec()),
            cbor_int!(-3) => Value::Bytes(y.to_vec()),
        }
    };
    let mut cose_bytes = AllocVec::with_capacity(if is_hybrid { 2100 } else { 80 });
    pqf_cbor::encode(&cose_key, &mut cose_bytes);
    auth_data.extend_from_slice(&cose_bytes);

    // Extensions output (CTAP 2.1 sec. 11.1). Emit only the ones the RP
    // actually asked for, and set the ED (Extension Data Included)
    // flag bit (0x80) if anything's included. The CBOR map ordering
    // here is matched to OpenSK's `MakeCredentialExtensions::From` impl
    // so RPs that hash-compare authData byte-for-byte across devices
    // still see consistent bytes.
    let mut ext_entries: AllocVec<(Value, Value)> = AllocVec::new();
    // credBlob output (canonical key order puts it before hmac-secret):
    // emit it ONLY when the RP actually sent a credBlob (or it was too
    // long), independent of hmac-secret. The old code pushed a spurious
    // credBlob:false on any hmac-secret registration, changing the signed
    // authData bytes and diverging from the C port (L8).
    if cred_blob_len_in > 0 || cred_blob_too_long {
        ext_entries.push((cbor_text!("credBlob"), cbor_bool!(cred_blob_accepted)));
    }
    if hmac_secret_requested {
        // CTAP 2.1 sec. 12.5.4 MakeCred extension output: just `true` to
        // confirm we generated the cred_random for this credential.
        ext_entries.push((cbor_text!("hmac-secret"), cbor_bool!(true)));
    }
    // credProtect extension output (CTAP 2.1 sec. 12.1.1.4). This is what
    // tells a relying party using `enforceCredentialProtectionPolicy`
    // that the policy it asked for was applied -- and the policy IS
    // applied, by the gate in `emit_get_assertion`. Withholding it
    // leaves the RP unable to confirm the thing the extension exists to
    // confirm.
    //
    // It used to be suppressed on hybrid builds, on the grounds that the
    // ML-DSA attestation "already consumes nearly all of the 7609 B
    // maxMsgSize budget" so 14 more bytes would truncate the response.
    // That was a claim about a number that nothing measured, and the
    // number has moved. tests/hybrid_msgsize.rs measures it now: the
    // largest hybrid MakeCredential this port produces is 4131 / 5660 /
    // 2988 bytes at ML-DSA 44 / 65 / 87, leaving between 1949 and 4621
    // bytes of headroom against a 14-byte cost. That test fails if the
    // headroom ever falls under the cost, which is when this decision
    // needs revisiting rather than this comment quietly going stale
    // again.
    if cred_protect_policy > 0 {
        ext_entries.push((
            cbor_text!("credProtect"),
            cbor_int!(cred_protect_policy as i64),
        ));
    }
    if min_pin_length_rp_allowed {
        let effective = if store.min_pin_length == 0 {
            client_pin::PIN_MIN_LENGTH_BYTES as u8
        } else {
            store.min_pin_length
        };
        ext_entries.push((cbor_text!("minPinLength"), cbor_int!(effective as i64)));
    }
    if !ext_entries.is_empty() {
        // Re-set the ED flag bit on top of UP|AT (and UV). The flags byte
        // is at offset 32 in authData (after rp_id_hash).
        auth_data[32] |= AUTHDATA_FLAG_ED;
        let ext_map = Value::Map(ext_entries);
        let mut ext_bytes = AllocVec::with_capacity(96);
        pqf_cbor::encode(&ext_map, &mut ext_bytes);
        auth_data.extend_from_slice(&ext_bytes);
    }

    // Packed self-attestation over (authData || clientDataHash).
    //
    // ES256 credential: signed with the credential's own ECDSA key.
    //
    // Hybrid credential: the FULL dual (ECDSA-DER || ML-DSA) signature,
    // with attStmt alg == the credential's hybrid alg -- at ML-DSA-44
    // and 65. An attStmt alg that differs from the credential's alg is
    // a PQC downgrade an RP is not obliged to accept, and conformant
    // verifiers refuse it outright (the conformance suite answers a
    // 44/65 ES256 attStmt with a flag-policy error). The dual signature
    // fits at these levels, so there is nothing to justify sending less.
    //
    // ML-DSA-87 is the sole exception, forced by the transport: the
    // dual attStmt makes the response 7617 B -- 8 over the CTAPHID
    // 7609 B structural ceiling -- so it truncates mid-signature and the
    // client rejects the corrupt CBOR. At 87 alone we emit an
    // ECDSA-P256-only self-attestation (attStmt alg ES256, ~72 B),
    // taking the response to ~2.9 KB. The ML-DSA public key still rides
    // in authData and still signs every GetAssertion (whose response
    // carries no public key and fits at every level).
    //
    // NOTE on the 87 path: it is a dedicated ECDSA sign over
    // SHA-256(authData||clientDataHash) with NO hybrid label -- the
    // hybrid ECDSA half signs SHA-256(LABEL||msg), so it is not
    // reusable. `signing_key` is the credential's EC key (its scalar is
    // also the hybrid ECDSA half), valid for hybrid.
    //
    // Mirrors the C port (ctap2.c); the per-level shape is pinned by
    // c/firmware/test/test_hybrid_msgsize.c.
    let mut to_sign = AllocVec::with_capacity(auth_data.len() + 32);
    to_sign.extend_from_slice(&auth_data);
    to_sign.extend_from_slice(&client_data_hash);

    let mut sign_cancelled = false;
    let final_sig: AllocVec<u8> = if is_hybrid {
        #[cfg(feature = "mldsa87")]
        {
            // Size-capped fallback, level 87 only.
            let ecdsa_sig: Signature = signing_key.sign(&to_sign);
            ecdsa_sig.to_der().as_bytes().to_vec()
        }
        #[cfg(not(feature = "mldsa87"))]
        {
            opensk_hybrid_sign(
                &signing_key_bytes,
                &mldsa_seed,
                &to_sign,
                host,
                &mut sign_cancelled,
            )
        }
    } else if is_ed25519 {
        #[cfg(feature = "ed25519")]
        {
            // `signing_key_bytes` was overwritten with the Ed25519
            // seed up in the key-gen block. Ed25519 sigs are 64 B raw.
            crate::ed25519_alg::sign_with_seed(&signing_key_bytes, &to_sign).to_vec()
        }
        #[cfg(not(feature = "ed25519"))]
        {
            unreachable!("is_ed25519 only set when feature enabled");
        }
    } else {
        let ecdsa_sig: Signature = signing_key.sign(&to_sign);
        ecdsa_sig.to_der().as_bytes().to_vec()
    };
    // L15: host sent CTAPHID_CANCEL during the hybrid sign -- answer
    // KEEPALIVE_CANCEL instead of returning an assertion it abandoned.
    if sign_cancelled {
        let _ = out.push(CTAP2_ERR_KEEPALIVE_CANCEL);
        return;
    }

    // Index the credential in flash ONLY when the RP asked for a
    // discoverable (resident) credential via `options.rk = true`
    // (M15). A non-resident registration (rk absent/false) stays
    // recoverable from the credentialId the RP holds, so it must NOT
    // consume one of the finite slots. When rk is requested and every
    // slot is occupied (and this isn't a re-registration overwrite),
    // `insert` returns Err and we report CTAP2_ERR_KEY_STORE_FULL
    // rather than silently FIFO-evicting another account's passkey.
    //
    // #2/#6/#9: this commit runs only AFTER the `sign_cancelled` guard
    // above, so a cancelled hybrid MakeCredential never persists (and
    // never overwrites) a resident credential -- matching GetAssertion's
    // commit-after-cancel ordering.
    if rk_requested {
        let cred = Credential {
            credential_id,
            rp_id_hash,
            counter: 1,
            user_id_len,
            user_id: user_id_buf,
            cred_protect: cred_protect_policy,
            cred_blob_len: if cred_blob_accepted {
                cred_blob_len_in
            } else {
                0
            },
            cred_blob: cred_blob_in,
            user_name_len,
            user_name: user_name_buf,
            user_display_name_len,
            user_display_name: user_display_name_buf,
            // CredStore::insert assigns `creation_order = max(existing)+1`,
            // so the value here is ignored.
            creation_order: 0,
            rp_id_len: rp_id_len_stored as u8,
            rp_id: rp_id_buf,
            large_blob_key: large_blob_key_requested,
        };
        if store.insert(cred).is_err() {
            let _ = out.push(CTAP2_ERR_KEY_STORE_FULL);
            return;
        }
    }

    // Per CTAP 2.1 sec. 6.1.5, the `largeBlobKey` requested via the
    // extension input is returned at the top of the MakeCred
    // response map under key `0x05`, NOT inside `authData`
    // extensions. The key is 32 raw bytes derived deterministically
    // from this credential's id.
    let large_blob_key_bytes = if large_blob_key_requested {
        Some(crate::credential_id::derive_large_blob_key(
            &store.key_handle_hmac_key,
            &credential_id,
        ))
    } else {
        None
    };

    // attStmt alg matches the attestation signature produced above: the
    // credential's own alg everywhere, EXCEPT a hybrid credential at
    // ML-DSA-87, where the size-capped fallback signed with ES256 (see
    // the sign block). At 44/65 a hybrid credential reports its hybrid
    // alg and carries the full dual signature.
    #[cfg(feature = "mldsa87")]
    let att_alg = if is_hybrid {
        COSE_ALG_ES256
    } else {
        chosen_alg
    };
    #[cfg(not(feature = "mldsa87"))]
    let att_alg = chosen_alg;
    let mut response_entries: AllocVec<(Value, Value)> = AllocVec::new();
    response_entries.push((cbor_int!(0x01), cbor_text!("packed")));
    response_entries.push((cbor_int!(0x02), Value::Bytes(auth_data)));
    response_entries.push((
        cbor_int!(0x03),
        cbor_map! {
            cbor_text!("alg") => cbor_int!(att_alg),
            cbor_text!("sig") => Value::Bytes(final_sig),
        },
    ));
    if let Some(k) = large_blob_key_bytes {
        response_entries.push((cbor_int!(0x05), Value::Bytes(k.to_vec())));
    }
    let response = Value::Map(response_entries);
    let mut response_bytes = AllocVec::with_capacity(256);
    pqf_cbor::encode(&response, &mut response_bytes);
    let _ = out.push(CTAP2_OK);
    let _ = out.extend_from_slice(&response_bytes);
}

/// `authenticatorGetAssertion` (CTAP 2.1 sec. 6.2).
fn emit_get_assertion(
    params: &[u8],
    trng: &mut impl CryptoRngCore,
    session: &mut PinSession,
    store: &mut CredStore,
    host: &mut dyn FnMut(HostOp) -> bool,
    now_us: u64,
    cid: [u8; 4],
    out: &mut CtapResponse,
) {
    let value = match parse_cbor(params) {
        Some(v) => v,
        None => {
            let _ = out.push(CTAP2_ERR_INVALID_CBOR);
            return;
        }
    };
    let map = match value {
        Value::Map(m) => m,
        _ => {
            let _ = out.push(CTAP2_ERR_INVALID_CBOR);
            return;
        }
    };

    // 0x01 rpId (text). Computed early -- same reason as MakeCred:
    // the PIN/UV-permission check needs `rp_id_hash`.
    let rp_id = match map_get(&map, 0x01) {
        Some(Value::Text(s)) => s.clone(),
        _ => {
            let _ = out.push(CTAP2_ERR_MISSING_PARAMETER);
            return;
        }
    };
    let rp_id_hash: [u8; 32] = {
        let mut h = Sha256Ctx::new();
        h.update(rp_id.as_bytes());
        h.finalize()
    };

    // 0x02 clientDataHash (bstr, 32)
    let client_data_hash = match map_get(&map, 0x02) {
        Some(Value::Bytes(b)) if b.len() == 32 => b.clone(),
        _ => {
            let _ = out.push(CTAP2_ERR_MISSING_PARAMETER);
            return;
        }
    };
    // CTAP 2.1 sec. 6.3: a fresh authenticatorGetAssertion invalidates any
    // pending getNextAssertion iterator. Reset it here -- the allowList
    // branch never set it, so a stale iterator from a previous
    // no-allowList request could otherwise drive numberOfCredentials /
    // PII release and let a following GetNext sign over the wrong
    // clientDataHash / rp_id_hash.
    session.assertion_iter = None;

    // 0x06 pinUvAuthParam, 0x07 pinUvAuthProtocol (note: GetAssertion
    // uses different map-keys than MakeCredential -- see CTAP 2.1 sec. 6.2)
    let pin_uv_auth_param = match map_get(&map, 0x06) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };
    let pin_uv_auth_protocol = match map_get(&map, 0x07) {
        Some(Value::Uint(u)) => Some(*u),
        _ => None,
    };
    // #1: `uv_present` MUST be derived from a PIN/UV verification that
    // actually succeeded, NEVER from mere field presence -- otherwise a
    // PIN-less device treats a structurally-present pinUvAuthParam as
    // "UV happened", bypassing credProtect-3 and handing out the with_uv
    // hmac-secret output. Mirrors MakeCredential's `uv_happened`:
    // initialise false here and set true only inside the verified branch
    // below.
    let mut uv_present = false;
    // pinUvAuthParam present but no PIN configured: we deliberately do NOT
    // return CTAP2_ERR_PIN_NOT_SET (0x35) here. MakeCredential ignores the
    // same case (see its pin_set==0 handling) so Chrome's silent-discovery
    // probe -- which sends pinUvAuthParam=h'' to PIN-less devices too -- keeps
    // surfacing the authenticator in the WebAuthn picker. The security
    // requirement (#1) is satisfied regardless: the verification block below
    // runs ONLY when a PIN is set, so on a PIN-less device `uv_present`
    // stays false and the supplied auth bytes can never spoof UV.
    if store.pin.pin_set != 0 {
        // A PIN being set does NOT force UV on GetAssertion: a normal
        // assertion proceeds on user-presence (touch) alone, exactly
        // like a YubiKey. We only VERIFY a supplied pinUvAuthParam here;
        // we do NOT refuse when one is absent. The cases that genuinely
        // require UV are enforced downstream and unchanged: an explicit
        // `uv=true` option, `alwaysUv`, and credProtect level 2/3 all
        // check `uv_present` below and reject when it's false.
        //
        // (Previously an absent pinUvAuthParam returned PUAT_REQUIRED
        // unconditionally once a PIN existed -- forcing the full UV flow
        // on every authentication and making Chrome drive our token
        // differently from a YubiKey: the "hijacking" symptom.)
        //
        // Error-code discipline when a token IS supplied (CTAP 2.1
        // sec. 6.2): present-but-invalid -> PIN_AUTH_INVALID (0x33), never
        // PUAT_REQUIRED. Chrome's silent discovery probe sends
        // `pinUvAuthParam: h''` (present, empty) and keys its picker
        // decision off getting 0x33 here -- the `if let Some` still lands
        // that probe in the verification-failure path.
        if let Some(auth_param) = &pin_uv_auth_param {
            let proto = match pin_uv_auth_protocol {
                Some(p) if p == client_pin::PIN_PROTOCOL_V1 || p == client_pin::PIN_PROTOCOL_V2 => {
                    p
                }
                _ => {
                    let _ = out.push(client_pin::ERR_PIN_AUTH_INVALID);
                    return;
                }
            };
            if client_pin::check_token_permission(
                session,
                client_pin::PERM_GET_ASSERTION,
                &rp_id_hash,
            )
            .is_err()
            {
                let _ = out.push(client_pin::ERR_PIN_AUTH_INVALID);
                return;
            }
            if !client_pin::verify_pin_uv_auth_param(
                session.pin_uv_auth_token(),
                &client_data_hash,
                auth_param,
                proto,
            ) {
                let _ = out.push(client_pin::ERR_PIN_AUTH_INVALID);
                return;
            }
            // PIN/UV verification succeeded -- UV genuinely happened. This
            // is the ONLY place `uv_present` is set true (see #1). It
            // gates downstream:
            //   - `credProtect` level 2/3 enforcement (level 3 needs UV)
            //   - which `cred_random` hmac-secret uses (no_uv vs with_uv)
            // and the AUTHDATA_FLAG_UV bit in the response authData.
            uv_present = true;
        }
    }

    // 0x05 options (CTAP 2.1 sec. 6.2) -- `up` / `uv`. Defaults: up = true,
    // uv = false. (`rk` is not a GetAssertion option.) Parsed here
    // (L1/L7/F3):
    //   - `up = false` performs a SILENT assertion (browser pre-flight
    //     / conditional mediation): we must NOT solicit user presence
    //     and must leave the UP flag clear in authData.
    //   - `uv = true` is only satisfiable when UV actually happened
    //     (a PIN/UV token verified above). On this hardware UV is only
    //     available via a PIN, so an explicit `uv = true` that didn't
    //     authenticate fails rather than silently downgrading the
    //     ceremony.
    let mut up_requested = true;
    let mut uv_option = false;
    if let Some(Value::Map(opts)) = map_get(&map, 0x05) {
        if let Some(Value::Bool(b)) = map_get_str(opts, "up") {
            up_requested = *b;
        }
        if let Some(Value::Bool(b)) = map_get_str(opts, "uv") {
            uv_option = *b;
        }
    }
    if uv_option && !uv_present {
        // Explicit uv=true the device can't satisfy. No PIN set -> no UV
        // method at all (UNSUPPORTED_OPTION); PIN set -> the host must
        // obtain a token first (PUAT_REQUIRED).
        let code = if store.pin.pin_set == 0 {
            CTAP2_ERR_UNSUPPORTED_OPTION
        } else {
            client_pin::ERR_PUAT_REQUIRED
        };
        let _ = out.push(code);
        return;
    }

    // `alwaysUv` enforcement on GetAssertion (CTAP 2.1 sec. 6.11.4).
    // If the device is configured to always require UV, reject any
    // GetAssertion that didn't authenticate with `pinUvAuthParam`.
    if store.always_uv && !uv_present {
        let _ = out.push(client_pin::ERR_PUAT_REQUIRED);
        return;
    }

    // 0x04 extensions input. Parse hmac-secret salts and the credBlob
    // request flag. credProtect on GetAssertion has no input -- it's a
    // MakeCred-time setting we enforce on the credential we look up.
    let mut hmac_secret_input: Option<HmacSecretInput> = None;
    let mut cred_blob_requested = false;
    let mut large_blob_key_requested = false;
    if let Some(Value::Map(ext_map)) = map_get(&map, 0x04) {
        if let Some(Value::Bool(true)) = map_get_str(ext_map, "credBlob") {
            cred_blob_requested = true;
        }
        if let Some(Value::Map(hs)) = map_get_str(ext_map, "hmac-secret") {
            hmac_secret_input = parse_hmac_secret_input(hs);
        }
        if let Some(Value::Bool(true)) = map_get_str(ext_map, "largeBlobKey") {
            large_blob_key_requested = true;
        }
    }

    // 0x03 allowList: optional array of { id, type, transports }
    // CTAP 2.1 sec. 6.2 branches on the *parameter*, not on how many entries
    // survived parsing: "If the allowList parameter is present and is
    // non-empty, locate all denoted credentials... If an allowList is not
    // present, locate all discoverable credentials", and an empty result
    // is CTAP2_ERR_NO_CREDENTIALS. Reading a present-but-unparseable
    // allowList as an absent one made the token answer with whichever
    // discoverable credential it held for that rpId -- not the one the
    // relying party named. On a token holding passkeys for two accounts
    // at one site that silently switched which account authenticated.
    // The fix that made allow_list_present track the PARAMETER rather
    // than the surviving entries closed the array-of-garbage case and
    // left this one open: a present key 0x03 that is not an array at all
    // still read as absent, and the request still fell into discovery.
    // Same wrong-account substitution, one CBOR major type over. Refused
    // as a type error, since the client did send valid CBOR.
    if let Some(v) = map_get(&map, 0x03) {
        if !matches!(v, Value::Array(_)) {
            let _ = out.push(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            return;
        }
    }
    let allow_list_present = matches!(
        map_get(&map, 0x03),
        Some(Value::Array(arr)) if !arr.is_empty()
    );
    let allow_list_ids: AllocVec<AllocVec<u8>> = match map_get(&map, 0x03) {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| match v {
                Value::Map(m) => match map_get_str(m, "id") {
                    Some(Value::Bytes(b)) => Some(b.clone()),
                    _ => None,
                },
                _ => None,
            })
            .collect(),
        _ => AllocVec::new(),
    };

    // (rp_id_hash was already computed at the top of this function
    // so the PIN/UV-permission check could reference it.)

    // v5: the wire credentialId IS the encrypted blob. Pick the source
    // bytes from either an allowList entry (Chrome's typical
    // username-supplied login) or from a resident slot matched by
    // rp_id_hash (Chrome's passwordless / discoverable-credential
    // flow). In both cases we then `decrypt_credential_id` to recover
    // the keys -- the slot itself no longer carries them.
    //
    // `cred_idx` is `Some(_)` iff the credentialId is currently in
    // our flash index, which lets us bump the per-credential counter
    // and surface the stored user handle in 0x04. For pure non-resident
    // creds (RP holds the only copy of the credentialId) `cred_idx`
    // stays `None`; we still sign, with counter=0 and no user.
    //
    // `pending_iter` is the rest of a multi-credential discovery. It is
    // staged here and committed to `session.assertion_iter` only at the
    // very end, once this assertion has been signed -- see there.
    let mut pending_iter: Option<AssertionIterState> = None;
    let (credential_id_bytes, cred_idx) = if allow_list_present {
        let mut found: Option<(AllocVec<u8>, Option<usize>)> = None;
        for id in &allow_list_ids {
            if id.len() != CREDENTIAL_ID_LEN {
                continue;
            }
            // Validate HMAC + rp_id_hash before committing to this id.
            if let Ok(src) = decrypt_credential_id(
                &store.key_handle_aes_key,
                &store.key_handle_hmac_key,
                id,
                &rp_id_hash,
            ) {
                // credProtect (CTAP 2.1 sec. 12.1.1): a level-3
                // (userVerificationRequired) credential must not be
                // used without UV even when presented in an allowList --
                // skip it (treated as not present). The policy comes
                // from the credentialId plaintext, so this holds for
                // non-resident / evicted credentials too. Level 2 is
                // satisfied by the allowList itself.
                if src.cred_protect == 3 && !uv_present {
                    continue;
                }
                let idx = store.find_by_id_idx(id);
                found = Some((id.clone(), idx));
                break;
            }
        }
        match found {
            Some((bytes, idx)) => (bytes, idx),
            None => {
                let _ = out.push(CTAP2_ERR_NO_CREDENTIALS);
                return;
            }
        }
    } else {
        // No allowList -- discover all resident credentials for this
        // RP, return the most-recent one, and stage the rest so the host
        // can pull them via `authenticatorGetNextAssertion` (CTAP 2.1
        // sec. 6.3).
        let mut matches: AllocVec<usize> = AllocVec::new();
        for (i, s) in store.iter_active_by_creation() {
            if s.rp_id_hash == rp_id_hash {
                // credProtect (CTAP 2.1 sec. 12.1.1): with no allowList,
                // level-2 (userVerificationOptionalWithCredentialIDList)
                // and level-3 credentials are only discoverable when
                // the request is user-verified. Filtering here keeps
                // both the returned credential AND the GetNextAssertion
                // stash clean, and makes numberOfCredentials count only
                // the credentials the host may actually use.
                if s.cred_protect >= 2 && !uv_present {
                    continue;
                }
                matches.push(i);
            }
        }
        if matches.is_empty() {
            let _ = out.push(CTAP2_ERR_NO_CREDENTIALS);
            return;
        }
        // Most recent first.
        matches.reverse();
        let first_idx = matches[0];
        let total = matches.len() as u32;
        // Stage the rest if there's more than one.
        if matches.len() > 1 {
            pending_iter = Some(AssertionIterState {
                remaining_slot_idxs: matches[1..].iter().copied().collect(),
                client_data_hash: {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&client_data_hash);
                    h
                },
                rp_id_hash,
                // Both written at the commit, from the checks that
                // completed by then. Nothing has tested presence yet.
                uv_present: false,
                up_present: false,
                total,
                deadline_us: now_us.saturating_add(30_000_000),
                _cid: cid,
            });
        }
        (
            store.slots[first_idx].credential_id.to_vec(),
            Some(first_idx),
        )
    };

    let source = match decrypt_credential_id(
        &store.key_handle_aes_key,
        &store.key_handle_hmac_key,
        &credential_id_bytes,
        &rp_id_hash,
    ) {
        Ok(s) => s,
        Err(_) => {
            let _ = out.push(CTAP2_ERR_NO_CREDENTIALS);
            return;
        }
    };

    // For resident credentials, snapshot metadata + bump counter. For
    // non-resident creds (no slot match), fall back to counter=0 and
    // no user handle -- both legal per CTAP 2.1.
    let (
        counter,
        user_id_len,
        user_id,
        cred_protect,
        cred_blob_len,
        cred_blob,
        user_name_len,
        user_name,
        user_display_name_len,
        user_display_name,
        // (L11) Whether THIS credential was minted with largeBlobKey.
        // Only resident credentials carry this flag; non-resident
        // (no slot match) credentials default to false so we never
        // over-disclose the key.
        cred_large_blob_key,
    ) = match cred_idx {
        Some(idx) => {
            let mut cred = store.read(idx);
            cred.counter = cred.counter.wrapping_add(1);
            (
                cred.counter,
                cred.user_id_len,
                cred.user_id,
                cred.cred_protect,
                cred.cred_blob_len,
                cred.cred_blob,
                cred.user_name_len,
                cred.user_name,
                cred.user_display_name_len,
                cred.user_display_name,
                cred.large_blob_key,
            )
        }
        None => (
            0u32,
            0u8,
            [0u8; MAX_USER_ID_LEN],
            0u8,
            0u8,
            [0u8; flash_store::MAX_CRED_BLOB_LEN],
            0u8,
            [0u8; MAX_USER_NAME_LEN],
            0u8,
            [0u8; MAX_USER_DISPLAY_NAME_LEN],
            // #14/#20: non-resident credential -- recover the largeBlobKey
            // flag from the decrypted credentialId (byte [97]) so an
            // allowList cred minted with the extension still gets its key.
            source.large_blob_key,
        ),
    };

    // credProtect enforcement (CTAP 2.1 sec. 12.1.1):
    //   - Level 3 (UserVerificationRequired): refuse without UV.
    //   - Level 2 (UserVerificationOptionalWithCredentialIDList):
    //     refuse if no allowList was supplied AND no UV. (Chrome's
    //     typical login always supplies the allowList, so this rarely
    //     fires in practice.)
    //   - Level 1 / 0: always allow.
    if cred_protect == 3 && !uv_present {
        let _ = out.push(client_pin::ERR_PUAT_REQUIRED);
        return;
    }
    if cred_protect == 2 && !uv_present && allow_list_ids.is_empty() {
        let _ = out.push(CTAP2_ERR_NO_CREDENTIALS);
        return;
    }

    // User-presence gate (CTAP 2.1 sec. 6.2.2). We've already confirmed
    // the credentialId decrypts cleanly under our master keys and
    // satisfies credProtect -- now wait for the user to actually
    // press the button. Same 10-second budget as MakeCred. Timeout
    // returns `CTAP2_ERR_OPERATION_DENIED`.
    //
    // (L7) `options.up = false` performs a silent assertion: we must
    // NOT solicit presence and the UP flag stays clear in authData
    // below. Skip the wait entirely in that case.
    //
    // `up_verified` is what the gate established, as against what was
    // asked for: the UP bit this assertion signs and the one its
    // GetNextAssertions inherit.
    let mut up_verified = false;
    if up_requested {
        if !host(HostOp::WaitForUp {
            timeout_us: 10_000_000,
        }) {
            let _ = out.push(CTAP2_ERR_OPERATION_DENIED);
            return;
        }
        up_verified = true;
    }

    // Compute the hmac-secret extension output now so we can inline it
    // into the extensions map below. We only do this if (a) the RP
    // asked for it and (b) the keyAgreement / saltEnc / saltAuth were
    // structurally valid (parse step above). Per CTAP 2.1 sec. 12.5.5 a
    // saltAuth failure aborts the assertion with ERR_EXTENSION_FIRST
    // (0xF0), but in practice browsers tolerate a missing output, so
    // we emit no hmac-secret output rather than failing the whole op.
    let hmac_secret_output: Option<AllocVec<u8>> = match &hmac_secret_input {
        Some(hs) => hmac_secret_compute_output(
            session,
            trng,
            &store.key_handle_hmac_key,
            &credential_id_bytes,
            uv_present,
            hs,
        ),
        None => None,
    };

    // authData: rpIdHash | flags([UP][|UV][|ED]) | counter [ | extensions ]
    let mut auth_data = AllocVec::with_capacity(if hmac_secret_output.is_some() {
        256
    } else {
        37
    });
    auth_data.extend_from_slice(&rp_id_hash);
    // (L7) The UP flag is set only when the presence test above ran and
    // passed. A silent (up=false) assertion clears it per CTAP 2.1
    // sec. 6.2.
    let mut flags = 0u8;
    if up_verified {
        flags |= AUTHDATA_FLAG_UP;
    }
    if uv_present {
        flags |= AUTHDATA_FLAG_UV;
    }
    auth_data.push(flags);
    auth_data.extend_from_slice(&counter.to_be_bytes());

    // Extensions output (CTAP 2.1 sec. 11.2.4). Same shape as the MakeCred
    // side: build a CBOR map of the extensions that were both
    // requested AND produced a payload, set the ED flag bit if
    // non-empty.
    let mut ext_entries: AllocVec<(Value, Value)> = AllocVec::new();
    if cred_blob_requested && cred_blob_len > 0 {
        let blob = cred_blob[..cred_blob_len as usize].to_vec();
        ext_entries.push((cbor_text!("credBlob"), Value::Bytes(blob)));
    }
    if let Some(hs_bytes) = &hmac_secret_output {
        ext_entries.push((cbor_text!("hmac-secret"), Value::Bytes(hs_bytes.clone())));
    }
    if !ext_entries.is_empty() {
        auth_data[32] |= AUTHDATA_FLAG_ED;
        let ext_map = Value::Map(ext_entries);
        let mut ext_bytes = AllocVec::with_capacity(128);
        pqf_cbor::encode(&ext_map, &mut ext_bytes);
        auth_data.extend_from_slice(&ext_bytes);
    }

    let mut to_sign = AllocVec::with_capacity(auth_data.len() + 32);
    to_sign.extend_from_slice(&auth_data);
    to_sign.extend_from_slice(&client_data_hash);

    let mut sign_cancelled = false;
    let final_sig: AllocVec<u8> = if source.alg == COSE_ALG_HYBRID_MLDSA {
        // Hybrid: hand off to core 1 with the recovered key material.
        opensk_hybrid_sign(
            &source.ecdsa_scalar,
            &source.mldsa_seed,
            &to_sign,
            host,
            &mut sign_cancelled,
        )
    } else if source.alg == COSE_ALG_ED25519 {
        // Ed25519: v2 credentialID, the `ecdsa_scalar` slot holds the
        // Ed25519 seed. Pure-Rust sign on core 0; ~1 ms.
        #[cfg(feature = "ed25519")]
        {
            crate::ed25519_alg::sign_with_seed(&source.ecdsa_scalar, &to_sign).to_vec()
        }
        #[cfg(not(feature = "ed25519"))]
        {
            // Unreachable: decrypt_credential_id rejects v2 blobs when
            // the feature is off, so source.alg can never be -8 here.
            let _ = out.push(CTAP2_ERR_NO_CREDENTIALS);
            return;
        }
    } else {
        // ES256-only: stays on core 0 (a single P-256 sign is ~5 ms even
        // at opt-level=s, no need for the multicore detour).
        let signing_key = match SigningKey::from_bytes((&source.ecdsa_scalar).into()) {
            Ok(k) => k,
            Err(_) => {
                let _ = out.push(CTAP2_ERR_NO_CREDENTIALS);
                return;
            }
        };
        let ecdsa_sig: Signature = signing_key.sign(&to_sign);
        ecdsa_sig.to_der().as_bytes().to_vec()
    };
    // L15: host cancelled (CTAPHID_CANCEL) during the hybrid sign --
    // answer KEEPALIVE_CANCEL rather than returning the assertion.
    if sign_cancelled {
        let _ = out.push(CTAP2_ERR_KEEPALIVE_CANCEL);
        return;
    }

    // Every check this assertion needed has now completed -- PIN/UV if a
    // token was supplied, presence if it was asked for, the signature --
    // so the staged continuation takes its flags from what they
    // established. An empty signature is a failed hybrid sign (the
    // errored path of `opensk_hybrid_sign`): that reply still goes out as
    // it always has, but it neither advertises nor arms a continuation.
    let continuation = match pending_iter {
        Some(mut it) if !final_sig.is_empty() => {
            it.up_present = up_verified;
            it.uv_present = uv_present;
            Some(it)
        }
        _ => None,
    };

    // Persist counter back (only if this credential is in our index).
    if let Some(idx) = cred_idx {
        store.bump_counter(idx, counter);
    }

    // Build the response. We always include the credential descriptor
    // (0x01), authData (0x02), and signature (0x03). 0x04 user is
    // emitted only when we have a stored user handle -- matching
    // OpenSK's behaviour (see `OpenSK/src/ctap/mod.rs::process_get_assertion`
    // around line 1052: `if !credential.user_handle.is_empty() { ... }`).
    // Without it Chrome's WebAuthn layer sets `userHandle` to null on
    // the JS-side AuthenticatorAssertionResponse, and a relying party
    // that keys accounts on it then can't bind the assertion to an
    // account and rejects the login.
    let mut resp_entries: AllocVec<(Value, Value)> = AllocVec::new();
    resp_entries.push((
        cbor_int!(0x01),
        cbor_map! {
            cbor_text!("type") => cbor_text!("public-key"),
            cbor_text!("id") => Value::Bytes(credential_id_bytes.clone()),
        },
    ));
    resp_entries.push((cbor_int!(0x02), Value::Bytes(auth_data)));
    resp_entries.push((cbor_int!(0x03), Value::Bytes(final_sig)));
    if user_id_len > 0 {
        // Per CTAP 2.1 sec. 6.2.2 step 12, the authenticator releases PII
        // (name/displayName) when EITHER (a) user verification was
        // performed in this op or (b) multiple credentials match this
        // request -- i.e. the client needs the human-readable label to
        // disambiguate in a picker UI. Without these fields Chrome's
        // account selector shows "Unknown account" for every entry.
        //
        // For single-credential, no-UV assertions we keep emitting just
        // the opaque user.id, which is what `uv = false && total = 1`
        // implies. This matches OpenSK's `PublicKeyCredentialUserEntity`
        // serialisation behaviour (see
        // `OpenSK/src/ctap/data_formats.rs::reduce_to_minimal`).
        let multi_credentials = continuation.as_ref().map(|i| i.total > 1).unwrap_or(false);
        let release_pii = uv_present || multi_credentials;
        let uid = user_id[..user_id_len as usize].to_vec();
        let mut user_map: AllocVec<(Value, Value)> = AllocVec::new();
        user_map.push((cbor_text!("id"), Value::Bytes(uid)));
        if release_pii {
            if user_name_len > 0 {
                if let Ok(s) = core::str::from_utf8(&user_name[..user_name_len as usize]) {
                    user_map.push((cbor_text!("name"), cbor_text!(s)));
                }
            }
            if user_display_name_len > 0 {
                if let Ok(s) =
                    core::str::from_utf8(&user_display_name[..user_display_name_len as usize])
                {
                    user_map.push((cbor_text!("displayName"), cbor_text!(s)));
                }
            }
        }
        resp_entries.push((cbor_int!(0x04), Value::Map(user_map)));
    }
    // 0x05 numberOfCredentials -- only present on the *first*
    // GetAssertion reply when there's more than one match. CTAP 2.1
    // sec. 6.2.3 lets us omit it for single-match cases. We populate from
    // `continuation` (staged above when `allowList` was empty and
    // matches > 1, kept only if this assertion was signed).
    if let Some(iter) = &continuation {
        if iter.total > 1 {
            resp_entries.push((cbor_int!(0x05), cbor_int!(iter.total as i64)));
        }
    }
    // 0x07 largeBlobKey -- Phase 10. When the RP asks via the
    // `largeBlobKey` extension input, return the same deterministic
    // key MakeCred would have returned for this credential -- but
    // ONLY for a credential that was actually minted with the
    // largeBlobKey extension (L11, CTAP 2.1 sec. 12.3). The key is
    // deterministically derivable from credentialId + hmac_key, so
    // emitting it for arbitrary credentials would over-disclose a
    // per-credential key. The "minted with largeBlobKey" flag is read
    // from the credential's flash slot -- and works for allowList creds
    // too, since the allowList path resolves the slot via
    // `find_by_id_idx` (so a resident cred presented by id still gets
    // its key). #14/#20: only resident credentials carry the flag, and
    // MakeCredential now only honors largeBlobKey for resident creds,
    // so the registration-vs-assertion promise is consistent.
    if large_blob_key_requested && cred_large_blob_key {
        let k = crate::credential_id::derive_large_blob_key(
            &store.key_handle_hmac_key,
            &credential_id_bytes,
        );
        resp_entries.push((cbor_int!(0x07), Value::Bytes(k.to_vec())));
    }
    let response = Value::Map(resp_entries);
    let mut response_bytes = AllocVec::with_capacity(256);
    pqf_cbor::encode(&response, &mut response_bytes);
    // Arm GetNextAssertion only now, with the assertion it continues
    // signed. It used to be armed at discovery, before the presence gate,
    // with UP copied from the request: a touch that timed out answered
    // OPERATION_DENIED and left the iterator behind, and a
    // GetNextAssertion sent straight after on the same channel signed the
    // next credential with UP set -- and UV, if a PIN had been verified --
    // although nobody had touched the token. Every return above leaves
    // it `None`, as dispatch and the reset near the top of this function
    // left it.
    session.assertion_iter = continuation;
    let _ = out.push(CTAP2_OK);
    let _ = out.extend_from_slice(&response_bytes);
}
