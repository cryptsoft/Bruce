// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Secure image -- Milestone 1 of the TrustZone-M split.
//! See `docs/TRUSTZONE.md`.
//!
//! Boots first (its `IMAGE_DEF` is `secure_exe()`, so the RP2350 boot
//! ROM launches it), then:
//!   1. claims the status LED (stays Secure-owned),
//!   2. programs the SAU so the upper flash / RAM become Non-secure and
//!      the veneer region becomes Non-secure-Callable,
//!   3. relaxes SCB AIRCR so faults/priorities behave for a NS world,
//!   4. hands off to the Non-secure image (`fw-nonsecure`) via BXNS.
//!
//! The one gateway it exposes is [`sg_led_set`]: the NS world's entire
//! M1 job is to call it in a blink loop. If the LED blinks, the whole
//! boundary -- SAU attribution, the S->NS handoff, the SG veneer call,
//! and the return to NS -- is proven end to end, with zero FIDO code
//! involved. Only then do later milestones move real functionality
//! across.
//!
//! Board: this M1 build targets the Feitian RP2350 (GP25 user LED,
//! active-HIGH) -- the board on the bench. Pin/polarity is the only
//! board-specific bit; generalising waits until the boundary is proven.

#![no_std]
#![no_main]
#![feature(cmse_nonsecure_entry)]
extern crate alloc;

mod bootsel;
mod cborw;
mod clientpin;
mod counter;
mod credstore;
mod ctap;
mod flash;
mod keystore;
mod pinstore;
mod signer;
mod trng;
mod upgate;

use cortex_m::cmse::{AccessType, TestTarget};
use cortex_m::peripheral::sau::{SauRegion, SauRegionAttribute};
use embedded_hal::digital::OutputPin;
use panic_halt as _;
use rp235x_hal as hal;

/// Boot ROM image definition -- Secure executable. This is the image the
/// ROM boots; the Non-secure image is launched by us, not the ROM.
#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

#[link_section = ".bi_entries"]
#[used]
pub static PICOTOOL_ENTRIES: [hal::binary_info::EntryAddr; 2] = [
    hal::binary_info::rp_cargo_bin_name!(),
    hal::binary_info::rp_program_description!(
        c"Bruce TrustZone Secure image (M1 boundary bring-up)"
    ),
];

/// GP25 user LED, active-high (Feitian RP2350). Owned by the Secure
/// world for the lifetime of the firmware; the NS world can only ask
/// for changes through [`sg_led_set`]. `static mut` because the veneer
/// is a free function with no `self` to carry state -- access is
/// single-threaded (NS calls are synchronous, one core drives them).
static mut LED: Option<
    hal::gpio::Pin<
        hal::gpio::bank0::Gpio25,
        hal::gpio::FunctionSio<hal::gpio::SioOutput>,
        hal::gpio::PullDown,
    >,
> = None;

/// Secure-gateway veneer: set the user LED. Callable from the
/// Non-secure world -- the compiler emits an SG stub into
/// `.gnu.sgstubs` (placed in the NSC flash region by the linker
/// script), which is the only way NS code is allowed to enter Secure
/// state here.
///
/// This is deliberately trivial: M1 proves the *mechanism*, not a real
/// security surface. A real gateway (M4+) copies argument buffers in
/// from range-checked NS memory; this one takes a single `bool` in a
/// register, so there is no pointer to validate yet.
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_led_set(on: bool) {
    // SAFETY: single-threaded synchronous access; `LED` is initialised
    // in `main` before the NS world (the only caller) is launched.
    unsafe {
        let led = &raw mut LED;
        if let Some(pin) = (*led).as_mut() {
            let _ = if on { pin.set_high() } else { pin.set_low() };
        }
    }
}

/// Scratch buffer the [`sg_echo`] gateway copies through, in Secure RAM.
/// Proves data physically transits the Secure world on the round trip.
const ECHO_BUF_LEN: usize = 256;
static mut ECHO_BUF: [u8; ECHO_BUF_LEN] = [0u8; ECHO_BUF_LEN];

/// Secure-gateway veneer (M2b-2): echo a buffer. The Non-secure world
/// hands in a pointer/length pair in NS RAM and an output buffer; we
/// copy the input into Secure RAM and back out, returning the byte
/// count. This is the first gateway that takes a *buffer* rather than a
/// scalar -- the shape every real CTAP gateway (sign, getInfo, ...) will
/// have. NS uses it to service a CTAPHID PING, proving a full
/// NS->Secure->NS data round trip.
///
/// M2b-2 does NOT yet range-check the NS pointers (a malicious caller
/// could pass a Secure address). That hardening -- a `cmse::TestTarget`
/// check that the whole buffer is NS-owned -- is M5; called out in
/// docs/TRUSTZONE.md so it isn't forgotten.
/// M5 -- SecureFault takes the device down cleanly instead of hanging.
///
/// A SecureFault means the NS world just attempted something the
/// attribution unit refused: calling into Secure at a non-SG address,
/// an illegal state transition, or an invalid exception return. The
/// default with `panic_halt` is to spin forever, which is the wrong
/// answer twice over -- the token becomes a brick that needs BOOT+RESET,
/// and it holds Secure state in RAM indefinitely for anyone with the
/// patience to glitch it.
///
/// Reset instead: wipe the Secure scratch first so nothing survives
/// into the next boot, then request a system reset. Reset is safe here
/// because the boot path re-establishes SAU/ACCESSCTRL from scratch.
///
/// Registered by name -- `cortex-m-rt` binds `SecureFault` from the
/// exception table, so this needs no wiring beyond existing.
#[cortex_m_rt::exception]
unsafe fn SecureFault() -> ! {
    unsafe {
        let buf = &raw mut ECHO_BUF;
        zeroize(core::slice::from_raw_parts_mut(
            buf as *mut u8,
            ECHO_BUF_LEN,
        ));
    }
    cortex_m::peripheral::SCB::sys_reset()
}

/// M5 -- validate a Non-secure caller's buffer before Secure touches it.
///
/// A veneer argument is just an integer the NS world chose. Without a
/// check, NS can hand us a SECURE address and have the Secure world
/// read it out (`sg_echo`'s input) or scribble over it (`sg_echo` and
/// `sg_get_info`'s output) -- a straightforward confidentiality and
/// integrity break, using Secure privilege as the weapon. The hardware
/// answers this directly: TT* interrogates the SAU/IDAU attribution
/// unit for an address, and `check_range` walks the whole span rather
/// than just the first word, so a buffer straddling the NS/S boundary
/// is caught too.
///
/// Fails closed. A zero length is accepted as a no-op; anything the
/// hardware will not confirm as NS-accessible is rejected.
fn ns_readable(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if ptr.is_null() {
        return false;
    }
    match TestTarget::check_range(ptr as *mut u32, len, AccessType::Current) {
        Some(t) => !t.secure() && t.ns_readable(),
        None => false,
    }
}

/// As [`ns_readable`], but the buffer must also be NS-*writable*.
fn ns_writable(ptr: *mut u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if ptr.is_null() {
        return false;
    }
    match TestTarget::check_range(ptr as *mut u32, len, AccessType::Current) {
        Some(t) => !t.secure() && t.ns_read_and_writable(),
        None => false,
    }
}

/// Wipe a Secure scratch buffer before returning to NS.
///
/// Volatile so the compiler cannot elide it as a dead store -- the same
/// mistake that made openssl-mini's OPENSSL_cleanse a no-op. Secure
/// scratch that held NS-visible data is not itself a secret today, but
/// M4 moves real key material through these buffers and the habit has
/// to be in place before that, not after.
fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_echo(
    in_ptr: *const u8,
    in_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> usize {
    let n = in_len.min(out_cap).min(256);
    // M5: both buffers must be NS-owned for their whole length. NS
    // choosing a Secure address here would otherwise turn this veneer
    // into an arbitrary Secure read AND an arbitrary Secure write.
    if !ns_readable(in_ptr, n) || !ns_writable(out_ptr, n) {
        return 0;
    }
    // SAFETY: `n` is clamped to the scratch buffer and the caller's
    // capacity, and both spans are hardware-confirmed NS-accessible.
    unsafe {
        let buf = &raw mut ECHO_BUF;
        core::ptr::copy_nonoverlapping(in_ptr, buf as *mut u8, n);
        core::ptr::copy_nonoverlapping(buf as *const u8, out_ptr, n);
        zeroize(core::slice::from_raw_parts_mut(buf as *mut u8, n));
    }
    n
}

/// Secure-gateway veneer: authenticatorGetInfo.
///
/// M3 returned a hand-encoded constant. It now comes from
/// [`ctap::get_info`], because the response has to name the algorithms
/// this build supports and the composite identifier moves with the
/// compiled ML-DSA level -- a constant would go stale the first time
/// the level changed.
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_get_info(out_ptr: *mut u8, out_cap: usize) -> usize {
    begin_command();
    if !ns_writable(out_ptr, out_cap) {
        return 0;
    }
    let mut buf = [0u8; 256];
    let n = match ctap::get_info(&mut buf) {
        Some(n) => n.min(out_cap),
        None => return 0,
    };
    // SAFETY: `out_ptr` is hardware-confirmed NS-writable for out_cap.
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), out_ptr, n);
    }
    n
}

// ---------------------------------------------------------------------
// M4c -- credential keys that never leave the Secure world
// ---------------------------------------------------------------------

/// The Secure world's heap.
///
/// ML-DSA needs an allocator; the ES256-only image did not. It lives in
/// Secure RAM, so every intermediate ML-DSA allocation -- expanded
/// secret key, NTT working set -- is unreachable from NS. That is why
/// the RAM split moved to 448 KiB Secure / 64 KiB NS.
#[global_allocator]
static HEAP: embedded_alloc::LlffHeap = embedded_alloc::LlffHeap::empty();

/// Matches the FIDO firmware's heap, sized empirically against ML-DSA
/// keygen and signing.
const HEAP_SIZE: usize = 256 * 1024;

/// Secure-only master key, seeded from the Secure-only TRNG at boot.
///
/// This is the secret the whole exercise exists to protect. It has no
/// getter: there is deliberately no `sg_get_master_key`, because a
/// veneer that hands the key out would defeat the boundary entirely
/// (design note point 1). Every credential key is derived from it
/// inside Secure, used inside Secure, and zeroized before return.
static mut MASTER_KEY: [u8; 32] = [0u8; 32];

/// The Secure world's TRNG, retained so veneers can draw entropy.
static mut SECURE_TRNG: Option<trng::Trng> = None;

/// Credential id: a 32-byte nonce plus a 32-byte tag binding it to this
/// token's master key and the relying party.
const CRED_ID_LEN: usize = 64;
/// Uncompressed P-256 public key minus the 0x04 tag: x || y.
#[cfg(feature = "dev-escape")]
const PUBKEY_LEN: usize = 64;
/// ECDSA P-256 signature as raw r || s.
#[cfg(feature = "dev-escape")]
const SIG_LEN: usize = 64;
const HASH_LEN: usize = 32;

/// Algorithm a credential was issued under.
///
/// Carried *inside* the credential id so GetAssertion can rebuild the
/// right keys with no per-credential state on the token -- the whole
/// point of the stateless design.
pub const ALG_ES256: u8 = 0;
pub const ALG_HYBRID: u8 = 1;

/// Credential id layout: `nonce(31) || alg(1) || tag(32)`.
///
/// 31 bytes of nonce rather than 32, so the algorithm byte fits without
/// changing the 64-byte id length the request struct and the M4c
/// veneers are built around. 248 bits is not a meaningful reduction.
/// The tag covers the algorithm byte, so flipping it to coax a different
/// key schedule out of the same nonce fails the tag check.
/// The credential id is nonce || alg || credProtect || tag, 30+1+1+32.
/// The nonce gave up a byte for the policy on 2026-09-02: a policy that
/// is signed into authData at registration has to travel with the
/// credential to be enforced at assertion, and for a non-resident
/// credential the id is all that travels. C bakes it in the same way.
/// (Old ids fail the tag check and read as "not ours".)
const NONCE_LEN: usize = 30;
const OFF_PROTECT: usize = NONCE_LEN + 1;
const OFF_ALG: usize = NONCE_LEN;

/// Domain separators. A third label for the ML-DSA seed, so the two
/// private keys of a hybrid credential are independent draws rather than
/// the same bytes used twice.
const LABEL_TAG: &[u8] = b"pqf-tz/cred-tag";
const LABEL_KEY: &[u8] = b"pqf-tz/cred-key";
const LABEL_MLDSA: &[u8] = b"pqf-tz/cred-mldsa";
/// Fourth label: the per-credential hmac-secret. A separate draw again,
/// so an extension output can never expose a signing key.
const LABEL_HMAC: &[u8] = b"pqf-tz/cred-hmac";

/// HMAC-SHA256 under the Secure master key.
fn derive(
    label: &[u8],
    nonce: &[u8; NONCE_LEN],
    alg: u8,
    protect: u8,
    rp_id_hash: &[u8; HASH_LEN],
) -> [u8; 32] {
    use hmac::{Mac, SimpleHmac};
    // SAFETY: single-threaded; MASTER_KEY is initialised in `main`
    // before the NS world (the only caller) exists.
    let key = unsafe { &*(&raw const MASTER_KEY) };
    let mut mac = <SimpleHmac<sha2::Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(label);
    mac.update(nonce);
    // The policy is under the MAC, so a flipped policy byte in a
    // presented id yields a different tag and reads as "not ours" rather
    // than as a downgraded credential.
    mac.update(&[alg, protect]);
    mac.update(rp_id_hash);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// A credential's private material, rebuilt from its id.
///
/// Only ever lives on a Secure stack frame, and is zeroized on drop:
/// for a hybrid credential this holds the ML-DSA seed, from which the
/// entire private key expands.
struct Credential {
    alg: u8,
    /// credProtect level 1..=3, or 0 for none. Recovered from the id.
    cred_protect: u8,
    ecdsa_scalar: [u8; 32],
    mldsa_seed: [u8; 32],
}

impl Drop for Credential {
    fn drop(&mut self) {
        zeroize(&mut self.ecdsa_scalar);
        zeroize(&mut self.mldsa_seed);
    }
}

impl Credential {
    fn from_parts(
        nonce: &[u8; NONCE_LEN],
        alg: u8,
        protect: u8,
        rp_id_hash: &[u8; HASH_LEN],
    ) -> Self {
        Self {
            alg,
            cred_protect: protect,
            ecdsa_scalar: derive(LABEL_KEY, nonce, alg, protect, rp_id_hash),
            mldsa_seed: derive(LABEL_MLDSA, nonce, alg, protect, rp_id_hash),
        }
    }

    /// The credential's hmac-secret material.
    fn cred_random(&self) -> [u8; 32] {
        use hmac::{Mac, SimpleHmac};
        // SAFETY: single-threaded; MASTER_KEY set up before NS runs.
        let key = unsafe { &*(&raw const MASTER_KEY) };
        let mut mac = <SimpleHmac<sha2::Sha256> as Mac>::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(LABEL_HMAC);
        mac.update(&self.ecdsa_scalar);
        let out = mac.finalize().into_bytes();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&out);
        buf
    }

    fn signing_key(&self) -> Option<p256::ecdsa::SigningKey> {
        p256::ecdsa::SigningKey::from_bytes((&self.ecdsa_scalar).into()).ok()
    }

    /// The P-256 public point, as x and y.
    fn public_xy(&self) -> Option<([u8; 32], [u8; 32])> {
        let k = self.signing_key()?;
        let point = p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(
            k.verifying_key().as_affine(),
            false,
        );
        let pb = point.as_bytes(); // 0x04 || x || y
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&pb[1..33]);
        y.copy_from_slice(&pb[33..65]);
        Some((x, y))
    }
}

/// Mint a fresh credential for `rp_id_hash` under `alg`.
fn new_credential(
    rp_id_hash: &[u8; HASH_LEN],
    alg: u8,
    protect: u8,
) -> Option<(Credential, [u8; CRED_ID_LEN])> {
    let mut nonce = [0u8; NONCE_LEN];
    // SAFETY: single-threaded; set up in `main` before NS runs.
    unsafe {
        match (&mut *(&raw mut SECURE_TRNG)).as_mut() {
            Some(t) => t.fill(&mut nonce),
            None => return None,
        }
    }
    let tag = derive(LABEL_TAG, &nonce, alg, protect, rp_id_hash);
    let mut id = [0u8; CRED_ID_LEN];
    id[..NONCE_LEN].copy_from_slice(&nonce);
    id[OFF_ALG] = alg;
    id[OFF_PROTECT] = protect;
    id[32..].copy_from_slice(&tag);
    Some((Credential::from_parts(&nonce, alg, protect, rp_id_hash), id))
}

/// Rebuild a credential from its id, checking the tag first.
///
/// Returns None when the tag does not match -- the credential was not
/// issued by this token, or not for this relying party. Comparison is
/// constant-time: a byte-at-a-time early exit here would leak the tag
/// one byte per query and let a caller forge a credential id.
fn recover_credential(
    rp_id_hash: &[u8; HASH_LEN],
    cred_id: &[u8; CRED_ID_LEN],
) -> Option<Credential> {
    use subtle::ConstantTimeEq;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&cred_id[..NONCE_LEN]);
    let alg = cred_id[OFF_ALG];
    if alg != ALG_ES256 && alg != ALG_HYBRID {
        return None;
    }
    let protect = cred_id[OFF_PROTECT];
    if protect > 3 {
        return None;
    }
    let want = derive(LABEL_TAG, &nonce, alg, protect, rp_id_hash);
    if !bool::from(want.ct_eq(&cred_id[32..])) {
        return None;
    }
    Some(Credential::from_parts(&nonce, alg, protect, rp_id_hash))
}

/// Sign `msg` with a credential, writing the signature into `out`.
///
/// ES256 gives a DER ECDSA signature. Hybrid gives
/// `ecdsa_der || mldsa_sig`, byte-identical to the FIDO firmware's
/// `opensk_hybrid_sign` -- it is literally the same worker code reached
/// through the same mailbox.
///
/// The hybrid path hands the scalar and the seed to core 1 and spins.
/// Core 1 is Secure-only, so neither ever crosses the boundary. The spin
/// is a busy-wait rather than `wfe` for the same reason the firmware
/// busy-waits: the worker signals once, at completion.
fn sign_with_credential(cred: &Credential, msg: &[u8], out: &mut [u8]) -> Option<usize> {
    if cred.alg == ALG_ES256 {
        use p256::ecdsa::signature::Signer;
        let key = cred.signing_key()?;
        let sig: p256::ecdsa::Signature = key.sign(msg);
        let der = sig.to_der();
        let b = der.as_bytes();
        if b.len() > out.len() {
            return None;
        }
        out[..b.len()].copy_from_slice(b);
        return Some(b.len());
    }

    let s = &signer::CORE1_SIGNER;
    s.submit(&cred.ecdsa_scalar, &cred.mldsa_seed, msg).ok()?;
    while !s.is_done() {
        core::hint::spin_loop();
    }
    let errored = s.errored();
    // Drained either way: leaving a result parked never returns the
    // mailbox to IDLE, and the next submit would spin forever.
    let mut result = alloc::vec::Vec::new();
    s.take_result(&mut result);
    if errored || result.len() > out.len() {
        return None;
    }
    out[..result.len()].copy_from_slice(&result);
    Some(result.len())
}

/// The credential's ML-DSA public key, encoded.
fn mldsa_public(cred: &Credential, out: &mut [u8]) -> Option<usize> {
    use bouncycastle_core_interface::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core_interface::traits::SignaturePublicKey;
    use bouncycastle_mldsa_lowmemory::MLDSATrait;
    use pqf_signer_core::mldsa_alg::MLDSA;
    let km = KeyMaterial::<32>::from_bytes_as_type(&cred.mldsa_seed, KeyType::Seed).ok()?;
    let (pk, _sk) = MLDSA::keygen_from_seed(&km).ok()?;
    let enc = pk.encode();
    if enc.len() > out.len() {
        return None;
    }
    out[..enc.len()].copy_from_slice(&enc);
    Some(enc.len())
}

/// What the M4c raw veneers sign: the relying party and the client
/// data. A stand-in for CTAP2's `authData || clientDataHash`; the real
/// CTAP2 path in [`ctap`] builds the genuine article.
#[cfg(feature = "dev-escape")]
fn signed_payload(rp_id_hash: &[u8; HASH_LEN], cdh: &[u8; HASH_LEN]) -> [u8; 64] {
    let mut msg = [0u8; 64];
    msg[..32].copy_from_slice(rp_id_hash);
    msg[32..].copy_from_slice(cdh);
    msg
}

/// Secure-gateway veneer (M4c): create a credential.
///
/// Behind `dev-escape`: this is a test protocol for the boundary, and
/// unlike the CTAP2 path it is not user-presence gated. An image built
/// for real use must not carry an ungated signing entry point, so it
/// does not carry this at all.
///
/// In:  rp_id_hash[32], client_data_hash[32].
/// Out: credential_id[64] || public_key[64] || signature[64].
///
/// The output length is fixed, so there is no capacity argument: the
/// `"C-cmse-nonsecure-entry"` ABI passes everything in r0-r3 and will
/// not compile with a fifth. Writing a fixed 192 bytes into checked NS
/// memory cannot harm the Secure world -- an NS caller that supplied a
/// shorter buffer only corrupts its own.
///
/// The private key is derived, used and destroyed inside this call. NS
/// receives a credential id, a public key and a signature -- everything
/// it needs, and nothing that would let it sign again on its own.
#[cfg(feature = "dev-escape")]
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_make_credential(
    rp_id_hash: *const u8,
    client_data_hash: *const u8,
    out: *mut u8,
) -> usize {
    const TOTAL: usize = CRED_ID_LEN + PUBKEY_LEN + SIG_LEN;
    // M5: every pointer NS hands in, checked before it is touched.
    if !ns_readable(rp_id_hash, HASH_LEN)
        || !ns_readable(client_data_hash, HASH_LEN)
        || !ns_writable(out, TOTAL)
    {
        return 0;
    }
    // Copy the arguments into Secure storage before use: NS must not be
    // able to change them after they have been checked.
    let mut rp = [0u8; HASH_LEN];
    let mut cdh = [0u8; HASH_LEN];
    // SAFETY: both spans are hardware-confirmed NS-readable, 32 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(rp_id_hash, rp.as_mut_ptr(), HASH_LEN);
        core::ptr::copy_nonoverlapping(client_data_hash, cdh.as_mut_ptr(), HASH_LEN);
    }

    let (cred, cred_id) = match new_credential(&rp, ALG_ES256, 0) {
        Some(v) => v,
        None => return 0,
    };
    let (x, y) = match cred.public_xy() {
        Some(v) => v,
        None => return 0,
    };
    // The raw M4c protocol predates DER and promised a fixed 64-byte
    // r || s, so sign directly rather than through
    // `sign_with_credential`. Kept as-is because the M4c tests check
    // that shape, and it stays a smaller surface than the CTAP2 path.
    use p256::ecdsa::signature::Signer;
    let key = match cred.signing_key() {
        Some(k) => k,
        None => return 0,
    };
    let sig: p256::ecdsa::Signature = key.sign(&signed_payload(&rp, &cdh));
    let sig_bytes = sig.to_bytes();

    let mut buf = [0u8; TOTAL];
    buf[..CRED_ID_LEN].copy_from_slice(&cred_id);
    buf[CRED_ID_LEN..CRED_ID_LEN + 32].copy_from_slice(&x);
    buf[CRED_ID_LEN + 32..CRED_ID_LEN + PUBKEY_LEN].copy_from_slice(&y);
    buf[CRED_ID_LEN + PUBKEY_LEN..].copy_from_slice(&sig_bytes);

    // SAFETY: `out` is hardware-confirmed NS-writable for TOTAL bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), out, TOTAL);
    }
    TOTAL
}

/// Secure-gateway veneer (M4c): assert an existing credential.
///
/// In:  rp_id_hash[32], client_data_hash[32], credential_id[64].
/// Out: signature[64]. Fixed length, no capacity argument -- see
/// [`sg_make_credential`].
///
/// Returns 0 for a credential id this token did not issue for this
/// relying party, so a forged or replayed id gets no signature.
#[cfg(feature = "dev-escape")]
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_get_assertion(
    rp_id_hash: *const u8,
    client_data_hash: *const u8,
    cred_id: *const u8,
    out: *mut u8,
) -> usize {
    if !ns_readable(rp_id_hash, HASH_LEN)
        || !ns_readable(client_data_hash, HASH_LEN)
        || !ns_readable(cred_id, CRED_ID_LEN)
        || !ns_writable(out, SIG_LEN)
    {
        return 0;
    }
    let mut rp = [0u8; HASH_LEN];
    let mut cdh = [0u8; HASH_LEN];
    let mut id = [0u8; CRED_ID_LEN];
    // SAFETY: all three spans hardware-confirmed NS-readable.
    unsafe {
        core::ptr::copy_nonoverlapping(rp_id_hash, rp.as_mut_ptr(), HASH_LEN);
        core::ptr::copy_nonoverlapping(client_data_hash, cdh.as_mut_ptr(), HASH_LEN);
        core::ptr::copy_nonoverlapping(cred_id, id.as_mut_ptr(), CRED_ID_LEN);
    }

    let cred = match recover_credential(&rp, &id) {
        Some(c) => c,
        None => return 0,
    };
    let signing = match cred.signing_key() {
        Some(k) => k,
        None => return 0,
    };
    use p256::ecdsa::signature::Signer;
    let sig: p256::ecdsa::Signature = signing.sign(&signed_payload(&rp, &cdh));
    let sig_bytes = sig.to_bytes();

    // SAFETY: `out` is hardware-confirmed NS-writable for SIG_LEN bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), out, SIG_LEN);
    }
    SIG_LEN
}

/// Secure-gateway veneer: CTAP2 authenticatorGetNextAssertion.
///
/// Deliberately does NOT consume user presence. CTAP2 treats the whole
/// sequence as authorised by the gesture that started it, and asking
/// again per credential would make choosing between two accounts need
/// two touches.
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_ctap_get_next_assertion(
    out: *mut u8,
    out_cap: usize,
) -> usize {
    ctap::cm_abandon();
    if !ns_writable(out, out_cap) {
        return 0;
    }
    let mut resp = [0u8; ctap::RESP_MAX];

    // SAFETY: single-threaded; Secure-only state.
    let state = unsafe { &mut *(&raw mut ASSERT_STATE) };
    let n = match state {
        Some(st) if st.next < st.total => {
            let index = st.next;
            let req = ctap::Request {
                rp_id_hash: st.rp_id_hash,
                client_data_hash: st.client_data_hash,
                cred_id: [0u8; CRED_ID_LEN],
                // Carried from the GetAssertion that started this
                // ceremony, where resolve_uv decided it. GetNextAssertion
                // continues that ceremony (sec. 6.3) rather than beginning a
                // new one, so it does not re-resolve -- and must not,
                // since the client sends no pinUvAuthParam with it.
                uv: st.uv,
                uv_requested: false,
                puat: [0u8; 32],
                puat_len: 0,
                puat_present: false,
                puat_malformed: false,
                puat_proto: 0,
                cred_id2: None,
                hybrid: false,
                rk: false,
                have_allow_list: false,
                user_id: [0u8; credstore::MAX_USER_ID],
                user_id_len: 0,
                want_min_pin: false,
                want_cred_blob: false,
                cred_blob: [0u8; credstore::MAX_CRED_BLOB],
                cred_blob_len: 0,
                rp_id: [0u8; ctap::MAX_RP_ID],
                rp_id_len: 0,
                name: [0u8; credstore::MAX_NAME],
                name_len: 0,
                display: [0u8; credstore::MAX_NAME],
                display_len: 0,
                want_hmac_secret: false,
                hs_kx: [0u8; 32],
                hs_ky: [0u8; 32],
                hs_salt: [0u8; 64],
                hs_salt_len: 0,
                hs_auth: [0u8; 32],
                hs_auth_len: 0,
                cred_protect: 0,
            };
            // Same filter as the GetAssertion that began this ceremony,
            // with the UV it resolved, so the index walks the same list.
            match credstore::nth_discoverable(&st.rp_id_hash, index, st.uv) {
                None => ctap::error(ctap::CTAP2_ERR_NOT_ALLOWED, &mut resp),
                Some(found) => match recover_credential(&st.rp_id_hash, &found.cred_id) {
                    None => ctap::error(ctap::CTAP2_ERR_NO_CREDENTIALS, &mut resp),
                    Some(cred) => {
                        let mut auth = [0u8; 256];
                        let mut msg = [0u8; 320];
                        match ctap::assertion_signed_message(&req, None, None, &mut auth, &mut msg)
                        {
                            None => ctap::error(ctap::CTAP2_ERR_INVALID_PARAMETER, &mut resp),
                            Some((alen, mlen)) => {
                                let mut sig = [0u8; ctap::SIG_MAX];
                                match sign_with_credential(&cred, &msg[..mlen], &mut sig) {
                                    None => {
                                        ctap::error(ctap::CTAP2_ERR_INVALID_PARAMETER, &mut resp)
                                    }
                                    Some(slen) => {
                                        st.next += 1;
                                        match ctap::get_assertion(
                                            &found.cred_id,
                                            &auth[..alen],
                                            &sig[..slen],
                                            Some(&found.user_id[..found.user_id_len]),
                                            // No numberOfCredentials: CTAP2
                                            // puts it in the first reply only.
                                            None,
                                            &mut resp,
                                        ) {
                                            Some(n) => n,
                                            None => ctap::error(
                                                ctap::CTAP2_ERR_INVALID_PARAMETER,
                                                &mut resp,
                                            ),
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }
        // No sequence in progress, or it is exhausted.
        _ => ctap::error(ctap::CTAP2_ERR_NOT_ALLOWED, &mut resp),
    };

    let n = n.min(out_cap);
    // SAFETY: `out` hardware-confirmed NS-writable for out_cap bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(resp.as_ptr(), out, n);
    }
    n
}

/// Where a multi-credential assertion got to.
///
/// CTAP2 answers an assertion that matches several discoverable
/// credentials one at a time: the first reply carries
/// numberOfCredentials, and the client calls GetNextAssertion for the
/// rest. Without this the other credentials are simply unreachable --
/// the count says three and only one can ever be fetched, which is
/// worse than not reporting a count at all.
///
/// Secure-side because the choice of credential is a Secure decision;
/// NS supplying an index would let it walk the store.
struct AssertState {
    rp_id_hash: [u8; HASH_LEN],
    client_data_hash: [u8; HASH_LEN],
    uv: bool,
    next: usize,
    total: usize,
}

static mut ASSERT_STATE: Option<AssertState> = None;

/// CTAP2: any command other than GetNextAssertion ends the sequence.
fn clear_assert_state() {
    // SAFETY: single-threaded; Secure-only state.
    unsafe {
        ASSERT_STATE = None;
    }
}

/// A CTAP command has arrived that is not a continuation of anything.
///
/// Both stateful iterators in this image -- the GetNextAssertion state
/// and the credentialManagement enumeration cursors -- are only valid as
/// the immediate successor of the command that armed them, and CTAP 2.1
/// says so for each (sec. 6.3, sec. 6.8). The C port resets its iterator on every
/// command but GetNextAssertion; this port cleared ASSERT_STATE only from
/// MakeCredential and GetAssertion, and never cleared the credMgmt
/// cursors at all, so both survived across unrelated traffic. One call,
/// at the top of every gateway that is not itself a continuation.
fn begin_command() {
    clear_assert_state();
    ctap::cm_abandon();
}

/// Secure-gateway veneer: does this credential id belong to us, for
/// this relying party?
///
/// CTAP2 requires MakeCredential to refuse with CREDENTIAL_EXCLUDED
/// when the excludeList names a credential the authenticator already
/// holds. That is a MUST, not an optional feature, and answering it
/// needs the master key -- so it has to be decided in Secure even
/// though the answer itself is a single bit.
///
/// The bit is not a new disclosure: NS can already learn the same thing
/// by asking for an assertion and seeing whether it succeeds.
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_cred_is_ours(
    rp_id: *const u8,
    rp_id_len: usize,
    cred_id: *const u8,
) -> u8 {
    if rp_id_len == 0
        || rp_id_len > ctap::MAX_RP_ID
        || !ns_readable(rp_id, rp_id_len)
        || !ns_readable(cred_id, CRED_ID_LEN)
    {
        return 0;
    }
    let mut rp = [0u8; ctap::MAX_RP_ID];
    let mut id = [0u8; CRED_ID_LEN];
    // SAFETY: both spans hardware-confirmed NS-readable.
    unsafe {
        core::ptr::copy_nonoverlapping(rp_id, rp.as_mut_ptr(), rp_id_len);
        core::ptr::copy_nonoverlapping(cred_id, id.as_mut_ptr(), CRED_ID_LEN);
    }
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(&rp[..rp_id_len]);
    let digest = h.finalize();
    let mut rp_id_hash = [0u8; HASH_LEN];
    rp_id_hash.copy_from_slice(&digest);
    // 0 = not ours. Otherwise 1 + the credProtect level baked into the
    // id, so Non-secure can tell a level-3 credential -- unusable in an
    // allowList without UV -- from one it can use, and offer Secure a
    // second candidate. The id carries the level under the MAC, so this
    // reveals nothing a holder of the id could not already compute.
    match recover_credential(&rp_id_hash, &id) {
        Some(c) => 1 + c.cred_protect,
        None => 0,
    }
}

/// Test-only: raw register/line values behind the sampler's decision.
#[cfg(feature = "dev-escape")]
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_up_probe() -> u32 {
    flash::with_core1_parked(bootsel::probe)
}

/// Test-only: read the button directly, bypassing the gesture logic.
#[cfg(feature = "dev-escape")]
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_up_raw() -> u8 {
    u8::from(upgate::raw_pressed())
}

/// Secure-gateway veneer: CTAP2 authenticatorSelection.
///
/// The whole command is "is a user at this device right now" -- which
/// is a presence question and therefore a Secure one. The gesture is
/// consumed exactly as MakeCredential consumes it.
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_ctap_selection(out: *mut u8, out_cap: usize) -> usize {
    begin_command();
    if !ns_writable(out, out_cap) {
        return 0;
    }
    let status = if upgate::consume() {
        ctap::CTAP2_OK
    } else {
        ctap::CTAP2_ERR_UP_REQUIRED
    };
    let mut resp = [0u8; 4];
    let n = ctap::error(status, &mut resp).min(out_cap);
    // SAFETY: `out` hardware-confirmed NS-writable for out_cap bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(resp.as_ptr(), out, n);
    }
    n
}

/// Secure-gateway veneer: CTAP2 authenticatorConfig (setMinPINLength).
///
/// Request layout: subCommand(1) | auth_len(1) | auth(32) |
/// params_len(2) | params(...) | new_len(1) | have_new(1) |
/// force(1) | have_force(1) | rp_count(1) | rp_ids(4 x (1+128)).
///
/// The raw subCommandParams bytes travel alongside the parsed fields
/// because the pinUvAuthParam is computed over them verbatim -- NS
/// cannot re-encode them and expect the MAC to match.
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_ctap_config(
    req: *const u8,
    req_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> usize {
    begin_command();
    if req_len != ctap::CONFIG_REQ_LEN
        || !ns_readable(req, ctap::CONFIG_REQ_LEN)
        || !ns_writable(out, out_cap)
    {
        return 0;
    }
    let mut buf = [0u8; ctap::CONFIG_REQ_LEN];
    // SAFETY: span hardware-confirmed NS-readable.
    unsafe {
        core::ptr::copy_nonoverlapping(req, buf.as_mut_ptr(), ctap::CONFIG_REQ_LEN);
    }
    let mut resp = [0u8; 8];
    let status = ctap::handle_config(&buf);
    let n = ctap::error(status, &mut resp).min(out_cap);
    // SAFETY: `out` hardware-confirmed NS-writable.
    unsafe {
        core::ptr::copy_nonoverlapping(resp.as_ptr(), out, n);
    }
    n
}

/// Secure-gateway veneer: CTAP2 authenticatorCredentialManagement.
///
/// Enumeration cursors live in Secure, not in the request: an index
/// supplied by NS would let it walk the credential store one entry at a
/// time regardless of what the relying party asked for.
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_ctap_cred_mgmt(
    req: *const u8,
    req_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> usize {
    clear_assert_state();
    if req_len != ctap::CM_REQ_LEN
        || !ns_readable(req, ctap::CM_REQ_LEN)
        || !ns_writable(out, out_cap)
    {
        return 0;
    }
    let mut buf = [0u8; ctap::CM_REQ_LEN];
    // SAFETY: span hardware-confirmed NS-readable.
    unsafe {
        core::ptr::copy_nonoverlapping(req, buf.as_mut_ptr(), ctap::CM_REQ_LEN);
    }
    let mut resp = [0u8; ctap::RESP_MAX];
    let mut pk = [0u8; ctap::MLDSA_PK_MAX];

    // Rebuilding a credential's public key needs the master key, so the
    // enumeration hands that step back to us rather than exporting
    // anything.
    //
    // The publicKey an enumeration entry carries for a HYBRID credential
    // is its classical ES256 half, deliberately, and this matches the C
    // and Rust ports (credential_management.c, ctap2.rs's
    // es256_cose_public_key). CTAP 2.1 sec. 6.8.3 permits either the full
    // composite key or the classical component, and the conformance
    // suite accepts both. The full key was tried here on
    // 2026-09-02 and reverted the same day: it costs an ML-DSA keygen
    // (~1 s) per enumerated credential, makes the reply ~2.2 KB instead
    // of ~300 B, and put this port at odds with the other two -- and the
    // client's credentialManagement buffer could not receive it. Whether a management UI should be able to tell a post-quantum
    // credential from an ES256 one via this field is a policy question
    // for all three ports together, not a fix for one.
    //
    // The scratch buffer stays in the closure's signature so enabling
    // the full key is a one-line change if that decision is made.
    let lookup = |rp: &[u8; HASH_LEN], id: &[u8; CRED_ID_LEN], _scratch: &mut [u8]| {
        let cred = recover_credential(rp, id)?;
        let (x, y) = cred.public_xy()?;
        Some((x, y, 0usize))
    };
    let n = match ctap::handle_cred_mgmt(&buf, &mut resp, &lookup, &mut pk[..]) {
        ctap::CmReply::Err(status) => ctap::error(status, &mut resp),
        ctap::CmReply::Bytes(n) => n,
    };

    let n = n.min(out_cap);
    // SAFETY: `out` hardware-confirmed NS-writable.
    unsafe {
        core::ptr::copy_nonoverlapping(resp.as_ptr(), out, n);
    }
    n
}

/// Secure-gateway veneer: CTAP2 authenticatorClientPIN.
///
/// The whole subcommand set is Secure-side because every piece of it
/// -- shared secret, PIN hash, retry counter, pinUvAuthToken -- undoes
/// the PIN if NS can reach it. The retry counter especially: rolling
/// it back turns eight guesses into unlimited ones.
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_ctap_client_pin(
    req: *const u8,
    req_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> usize {
    begin_command();
    if req_len != clientpin::PIN_REQ_LEN
        || !ns_readable(req, clientpin::PIN_REQ_LEN)
        || !ns_writable(out, out_cap)
    {
        return 0;
    }
    let mut buf = [0u8; clientpin::PIN_REQ_LEN];
    // SAFETY: span hardware-confirmed NS-readable for PIN_REQ_LEN.
    unsafe {
        core::ptr::copy_nonoverlapping(req, buf.as_mut_ptr(), clientpin::PIN_REQ_LEN);
    }
    let mut resp = [0u8; 256];
    let n = match clientpin::handle_raw(&buf) {
        clientpin::PinReply::Err(status) => ctap::error(status, &mut resp),
        clientpin::PinReply::Ok => ctap::error(ctap::CTAP2_OK, &mut resp),
        clientpin::PinReply::Retries(r) => ctap::pin_retries(r, &mut resp).unwrap_or(0),
        clientpin::PinReply::KeyAgreement(x, y) => {
            ctap::pin_key_agreement(&x, &y, &mut resp).unwrap_or(0)
        }
        clientpin::PinReply::Token(t) => ctap::pin_token(&t, &mut resp).unwrap_or(0),
    };
    let n = n.min(out_cap);
    // SAFETY: `out` hardware-confirmed NS-writable for out_cap bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(resp.as_ptr(), out, n);
    }
    n
}

/// Secure-gateway veneer: open a user-presence window.
///
/// NS cannot decide user presence -- if it could, a compromised NS
/// would sign anything with keys it can never read. It only drives the
/// timing: `begin`, then poll while pumping USB, because the wait is
/// seconds long and the host needs KEEPALIVE frames in the meantime.
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_up_begin() {
    upgate::begin();
}

/// Secure-gateway veneer: sample the button and report progress.
///
/// 0 pending, 1 confirmed, 2 timed out. Takes no pointers.
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_up_poll() -> u8 {
    upgate::poll()
}

/// Test-only: simulate a press, so the gate can be exercised from both
/// sides without a finger on the board. Additive -- the real sampler
/// still runs -- and behind `dev-escape` with the other weakenings.
#[cfg(feature = "dev-escape")]
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_up_inject(mode: u8) {
    match mode {
        // 1 / 2: latch presence on or off, for conformance suites that
        // cannot press a button. 0 (or anything else): one simulated
        // touch, which is what the gate was validated with.
        1 => upgate::set_auto(true),
        2 => upgate::set_auto(false),
        _ => upgate::inject_press(),
    }
}

/// Secure-gateway veneer (M4e): CTAP2 authenticatorMakeCredential.
///
/// In:  a fixed-layout [`ctap::Request`] buffer built by NS.
/// Out: status byte followed by the attestation object CBOR.
///
/// NS parses the request CBOR and passes copied values; Secure hashes
/// the rp id, derives the key, and builds the `authData` that gets
/// signed. Building `authData` here is the point -- letting NS build it
/// would let NS choose what a Secure key attests to.
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_ctap_make_credential(
    req: *const u8,
    req_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> usize {
    if req_len != ctap::REQ_LEN || !ns_readable(req, ctap::REQ_LEN) || !ns_writable(out, out_cap) {
        return 0;
    }
    let mut buf = [0u8; ctap::REQ_LEN];
    // SAFETY: span hardware-confirmed NS-readable for REQ_LEN bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(req, buf.as_mut_ptr(), ctap::REQ_LEN);
    }
    let mut resp = [0u8; ctap::RESP_MAX];
    begin_command();

    // M4g: no signature without a gesture. Checked here, inside Secure,
    // against a confirmation only Secure can produce -- and consumed,
    // so one touch authorises one operation.
    if !upgate::consume() {
        let n = ctap::error(ctap::CTAP2_ERR_UP_REQUIRED, &mut resp).min(out_cap);
        // SAFETY: `out` hardware-confirmed NS-writable for out_cap.
        unsafe {
            core::ptr::copy_nonoverlapping(resp.as_ptr(), out, n);
        }
        return n;
    }

    let n = match ctap::parse(&buf) {
        None => ctap::error(ctap::CTAP2_ERR_INVALID_PARAMETER, &mut resp),
        // Resolve user verification before anything is minted. The UV
        // bit goes into signed authenticator data, so it has to be
        // decided from a pinUvAuthParam checked here -- not from the
        // `options.uv` the client asked for, which is what used to
        // reach the signature.
        Some(mut r) => match ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL) {
            Err(status) => ctap::error(status, &mut resp),
            // makeCredUvNotRqd exempts only NON-discoverable credentials.
            // A discoverable one can be asserted with no allowList, so
            // minting it on presence alone would let anyone holding the
            // device sign in silently; once a PIN exists it requires UV
            // (CTAP 2.1 sec. 6.1.2 step 9). C and Rust have this gate; this
            // port did not, so a PIN-protected token minted passkeys with
            // no PIN presented.
            Ok(()) if r.rk && !r.uv && clientpin::pin_is_set() => {
                ctap::error(ctap::CTAP2_ERR_PUAT_REQUIRED, &mut resp)
            }
            Ok(()) => {
                let alg = if r.hybrid { ALG_HYBRID } else { ALG_ES256 };
                match new_credential(&r.rp_id_hash, alg, r.cred_protect) {
                    None => ctap::error(ctap::CTAP2_ERR_INVALID_PARAMETER, &mut resp),
                    Some((cred, cred_id)) => match cred.public_xy() {
                        None => ctap::error(ctap::CTAP2_ERR_INVALID_PARAMETER, &mut resp),
                        Some((x, y)) => {
                            // Derived only for a hybrid credential: keygen
                            // is the expensive half of ML-DSA and an ES256
                            // credential has no use for the result.
                            let mut pk = [0u8; ctap::MLDSA_PK_MAX];
                            let pk_len = if alg == ALG_HYBRID {
                                mldsa_public(&cred, &mut pk).unwrap_or(0)
                            } else {
                                0
                            };
                            if alg == ALG_HYBRID && pk_len == 0 {
                                ctap::error(ctap::CTAP2_ERR_INVALID_PARAMETER, &mut resp)
                            } else if r.rk
                                && !credstore::store(
                                    &r.rp_id_hash,
                                    &cred_id,
                                    &r.user_id[..r.user_id_len],
                                    &r.rp_id[..r.rp_id_len],
                                    &r.cred_blob[..r.cred_blob_len],
                                    &r.name[..r.name_len],
                                    &r.display[..r.display_len],
                                    r.cred_protect,
                                )
                            {
                                // Asked for a discoverable credential and we
                                // cannot keep it. Returning the credential
                                // anyway would be worse than refusing: the
                                // client would believe it is discoverable
                                // and never send it in an allowList again.
                                ctap::error(ctap::CTAP2_ERR_KEY_STORE_FULL, &mut resp)
                            } else {
                                match ctap::make_credential(
                                    &r,
                                    &cred_id,
                                    &x,
                                    &y,
                                    &pk[..pk_len],
                                    // A blob only survives on a resident
                                    // credential -- there is nowhere else
                                    // to keep it -- so say so honestly
                                    // rather than echo an unconditional
                                    // true.
                                    if r.cred_blob_len > 0 {
                                        Some(r.rk)
                                    } else {
                                        None
                                    },
                                    r.want_hmac_secret,
                                    &mut resp,
                                ) {
                                    Some(n) => n,
                                    None => {
                                        ctap::error(ctap::CTAP2_ERR_INVALID_PARAMETER, &mut resp)
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
    };

    let n = n.min(out_cap);
    // SAFETY: `out` hardware-confirmed NS-writable for out_cap bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(resp.as_ptr(), out, n);
    }
    n
}

/// Secure-gateway veneer (M4e): CTAP2 authenticatorGetAssertion.
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_ctap_get_assertion(
    req: *const u8,
    req_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> usize {
    if req_len != ctap::REQ_LEN || !ns_readable(req, ctap::REQ_LEN) || !ns_writable(out, out_cap) {
        return 0;
    }
    let mut buf = [0u8; ctap::REQ_LEN];
    // SAFETY: span hardware-confirmed NS-readable for REQ_LEN bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(req, buf.as_mut_ptr(), ctap::REQ_LEN);
    }
    let mut resp = [0u8; ctap::RESP_MAX];
    begin_command();

    // M4g: same gate as MakeCredential. An assertion is a signature
    // over a challenge the relying party chose, so it needs a gesture
    // every bit as much as registration does.
    if !upgate::consume() {
        let n = ctap::error(ctap::CTAP2_ERR_UP_REQUIRED, &mut resp).min(out_cap);
        // SAFETY: `out` hardware-confirmed NS-writable for out_cap.
        unsafe {
            core::ptr::copy_nonoverlapping(resp.as_ptr(), out, n);
        }
        return n;
    }

    let n = match ctap::parse(&buf) {
        None => ctap::error(ctap::CTAP2_ERR_INVALID_PARAMETER, &mut resp),
        // Same as MakeCredential: the UV bit is signed, so it is
        // decided here from a verified pinUvAuthParam rather than
        // from the client's own options.uv.
        Some(mut r) => match ctap::resolve_uv(&mut r, clientpin::PERM_GET_ASSERTION) {
            Err(status) => ctap::error(status, &mut resp),
            Ok(()) => {
                ctap::choose_allow_list_credential(&mut r);
                // No allowList means the client expects a discoverable
                // credential. Look one up before trying to recover the id
                // it did not send.
                let mut resident: Option<([u8; credstore::MAX_USER_ID], usize, usize)> = None;
                if !r.have_allow_list {
                    // Discovery surfaces only what credProtect allows for a
                    // request with this UV state: a level-2 or level-3
                    // credential is invisible here without UV. The count
                    // uses the same filter, or numberOfCredentials would
                    // promise assertions GetNextAssertion then refuses.
                    match credstore::nth_discoverable(&r.rp_id_hash, 0, r.uv) {
                        Some(found) => {
                            r.cred_id = found.cred_id;
                            let total = credstore::count_discoverable(&r.rp_id_hash, r.uv);
                            resident = Some((found.user_id, found.user_id_len, total));
                            if total > 1 {
                                // SAFETY: single-threaded; Secure-only.
                                unsafe {
                                    ASSERT_STATE = Some(AssertState {
                                        rp_id_hash: r.rp_id_hash,
                                        client_data_hash: r.client_data_hash,
                                        uv: r.uv,
                                        next: 1,
                                        total,
                                    });
                                }
                            }
                        }
                        None => {
                            let n =
                                ctap::error(ctap::CTAP2_ERR_NO_CREDENTIALS, &mut resp).min(out_cap);
                            // SAFETY: `out` NS-writable for out_cap bytes.
                            unsafe {
                                core::ptr::copy_nonoverlapping(resp.as_ptr(), out, n);
                            }
                            return n;
                        }
                    }
                }
                match recover_credential(&r.rp_id_hash, &r.cred_id) {
                    // Not ours, or not for this relying party. Same answer
                    // either way -- distinguishing them would tell a caller
                    // which credential ids this token issued.
                    None => ctap::error(ctap::CTAP2_ERR_NO_CREDENTIALS, &mut resp),
                    // Ours, but its credProtect policy forbids this request: a
                    // level-3 credential named in an allowList with no UV. The
                    // policy was stored at MakeCredential, echoed to the relying
                    // party as applied, and until now never consulted here. Same
                    // answer as "not ours" so the refusal reveals nothing about
                    // which ids this token holds. The level comes from the
                    // credential id, so this holds for non-resident credentials
                    // too -- the first version looked the policy up in the store
                    // and so enforced nothing for the credentials that are not in
                    // it, which is most of them.
                    Some(cred)
                        if !credstore::policy_allows(
                            cred.cred_protect,
                            r.uv,
                            r.have_allow_list,
                        ) =>
                    {
                        ctap::error(ctap::CTAP2_ERR_NO_CREDENTIALS, &mut resp)
                    }
                    Some(cred) => {
                        let mut auth = [0u8; 256];
                        let mut msg = [0u8; 320];
                        // credBlob comes back only for a credential that has
                        // one, and only when the client asked.
                        let blob = if r.want_cred_blob {
                            credstore::find_by_id(&r.cred_id)
                        } else {
                            None
                        };
                        let blob_ref = blob
                            .as_ref()
                            .filter(|b| b.blob_len > 0)
                            .map(|b| &b.blob[..b.blob_len]);
                        // hmac-secret: evaluated here, from a per-credential
                        // secret derived inside Secure. The salts arrive
                        // encrypted under the PIN shared secret and the output
                        // goes back the same way.
                        let mut hs_buf = [0u8; 64];
                        let mut hs_len = 0usize;
                        if r.want_hmac_secret && r.hs_salt_len > 0 {
                            match clientpin::hmac_secret(
                                &cred.cred_random(),
                                &r.hs_kx,
                                &r.hs_ky,
                                &r.hs_salt[..r.hs_salt_len],
                                &r.hs_auth[..r.hs_auth_len],
                            ) {
                                Ok(v) => {
                                    hs_len = v.len().min(64);
                                    hs_buf[..hs_len].copy_from_slice(&v[..hs_len]);
                                }
                                Err(_) => hs_len = 0,
                            }
                        }
                        let hs_ref = if hs_len > 0 {
                            Some(&hs_buf[..hs_len])
                        } else {
                            None
                        };
                        match ctap::assertion_signed_message(
                            &r, blob_ref, hs_ref, &mut auth, &mut msg,
                        ) {
                            None => ctap::error(ctap::CTAP2_ERR_INVALID_PARAMETER, &mut resp),
                            Some((alen, mlen)) => {
                                // For a hybrid credential this is
                                // ecdsa_der || mldsa_sig, produced on Secure-only
                                // core 1; the algorithm comes from the
                                // authenticated credential id, not the caller.
                                let mut sig = [0u8; ctap::SIG_MAX];
                                match sign_with_credential(&cred, &msg[..mlen], &mut sig) {
                                    None => {
                                        ctap::error(ctap::CTAP2_ERR_INVALID_PARAMETER, &mut resp)
                                    }
                                    Some(slen) => match ctap::get_assertion(
                                        &r.cred_id,
                                        &auth[..alen],
                                        &sig[..slen],
                                        resident.as_ref().map(|(u, l, _)| &u[..*l]),
                                        resident.as_ref().map(|(_, _, total)| *total),
                                        &mut resp,
                                    ) {
                                        Some(n) => n,
                                        None => ctap::error(
                                            ctap::CTAP2_ERR_INVALID_PARAMETER,
                                            &mut resp,
                                        ),
                                    },
                                }
                            }
                        }
                    }
                }
            }
        },
    };

    let n = n.min(out_cap);
    // SAFETY: `out` hardware-confirmed NS-writable for out_cap bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(resp.as_ptr(), out, n);
    }
    n
}

/// Dev escape hatch: hands-free recovery from a broken Non-secure image.
///
/// `sg_reboot_bootsel` only helps if NS gets far enough to serve USB. An
/// NS image that faults before enumerating, or wedges in USB bring-up,
/// would otherwise be recoverable only with the physical BOOTSEL button
/// -- which is exactly the failure that makes unattended TrustZone
/// bring-up impossible.
///
/// So the Secure world runs a dead-man's switch across resets:
///
///   1. Secure boots, reads a magic+counter from watchdog SCRATCH7
///      (SCRATCH registers survive a watchdog reset).
///   2. At [`ESCAPE_MAX_TRIES`] consecutive unhealthy boots it stops
///      launching NS at all and drops straight to BOOTSEL.
///   3. Otherwise it increments the counter, arms the watchdog, and
///      launches NS.
///   4. NS calls [`sg_healthy`] once USB has enumerated; that clears the
///      counter and disables the watchdog.
///
/// A hung NS therefore costs three watchdog resets and lands in BOOTSEL
/// on its own, with no hands. Recovery is Secure-side and needs nothing
/// from NS, which is the whole point.
#[cfg(feature = "dev-escape")]
mod escape {
    use super::hal;
    use hal::watchdog::ScratchRegister::Scratch7;

    /// Tag the counter so unrelated scratch contents (a cold boot, or
    /// another image's leftovers) read as "no attempts yet".
    const ESCAPE_MAGIC: u32 = 0x5a3c_0000;
    const ESCAPE_MASK: u32 = 0xffff_0000;
    /// Boots to allow before giving up on NS. Three rides out a one-off
    /// enumeration hiccup without making a genuinely broken image take
    /// visibly long to recover.
    const ESCAPE_MAX_TRIES: u32 = 3;
    /// Long enough for clocks, SAU, NS start-up and USB enumeration;
    /// short enough that three of them is a few seconds, not a minute.
    ///
    /// Measured on a Feitian RP2350: the NS image reaches Configured at
    /// ~1.2 s, so this leaves ~6 s of headroom for M4's heavier NS
    /// bring-up. Recovery costs ~25 s. Do not raise much further --
    /// hal's `Watchdog::start` panics above 0xFFFFFF/2 us (~8.39 s).
    const ESCAPE_WINDOW_MS: u32 = 7_000;

    /// Step the boot counter. Returns true when NS has failed to check
    /// in too many times and the caller should go to BOOTSEL instead of
    /// launching it again.
    pub fn note_boot(watchdog: &mut hal::Watchdog) -> bool {
        let raw = watchdog.read_scratch(Scratch7);
        let tries = if raw & ESCAPE_MASK == ESCAPE_MAGIC {
            raw & !ESCAPE_MASK
        } else {
            0
        };
        if tries >= ESCAPE_MAX_TRIES {
            // Clear first: BOOTSEL must be a one-shot, or the board
            // would come back into recovery after being reflashed.
            watchdog.write_scratch(Scratch7, 0);
            return true;
        }
        watchdog.write_scratch(Scratch7, ESCAPE_MAGIC | (tries + 1));
        false
    }

    /// Arm the dead-man's switch immediately before the NS launch.
    pub fn arm(watchdog: &mut hal::Watchdog) {
        watchdog.start(hal::fugit::MicrosDurationU32::millis(ESCAPE_WINDOW_MS));
    }

    /// NS reached a healthy state: disarm, and forget the attempts.
    pub fn healthy(watchdog: &mut hal::Watchdog) {
        watchdog.disable();
        watchdog.write_scratch(Scratch7, 0);
    }

    /// Reboot into BOOTSEL. Diverges.
    pub fn to_bootsel() -> ! {
        hal::reboot::reboot(
            hal::reboot::RebootKind::BootSel {
                picoboot_disabled: false,
                msd_disabled: false,
            },
            hal::reboot::RebootArch::Normal,
        )
    }
}

/// The Secure world's watchdog handle, retained past `main` so the
/// escape veneers can disarm the dead-man's switch.
#[cfg(feature = "dev-escape")]
static mut ESCAPE_WATCHDOG: Option<hal::Watchdog> = None;

/// Dev escape hatch: NS reports itself healthy (USB enumerated).
///
/// Disarms the dead-man's switch described on [`escape`]. Takes no
/// pointers, so there is nothing to range-check; the worst a hostile NS
/// can do by calling it is keep its own recovery from firing.
#[cfg(feature = "dev-escape")]
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_healthy() {
    // SAFETY: single-threaded; initialised in `main` before NS runs.
    unsafe {
        if let Some(wd) = (&mut *(&raw mut ESCAPE_WATCHDOG)).as_mut() {
            escape::healthy(wd);
        }
    }
}

/// Dev escape hatch -- reboot into BOOTSEL from the Secure world.
///
/// The TrustZone image has no CDC console and no CTAP2 stack, so
/// without this the only way out is the physical BOOTSEL button and a
/// power cycle. That makes every bring-up iteration a hands-on event,
/// which is why this lands before M4 rather than after it.
///
/// Deliberately NOT user-presence gated: hands-free iteration is the
/// entire point. That makes it a genuine hole in the Secure world's
/// posture -- NS can reach BOOTSEL and from there rewrite flash -- so it
/// is behind the default-off `dev-escape` feature and must never be
/// enabled in an image whose Secure world is meant to hold real keys.
///
/// Diverges: the chip re-enumerates as a mass-storage/PICOBOOT device.
#[cfg(feature = "dev-escape")]
#[no_mangle]
pub extern "C-cmse-nonsecure-entry" fn sg_reboot_bootsel() {
    escape::to_bootsel()
}

/// Fail-closed check that the Secure secrets really are unreachable
/// from the Non-secure world.
///
/// The SAU is programmed from constants a few hundred lines below, and
/// an off-by-one in a limit address is both easy to write and invisible
/// -- nothing misbehaves, NS simply gains the ability to read a key. So
/// rather than trust the constants, ask the hardware: `TestTarget` is
/// the same primitive the M5 veneer checks use, and it answers for the
/// SAU as actually programmed.
///
/// Refuses to launch NS if either secret is reachable. A token that does
/// not come up is a bug report; a token that comes up and quietly leaks
/// its master key is not.
fn secrets_unreachable_from_ns() -> bool {
    // The key sector, through the XIP window.
    const STORE_ADDR: *const u8 = 0x101F_F000 as *const u8;
    // SAFETY: address-only test; TestTarget does not dereference.
    if ns_readable(STORE_ADDR, 4096) {
        return false;
    }
    // The live copy in Secure RAM.
    let key_ptr = &raw const MASTER_KEY as *const u8;
    if ns_readable(key_ptr, 32) {
        return false;
    }
    // M4f: the core-1 mailbox. It carries the ECDSA scalar and the
    // ML-DSA seed as *inputs*, so an NS-reachable mailbox would hand
    // over every credential's private key -- and worse, let NS forge
    // requests to a core running with Secure privilege. Design point 3
    // says the mailbox must move into Secure RAM; this is the assertion
    // that it actually did.
    let mbox = &signer::CORE1_SIGNER as *const _ as *const u8;
    if ns_readable(mbox, core::mem::size_of_val(&signer::CORE1_SIGNER)) {
        return false;
    }
    true
}

// Base address the Non-secure image is linked at; its vector table
// sits at the very start. Provided by the linker script
// (`memory-secure.x`), kept in sync with `fw-nonsecure`.
extern "C" {
    static _ns_image_base: u32;
}

/// RP2350 crystal on all supported boards.
const XTAL_FREQ_HZ: u32 = 12_000_000;

#[hal::entry]
fn main() -> ! {
    let mut core = cortex_m::Peripherals::take().unwrap();
    let mut pac = hal::pac::Peripherals::take().unwrap();

    // --- Clocks (Secure-owned) ---
    // Set up XOSC + PLLs + the clock generators, including clk_usb
    // (48 MHz from PLL_USB). Without this the USB controller has no
    // clock, so it never completes reset -- the M2a hang. Clock setup
    // stays entirely in the Secure world (the NS side just uses the
    // running clocks). This is the same bring-up the FIDO firmware does.
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);
    let _clocks = hal::clocks::init_clocks_and_plls(
        XTAL_FREQ_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .ok()
    .unwrap();

    // --- Dev escape: dead-man's switch (see `escape`) ---
    // Before anything else can wedge, decide whether the previous boots
    // failed to check in. Done after clocks so the watchdog counts at a
    // known rate, and before the LED/SAU work so a wedge there is
    // recoverable too.
    #[cfg(feature = "dev-escape")]
    if escape::note_boot(&mut watchdog) {
        escape::to_bootsel();
    }
    // Arm here, not just before the NS handoff: everything below --
    // TRNG collection, a flash write, SAU programming -- can hang, and
    // until the watchdog is running none of it is recoverable.
    #[cfg(feature = "dev-escape")]
    escape::arm(&mut watchdog);

    // --- Heap, before anything can allocate ---
    {
        use core::mem::MaybeUninit;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        // SAFETY: sole initialisation, before any allocation and before
        // the NS world exists.
        unsafe {
            HEAP.init((&raw const HEAP_MEM) as usize, HEAP_SIZE);
        }
    }

    // --- M4c: master key, from the Secure-only TRNG ---
    // Generated here, before the NS world exists, and never leaves this
    // image. The TRNG peripheral is not in ACCESSCTRL's NS allow-list,
    // so NS cannot read the entropy source either.
    //
    // M4d: persisted in a Secure-only flash sector, so credentials
    // survive a reset. Minted from the TRNG only on first boot.
    let mut secure_trng = trng::Trng::new(pac.TRNG);
    // SAFETY: sole writer, before the NS world exists.
    unsafe {
        let key = &mut *(&raw mut MASTER_KEY);
        if !keystore::load(key) {
            // First boot on this board (or a blank/failed sector):
            // mint a key and persist it, so credentials issued now
            // still verify after a reset.
            secure_trng.fill(key);
            keystore::store(key);
        }
        SECURE_TRNG = Some(secure_trng);
    }
    // Resume the signature counter and reserve a block. After the key
    // store, because both live in Secure flash and this one wants the
    // key sector already settled.
    counter::init();
    pinstore::init();
    // SAFETY: single-threaded; the TRNG is live from a few lines above.
    unsafe {
        if let Some(t) = (&mut *(&raw mut SECURE_TRNG)).as_mut() {
            clientpin::init(t);
        }
    }

    // --- Claim the LED (Secure-owned) ---
    let mut sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );
    let mut led = pins.gpio25.into_push_pull_output();
    let _ = led.set_low(); // off (active-high)
                           // SAFETY: sole writer, before the NS world exists.
    unsafe {
        LED = Some(led);
    }

    // --- M4f: launch core 1 as a Secure-only signing worker ---
    // Started before the SAU is programmed and long before the NS world
    // exists, so core 1 never executes a single Non-secure instruction.
    // Both cores reset into Secure state and core 1's own SAU is left
    // disabled, which on Armv8-M means every address is Secure to it --
    // what a core handling raw key material should see. The mailbox it
    // polls is in Secure RAM for the same reason: it carries the ECDSA
    // scalar and the ML-DSA seed as inputs.
    {
        let mut mc = hal::multicore::Multicore::new(&mut pac.PSM, &mut pac.PPB, &mut sio.fifo);
        let cores = mc.cores();
        let core1 = &mut cores[1];
        let stack = signer::CORE1_STACK
            .take()
            .expect("core1 stack already taken");
        core1
            .spawn(stack, || signer::CORE1_SIGNER.worker())
            .expect("core1 spawn");
        // From here on, anything that suspends XIP must park core 1.
        flash::note_core1_running();
    }

    // --- Program the SAU (datasheet sec. 3.7; docs/TRUSTZONE.md map) ---
    // Regions carve the upper flash + upper RAM out as Non-secure, and
    // the veneer window as Non-secure-Callable. Everything not covered
    // by an SAU region stays Secure (SAU_CTRL.ALLNS = 0).
    let sau = &mut core.SAU;
    // Region 0: Non-secure flash -- the NS image lives here (kept in the
    // low 2 MiB; see memory-secure.x for why).
    //
    // The limit stops at 0x101EFFFF, matching memory-nonsecure.x exactly.
    // It used to run to 0x101FFFFF, 64 KiB past the end of the NS image
    // region -- harmless while nothing lived there, but M4d puts the
    // Secure key store in that top sector, and an SAU region covering it
    // would have let NS read the master key straight out of flash.
    sau.set_region(
        0,
        SauRegion {
            base_address: 0x1010_0000,
            limit_address: 0x101E_FFFF,
            attribute: SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();
    // Region 1: Non-secure RAM (upper 64 KiB). Was 256 KiB from
    // 0x20040000; M4f moved the boundary up so the Secure world can host
    // the ML-DSA heap and core 1's stack. Must match memory-nonsecure.x.
    sau.set_region(
        1,
        SauRegion {
            base_address: 0x2007_0000,
            limit_address: 0x2007_FFFF,
            attribute: SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();
    // Region 2: the veneer window -- Non-secure-Callable, so NS code can
    // execute the SG instruction that fronts each gateway. Sits at the
    // top of the Secure flash region (0x100F0000), just below NS flash.
    sau.set_region(
        2,
        SauRegion {
            base_address: 0x100F_0000,
            limit_address: 0x100F_FFFF,
            attribute: SauRegionAttribute::NonSecureCallable,
        },
    )
    .unwrap();
    // Region 3 (M2a): the USB controller window (DPRAM 0x50100000 +
    // registers 0x50110000) -- Non-secure, so the NS world can drive
    // USB. SAU attribution alone isn't enough; ACCESSCTRL must also
    // grant NS access (below).
    sau.set_region(
        3,
        SauRegion {
            base_address: 0x5010_0000,
            limit_address: 0x5011_FFFF,
            attribute: SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();
    // Regions 4 & 5 (M2b, Path A): the CLOCKS and RESETS peripheral
    // windows (each a 16 KiB slot incl. the atomic SET/CLR/XOR aliases)
    // -- Non-secure, so the NS USB stack can build a UsbClock token via
    // ClocksManager::new and let hal `UsbBus::new` reset the USB block.
    // This is a DoS-class widening of NS (it can reset peripherals /
    // reconfigure clocks) but NEVER a confidentiality one -- keys and
    // crypto stay Secure. See docs/TRUSTZONE.md "Open decision (M2b)";
    // to be tightened in M5.
    sau.set_region(
        4,
        SauRegion {
            base_address: 0x4001_0000, // CLOCKS
            limit_address: 0x4001_3FFF,
            attribute: SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();
    sau.set_region(
        5,
        SauRegion {
            base_address: 0x4002_0000, // RESETS
            limit_address: 0x4002_3FFF,
            attribute: SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();
    sau.enable();

    // --- USB -> Non-secure (M2a) ---
    // Take the USB controller out of reset (Secure owns RESETS): clear
    // its reset bit, then wait for RESET_DONE. (The HAL's SubsystemReset
    // helper is private, so drive RESETS directly.)
    pac.RESETS.reset().modify(|_, w| w.usbctrl().clear_bit());
    while pac.RESETS.reset_done().read().usbctrl().bit_is_clear() {}

    // Open USB to the Non-secure world in ACCESSCTRL. Every ACCESSCTRL
    // register write MUST carry the 0xACCE password in the top 16 bits
    // (RP2350 datasheet sec. 10.6) or the hardware silently ignores it -- a
    // missing password is exactly what left NS unable to reach USB on
    // the first M2a attempt. Value 0x3A = CORE0|CORE1|SP|NSP: both
    // cores at Secure- and Non-secure-Privileged; DBG/DMA/SU/NSU
    // denied. Everything else (TRNG/OTP/SHA-256) stays Secure-only.
    const ACCESSCTRL_PW: u32 = 0xACCE_0000;
    const NS_ACCESS: u32 = (1 << 4) | (1 << 5) | (1 << 3) | (1 << 1); // CORE0|CORE1|SP|NSP
    pac.ACCESSCTRL
        .usbctrl()
        .write(|w| unsafe { w.bits(ACCESSCTRL_PW | NS_ACCESS) });
    // M2b (Path A): also open CLOCKS + RESETS to NS so its USB stack can
    // mint a UsbClock token and reset the USB block. Same DoS-class /
    // not-confidentiality tradeoff as the SAU regions above.
    pac.ACCESSCTRL
        .clocks()
        .write(|w| unsafe { w.bits(ACCESSCTRL_PW | NS_ACCESS) });
    pac.ACCESSCTRL
        .resets()
        .write(|w| unsafe { w.bits(ACCESSCTRL_PW | NS_ACCESS) });

    // --- SCB AIRCR: make faults / priorities NS-world-friendly ---
    // Set PRIS (bit 14, Non-secure priorities are deprioritised) and
    // BFHFNMINS (bit 13, BusFault/HardFault/NMI target Non-secure).
    // AIRCR writes require the VECTKEY (0x05FA) in the top half.
    const AIRCR: *mut u32 = 0xE000_ED0C as *mut u32;
    const AIRCR_VECTKEY: u32 = 0x05FA << 16;
    const AIRCR_PRIS: u32 = 1 << 14;
    const AIRCR_BFHFNMINS: u32 = 1 << 13;
    // SAFETY: architected SCB register; single write during bring-up.
    unsafe {
        let cur = AIRCR.read_volatile() & 0x0000_FFFF & !AIRCR_VECTKEY;
        AIRCR.write_volatile(AIRCR_VECTKEY | cur | AIRCR_PRIS | AIRCR_BFHFNMINS);
    }

    // --- Dev escape: arm before we lose control to NS ---
    // From here on the Secure world only runs when NS calls a veneer, so
    // this is the last chance to start the timer that recovers a broken
    // NS image.
    #[cfg(feature = "dev-escape")]
    {
        // Already armed at the top of main; just hand the timer to the
        // veneers so NS can check in.
        escape::arm(&mut watchdog); // restart the window for NS bring-up
                                    // SAFETY: sole writer, before the NS world exists.
        unsafe {
            ESCAPE_WATCHDOG = Some(watchdog);
        }
    }

    // --- Refuse to launch NS if the secrets are exposed ---
    if !secrets_unreachable_from_ns() {
        #[cfg(feature = "dev-escape")]
        escape::to_bootsel();
        #[cfg(not(feature = "dev-escape"))]
        loop {
            cortex_m::asm::wfe();
        }
    }

    // --- Hand off to the Non-secure world ---
    // The NS vector table sits at `_ns_image_base`: word 0 is the
    // initial NS MSP, word 1 the NS reset vector. Set the NS VTOR, load
    // MSP_NS, then BXNS into the NS reset handler (clearing the Thumb
    // bit -- bx_ns sets it).
    let ns_base = &raw const _ns_image_base as u32;
    // SAFETY: reading the NS image's own vector table from flash it is
    // linked into, then performing the architected S->NS transition.
    unsafe {
        let ns_vt = ns_base as *const u32;
        let ns_msp = ns_vt.read();
        let ns_reset = ns_vt.offset(1).read();

        // VTOR_NS (Non-secure alias of the SCB VTOR).
        const VTOR_NS: *mut u32 = 0xE002_ED08 as *mut u32;
        VTOR_NS.write_volatile(ns_base);

        cortex_m::register::msp::write_ns(ns_msp);
        cortex_m::asm::bx_ns(ns_reset & !1);
    }

    // bx_ns does not return; if the NS world ever branches back to a
    // Secure reset, park safely rather than run undefined code.
    loop {
        cortex_m::asm::wfe();
    }
}
