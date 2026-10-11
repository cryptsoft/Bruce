// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Persistent credential storage in QSPI flash, using the RP2350 boot
//! ROM's flash routines.
//!
//! Layout (top of the 4 MiB flash, each region one 4 KiB sector):
//!   - `STORE_OFFSET` (last sector): the main image -- PIN state,
//!     AuthenticatorConfig, and the resident-credential index slots.
//!     The WHOLE sector is rewritten (erase + program) on any routine
//!     mutation (counter bump / PIN change / config / credential
//!     insert); there is no journal or append log.
//!   - `LARGE_BLOB_OFFSET` (one sector below): the
//!     `authenticatorLargeBlobs` array.
//!   - `KEY_OFFSET` (one sector below that): the two device-wide
//!     master keys (`key_handle_aes_key` / `key_handle_hmac_key`).
//!     This sector is written ONLY on first-boot provisioning and on
//!     authenticatorReset -- NEVER by a routine counter-bump / PIN /
//!     config / credential write. See the H1 note below. The one
//!     exception is program-only: the PIN-armed word in its second
//!     page, programmed once when a PIN is first set ([`arm_pin`]).
//!   - `overflow_offset(0..RESIDENT_EXTRA_SECTORS)` (directly below the
//!     key sector, highest first): optional overflow sectors holding
//!     further discoverable-credential slots, [`OVERFLOW_SLOTS`] each.
//!     None by default; the build-time variable
//!     `PQF_RESIDENT_EXTRA_SECTORS` adds them (see
//!     [`RESIDENT_EXTRA_SECTORS`]). The sectors above are untouched by
//!     the option, so a default-layout store reads the same either way.
//!
//! H1 -- master keys survive a torn routine write.
//!   Every credentialId decrypts ONLY under its minting device's
//!   master keys. If those keys were regenerated, every previously
//!   issued (resident OR non-resident) credential would become
//!   permanently undecryptable. The master keys therefore live in
//!   their own sector that routine writes never touch, so a power
//!   loss during a counter-bump / PIN-change / credential-insert can
//!   at worst reset the PIN/config/resident-credential index (treated
//!   as a fresh main sector) but can NEVER lose the master keys --
//!   non-resident credentials always survive.
//!
//! PIN-armed word -- a torn write never removes the PIN.
//!   Keys that survive a lost main sector would otherwise outlive the
//!   PIN that guarded them: the token would boot PIN-less, anyone could
//!   set a new PIN, and every credential id it ever issued would still
//!   decrypt, user verification included. So the first setPIN also
//!   programs a word in the key sector ([`arm_pin`]), and a token that
//!   boots with that word set and no PIN in the main sector comes up
//!   PIN-blocked (`ctap2::CredStore::load`): no PIN can be set or
//!   used until authenticatorReset, which rotates the master keys and
//!   so retires every old credential id.
//!
//! Torn-write safety for the main sector: `write_sector` programs the
//! credential-slot pages first, then the header page with its magic
//! left erased, then the magic alone LAST, so a power loss anywhere
//! before the magic is complete leaves a magic that does not match.
//! `read_sector` treats that as an empty/cold sector rather than a
//! falsely-valid header pointing at 0xFF slot data or carrying erased
//! header fields.
//!
//! Flash sequencing requirements per the RP2350 datasheet (QMI / XIP
//! chapter): the QSPI device must be taken out of XIP mode before
//! erase/program, then put back. While the flash is being driven in
//! serial command mode the XIP window (0x10000000..) is NOT readable --
//! any instruction fetch or data load from it on EITHER core hangs or
//! bus-faults.
//!
//! M1 -- multicore lockout. The flash erase/program sequence and the
//! core-1 park routine it coordinates with are placed in RAM (a true
//! ramfunc -- see [`crate::ramfunc`]) so that neither core fetches an
//! instruction from XIP during the op. Before each erase/program,
//! core 0 parks core 1 in its RAM-resident spin loop (via
//! [`crate::core1_signer::CORE1_SIGNER`]'s park handshake) and waits
//! for the ack; afterwards it releases core 1. Flash writes only ever
//! happen while core 1 is idle (the signer reserves itself before
//! signing), so the worker is always in its idle loop able to observe
//! the park request.
//!
//! Overflow sectors: each carries its own 16-byte header (magic,
//! slot-layout version, its own index, and a tag bound to the master
//! keys) and is written slots first, header bytes last (the main
//! sector's order; see [`write_overflow_sector`]), so a torn overflow
//! write reads back as an empty overflow sector and never touches any
//! other sector. Only the
//! sector holding the changed slot is rewritten on a counter bump /
//! insert / delete / user-information update, so the wear per sector
//! does not grow with the capacity. A sector whose header is absent,
//! from another index, or tagged under other master keys (written
//! before an authenticatorReset by a build that did not know about it)
//! reads as empty and is not written until a credential lands in it.
//!
//! Limitations:
//!   - No wear levelling -- every modify cycle erases and rewrites
//!     the whole sector. For ~10k erase cycles guaranteed, that's
//!     plenty of credentials over the device's lifetime.

extern crate alloc;

use alloc::vec::Vec as AllocVec;
use core::mem::size_of;
use rp235x_hal::rom_data;

use crate::ramfunc;

/// Physical flash start. RP2350 maps XIP at this address.
/// Base of the XIP window the store is read through.
///
/// A real address on the board; on a host build, the base of a simulated
/// die instead, so the store's logic can be tested without a token. Same
/// seam the Secure world's stores use. See `crates/firmware-hosttest`.
#[cfg(any(target_arch = "arm", target_arch = "riscv32"))]
const XIP_BASE: usize = 0x1000_0000;
#[cfg(not(any(target_arch = "arm", target_arch = "riscv32")))]
#[allow(non_snake_case)]
fn XIP_BASE_fn() -> usize {
    rp235x_hal::window() as usize
}

#[inline]
fn xip_base() -> usize {
    #[cfg(any(target_arch = "arm", target_arch = "riscv32"))]
    {
        XIP_BASE
    }
    #[cfg(not(any(target_arch = "arm", target_arch = "riscv32")))]
    {
        XIP_BASE_fn()
    }
}

/// Offset within flash of the credential-store sector.
/// 4 MiB flash -> last 4 KiB.
const STORE_OFFSET: u32 = 4 * 1024 * 1024 - 4096;
/// Phase 10: separate sector for the `authenticatorLargeBlobs` array.
/// Sits immediately below the credential-store sector. 4 KiB total,
/// with a 16-byte header and up to [`MAX_LARGE_BLOB_LEN`] bytes of
/// array payload.
pub const LARGE_BLOB_OFFSET: u32 = STORE_OFFSET - 4096;
/// H1: dedicated sector for the two device-wide master keys. One 4 KiB
/// sector below the large-blob sector. Written ONLY on first-boot
/// provisioning and on authenticatorReset -- never by routine writes --
/// so a torn routine main-sector write can never lose the master keys.
pub const KEY_OFFSET: u32 = LARGE_BLOB_OFFSET - 4096;
/// Largest accepted `PQF_RESIDENT_EXTRA_SECTORS`. Every slot is held in
/// RAM by `ctap2::CredStore` (580 B each, 7 per overflow sector =
/// 4060 B per sector), on core 0's stack, so the cap keeps the worst
/// case (8 sectors, 32480 B, 62 slots in all) a small fraction of that
/// stack. `build.rs` enforces the same bound before anything compiles.
pub const MAX_RESIDENT_EXTRA_SECTORS: usize = 8;

/// Parse `PQF_RESIDENT_EXTRA_SECTORS` at compile time. Unset or empty
/// means 0; anything but a decimal number up to
/// [`MAX_RESIDENT_EXTRA_SECTORS`] fails the build.
const fn parse_extra_sectors(v: Option<&str>) -> usize {
    let b = match v {
        None => return 0,
        Some(s) => s.as_bytes(),
    };
    let mut n = 0usize;
    let mut i = 0;
    while i < b.len() {
        let d = b[i];
        if d < b'0' || d > b'9' {
            panic!("PQF_RESIDENT_EXTRA_SECTORS must be a decimal number");
        }
        n = n * 10 + (d - b'0') as usize;
        if n > MAX_RESIDENT_EXTRA_SECTORS {
            panic!("PQF_RESIDENT_EXTRA_SECTORS is larger than MAX_RESIDENT_EXTRA_SECTORS (8)");
        }
        i += 1;
    }
    n
}

/// Number of overflow discoverable-credential sectors, from the
/// build-time variable `PQF_RESIDENT_EXTRA_SECTORS` (default 0). Read
/// here with `option_env!` rather than from a `build.rs`-generated
/// file so the host test harness, which pulls this file in by
/// `#[path]`, sees the same value; `build.rs` validates the same
/// variable and grows the linker-script reservation with it.
pub const RESIDENT_EXTRA_SECTORS: usize =
    parse_extra_sectors(option_env!("PQF_RESIDENT_EXTRA_SECTORS"));

/// Flash offset of overflow sector `k` (0-based): directly below the
/// master-key sector, highest first.
pub const fn overflow_offset(k: usize) -> u32 {
    KEY_OFFSET - (k as u32 + 1) * SECTOR_SIZE as u32
}

/// Lowest flash offset our persistent regions occupy. `.text` must end
/// below this (enforced by an ASSERT in `memory.x`) so a large build
/// can never overlap a sector that `erase_region` will wipe. The
/// `memory.x` ASSERT reserves `3 + PQF_RESIDENT_EXTRA_SECTORS` 4 KiB
/// sectors at the top of flash (build.rs generates the count); the
/// static asserts below keep that count in lockstep with the region
/// offsets defined here.
pub const RESERVED_FLASH_OFFSET: u32 = KEY_OFFSET - (RESIDENT_EXTRA_SECTORS * SECTOR_SIZE) as u32;

const SECTOR_SIZE: usize = 4096;
const PAGE_SIZE: usize = 256;

// The persistent sectors must be the top `3 + RESIDENT_EXTRA_SECTORS`
// 4 KiB sectors of flash, contiguous and in the expected order,
// matching the `_reserved_flash_start` reservation in `memory.x`.
const _: () = assert!(
    RESIDENT_EXTRA_SECTORS == 0
        || RESERVED_FLASH_OFFSET == overflow_offset(RESIDENT_EXTRA_SECTORS - 1)
);
const _: () = assert!(RESIDENT_EXTRA_SECTORS != 0 || RESERVED_FLASH_OFFSET == KEY_OFFSET);
const _: () = assert!(
    STORE_OFFSET as usize - RESERVED_FLASH_OFFSET as usize
        == (2 + RESIDENT_EXTRA_SECTORS) * SECTOR_SIZE
);
const _: () = assert!(LARGE_BLOB_OFFSET == KEY_OFFSET + SECTOR_SIZE as u32);
const _: () = assert!(STORE_OFFSET == LARGE_BLOB_OFFSET + SECTOR_SIZE as u32);
const _: () = assert!(STORE_OFFSET as usize == 4 * 1024 * 1024 - SECTOR_SIZE);
const BLOCK_ERASE_CMD: u8 = 0x20; // 4 KiB sector erase (W25Q)

/// Magic at the start of a valid sector so a freshly-erased (all-0xff)
/// sector is clearly distinguishable from corrupt data.
const SECTOR_MAGIC: u32 = 0x46_49_44_4F; // "FIDO"
/// v3: CTAP2 PIN protocol persistent state (pin hash + retries).
/// v4: per-credential WebAuthn user handle (PublicKeyCredentialUserEntity.id)
///     -- required for Chrome's WebAuthn GetAssertion flow to identify the
///     account being authenticated. Without it, Chrome accepts MakeCred
///     but rejects the subsequent login (the assertion response's
///     userHandle is null, and the RP can't bind the credential to a user).
/// v5: two device-wide master keys for OpenSK-style stateless encrypted
///     credential IDs. Original 241-byte OpenSK CBOR v1 format.
/// v6: shrunk credentialId from 241 -> 145 bytes (raw fixed-field
///     plaintext, no CBOR / no PKCS padding). base64url of 145 B is
///     194 chars, which fits an RP `credential_id VARCHAR(255)`
///     column; the v5 241-byte format encoded to 322 chars and
///     overflowed at the relying party it was developed against.
///     Slot layout also changes (credential_id field is now 145 B
///     instead of 241 B) so v5 sectors don't survive the bump.
/// v7: per-credential `credProtect` policy byte (CTAP 2.1 sec. 12.1.1)
///     and `credBlob` payload (CTAP 2.1 sec. 12.4) inside the flash slot.
///     `hmac-secret` (CTAP 2.1 sec. 12.5) doesn't need slot storage -- its
///     `cred_random` is derived deterministically from
///     `HMAC(key_handle_hmac_key, credentialId || uv_byte)` so it
///     survives across power cycles without any per-credential state.
/// v8: per-credential `user_name` + `user_display_name` (up to 64 B
///     each) + monotonic `creation_order: u32` -- required by
///     `authenticatorCredentialManagement` (CTAP 2.1 sec. 6.8). The
///     CM `enumerateRPs` / `enumerateCredentials` subcommands sort
///     by `creation_order` to give clients a stable iteration order.
///     `updateUserInformation` (0x07) mutates the name / display name
///     fields in place.
/// v9: `authenticatorConfig` (CTAP 2.1 sec. 6.11) persistent state in
///     the sector header -- `alwaysUv` flag, `enterpriseAttestation`
///     flag (accepted but no-op since we don't ship a vendor cert),
///     `minPinLength` override + RPID allowlist (up to 4 RP-id
///     hashes the device will report `minPinLength` to via the
///     MakeCred `minPinLength` extension).
/// v10: credentialId grew 145 -> 161 B (the plaintext now carries the
///     credProtect policy byte so the policy is enforceable on
///     non-resident / evicted credentials -- CTAP 2.1 sec. 12.1.1). The
///     `StoredCredential.credential_id` field grew with it, so the
///     slot layout changed; the version bump regenerates the sector
///     on first boot (old credentials are invalid under the new
///     credentialId format anyway).
/// v11: (H1) master keys moved OUT of this sector into their own
///     [`KEY_OFFSET`] sector so a torn routine write can never lose
///     them; the main image header now keeps only PIN/config state.
///     (F4) `StoredCredential` gained a per-slot UTF-8 `rp_id`
///     (+ `rp_id_len`) field so `enumerateRPs` can return the real
///     RP id string instead of `""`. The slot grew, so the slot
///     layout changed and the version bump regenerates the sector on
///     first boot -- existing credentials are intentionally
///     invalidated once on upgrade.
/// v12: (X13) the previously-reserved header byte at offset 108 now
///     carries the persistent `force_pin_change` flag (getInfo `0x0C
///     forcePINChange`). On a v11 sector that byte was left at its
///     erased `0xFF` value, which would read as "force change on" --
///     so the version bump regenerates the main sector once on
///     upgrade rather than spuriously forcing a PIN change. The master
///     keys live in their own sector and are untouched, so non-resident
///     credentials still decrypt across the bump.
/// Bumping invalidates older sectors automatically on first boot.
const SECTOR_VERSION: u32 = 12;

/// Hard cap on PublicKeyCredentialUserEntity.id length. WebAuthn allows
/// up to 64 bytes; libraries we care about (Chrome, Firefox, WebAuthn
/// browser shims) all stay well under that.
pub const MAX_USER_ID_LEN: usize = 64;

/// Maximum `credBlob` length per CTAP 2.1 sec. 12.4: 32 bytes. Exposed in
/// `getInfo` as `maxCredBlobLength = 32` (Phase 6) so RPs know the
/// hard ceiling. Anything longer is rejected at MakeCred time.
pub const MAX_CRED_BLOB_LEN: usize = 32;

/// Per-credential UTF-8 user name length cap. Matches OpenSK's
/// `STORAGE_USER_NAME_MAX_LEN`. WebAuthn doesn't dictate a hard
/// ceiling but every browser we care about stays well under 64 B,
/// and the slot growth has to come out of our flash budget.
pub const MAX_USER_NAME_LEN: usize = 64;
/// Per-credential UTF-8 user displayName length cap.
pub const MAX_USER_DISPLAY_NAME_LEN: usize = 64;

/// Largest `authenticatorLargeBlobs` array we'll persist. CTAP 2.1
/// sec. 6.10 allows up to 1024 + extensions; we cap at 2048 B to fit
/// inside one 4 KiB flash sector with a 16-byte header. Advertised
/// in getInfo as `0x0B maxSerializedLargeBlobArray`.
pub const MAX_LARGE_BLOB_LEN: usize = 2048;

/// Per-credential UTF-8 RP-id length cap (F4). WebAuthn rp.id is a
/// registrable-domain string; 128 bytes covers any realistic domain
/// (the longest public-suffix-list entries are well under that) and
/// keeps the slot growth within the flash budget. RP ids longer than
/// this are truncated to the first `MAX_RP_ID_LEN` bytes for the
/// stored copy -- the authoritative binding stays the `rp_id_hash`,
/// which is computed over the full untruncated string.
pub const MAX_RP_ID_LEN: usize = 128;

/// Magic at the start of the large-blob sector -- distinguishes a
/// freshly-erased (all-0xFF) sector from a v1 one.
pub const LB_SECTOR_MAGIC: u32 = 0x4C_42_4C_42; // "LBLB"
pub const LB_SECTOR_VERSION: u32 = 1;

/// Magic + version for the dedicated master-key sector (H1). A
/// freshly-erased (all-0xFF) key sector reads as "no keys yet" and
/// triggers first-boot provisioning.
pub const KEY_SECTOR_MAGIC: u32 = 0x4B_45_59_53; // "KEYS"
pub const KEY_SECTOR_VERSION: u32 = 1;

/// Key-sector layout (4 KiB; the first 72 bytes and one word of page 1
/// are meaningful):
///   off 0   : KEY_SECTOR_MAGIC (4)
///   off 4   : KEY_SECTOR_VERSION (4)
///   off 8   : key_handle_aes_key  (32)
///   off 40  : key_handle_hmac_key (32)
///   off 256 : PIN-armed word (4) -- erased until a PIN is set under
///             these keys, then programmed once (see [`arm_pin`])
const KEY_OFF_MAGIC: usize = 0;
const KEY_OFF_VERSION: usize = 4;
const KEY_OFF_AES: usize = 8;
const KEY_OFF_HMAC: usize = 40;
/// The PIN-armed word: the first word of the key sector's second page.
/// [`write_key_sector`] programs the whole sector from an all-`0xFF`
/// buffer, so on every token -- including one whose keys an older build
/// minted -- this word reads erased until [`arm_pin`] programs it.
const KEY_OFF_PIN_ARMED: usize = PAGE_SIZE;
// The marker's page must not be the keys' page: arming programs only
// page 1, so a power loss while arming cannot reach the keys.
const _: () = assert!(KEY_OFF_HMAC + 32 <= KEY_OFF_PIN_ARMED);

/// Sector layout (4 KiB):
///   off 0  : LB_SECTOR_MAGIC (4)
///   off 4  : LB_SECTOR_VERSION (4)
///   off 8  : array_len (u32) -- number of valid bytes in payload
///   off 12 : _pad (4)
///   off 16 : array payload (up to MAX_LARGE_BLOB_LEN B)
pub const LB_HEADER_SIZE: usize = 16;

/// On-wire credential ID size -- matches `crate::credential_id::CRED_ID_LEN`.
/// Replicated here to avoid a cross-module dep cycle (flash_store ->
/// credential_id -> flash_store). v6 shrank this from 241 to 145 to
/// keep base64url(credential_id) under the 255-char column cap that
/// many WebAuthn relying parties default to in their SQL schema.
pub const STORED_CRED_ID_LEN: usize = 161;

/// Stored credential format (must be `#[repr(C)]` for stable layout
/// across builds -- this is what's actually written to flash).
///
/// v5 design: the slot holds only what's needed for *resident-key
/// discoverability* (CTAP rk=true / WebAuthn passwordless). All key
/// material lives inside the encrypted credentialId itself, so:
///   - This struct no longer stores ECDSA scalars or ML-DSA seeds.
///   - The slot's `credential_id` field is the exact bytes we put on
///     the wire and the RP echoes back on every GetAssertion.
///   - Counter, rp_id_hash, and user metadata stay here for
///     bookkeeping (rk lookup by rp, counter monotonicity, surfacing
///     the user entity in the assertion response).
///
/// Slot size: 580 B in v11 (was 448 B in v10 before the F4 `rp_id`
/// field was added). With a 240 B header and a 4 KiB sector that
/// gives us 6 discoverable-credential slots (see the static asserts
/// below). Stateless (non-rk) credentials remain recoverable from the
/// credentialId the RP holds, so they don't strictly need a slot.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StoredCredential {
    /// 0x55_AA_FF_C0 = active, 0xff_ff_ff_ff = empty slot,
    /// 0x00_00_00_00 = tombstoned (deleted).
    pub state: u32,
    /// The 241-byte encrypted credentialId we returned to the RP at
    /// MakeCredential time. Both the wire identifier and the carrier
    /// of all key material -- decrypt with `credential_id::
    /// decrypt_credential_id` using `CredStore`'s master keys.
    pub credential_id: [u8; STORED_CRED_ID_LEN],
    /// Padding so subsequent fields stay 4-byte aligned.
    pub _pad1: [u8; 3],
    /// SHA-256(rp.id), redundant with the rp_id_hash that's also
    /// embedded inside `credential_id`'s plaintext. We keep it here
    /// in cleartext so rk-discoverability lookups can scan flash
    /// without decrypting every slot.
    pub rp_id_hash: [u8; 32],
    /// Monotonic CTAP signature counter. Bumped per GetAssertion.
    pub counter: u32,
    /// WebAuthn user handle length (in bytes). 0 means no user handle
    /// -- Chrome's WebAuthn flow always supplies one for rk=true.
    pub user_id_len: u8,
    /// 3 bytes padding so `user_id` is 4-byte aligned.
    pub _pad2: [u8; 3],
    /// WebAuthn user handle (`user.id` from MakeCredential 0x03).
    /// Opaque to the authenticator; returned in GetAssertion 0x04.
    pub user_id: [u8; MAX_USER_ID_LEN],
    /// `credProtect` policy (CTAP 2.1 sec. 12.1.1):
    ///   0 = unset / level 1 default (always usable),
    ///   1 = UserVerificationOptional,
    ///   2 = UserVerificationOptionalWithCredentialIDList,
    ///   3 = UserVerificationRequired.
    /// Read on GetAssertion to gate enumeration / signing.
    pub cred_protect: u8,
    /// `credBlob` length in bytes (0..=32). 0 means no blob was set.
    pub cred_blob_len: u8,
    /// 2 bytes padding so `cred_blob` is 4-byte aligned and the whole
    /// struct stays repr-stable.
    pub _pad3: [u8; 2],
    /// `credBlob` payload -- opaque <=32 B byte string the RP supplied
    /// at MakeCred time and gets back verbatim in the GetAssertion
    /// extensions output when the request includes `"credBlob": true`.
    pub cred_blob: [u8; MAX_CRED_BLOB_LEN],
    /// WebAuthn `user.name` (UTF-8, <=64 B) -- surfaced by
    /// `authenticatorCredentialManagement::enumerateCredentialsGetNextCredential`
    /// and mutable via `updateUserInformation` (CTAP 2.1 sec. 6.8).
    pub user_name_len: u8,
    pub _pad4: [u8; 3],
    pub user_name: [u8; MAX_USER_NAME_LEN],
    /// WebAuthn `user.displayName` (UTF-8, <=64 B). Same lifecycle.
    pub user_display_name_len: u8,
    pub _pad5: [u8; 3],
    pub user_display_name: [u8; MAX_USER_DISPLAY_NAME_LEN],
    /// Monotonic per-credential timestamp (incrementing u32). Used
    /// by CM enumeration to give clients a stable order across
    /// reboots. Bumped by the global counter in the sector header.
    pub creation_order: u32,
    /// (F4) WebAuthn `rp.id` UTF-8 string length (in bytes, <=
    /// [`MAX_RP_ID_LEN`]). 0 means "not stored" -- `enumerateRPs`
    /// falls back to the empty string for such slots.
    pub rp_id_len: u8,
    /// (L11) Nonzero iff this credential was minted with the
    /// `largeBlobKey` extension (CTAP 2.1 sec. 12.3). GetAssertion only
    /// returns the per-credential `0x07 largeBlobKey` for credentials
    /// created with the extension, so the deterministic key is not
    /// over-disclosed for arbitrary credentials.
    pub large_blob_key: u8,
    /// 2 bytes padding so `rp_id` stays 4-byte aligned and the whole
    /// struct keeps a stable `repr(C)` size.
    pub _pad6: [u8; 2],
    /// (F4) WebAuthn `rp.id` text (UTF-8, <= [`MAX_RP_ID_LEN`] B).
    /// Captured at MakeCredential time from the `rp.id` field so
    /// `authenticatorCredentialManagement::enumerateRPs` (CTAP 2.1
    /// sec. 6.8.2) can return the real RP id string. The `rp_id_hash`
    /// above remains the authoritative binding.
    pub rp_id: [u8; MAX_RP_ID_LEN],
}

pub const STATE_ACTIVE: u32 = 0x55_AA_FF_C0;
pub const STATE_EMPTY: u32 = 0xFFFF_FFFF;
/// A schema value the host tests assert on; the firmware never writes
/// a tombstone today, so the lint is silenced rather than the value
/// dropped from the layout's vocabulary.
#[allow(dead_code)]
pub const STATE_TOMBSTONE: u32 = 0x0000_0000;

impl StoredCredential {
    /// A fully-zeroed empty slot. Centralises the (now long) field
    /// list so the several call sites that build an empty array of
    /// slots can't drift out of sync with the `repr(C)` layout.
    pub const fn empty() -> Self {
        Self {
            state: STATE_EMPTY,
            credential_id: [0; STORED_CRED_ID_LEN],
            _pad1: [0; 3],
            rp_id_hash: [0; 32],
            counter: 0,
            user_id_len: 0,
            _pad2: [0; 3],
            user_id: [0; MAX_USER_ID_LEN],
            cred_protect: 0,
            cred_blob_len: 0,
            _pad3: [0; 2],
            cred_blob: [0; MAX_CRED_BLOB_LEN],
            user_name_len: 0,
            _pad4: [0; 3],
            user_name: [0; MAX_USER_NAME_LEN],
            user_display_name_len: 0,
            _pad5: [0; 3],
            user_display_name: [0; MAX_USER_DISPLAY_NAME_LEN],
            creation_order: 0,
            rp_id_len: 0,
            large_blob_key: 0,
            _pad6: [0; 2],
            rp_id: [0; MAX_RP_ID_LEN],
        }
    }

    /// (#21) True iff every persisted per-field length is within its
    /// array capacity. Downstream code slices the fixed-size arrays by
    /// these lengths, so a value loaded from a corrupt flash sector that
    /// exceeds its capacity would panic (overflow-checks=false /
    /// panic=abort) or over-read adjacent bytes. `read_sector` calls
    /// this to drop any active slot that fails the check rather than
    /// trusting the persisted lengths verbatim.
    fn lengths_in_bounds(&self) -> bool {
        (self.user_id_len as usize) <= MAX_USER_ID_LEN
            && (self.user_name_len as usize) <= MAX_USER_NAME_LEN
            && (self.user_display_name_len as usize) <= MAX_USER_DISPLAY_NAME_LEN
            && (self.cred_blob_len as usize) <= MAX_CRED_BLOB_LEN
            && (self.rp_id_len as usize) <= MAX_RP_ID_LEN
    }
}

/// Header layout (240 bytes total).
///   off 0   : SECTOR_MAGIC (4)
///   off 4   : SECTOR_VERSION (4)
///   off 8   : pin_hash (16)
///   off 24  : pin_set (1) | retries_left (1) | pad (2)
///   off 28  : reserved (12) for future config flags
///   off 40  : reserved (64) -- v5..v10 held the two 32-byte master
///             keys here; v11 (H1) moved them to the [`KEY_OFFSET`]
///             sector, leaving this span reserved.
///   off 104 : always_uv (1) -- v9: AuthenticatorConfig 0x02
///   off 105 : enterprise_attestation (1) -- v9: AC 0x01 (no-op)
///   off 106 : min_pin_length (1) -- v9: AC 0x03 setMinPinLength
///   off 107 : min_pin_length_rpid_count (1) -- v9
///   off 108 : force_pin_change (1) -- X13: getInfo 0x0C forcePINChange
///   off 109 : reserved (3) for future config flags
///   off 112 : min_pin_length_rpid_hashes (4 * 32 = 128) -- v9
///   off 240 : start of credential slots
const HEADER_SIZE: usize = 240;
const OFF_ALWAYS_UV: usize = 104;
const OFF_ENT_ATTESTATION: usize = 105;
const OFF_MIN_PIN_LEN: usize = 106;
const OFF_MIN_PIN_LEN_RPID_COUNT: usize = 107;
/// X13: persistent `forcePINChange` flag. Set by AuthenticatorConfig
/// `setMinPINLength`'s `forceChangePin` (CTAP 2.1 sec. 6.11.4); surfaced in
/// `getInfo` as the `0x0C forcePINChange` member so the host runs an
/// old-PIN-authenticated `changePIN` before the credential is used
/// again. The PIN itself stays active (pin_set unchanged).
const OFF_FORCE_PIN_CHANGE: usize = 108;
const OFF_MIN_PIN_LEN_RPID_HASHES: usize = 112;
/// Maximum number of RP-id hashes the `minPinLengthRPIDs` allowlist
/// can hold. CTAP 2.1 doesn't specify a minimum; OpenSK uses a
/// configurable bound. We pick 4 -- fits the header growth budget
/// and covers typical "one corporate RP + a couple of related
/// subdomains" deployments.
pub const MAX_MIN_PIN_LEN_RPIDS: usize = 4;
/// Number of discoverable (resident) credential slots that fit after
/// the header in the 4 KiB store sector. Derived, not hand-tuned:
/// `(SECTOR_SIZE - HEADER_SIZE) / size_of::<StoredCredential>()`
/// = `(4096 - 240) / 580` = **6** at the current v12 layout. The slot
/// is 580 B because `MAX_RP_ID_LEN = 128` (the F4 per-slot `rp_id`
/// field dominates the slot growth); shrinking `MAX_RP_ID_LEN` would
/// shrink the slot and admit more slots, but the layout is frozen by
/// the `size_of::<StoredCredential>() == 580` static assert below -- do
/// not change it without bumping `SECTOR_VERSION`.
pub const MAX_SLOTS: usize = (SECTOR_SIZE - HEADER_SIZE) / size_of::<StoredCredential>();

/// Magic at the start of a valid overflow sector ("RKOV"). Distinct
/// from every other sector's magic, so no other sector can be misread
/// as an overflow one.
pub const OVERFLOW_SECTOR_MAGIC: u32 = 0x52_4B_4F_56; // "RKOV"

/// Overflow-sector header layout (16 bytes):
///   off 0  : OVERFLOW_SECTOR_MAGIC (4)
///   off 4  : SECTOR_VERSION (4) -- the slot layout version, shared with
///            the main sector, so a slot-layout change invalidates the
///            overflow sectors together with the main one
///   off 8  : this sector's index k (4) -- a sector read at the wrong
///            offset is refused
///   off 12 : key tag (4) -- `ctap2::CredStore`'s binding to the master
///            keys; a sector left behind across an authenticatorReset
///            reads as empty
///   off 16 : credential slots, same `StoredCredential` layout
const OVERFLOW_HEADER_SIZE: usize = 16;

/// Discoverable-credential slots per overflow sector:
/// `(4096 - 16) / 580` = **7**.
pub const OVERFLOW_SLOTS: usize =
    (SECTOR_SIZE - OVERFLOW_HEADER_SIZE) / size_of::<StoredCredential>();

/// All discoverable-credential slots: the main sector's [`MAX_SLOTS`]
/// plus [`OVERFLOW_SLOTS`] per overflow sector. 6 by default.
pub const TOTAL_SLOTS: usize = MAX_SLOTS + RESIDENT_EXTRA_SECTORS * OVERFLOW_SLOTS;

// Compile-time layout guards (X4): catch any silent change to the
// repr(C) slot size or a sector-budget overflow -- the docs above quote
// these numbers, and a torn StoredCredential layout would corrupt the
// whole credential index on flash.
const _: () = assert!(size_of::<StoredCredential>() == 580);
const _: () = assert!(HEADER_SIZE + MAX_SLOTS * size_of::<StoredCredential>() <= SECTOR_SIZE);
const _: () = assert!(MAX_SLOTS == 6);
const _: () = assert!(OVERFLOW_SLOTS == 7);
const _: () =
    assert!(OVERFLOW_HEADER_SIZE + OVERFLOW_SLOTS * size_of::<StoredCredential>() <= SECTOR_SIZE);
// The header page (programmed last) must hold the whole header.
const _: () = assert!(OVERFLOW_HEADER_SIZE <= PAGE_SIZE);

/// The main persistent image: PIN state + the resident-credential
/// index slots + AuthenticatorConfig state. The per-device master keys
/// live in their OWN sector (see [`read_key_sector`] /
/// [`write_key_sector`]) so a torn routine write of this image can
/// never lose them (H1).
pub struct StoredImage {
    pub pin_hash: [u8; 16],
    pub pin_set: u8,
    pub retries_left: u8,
    /// `alwaysUv` flag (CTAP 2.1 sec. 6.11.1 subcmd 0x02). When set,
    /// MakeCred / GetAssert refuse to operate without PIN/UV.
    pub always_uv: u8,
    /// `enterpriseAttestation` flag (subcmd 0x01). Stored but
    /// behavioural no-op -- we don't ship a vendor cert chain.
    pub enterprise_attestation: u8,
    /// `minPinLength` override (subcmd 0x03). 0 means "use the
    /// default (`PIN_MIN_LENGTH_BYTES = 4`)"; any nonzero value is
    /// enforced by the PIN-set / change paths.
    pub min_pin_length: u8,
    /// Number of valid entries in `min_pin_length_rpid_hashes`.
    pub min_pin_length_rpid_count: u8,
    /// SHA-256 hashes of RP ids allowed to read back
    /// `minPinLength` via the MakeCred `minPinLength` extension
    /// output (Phase 11 wire). Set via subcmd 0x03's
    /// `minPinLengthRPIDs` parameter.
    pub min_pin_length_rpid_hashes: [[u8; 32]; MAX_MIN_PIN_LEN_RPIDS],
    /// (X13) `forcePINChange`: when nonzero the device wants the host
    /// to run `authenticatorClientPin::changePIN` (old-PIN-authenticated)
    /// before the credential is usable again. The PIN stays active --
    /// this is a "must change", not a "PIN removed", flag (CTAP 2.1
    /// sec. 6.11.4). Surfaced in `getInfo` as the `0x0C forcePINChange`
    /// member.
    pub force_pin_change: u8,
    pub creds: [StoredCredential; MAX_SLOTS],
}

/// Read the entire store sector into RAM. Just a memcpy from XIP.
/// Returns None if the sector header is invalid (uninitialised / corrupt).
pub fn read_sector() -> Option<StoredImage> {
    let xip_ptr = (xip_base() + STORE_OFFSET as usize) as *const u8;
    let magic = unsafe { core::ptr::read_unaligned(xip_ptr as *const u32) };
    let version = unsafe { core::ptr::read_unaligned(xip_ptr.add(4) as *const u32) };
    if magic != SECTOR_MAGIC || version != SECTOR_VERSION {
        return None;
    }
    let mut pin_hash = [0u8; 16];
    unsafe {
        core::ptr::copy_nonoverlapping(xip_ptr.add(8), pin_hash.as_mut_ptr(), 16);
    }
    let pin_set = unsafe { *xip_ptr.add(24) };
    let retries_left = unsafe { *xip_ptr.add(25) };

    // (H1) The master keys are NOT in this sector -- they live in the
    // dedicated key sector (see `read_key_sector`). Bytes 40..104 are
    // reserved here.

    // v9 AuthenticatorConfig state.
    let always_uv = unsafe { *xip_ptr.add(OFF_ALWAYS_UV) };
    let enterprise_attestation = unsafe { *xip_ptr.add(OFF_ENT_ATTESTATION) };
    let min_pin_length = unsafe { *xip_ptr.add(OFF_MIN_PIN_LEN) };
    let min_pin_length_rpid_count = unsafe { *xip_ptr.add(OFF_MIN_PIN_LEN_RPID_COUNT) };
    // X13: persistent forcePINChange flag.
    let force_pin_change = unsafe { *xip_ptr.add(OFF_FORCE_PIN_CHANGE) };
    let mut min_pin_length_rpid_hashes = [[0u8; 32]; MAX_MIN_PIN_LEN_RPIDS];
    unsafe {
        core::ptr::copy_nonoverlapping(
            xip_ptr.add(OFF_MIN_PIN_LEN_RPID_HASHES),
            min_pin_length_rpid_hashes.as_mut_ptr() as *mut u8,
            MAX_MIN_PIN_LEN_RPIDS * 32,
        );
    }

    let mut creds = [StoredCredential::empty(); MAX_SLOTS];
    let entries_ptr = unsafe { xip_ptr.add(HEADER_SIZE) as *const StoredCredential };
    load_slots(entries_ptr, &mut creds);
    Some(StoredImage {
        pin_hash,
        pin_set,
        retries_left,
        always_uv,
        enterprise_attestation,
        min_pin_length,
        min_pin_length_rpid_count,
        min_pin_length_rpid_hashes,
        force_pin_change,
        creds,
    })
}

/// Copy `out.len()` slots from flash at `entries_ptr`, dropping any
/// active slot whose persisted lengths do not fit (#21). Shared by the
/// main and the overflow sectors.
fn load_slots(entries_ptr: *const StoredCredential, out: &mut [StoredCredential]) {
    for (i, slot) in out.iter_mut().enumerate() {
        let loaded = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) };
        // (#21) The sector is gated only by the magic + version word --
        // there is no CRC -- so a torn / corrupt sector can yield an
        // active slot whose persisted per-field length fields exceed
        // their array capacities. Downstream code slices the fixed
        // arrays by these lengths (e.g. `user_id[..user_id_len]`); with
        // overflow-checks=false / panic=abort an out-of-range length
        // either panics (start<=len<=end violated = device brick) or
        // over-reads adjacent slot bytes into a CBOR response. Defend on
        // load: any ACTIVE slot whose lengths don't all fit is treated
        // as corruption and dropped to an empty slot. Non-active
        // (empty / tombstone) slots are copied verbatim; their length
        // fields are never sliced.
        *slot = if loaded.state == STATE_ACTIVE && !loaded.lengths_in_bounds() {
            StoredCredential::empty()
        } else {
            loaded
        };
    }
}

/// Read overflow sector `k`'s slots. Returns `None` -- the caller
/// treats the sector as empty -- when `k` is out of range, or the
/// header is absent (erased, or torn: the header page is programmed
/// last), of another slot-layout version, from another index, or
/// tagged under other master keys (`tag`, see
/// `ctap2::CredStore::load`).
pub fn read_overflow_sector(k: usize, tag: u32) -> Option<[StoredCredential; OVERFLOW_SLOTS]> {
    if k >= RESIDENT_EXTRA_SECTORS {
        return None;
    }
    let xip_ptr = (xip_base() + overflow_offset(k) as usize) as *const u8;
    let rd = |off: usize| unsafe { core::ptr::read_unaligned(xip_ptr.add(off) as *const u32) };
    if rd(0) != OVERFLOW_SECTOR_MAGIC
        || rd(4) != SECTOR_VERSION
        || rd(8) != k as u32
        || rd(12) != tag
    {
        return None;
    }
    let mut creds = [StoredCredential::empty(); OVERFLOW_SLOTS];
    let entries_ptr = unsafe { xip_ptr.add(OVERFLOW_HEADER_SIZE) as *const StoredCredential };
    load_slots(entries_ptr, &mut creds);
    Some(creds)
}

/// Write overflow sector `k`: erase, program every slot byte, then the
/// 16 header bytes LAST -- the main sector's torn-write order, taken
/// one step further. The main sector programs its header page last, but
/// that page also carries the head of slot 0; here the whole sector is
/// first programmed with the header bytes left erased, and page 0 is
/// then programmed again with the header filled in (NOR programming
/// only clears bits, so re-programming the slot bytes already there is
/// a no-op). A power loss anywhere in here therefore leaves this sector
/// reading as empty, or -- once all the slot bytes are down -- as the
/// complete new content; never a valid header over partial slots, and
/// never a change to any other sector. Refuses an out-of-range `k` and
/// a `creds` that is not exactly [`OVERFLOW_SLOTS`] long.
pub fn write_overflow_sector(k: usize, tag: u32, creds: &[StoredCredential]) {
    if k >= RESIDENT_EXTRA_SECTORS || creds.len() != OVERFLOW_SLOTS {
        return;
    }
    let mut buf = [0xffu8; SECTOR_SIZE];
    buf[0..4].copy_from_slice(&OVERFLOW_SECTOR_MAGIC.to_le_bytes());
    buf[4..8].copy_from_slice(&SECTOR_VERSION.to_le_bytes());
    buf[8..12].copy_from_slice(&(k as u32).to_le_bytes());
    buf[12..16].copy_from_slice(&tag.to_le_bytes());
    for (i, e) in creds.iter().enumerate() {
        let off = OVERFLOW_HEADER_SIZE + i * size_of::<StoredCredential>();
        // SAFETY: StoredCredential is #[repr(C)] and POD -- bitwise copy is fine.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                e as *const StoredCredential as *const u8,
                size_of::<StoredCredential>(),
            )
        };
        buf[off..off + bytes.len()].copy_from_slice(bytes);
    }
    let base = overflow_offset(k);
    let mut header = [0u8; OVERFLOW_HEADER_SIZE];
    header.copy_from_slice(&buf[..OVERFLOW_HEADER_SIZE]);
    buf[..OVERFLOW_HEADER_SIZE].fill(0xff);
    erase_region(base);
    program(base, &buf);
    buf[..OVERFLOW_HEADER_SIZE].copy_from_slice(&header);
    program(base, &buf[..PAGE_SIZE]);
}

/// Erase overflow sector `k` (authenticatorReset). Refuses an
/// out-of-range `k`.
pub fn erase_overflow_sector(k: usize) {
    if k < RESIDENT_EXTRA_SECTORS {
        erase_region(overflow_offset(k));
    }
}

/// Read the two device-wide master keys out of their dedicated sector
/// (H1). Returns `None` if the sector is freshly erased / invalid --
/// the caller treats that as a fresh device and provisions new keys.
pub fn read_key_sector() -> Option<([u8; 32], [u8; 32])> {
    let xip_ptr = (xip_base() + KEY_OFFSET as usize) as *const u8;
    let magic = unsafe { core::ptr::read_unaligned(xip_ptr.add(KEY_OFF_MAGIC) as *const u32) };
    let version = unsafe { core::ptr::read_unaligned(xip_ptr.add(KEY_OFF_VERSION) as *const u32) };
    if magic != KEY_SECTOR_MAGIC || version != KEY_SECTOR_VERSION {
        return None;
    }
    let mut aes_key = [0u8; 32];
    let mut hmac_key = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(xip_ptr.add(KEY_OFF_AES), aes_key.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(xip_ptr.add(KEY_OFF_HMAC), hmac_key.as_mut_ptr(), 32);
    }
    Some((aes_key, hmac_key))
}

/// Write the two device-wide master keys to their dedicated sector
/// (H1). Called ONLY on first-boot provisioning and on
/// authenticatorReset -- NEVER by a routine counter-bump / PIN /
/// config / credential write -- so a torn routine main-sector write can
/// never disturb the keys.
pub fn write_key_sector(aes_key: &[u8; 32], hmac_key: &[u8; 32]) {
    let mut buf = [0xffu8; SECTOR_SIZE];
    buf[KEY_OFF_MAGIC..KEY_OFF_MAGIC + 4].copy_from_slice(&KEY_SECTOR_MAGIC.to_le_bytes());
    buf[KEY_OFF_VERSION..KEY_OFF_VERSION + 4].copy_from_slice(&KEY_SECTOR_VERSION.to_le_bytes());
    buf[KEY_OFF_AES..KEY_OFF_AES + 32].copy_from_slice(aes_key);
    buf[KEY_OFF_HMAC..KEY_OFF_HMAC + 32].copy_from_slice(hmac_key);
    erase_region(KEY_OFFSET);
    program(KEY_OFFSET, &buf);
}

/// True once a PIN has been set on this device under its current
/// master keys (see [`arm_pin`]). Any value but the erased one counts:
/// a power loss while arming leaves some bits cleared, and that fails
/// closed.
pub fn pin_armed() -> bool {
    let p = (xip_base() + KEY_OFFSET as usize + KEY_OFF_PIN_ARMED) as *const u32;
    unsafe { core::ptr::read_unaligned(p) != 0xFFFF_FFFF }
}

/// Record in the master-key sector that a PIN has been set under these
/// keys. The main sector holds the PIN itself and is rewritten on every
/// routine write, so a torn write there reads back as a store with no
/// PIN; this word outlives it, and [`crate::ctap2::CredStore::load`]
/// boots such a token PIN-blocked instead of PIN-less, until an
/// authenticatorReset rotates the keys that every old credential id
/// needs. Program-only, no erase: NOR programming only clears bits,
/// every byte of the programmed page but the marker is `0xFF` (a
/// no-op), and the keys are in page 0, so this cannot disturb them.
/// Erased again only with the key sector: first-boot provisioning and
/// authenticatorReset. A no-op once armed.
pub fn arm_pin() {
    if pin_armed() {
        return;
    }
    let mut page = [0xffu8; PAGE_SIZE];
    page[..4].fill(0);
    program(KEY_OFFSET + KEY_OFF_PIN_ARMED as u32, &page);
}

/// Erase one 4 KiB sector at `offset`. Must be called from a non-IRQ
/// context. Parks core 1 in RAM and disables interrupts for the
/// duration of the actual flash sequence (M1).
fn erase_region(offset: u32) {
    // SAFETY: see `ramfunc::flash_op_locked`. The closure body runs
    // entirely from RAM (the boot-ROM flash routines are in the ROM,
    // not XIP) so no XIP fetch occurs on this core while QSPI is in
    // command mode, and core 1 is parked in its own RAM spin loop.
    unsafe {
        ramfunc::flash_op_locked(|| {
            rom_data::connect_internal_flash();
            rom_data::flash_exit_xip();
            rom_data::flash_range_erase(offset, SECTOR_SIZE, SECTOR_SIZE as u32, BLOCK_ERASE_CMD);
            rom_data::flash_flush_cache();
            rom_data::flash_enter_cmd_xip();
        });
    }
}

/// Program `data` (a multiple of [`PAGE_SIZE`] bytes, page-aligned
/// `addr`) into flash. Parks core 1 and disables interrupts for the
/// duration of the flash sequence (M1).
fn program(addr: u32, data: &[u8]) {
    let ptr = data.as_ptr();
    let len = data.len();
    // SAFETY: as `erase_region`. `ptr`/`len` reference a RAM buffer
    // (the caller's stack/`AllocVec`), which stays readable while XIP
    // is suspended; the boot ROM streams from it into the QSPI device.
    unsafe {
        ramfunc::flash_op_locked(|| {
            rom_data::connect_internal_flash();
            rom_data::flash_exit_xip();
            rom_data::flash_range_program(addr, ptr, len);
            rom_data::flash_flush_cache();
            rom_data::flash_enter_cmd_xip();
        });
    }
}

/// Read the `authenticatorLargeBlobs` array out of its dedicated
/// sector. Returns the array bytes (up to [`MAX_LARGE_BLOB_LEN`]).
/// On a freshly-erased / unrecognised sector, returns `None` so the
/// caller can substitute the spec-mandated initial `[0x80] || hash`.
pub fn read_large_blob_sector() -> Option<AllocVec<u8>> {
    let xip_ptr = (xip_base() + LARGE_BLOB_OFFSET as usize) as *const u8;
    let magic = unsafe { core::ptr::read_unaligned(xip_ptr as *const u32) };
    let version = unsafe { core::ptr::read_unaligned(xip_ptr.add(4) as *const u32) };
    if magic != LB_SECTOR_MAGIC || version != LB_SECTOR_VERSION {
        return None;
    }
    let array_len = unsafe { core::ptr::read_unaligned(xip_ptr.add(8) as *const u32) } as usize;
    if array_len > MAX_LARGE_BLOB_LEN {
        return None;
    }
    let mut out = AllocVec::with_capacity(array_len);
    out.resize(array_len, 0);
    unsafe {
        core::ptr::copy_nonoverlapping(xip_ptr.add(LB_HEADER_SIZE), out.as_mut_ptr(), array_len);
    }
    Some(out)
}

/// Replace the entire large-blob array. Erases + reprograms the
/// sector. `array.len()` must fit within [`MAX_LARGE_BLOB_LEN`].
pub fn write_large_blob_sector(array: &[u8]) {
    // Self-protect in release: the sole caller already bounds this, but a
    // future caller passing an over-long array would otherwise panic on
    // the bounds-checked slice copy below (debug_assert is compiled out).
    // Refuse the write rather than panic.
    if array.len() > MAX_LARGE_BLOB_LEN {
        return;
    }
    let mut buf = [0xffu8; SECTOR_SIZE];
    buf[..4].copy_from_slice(&LB_SECTOR_MAGIC.to_le_bytes());
    buf[4..8].copy_from_slice(&LB_SECTOR_VERSION.to_le_bytes());
    buf[8..12].copy_from_slice(&(array.len() as u32).to_le_bytes());
    let end = LB_HEADER_SIZE + array.len();
    buf[LB_HEADER_SIZE..end].copy_from_slice(array);
    erase_region(LARGE_BLOB_OFFSET);
    program(LARGE_BLOB_OFFSET, &buf);
}

/// Reset the large-blob array to the spec-mandated initial value by
/// erasing its sector -- subsequent `read_large_blob_sector()` returns
/// `None` and the caller substitutes `[0x80] || sha256("\x80")[..16]`.
/// Used by authenticatorReset (CTAP 2.1 sec. 6.6 requires reset to destroy
/// device data, which includes the large-blob array).
pub fn reset_large_blob_sector() {
    erase_region(LARGE_BLOB_OFFSET);
}

/// Write the full image (PIN state + config + credentials) to flash.
///
/// Torn-write safety (H1): we erase the sector, then program the
/// credential-slot pages (offsets 256.. ) FIRST, the header page
/// (offset 0..256) with its magic left erased next, and the magic
/// LAST. A power loss before the magic is complete therefore leaves a
/// magic that does not match, which `read_sector` treats as an empty /
/// cold sector -- never a falsely-valid header pointing at 0xFF slot
/// data, and never a header whose later fields are still erased. The
/// master keys are NOT written here; they live in their own sector
/// (`write_key_sector`) untouched by routine writes.
pub fn write_sector(image: &StoredImage) {
    let mut buf = [0xffu8; SECTOR_SIZE];
    buf[..4].copy_from_slice(&SECTOR_MAGIC.to_le_bytes());
    buf[4..8].copy_from_slice(&SECTOR_VERSION.to_le_bytes());
    buf[8..24].copy_from_slice(&image.pin_hash);
    buf[24] = image.pin_set;
    buf[25] = image.retries_left;
    // bytes 26..40 reserved for future use.
    // bytes 40..104 reserved (H1: master keys moved to their own sector).
    // v9 AuthenticatorConfig state.
    buf[OFF_ALWAYS_UV] = image.always_uv;
    buf[OFF_ENT_ATTESTATION] = image.enterprise_attestation;
    buf[OFF_MIN_PIN_LEN] = image.min_pin_length;
    buf[OFF_MIN_PIN_LEN_RPID_COUNT] = image.min_pin_length_rpid_count;
    buf[OFF_FORCE_PIN_CHANGE] = image.force_pin_change;
    for (i, h) in image.min_pin_length_rpid_hashes.iter().enumerate() {
        let off = OFF_MIN_PIN_LEN_RPID_HASHES + i * 32;
        buf[off..off + 32].copy_from_slice(h);
    }
    let entries_base = HEADER_SIZE;
    for (i, e) in image.creds.iter().enumerate() {
        let off = entries_base + i * size_of::<StoredCredential>();
        // SAFETY: StoredCredential is #[repr(C)] and POD -- bitwise copy is fine.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                e as *const StoredCredential as *const u8,
                size_of::<StoredCredential>(),
            )
        };
        buf[off..off + bytes.len()].copy_from_slice(bytes);
    }
    erase_region(STORE_OFFSET);
    // Program the header page (carrying the magic at offset 0) LAST so
    // a torn write leaves magic = 0xFF (read as empty) instead of a
    // valid-looking header over partially-written slots. PAGE_SIZE
    // (256 B) covers the whole 240 B header; everything from PAGE_SIZE
    // onward is credential-slot data, programmed first.
    program(STORE_OFFSET + PAGE_SIZE as u32, &buf[PAGE_SIZE..]);
    // The header page itself goes down in two passes, the magic in the
    // second, the overflow sectors' order (`write_overflow_sector`). In
    // one pass, a power loss after the magic and version but before
    // the rest of the header left a header that reads as valid with
    // erased fields after the cut: `retries_left` erased reads as
    // corrupt and loads as the full count, so a tear at the right
    // moment handed back eight more PIN guesses. Now the header is
    // complete before the magic is written, and a magic cut short
    // does not match: the sector reads as empty. Re-programming the
    // bytes the first pass laid down is a no-op (NOR only clears bits).
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&buf[..4]);
    buf[..4].fill(0xff);
    program(STORE_OFFSET, &buf[..PAGE_SIZE]);
    buf[..4].copy_from_slice(&magic);
    program(STORE_OFFSET, &buf[..PAGE_SIZE]);
}
