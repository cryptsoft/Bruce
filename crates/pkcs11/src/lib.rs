// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! pqf-pkcs11 -- PKCS#11 module exposing the Bruce token as a random
//! number source. The Rust sibling of the C module in `c/pkcs11/`.
//!
//! Only `C_GenerateRandom` does real work: bytes are pulled from the
//! token's ring-oscillator TRNG over USB via the vendor command
//! `CTAPHID_CMD_RNG` ([`pqf_ctaphid::hid::Device::rng`]). No
//! authentication, no objects, no mechanisms -- the full Cryptoki v2.40
//! function list is present so any application accepts the module, but
//! everything outside the RNG path answers `CKR_FUNCTION_NOT_SUPPORTED`
//! (the generated stubs in [`unsupported`]).
//!
//! Model (identical to the C module):
//!   - One slot per FIDO authenticator on the USB bus. `C_GetSlotList`
//!     rescans every call, so hot-plug is visible to apps that re-list.
//!     Slot IDs are indices into the latest scan -- not stable across
//!     replug (v1 simplification).
//!   - Each session owns its own opened HID handle (its own CTAP HID
//!     channel), so concurrent sessions to one token multiplex cleanly.
//!   - `C_SeedRandom` is an accepted no-op: the TRNG takes no seed.
//!
//! Threading: a single global `Mutex` serialises all state, so the
//! module is safe to call from multiple threads even though the
//! intended consumers (`pkcs11-tool`, `openssl rand`) are
//! single-threaded.

#![allow(non_snake_case)]
// The safety contract for every entry point here is the PKCS#11
// specification (valid pointers, correct buffer sizes, C_Initialize
// called first, ...), enforced by the calling application -- not a
// per-function `# Safety` note.
#![allow(clippy::missing_safety_doc)]

use std::sync::Mutex;

use cryptoki_sys as ck;
use pqf_ctaphid::hid::{self, Device, DeviceInfo};

mod unsupported;
use unsupported::*;

#[cfg(test)]
mod tests;

// ---- Module constants ------------------------------------------------

const MANUFACTURER: &str = "Bruce";
const LIB_DESCRIPTION: &str = "Bruce token RNG bridge";
const SLOT_DESCRIPTION: &str = "Bruce USB CTAP HID slot";
const TOKEN_MODEL: &str = "Bruce";

const MAX_SLOTS: usize = 8;
const MAX_SESSIONS: usize = 16;

const LIB_VERSION_MAJOR: ck::CK_BYTE = 0;
const LIB_VERSION_MINOR: ck::CK_BYTE = 1;

// CK_RV constants are `u32`-typed in the bindings; alias the handful we
// return, cast once, so the bodies stay readable.
const OK: ck::CK_RV = ck::CKR_OK as ck::CK_RV;
const ARGS_BAD: ck::CK_RV = ck::CKR_ARGUMENTS_BAD as ck::CK_RV;
const NOT_INIT: ck::CK_RV = ck::CKR_CRYPTOKI_NOT_INITIALIZED as ck::CK_RV;
const ALREADY_INIT: ck::CK_RV = ck::CKR_CRYPTOKI_ALREADY_INITIALIZED as ck::CK_RV;
const SLOT_INVALID: ck::CK_RV = ck::CKR_SLOT_ID_INVALID as ck::CK_RV;
const SESSION_INVALID: ck::CK_RV = ck::CKR_SESSION_HANDLE_INVALID as ck::CK_RV;
const SESSION_COUNT: ck::CK_RV = ck::CKR_SESSION_COUNT as ck::CK_RV;
const PARALLEL_NOPE: ck::CK_RV = ck::CKR_SESSION_PARALLEL_NOT_SUPPORTED as ck::CK_RV;
const BUFFER_SMALL: ck::CK_RV = ck::CKR_BUFFER_TOO_SMALL as ck::CK_RV;
const DEVICE_ERROR: ck::CK_RV = ck::CKR_DEVICE_ERROR as ck::CK_RV;
const DEVICE_REMOVED: ck::CK_RV = ck::CKR_DEVICE_REMOVED as ck::CK_RV;
const TOKEN_NOT_PRESENT: ck::CK_RV = ck::CKR_TOKEN_NOT_PRESENT as ck::CK_RV;
const NOT_PARALLEL: ck::CK_RV = ck::CKR_FUNCTION_NOT_PARALLEL as ck::CK_RV;

// ---- Module state ----------------------------------------------------

struct Session {
    slot: ck::CK_SLOT_ID,
    flags: ck::CK_FLAGS,
    dev: Device,
}

struct State {
    initialized: bool,
    /// Most recent USB scan. Slot ID n == devices[n].
    devices: Vec<DeviceInfo>,
    /// Handle n == sessions[n - 1] (0 is never a valid handle).
    sessions: Vec<Option<Session>>,
}

static STATE: Mutex<State> = Mutex::new(State {
    initialized: false,
    devices: Vec::new(),
    sessions: Vec::new(),
});

fn lock() -> std::sync::MutexGuard<'static, State> {
    // panic = "abort" for this profile, so a poisoned lock can't
    // actually occur; recover the guard anyway rather than risk an
    // abort inside a dlopen'd module.
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

// ---- Helpers ---------------------------------------------------------

/// Cryptoki string fields are fixed-width, space-padded, and NOT
/// NUL-terminated (PKCS#11 v3.0 base sec. 4.1).
fn pad(dst: &mut [u8], src: &str) {
    let b = src.as_bytes();
    let n = b.len().min(dst.len());
    dst[..n].copy_from_slice(&b[..n]);
    for x in &mut dst[n..] {
        *x = b' ';
    }
}

fn rescan(st: &mut State) -> bool {
    match hid::enumerate() {
        Ok(list) => {
            st.devices = list.into_iter().take(MAX_SLOTS).collect();
            true
        }
        Err(_) => false,
    }
}

/// Map a transport error from the RNG path onto a Cryptoki return.
/// A device that answered `CTAPHID_ERROR` (its firmware predates the
/// vendor command) is a device error; anything else in the RNG path
/// means the cable/token went away mid-call.
fn rng_err(e: hid::Error) -> ck::CK_RV {
    match e {
        hid::Error::HidError(_) => DEVICE_ERROR,
        _ => DEVICE_REMOVED,
    }
}

/// Resolve a session handle to an index into `sessions`.
fn session_index(st: &State, h: ck::CK_SESSION_HANDLE) -> Option<usize> {
    if h == 0 {
        return None;
    }
    let idx = (h - 1) as usize;
    match st.sessions.get(idx) {
        Some(Some(_)) => Some(idx),
        _ => None,
    }
}

// ---- General-purpose -------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn C_Initialize(pInitArgs: ck::CK_VOID_PTR) -> ck::CK_RV {
    let mut st = lock();
    if st.initialized {
        return ALREADY_INIT;
    }
    if !pInitArgs.is_null() {
        let args = pInitArgs as *const ck::CK_C_INITIALIZE_ARGS;
        if !(*args).pReserved.is_null() {
            return ARGS_BAD;
        }
        // Locking arguments are accepted but not acted upon: the global
        // Mutex already makes every entry point thread-safe.
    }
    st.sessions.clear();
    st.devices.clear();
    st.initialized = true;
    OK
}

#[no_mangle]
pub unsafe extern "C" fn C_Finalize(pReserved: ck::CK_VOID_PTR) -> ck::CK_RV {
    let mut st = lock();
    if !st.initialized {
        return NOT_INIT;
    }
    if !pReserved.is_null() {
        return ARGS_BAD;
    }
    st.sessions.clear(); // drops every open Device (closes the HID handle)
    st.initialized = false;
    OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetInfo(pInfo: *mut ck::CK_INFO) -> ck::CK_RV {
    let st = lock();
    if !st.initialized {
        return NOT_INIT;
    }
    if pInfo.is_null() {
        return ARGS_BAD;
    }
    let mut info: ck::CK_INFO = std::mem::zeroed();
    info.cryptokiVersion = ck::CK_VERSION {
        major: 2,
        minor: 40,
    };
    pad(&mut info.manufacturerID, MANUFACTURER);
    info.flags = 0;
    pad(&mut info.libraryDescription, LIB_DESCRIPTION);
    info.libraryVersion = ck::CK_VERSION {
        major: LIB_VERSION_MAJOR,
        minor: LIB_VERSION_MINOR,
    };
    *pInfo = info;
    OK
}

// ---- Slot and token management ---------------------------------------

#[no_mangle]
pub unsafe extern "C" fn C_GetSlotList(
    _tokenPresent: ck::CK_BBOOL,
    pSlotList: *mut ck::CK_SLOT_ID,
    pulCount: *mut ck::CK_ULONG,
) -> ck::CK_RV {
    let mut st = lock();
    if !st.initialized {
        return NOT_INIT;
    }
    if pulCount.is_null() {
        return ARGS_BAD;
    }
    // Hot-plug: rescan on every list. A slot exists only where a token
    // is enumerated, so `tokenPresent` doesn't change the answer.
    if !rescan(&mut st) {
        return DEVICE_ERROR;
    }
    let n = st.devices.len() as ck::CK_ULONG;
    if pSlotList.is_null() {
        *pulCount = n;
        return OK;
    }
    if *pulCount < n {
        *pulCount = n;
        return BUFFER_SMALL;
    }
    for i in 0..st.devices.len() {
        *pSlotList.add(i) = i as ck::CK_SLOT_ID;
    }
    *pulCount = n;
    OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetSlotInfo(
    slotID: ck::CK_SLOT_ID,
    pInfo: *mut ck::CK_SLOT_INFO,
) -> ck::CK_RV {
    let st = lock();
    if !st.initialized {
        return NOT_INIT;
    }
    if pInfo.is_null() {
        return ARGS_BAD;
    }
    let dev = match st.devices.get(slotID as usize) {
        Some(d) => d,
        None => return SLOT_INVALID,
    };
    let mut info: ck::CK_SLOT_INFO = std::mem::zeroed();
    pad(&mut info.slotDescription, SLOT_DESCRIPTION);
    pad(
        &mut info.manufacturerID,
        dev.manufacturer.as_deref().unwrap_or(MANUFACTURER),
    );
    info.flags =
        (ck::CKF_TOKEN_PRESENT | ck::CKF_REMOVABLE_DEVICE | ck::CKF_HW_SLOT) as ck::CK_FLAGS;
    *pInfo = info;
    OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetTokenInfo(
    slotID: ck::CK_SLOT_ID,
    pInfo: *mut ck::CK_TOKEN_INFO,
) -> ck::CK_RV {
    let st = lock();
    if !st.initialized {
        return NOT_INIT;
    }
    if pInfo.is_null() {
        return ARGS_BAD;
    }
    let dev = match st.devices.get(slotID as usize) {
        Some(d) => d,
        None => return SLOT_INVALID,
    };
    let mut info: ck::CK_TOKEN_INFO = std::mem::zeroed();
    pad(
        &mut info.label,
        dev.product.as_deref().unwrap_or(TOKEN_MODEL),
    );
    pad(
        &mut info.manufacturerID,
        dev.manufacturer.as_deref().unwrap_or(MANUFACTURER),
    );
    pad(&mut info.model, TOKEN_MODEL);
    pad(
        &mut info.serialNumber,
        dev.serial_number.as_deref().unwrap_or(""),
    );
    // CKF_RNG is the whole point. No CKF_LOGIN_REQUIRED (no PIN);
    // CKF_WRITE_PROTECTED (nothing here writes).
    info.flags =
        (ck::CKF_RNG | ck::CKF_TOKEN_INITIALIZED | ck::CKF_WRITE_PROTECTED) as ck::CK_FLAGS;
    info.ulMaxSessionCount = MAX_SESSIONS as ck::CK_ULONG;
    info.ulMaxRwSessionCount = 0;
    info.ulMaxPinLen = 0;
    info.ulMinPinLen = 0;
    let unavail = ck::CK_UNAVAILABLE_INFORMATION as ck::CK_ULONG;
    info.ulTotalPublicMemory = unavail;
    info.ulFreePublicMemory = unavail;
    info.ulTotalPrivateMemory = unavail;
    info.ulFreePrivateMemory = unavail;
    info.firmwareVersion = ck::CK_VERSION {
        major: LIB_VERSION_MAJOR,
        minor: LIB_VERSION_MINOR,
    };
    *pInfo = info;
    OK
}

// ---- Session management ----------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn C_OpenSession(
    slotID: ck::CK_SLOT_ID,
    flags: ck::CK_FLAGS,
    _pApplication: ck::CK_VOID_PTR,
    _Notify: ck::CK_NOTIFY,
    phSession: *mut ck::CK_SESSION_HANDLE,
) -> ck::CK_RV {
    let mut st = lock();
    if !st.initialized {
        return NOT_INIT;
    }
    if phSession.is_null() {
        return ARGS_BAD;
    }
    if flags & (ck::CKF_SERIAL_SESSION as ck::CK_FLAGS) == 0 {
        return PARALLEL_NOPE;
    }
    // Sessions may be opened before any C_GetSlotList -- populate the
    // slot table on demand.
    if st.devices.is_empty() && !rescan(&mut st) {
        return DEVICE_ERROR;
    }
    let info = match st.devices.get(slotID as usize) {
        Some(d) => d.clone(),
        None => return SLOT_INVALID,
    };
    let dev = match Device::open(&info) {
        Ok(d) => d,
        Err(hid::Error::NoDevice) => return TOKEN_NOT_PRESENT,
        Err(_) => return DEVICE_ERROR,
    };

    // Reuse a freed slot if there is one, else grow the table.
    let idx = match st.sessions.iter().position(|s| s.is_none()) {
        Some(i) => i,
        None => {
            if st.sessions.len() >= MAX_SESSIONS {
                return SESSION_COUNT;
            }
            st.sessions.push(None);
            st.sessions.len() - 1
        }
    };
    st.sessions[idx] = Some(Session {
        slot: slotID,
        flags,
        dev,
    });
    *phSession = (idx + 1) as ck::CK_SESSION_HANDLE;
    OK
}

#[no_mangle]
pub unsafe extern "C" fn C_CloseSession(hSession: ck::CK_SESSION_HANDLE) -> ck::CK_RV {
    let mut st = lock();
    if !st.initialized {
        return NOT_INIT;
    }
    match session_index(&st, hSession) {
        Some(idx) => {
            st.sessions[idx] = None; // drops the Device
            OK
        }
        None => SESSION_INVALID,
    }
}

#[no_mangle]
pub unsafe extern "C" fn C_CloseAllSessions(slotID: ck::CK_SLOT_ID) -> ck::CK_RV {
    let mut st = lock();
    if !st.initialized {
        return NOT_INIT;
    }
    if slotID as usize >= st.devices.len() {
        return SLOT_INVALID;
    }
    for s in st.sessions.iter_mut() {
        if s.as_ref().map(|x| x.slot) == Some(slotID) {
            *s = None;
        }
    }
    OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetSessionInfo(
    hSession: ck::CK_SESSION_HANDLE,
    pInfo: *mut ck::CK_SESSION_INFO,
) -> ck::CK_RV {
    let st = lock();
    if !st.initialized {
        return NOT_INIT;
    }
    if pInfo.is_null() {
        return ARGS_BAD;
    }
    let idx = match session_index(&st, hSession) {
        Some(i) => i,
        None => return SESSION_INVALID,
    };
    let s = st.sessions[idx].as_ref().unwrap();
    let mut info: ck::CK_SESSION_INFO = std::mem::zeroed();
    info.slotID = s.slot;
    // No login concept: a session is always in the public state.
    info.state = if s.flags & (ck::CKF_RW_SESSION as ck::CK_FLAGS) != 0 {
        ck::CKS_RW_PUBLIC_SESSION as ck::CK_STATE
    } else {
        ck::CKS_RO_PUBLIC_SESSION as ck::CK_STATE
    };
    info.flags = s.flags;
    info.ulDeviceError = 0;
    *pInfo = info;
    OK
}

// ---- Random numbers (the whole point) --------------------------------

#[no_mangle]
pub unsafe extern "C" fn C_SeedRandom(
    hSession: ck::CK_SESSION_HANDLE,
    pSeed: *mut ck::CK_BYTE,
    ulSeedLen: ck::CK_ULONG,
) -> ck::CK_RV {
    let st = lock();
    if !st.initialized {
        return NOT_INIT;
    }
    if session_index(&st, hSession).is_none() {
        return SESSION_INVALID;
    }
    if pSeed.is_null() && ulSeedLen != 0 {
        return ARGS_BAD;
    }
    // Accepted and ignored: the ring-oscillator TRNG takes no seed.
    OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GenerateRandom(
    hSession: ck::CK_SESSION_HANDLE,
    RandomData: *mut ck::CK_BYTE,
    ulRandomLen: ck::CK_ULONG,
) -> ck::CK_RV {
    let st = lock();
    if !st.initialized {
        return NOT_INIT;
    }
    let idx = match session_index(&st, hSession) {
        Some(i) => i,
        None => return SESSION_INVALID,
    };
    if ulRandomLen == 0 {
        return OK;
    }
    if RandomData.is_null() {
        return ARGS_BAD;
    }
    let buf = std::slice::from_raw_parts_mut(RandomData, ulRandomLen as usize);
    let dev = &st.sessions[idx].as_ref().unwrap().dev;
    match dev.rng(buf) {
        Ok(()) => OK,
        Err(e) => rng_err(e),
    }
}

// ---- Parallel-execution legacy stubs (PKCS#11 v3.0 base sec. 5.20) --------
// These two must return CKR_FUNCTION_NOT_PARALLEL, not
// CKR_FUNCTION_NOT_SUPPORTED, per the spec.

#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionStatus(_hSession: ck::CK_SESSION_HANDLE) -> ck::CK_RV {
    NOT_PARALLEL
}

#[no_mangle]
pub unsafe extern "C" fn C_CancelFunction(_hSession: ck::CK_SESSION_HANDLE) -> ck::CK_RV {
    NOT_PARALLEL
}

// ---- The function list -----------------------------------------------
// Fully populated so any application accepts the module. Field order is
// the PKCS#11 v2.40 order the CK_FUNCTION_LIST struct defines; the real
// entry points above, the two NOT_PARALLEL stubs, and the generated
// CKR_FUNCTION_NOT_SUPPORTED stubs in `unsupported` fill the rest.

static FUNCTION_LIST: ck::CK_FUNCTION_LIST = ck::CK_FUNCTION_LIST {
    version: ck::CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

/// The one symbol a Cryptoki application dlsyms by name. Callable
/// before `C_Initialize` -- that is the whole point of the function
/// list. Every other entry point is reached through the returned
/// table.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(
    ppFunctionList: *mut *mut ck::CK_FUNCTION_LIST,
) -> ck::CK_RV {
    if ppFunctionList.is_null() {
        return ARGS_BAD;
    }
    *ppFunctionList = &FUNCTION_LIST as *const ck::CK_FUNCTION_LIST as *mut ck::CK_FUNCTION_LIST;
    OK
}
