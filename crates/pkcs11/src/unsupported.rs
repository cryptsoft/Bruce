// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Generated CKR_FUNCTION_NOT_SUPPORTED stubs for every Cryptoki v2.40
//! entry point this module does not implement.
//!
//! "Fake the entire API surface, do not authenticate, just hand over
//! RNG output" -- so the function list is fully populated (a NULL
//! pointer would make some callers reject the module) and every
//! function outside the RNG path exists and politely declines.
//!
//! Signatures are generated from the `cryptoki-sys` bindings so they
//! match `CK_FUNCTION_LIST` exactly; do not hand-edit. The RNG path
//! and the session/slot/token machinery live in `lib.rs`.

#![allow(non_snake_case, unused_variables, clippy::too_many_arguments)]

use crate::ck;
use cryptoki_sys::*;

pub unsafe extern "C" fn C_GetMechanismList(
    _a0: CK_SLOT_ID,
    _a1: *mut CK_MECHANISM_TYPE,
    _a2: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_GetMechanismInfo(
    _a0: CK_SLOT_ID,
    _a1: CK_MECHANISM_TYPE,
    _a2: *mut CK_MECHANISM_INFO,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_InitToken(
    _a0: CK_SLOT_ID,
    _a1: *mut CK_UTF8CHAR,
    _a2: CK_ULONG,
    _a3: *mut CK_UTF8CHAR,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_InitPIN(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_UTF8CHAR,
    _a2: CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_SetPIN(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_UTF8CHAR,
    _a2: CK_ULONG,
    _a3: *mut CK_UTF8CHAR,
    _a4: CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_GetOperationState(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_SetOperationState(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: CK_OBJECT_HANDLE,
    _a4: CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_Login(
    _a0: CK_SESSION_HANDLE,
    _a1: CK_USER_TYPE,
    _a2: *mut CK_UTF8CHAR,
    _a3: CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_Logout(_a0: CK_SESSION_HANDLE) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_CreateObject(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_ATTRIBUTE,
    _a2: CK_ULONG,
    _a3: *mut CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_CopyObject(
    _a0: CK_SESSION_HANDLE,
    _a1: CK_OBJECT_HANDLE,
    _a2: *mut CK_ATTRIBUTE,
    _a3: CK_ULONG,
    _a4: *mut CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_DestroyObject(
    _a0: CK_SESSION_HANDLE,
    _a1: CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_GetObjectSize(
    _a0: CK_SESSION_HANDLE,
    _a1: CK_OBJECT_HANDLE,
    _a2: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_GetAttributeValue(
    _a0: CK_SESSION_HANDLE,
    _a1: CK_OBJECT_HANDLE,
    _a2: *mut CK_ATTRIBUTE,
    _a3: CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_SetAttributeValue(
    _a0: CK_SESSION_HANDLE,
    _a1: CK_OBJECT_HANDLE,
    _a2: *mut CK_ATTRIBUTE,
    _a3: CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_FindObjectsInit(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_ATTRIBUTE,
    _a2: CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_FindObjects(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_OBJECT_HANDLE,
    _a2: CK_ULONG,
    _a3: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_FindObjectsFinal(_a0: CK_SESSION_HANDLE) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_EncryptInit(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_MECHANISM,
    _a2: CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_Encrypt(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_EncryptUpdate(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_EncryptFinal(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_DecryptInit(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_MECHANISM,
    _a2: CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_Decrypt(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_DecryptUpdate(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_DecryptFinal(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_DigestInit(_a0: CK_SESSION_HANDLE, _a1: *mut CK_MECHANISM) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_Digest(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_DigestUpdate(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_DigestKey(_a0: CK_SESSION_HANDLE, _a1: CK_OBJECT_HANDLE) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_DigestFinal(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_SignInit(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_MECHANISM,
    _a2: CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_Sign(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_SignUpdate(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_SignFinal(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_SignRecoverInit(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_MECHANISM,
    _a2: CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_SignRecover(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_VerifyInit(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_MECHANISM,
    _a2: CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_Verify(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_VerifyUpdate(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_VerifyFinal(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_VerifyRecoverInit(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_MECHANISM,
    _a2: CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_VerifyRecover(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_DigestEncryptUpdate(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_DecryptDigestUpdate(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_SignEncryptUpdate(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_DecryptVerifyUpdate(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_BYTE,
    _a2: CK_ULONG,
    _a3: *mut CK_BYTE,
    _a4: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_GenerateKey(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_MECHANISM,
    _a2: *mut CK_ATTRIBUTE,
    _a3: CK_ULONG,
    _a4: *mut CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_GenerateKeyPair(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_MECHANISM,
    _a2: *mut CK_ATTRIBUTE,
    _a3: CK_ULONG,
    _a4: *mut CK_ATTRIBUTE,
    _a5: CK_ULONG,
    _a6: *mut CK_OBJECT_HANDLE,
    _a7: *mut CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_WrapKey(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_MECHANISM,
    _a2: CK_OBJECT_HANDLE,
    _a3: CK_OBJECT_HANDLE,
    _a4: *mut CK_BYTE,
    _a5: *mut CK_ULONG,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_UnwrapKey(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_MECHANISM,
    _a2: CK_OBJECT_HANDLE,
    _a3: *mut CK_BYTE,
    _a4: CK_ULONG,
    _a5: *mut CK_ATTRIBUTE,
    _a6: CK_ULONG,
    _a7: *mut CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_DeriveKey(
    _a0: CK_SESSION_HANDLE,
    _a1: *mut CK_MECHANISM,
    _a2: CK_OBJECT_HANDLE,
    _a3: *mut CK_ATTRIBUTE,
    _a4: CK_ULONG,
    _a5: *mut CK_OBJECT_HANDLE,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}

pub unsafe extern "C" fn C_WaitForSlotEvent(
    _a0: CK_FLAGS,
    _a1: *mut CK_SLOT_ID,
    _a2: *mut core::ffi::c_void,
) -> ck::CK_RV {
    ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV
}
