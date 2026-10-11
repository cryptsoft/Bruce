// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Cryptoki conformance tests for the module's state machine.
//!
//! These live inside the crate rather than in `tests/` because the lib is
//! a `cdylib`: there is no rlib for an integration test to link against,
//! and adding one would change what a release build emits.
//!
//! Everything here runs with no token attached. The module's whole
//! surface is a state machine over one global `STATE`, and the rules an
//! application actually depends on -- initialize-before-use, the
//! two-call buffer protocol, which errors mean "your handle is wrong"
//! versus "your cable fell out" -- are all decidable without hardware.
//! The one path that genuinely needs a token, `C_GenerateRandom` over
//! `CTAPHID_CMD_RNG`, is exercised by `c/pkcs11`'s own harness and on
//! silicon; here it is only checked for its argument handling.
//!
//! `STATE` is process-global, so every test takes [`SERIAL`] first. The
//! harness runs tests on threads by default and two of these racing would
//! produce failures that depend on scheduling.
//!
//! Four of these used to be `#[ignore]`d. They call `C_GetSlotList`,
//! which rescans the USB bus, and that path took the whole process down
//! when entered from more than one thread. That was fixed at the layer
//! that owns the problem -- all `hidapi` use in `pqf-ctaphid` is now
//! confined to a single worker thread -- so they run normally, in
//! parallel, with the rest. `crates/ctaphid-client/tests/thread_safety.rs`
//! guards the regression directly.

use super::*;
use std::sync::{Mutex, MutexGuard};

/// Serialises the tests against the module's global state. Poison is
/// ignored: a panic in one test has already been reported, and letting it
/// cascade into every later test only obscures the first failure.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// A test fixture that guarantees `C_Finalize` runs even on panic, so one
/// failing test cannot leave the module initialized for the next.
struct Initialized {
    _guard: MutexGuard<'static, ()>,
}

impl Initialized {
    fn new() -> Self {
        let guard = serial();
        // Whatever a previous test left behind.
        unsafe { C_Finalize(std::ptr::null_mut()) };
        assert_eq!(unsafe { C_Initialize(std::ptr::null_mut()) }, OK);
        Self { _guard: guard }
    }
}

impl Drop for Initialized {
    fn drop(&mut self) {
        unsafe { C_Finalize(std::ptr::null_mut()) };
    }
}

/// Ask for the slot count without asking for the slots -- the first half
/// of Cryptoki's two-call buffer protocol.
fn slot_count() -> ck::CK_ULONG {
    let mut n: ck::CK_ULONG = 0;
    assert_eq!(
        unsafe { C_GetSlotList(0, std::ptr::null_mut(), &mut n) },
        OK
    );
    n
}

// ---- initialize / finalize -------------------------------------------

#[test]
fn initialize_twice_is_rejected() {
    let _fx = Initialized::new();
    assert_eq!(unsafe { C_Initialize(std::ptr::null_mut()) }, ALREADY_INIT);
}

#[test]
fn finalize_without_initialize_is_rejected() {
    let _g = serial();
    unsafe { C_Finalize(std::ptr::null_mut()) };
    assert_eq!(unsafe { C_Finalize(std::ptr::null_mut()) }, NOT_INIT);
}

#[test]
fn finalize_rejects_a_non_null_reserved_argument() {
    let _fx = Initialized::new();
    let mut junk: u8 = 0;
    assert_eq!(
        unsafe { C_Finalize(&mut junk as *mut u8 as ck::CK_VOID_PTR) },
        ARGS_BAD
    );
    // ...and having been rejected, the module is still usable.
    let mut info: ck::CK_INFO = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { C_GetInfo(&mut info) }, OK);
}

#[test]
fn initialize_rejects_reserved_inside_the_args_struct() {
    let _g = serial();
    unsafe { C_Finalize(std::ptr::null_mut()) };
    let mut junk: u8 = 0;
    let mut args: ck::CK_C_INITIALIZE_ARGS = unsafe { std::mem::zeroed() };
    args.pReserved = &mut junk as *mut u8 as ck::CK_VOID_PTR;
    assert_eq!(
        unsafe { C_Initialize(&mut args as *mut _ as ck::CK_VOID_PTR) },
        ARGS_BAD
    );
}

#[test]
fn initialize_accepts_os_locking_arguments() {
    // Applications routinely pass CKF_OS_LOCKING_OK. The global Mutex
    // already makes every entry point thread-safe, so this is accepted
    // rather than refused -- refusing it locks out most callers.
    let _g = serial();
    unsafe { C_Finalize(std::ptr::null_mut()) };
    let mut args: ck::CK_C_INITIALIZE_ARGS = unsafe { std::mem::zeroed() };
    args.flags = ck::CKF_OS_LOCKING_OK as ck::CK_FLAGS;
    assert_eq!(
        unsafe { C_Initialize(&mut args as *mut _ as ck::CK_VOID_PTR) },
        OK
    );
    unsafe { C_Finalize(std::ptr::null_mut()) };
}

#[test]
fn every_stateful_entry_point_refuses_before_initialize() {
    let _g = serial();
    unsafe { C_Finalize(std::ptr::null_mut()) };

    let mut n: ck::CK_ULONG = 0;
    let mut h: ck::CK_SESSION_HANDLE = 0;
    let mut info: ck::CK_INFO = unsafe { std::mem::zeroed() };
    let mut slot: ck::CK_SLOT_INFO = unsafe { std::mem::zeroed() };
    let mut tok: ck::CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    let mut byte: ck::CK_BYTE = 0;

    unsafe {
        assert_eq!(C_GetInfo(&mut info), NOT_INIT);
        assert_eq!(C_GetSlotList(0, std::ptr::null_mut(), &mut n), NOT_INIT);
        assert_eq!(C_GetSlotInfo(0, &mut slot), NOT_INIT);
        assert_eq!(C_GetTokenInfo(0, &mut tok), NOT_INIT);
        assert_eq!(
            C_OpenSession(
                0,
                ck::CKF_SERIAL_SESSION as ck::CK_FLAGS,
                std::ptr::null_mut(),
                None,
                &mut h
            ),
            NOT_INIT
        );
        assert_eq!(C_CloseSession(1), NOT_INIT);
        assert_eq!(C_CloseAllSessions(0), NOT_INIT);
        assert_eq!(C_GenerateRandom(1, &mut byte, 1), NOT_INIT);
        assert_eq!(C_SeedRandom(1, &mut byte, 1), NOT_INIT);
    }
}

#[test]
fn finalize_closes_the_session_table() {
    // Sessions must not survive a finalize/initialize cycle: their
    // handles would still resolve while the HID devices behind them have
    // been dropped.
    let _fx = Initialized::new();
    let mut byte: ck::CK_BYTE = 0;
    unsafe {
        C_Finalize(std::ptr::null_mut());
        assert_eq!(C_Initialize(std::ptr::null_mut()), OK);
        assert_eq!(C_GenerateRandom(1, &mut byte, 1), SESSION_INVALID);
    }
}

// ---- C_GetInfo -------------------------------------------------------

#[test]
fn getinfo_reports_cryptoki_2_40_and_the_library_version() {
    let _fx = Initialized::new();
    let mut info: ck::CK_INFO = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { C_GetInfo(&mut info) }, OK);
    assert_eq!(info.cryptokiVersion.major, 2);
    assert_eq!(info.cryptokiVersion.minor, 40);
    assert_eq!(info.libraryVersion.major, LIB_VERSION_MAJOR);
    assert_eq!(info.libraryVersion.minor, LIB_VERSION_MINOR);
    assert_eq!(info.flags, 0);
}

#[test]
fn getinfo_rejects_a_null_pointer() {
    let _fx = Initialized::new();
    assert_eq!(unsafe { C_GetInfo(std::ptr::null_mut()) }, ARGS_BAD);
}

#[test]
fn cryptoki_strings_are_space_padded_and_not_nul_terminated() {
    // PKCS#11 v3.0 base 4.1. A NUL-terminated field here shows up in
    // pkcs11-tool as trailing garbage, and some applications compare the
    // full fixed width.
    let _fx = Initialized::new();
    let mut info: ck::CK_INFO = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { C_GetInfo(&mut info) }, OK);

    assert!(info.manufacturerID.starts_with(MANUFACTURER.as_bytes()));
    assert!(
        !info.manufacturerID.contains(&0),
        "manufacturerID must not be NUL-terminated"
    );
    assert_eq!(
        info.manufacturerID[MANUFACTURER.len()..],
        vec![b' '; info.manufacturerID.len() - MANUFACTURER.len()][..],
        "the tail must be spaces"
    );

    assert!(info
        .libraryDescription
        .starts_with(LIB_DESCRIPTION.as_bytes()));
    assert!(!info.libraryDescription.contains(&0));
}

#[test]
fn pad_truncates_rather_than_overflowing() {
    let mut dst = [0u8; 4];
    pad(&mut dst, "much longer than four");
    assert_eq!(&dst, b"much");
}

// ---- slots: the two-call buffer protocol -----------------------------

#[test]
fn getslotlist_rejects_a_null_count() {
    let _fx = Initialized::new();
    assert_eq!(
        unsafe { C_GetSlotList(0, std::ptr::null_mut(), std::ptr::null_mut()) },
        ARGS_BAD
    );
}

#[test]
fn getslotlist_with_a_null_buffer_reports_the_count() {
    // First call of the two-call protocol: the count is written and no
    // slots are. Whether a token happens to be plugged in only changes
    // the number.
    let _fx = Initialized::new();
    let mut n: ck::CK_ULONG = 0xdead;
    assert_eq!(
        unsafe { C_GetSlotList(0, std::ptr::null_mut(), &mut n) },
        OK
    );
    assert_ne!(n, 0xdead, "count was not written");
    assert!(n as usize <= MAX_SLOTS);
}

#[test]
fn getslotlist_reports_the_same_count_for_present_and_all() {
    // A slot exists only where a token is enumerated, so tokenPresent
    // cannot change the answer. An application that trusts the flag would
    // otherwise see a slot vanish between two calls.
    let _fx = Initialized::new();
    let mut with: ck::CK_ULONG = 0;
    let mut without: ck::CK_ULONG = 0;
    unsafe {
        assert_eq!(C_GetSlotList(1, std::ptr::null_mut(), &mut with), OK);
        assert_eq!(C_GetSlotList(0, std::ptr::null_mut(), &mut without), OK);
    }
    assert_eq!(with, without);
}

#[test]
fn a_too_small_slot_buffer_reports_the_size_it_needed() {
    let _fx = Initialized::new();
    let n = slot_count();
    if n == 0 {
        // No token attached: a zero-length request is satisfiable, so
        // there is no undersized case to provoke.
        let mut count: ck::CK_ULONG = 0;
        let mut slots = [0 as ck::CK_SLOT_ID; 1];
        assert_eq!(
            unsafe { C_GetSlotList(0, slots.as_mut_ptr(), &mut count) },
            OK
        );
        assert_eq!(count, 0);
        return;
    }
    let mut count: ck::CK_ULONG = n - 1;
    let mut slots = vec![0 as ck::CK_SLOT_ID; n as usize];
    assert_eq!(
        unsafe { C_GetSlotList(0, slots.as_mut_ptr(), &mut count) },
        BUFFER_SMALL
    );
    assert_eq!(count, n, "the required size must be reported back");
}

#[test]
fn slot_ids_are_dense_indices_from_zero() {
    let _fx = Initialized::new();
    let n = slot_count();
    let mut count = n;
    let mut slots = vec![0 as ck::CK_SLOT_ID; n as usize + 1];
    assert_eq!(
        unsafe { C_GetSlotList(0, slots.as_mut_ptr(), &mut count) },
        OK
    );
    assert_eq!(count, n);
    for i in 0..n as usize {
        assert_eq!(slots[i], i as ck::CK_SLOT_ID);
    }
}

#[test]
fn slot_and_token_info_reject_an_out_of_range_slot() {
    let _fx = Initialized::new();
    let bogus = (MAX_SLOTS + 1) as ck::CK_SLOT_ID;
    let mut slot: ck::CK_SLOT_INFO = unsafe { std::mem::zeroed() };
    let mut tok: ck::CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    unsafe {
        assert_eq!(C_GetSlotInfo(bogus, &mut slot), SLOT_INVALID);
        assert_eq!(C_GetTokenInfo(bogus, &mut tok), SLOT_INVALID);
    }
}

#[test]
fn slot_info_rejects_a_null_pointer() {
    let _fx = Initialized::new();
    assert_eq!(unsafe { C_GetSlotInfo(0, std::ptr::null_mut()) }, ARGS_BAD);
}

// ---- sessions --------------------------------------------------------

#[test]
fn opensession_requires_the_serial_flag() {
    // CKF_SERIAL_SESSION is mandatory in every current Cryptoki version;
    // its absence is specifically CKR_SESSION_PARALLEL_NOT_SUPPORTED and
    // not a generic argument error. Checked before the slot is resolved,
    // so this needs no token.
    let _fx = Initialized::new();
    let mut h: ck::CK_SESSION_HANDLE = 0;
    assert_eq!(
        unsafe { C_OpenSession(0, 0, std::ptr::null_mut(), None, &mut h) },
        PARALLEL_NOPE
    );
}

#[test]
fn opensession_rejects_a_null_handle_pointer() {
    let _fx = Initialized::new();
    assert_eq!(
        unsafe {
            C_OpenSession(
                0,
                ck::CKF_SERIAL_SESSION as ck::CK_FLAGS,
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        },
        ARGS_BAD
    );
}

#[test]
fn session_handles_are_never_zero() {
    // Zero is the null handle in Cryptoki; handing it out as a real
    // session makes every later validity check wrong. `session_index`
    // encodes that rule, so it can be checked without opening anything.
    let _fx = Initialized::new();
    let st = lock();
    assert!(session_index(&st, 0).is_none());
}

#[test]
fn unknown_session_handles_are_rejected_everywhere() {
    let _fx = Initialized::new();
    let mut byte: ck::CK_BYTE = 0;
    let mut info: ck::CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    unsafe {
        assert_eq!(C_CloseSession(1), SESSION_INVALID);
        assert_eq!(C_CloseSession(99), SESSION_INVALID);
        assert_eq!(C_GetSessionInfo(1, &mut info), SESSION_INVALID);
        assert_eq!(C_GenerateRandom(1, &mut byte, 1), SESSION_INVALID);
        assert_eq!(C_SeedRandom(1, &mut byte, 1), SESSION_INVALID);
    }
}

#[test]
fn closeallsessions_rejects_a_slot_that_does_not_exist() {
    let _fx = Initialized::new();
    let bogus = (MAX_SLOTS + 1) as ck::CK_SLOT_ID;
    assert_eq!(unsafe { C_CloseAllSessions(bogus) }, SLOT_INVALID);
}

// ---- the RNG path's argument handling --------------------------------

#[test]
fn generaterandom_checks_the_session_before_the_buffer() {
    // A null buffer with a bad handle is a handle error, not an argument
    // error: the session check comes first, so an application debugging
    // its handle plumbing gets the useful message.
    let _fx = Initialized::new();
    assert_eq!(
        unsafe { C_GenerateRandom(1, std::ptr::null_mut(), 8) },
        SESSION_INVALID
    );
}

#[test]
fn seedrandom_tolerates_a_null_seed_of_length_zero() {
    // Still a session error here -- the point is that the null pointer
    // itself is not what is objected to when the length is zero.
    let _fx = Initialized::new();
    assert_eq!(
        unsafe { C_SeedRandom(1, std::ptr::null_mut(), 0) },
        SESSION_INVALID
    );
}

// ---- the function list -----------------------------------------------

#[test]
fn getfunctionlist_rejects_a_null_out_pointer() {
    // Callable before C_Initialize by design -- it is how an application
    // finds C_Initialize in the first place.
    let _g = serial();
    assert_eq!(unsafe { C_GetFunctionList(std::ptr::null_mut()) }, ARGS_BAD);
}

#[test]
fn getfunctionlist_works_before_initialize() {
    let _g = serial();
    unsafe { C_Finalize(std::ptr::null_mut()) };
    let mut list: *mut ck::CK_FUNCTION_LIST = std::ptr::null_mut();
    assert_eq!(unsafe { C_GetFunctionList(&mut list) }, OK);
    assert!(!list.is_null());
    let l = unsafe { &*list };
    assert_eq!(l.version.major, 2);
    assert_eq!(l.version.minor, 40);
}

#[test]
fn the_function_list_is_fully_populated() {
    // A single None here is a null pointer in the C table, and an
    // application that calls it segfaults rather than getting
    // CKR_FUNCTION_NOT_SUPPORTED. Checked structurally: every field of
    // CK_FUNCTION_LIST after `version` is an Option<fn>, and the struct
    // is all-pointers, so a scan for a zero word finds any gap.
    let mut list: *mut ck::CK_FUNCTION_LIST = std::ptr::null_mut();
    assert_eq!(unsafe { C_GetFunctionList(&mut list) }, OK);

    let bytes = std::mem::size_of::<ck::CK_FUNCTION_LIST>();
    let words = bytes / std::mem::size_of::<usize>();
    let raw = unsafe { std::slice::from_raw_parts(list as *const usize, words) };
    // Word 0 is `version` (two CK_BYTEs plus padding), not a pointer.
    for (i, w) in raw.iter().enumerate().skip(1) {
        assert_ne!(*w, 0, "function list entry {i} is a null pointer");
    }
}

#[test]
fn the_function_list_points_at_the_exported_symbols() {
    // The table and the `#[no_mangle]` exports have to be the same
    // functions: an application may find either, and a mismatch means two
    // different behaviours from one module.
    let mut list: *mut ck::CK_FUNCTION_LIST = std::ptr::null_mut();
    assert_eq!(unsafe { C_GetFunctionList(&mut list) }, OK);
    let l = unsafe { &*list };
    assert_eq!(l.C_Initialize.unwrap() as usize, C_Initialize as usize);
    assert_eq!(l.C_Finalize.unwrap() as usize, C_Finalize as usize);
    assert_eq!(l.C_GetInfo.unwrap() as usize, C_GetInfo as usize);
    assert_eq!(l.C_GetSlotList.unwrap() as usize, C_GetSlotList as usize);
    assert_eq!(l.C_OpenSession.unwrap() as usize, C_OpenSession as usize);
    assert_eq!(
        l.C_GenerateRandom.unwrap() as usize,
        C_GenerateRandom as usize
    );
    assert_eq!(
        l.C_GetFunctionList.unwrap() as usize,
        C_GetFunctionList as usize
    );
}

// ---- the stubs -------------------------------------------------------

#[test]
fn unimplemented_functions_report_not_supported() {
    // Not an error path: this is the module telling an application it is
    // an RNG and nothing else, so the application can fall back rather
    // than fail.
    let not_supported = ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV;
    unsafe {
        assert_eq!(C_Login(1, 0, std::ptr::null_mut(), 0), not_supported);
        assert_eq!(C_Logout(1), not_supported);
        assert_eq!(
            C_InitToken(0, std::ptr::null_mut(), 0, std::ptr::null_mut()),
            not_supported
        );
        assert_eq!(
            C_CreateObject(1, std::ptr::null_mut(), 0, std::ptr::null_mut()),
            not_supported
        );
        assert_eq!(C_DestroyObject(1, 0), not_supported);
        assert_eq!(
            C_GetMechanismList(0, std::ptr::null_mut(), std::ptr::null_mut()),
            not_supported
        );
        assert_eq!(C_DigestInit(1, std::ptr::null_mut()), not_supported);
        assert_eq!(C_SignInit(1, std::ptr::null_mut(), 0), not_supported);
    }
}

#[test]
fn the_parallel_stubs_report_not_parallel_not_unsupported() {
    // PKCS#11 v3.0 base 5.20 names these two specifically: legacy
    // functions that must answer CKR_FUNCTION_NOT_PARALLEL. Returning
    // CKR_FUNCTION_NOT_SUPPORTED instead trips conformance checkers.
    unsafe {
        assert_eq!(C_GetFunctionStatus(1), NOT_PARALLEL);
        assert_eq!(C_CancelFunction(1), NOT_PARALLEL);
    }
    assert_ne!(NOT_PARALLEL, ck::CKR_FUNCTION_NOT_SUPPORTED as ck::CK_RV);
}
