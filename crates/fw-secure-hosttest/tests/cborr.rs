// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The Non-secure world's CBOR reader.
//!
//! 159 lines that had no tests, sitting on the wrong side of the
//! TrustZone boundary by design: everything a host sends reaches this
//! before anything else looks at it. Its own header comment says
//! parsing attacker-controlled CBOR "is the historical CVE surface in
//! this class of device", which makes zero coverage the wrong place to
//! leave it.
//!
//! Rust bounds-checks slices, so the failure this cannot have is a
//! buffer overrun. The failures it *can* have are a parser that accepts
//! something malformed, that desynchronises and reads one field as
//! another, or that recurses further than the stack allows. Those are
//! what this goes after.

use pqf_fw_secure_hosttest::cborr::{
    Reader, MAJOR_ARRAY, MAJOR_BYTES, MAJOR_MAP, MAJOR_NINT, MAJOR_SIMPLE, MAJOR_TEXT, MAJOR_UINT,
};

/// Encode a CBOR header the long way, so the tests are not written
/// against the same code they check.
fn hdr(major: u8, arg: u64) -> Vec<u8> {
    let m = major << 5;
    if arg <= 23 {
        vec![m | arg as u8]
    } else if arg <= u8::MAX as u64 {
        vec![m | 24, arg as u8]
    } else if arg <= u16::MAX as u64 {
        let a = (arg as u16).to_be_bytes();
        vec![m | 25, a[0], a[1]]
    } else if arg <= u32::MAX as u64 {
        let a = (arg as u32).to_be_bytes();
        let mut v = vec![m | 26];
        v.extend_from_slice(&a);
        v
    } else {
        let a = arg.to_be_bytes();
        let mut v = vec![m | 27];
        v.extend_from_slice(&a);
        v
    }
}

fn bstr(payload: &[u8]) -> Vec<u8> {
    let mut v = hdr(MAJOR_BYTES, payload.len() as u64);
    v.extend_from_slice(payload);
    v
}

// ---------- headers ----------

#[test]
fn every_argument_width_round_trips() {
    // 0..23 inline, then the 1/2/4/8-byte forms. A width read with the
    // wrong number of bytes desynchronises everything after it, so this
    // is the foundation the rest of the parser stands on.
    for arg in [
        0u64,
        1,
        23,
        24,
        255,
        256,
        65535,
        65536,
        0xFFFF_FFFF,
        0x1_0000_0000,
        u64::MAX,
    ] {
        let enc = hdr(MAJOR_UINT, arg);
        let mut r = Reader::new(&enc);
        assert_eq!(
            r.header(),
            Some((MAJOR_UINT, arg)),
            "arg {arg} ({enc:02x?})"
        );
        assert_eq!(
            r.position(),
            enc.len(),
            "arg {arg} consumed the wrong width"
        );
    }
}

#[test]
fn every_major_type_is_reported() {
    for major in [
        MAJOR_UINT,
        MAJOR_NINT,
        MAJOR_BYTES,
        MAJOR_TEXT,
        MAJOR_ARRAY,
        MAJOR_MAP,
        MAJOR_SIMPLE,
    ] {
        let enc = hdr(major, 5);
        assert_eq!(
            Reader::new(&enc).header(),
            Some((major, 5)),
            "major {major}"
        );
    }
}

#[test]
fn reserved_additional_info_is_rejected() {
    // 28, 29 and 30 are reserved by RFC 8949. Treating them as anything
    // is inventing a wire format.
    for ai in [28u8, 29, 30] {
        let enc = [MAJOR_UINT << 5 | ai];
        assert_eq!(
            Reader::new(&enc).header(),
            None,
            "additional info {ai} was accepted"
        );
    }
}

#[test]
fn indefinite_length_is_rejected_for_every_major_type() {
    // CTAP2 canonical CBOR forbids indefinite length, and the module
    // rejects it rather than supporting it -- deliberately, so there is
    // only one length model to get wrong. Check it holds for the
    // container types too, not just for scalars.
    for major in [
        MAJOR_BYTES,
        MAJOR_TEXT,
        MAJOR_ARRAY,
        MAJOR_MAP,
        MAJOR_SIMPLE,
    ] {
        let enc = [major << 5 | 31];
        assert_eq!(
            Reader::new(&enc).header(),
            None,
            "indefinite length accepted for major {major}"
        );
    }
}

#[test]
fn a_truncated_header_yields_none_rather_than_a_partial_value() {
    // Each multi-byte width, one byte short.
    for (ai, width) in [(24u8, 1usize), (25, 2), (26, 4), (27, 8)] {
        let mut enc = vec![MAJOR_UINT << 5 | ai];
        enc.extend(std::iter::repeat(0xAA).take(width - 1));
        assert_eq!(
            Reader::new(&enc).header(),
            None,
            "ai {ai} truncated was accepted"
        );
    }
}

#[test]
fn an_empty_buffer_reads_as_none_not_a_panic() {
    let mut r = Reader::new(&[]);
    assert_eq!(r.header(), None);
    assert_eq!(r.uint(), None);
    assert_eq!(r.map(), None);
    assert_eq!(r.array(), None);
    assert_eq!(r.str_bytes(MAJOR_BYTES), None);
    assert_eq!(r.take(1), None);
    assert_eq!(r.skip(), None);
    assert_eq!(r.position(), 0, "a failed read still moved the cursor");
}

// ---------- typed accessors ----------

#[test]
fn typed_readers_refuse_the_wrong_major_type() {
    // uint() on a map, map() on an array, and so on. A reader that
    // accepted the wrong type here would hand Secure a length where it
    // expected a value.
    let m = hdr(MAJOR_MAP, 2);
    let a = hdr(MAJOR_ARRAY, 2);
    let u = hdr(MAJOR_UINT, 2);
    assert_eq!(Reader::new(&m).uint(), None);
    assert_eq!(Reader::new(&a).uint(), None);
    assert_eq!(Reader::new(&u).map(), None);
    assert_eq!(Reader::new(&a).map(), None);
    assert_eq!(Reader::new(&u).array(), None);
    assert_eq!(Reader::new(&m).array(), None);
    // ...and accept the right one.
    assert_eq!(Reader::new(&m).map(), Some(2));
    assert_eq!(Reader::new(&a).array(), Some(2));
    assert_eq!(Reader::new(&u).uint(), Some(2));
}

#[test]
fn str_bytes_borrows_exactly_the_declared_payload() {
    let enc = bstr(b"\x01\x02\x03\x04");
    let mut r = Reader::new(&enc);
    assert_eq!(r.str_bytes(MAJOR_BYTES), Some(&b"\x01\x02\x03\x04"[..]));
    assert_eq!(r.position(), enc.len());
    // Nothing left.
    assert_eq!(r.header(), None);
}

#[test]
fn str_bytes_refuses_a_payload_that_runs_past_the_buffer() {
    // The declared length is the attacker's field. Claiming more than
    // was sent must fail rather than return a short slice.
    let mut enc = hdr(MAJOR_TEXT, 32);
    enc.extend_from_slice(b"only eight");
    let mut r = Reader::new(&enc);
    assert_eq!(r.str_bytes(MAJOR_TEXT), None);
}

#[test]
fn str_bytes_refuses_a_length_that_would_overflow_the_cursor() {
    // u64::MAX as a length. On a 64-bit host `pos + len` overflows and
    // checked_add catches it; the same encoding on the 32-bit target
    // truncates in the `as usize` cast first. Either way the answer
    // must be None, which is what this pins.
    let enc = hdr(MAJOR_BYTES, u64::MAX);
    assert_eq!(Reader::new(&enc).str_bytes(MAJOR_BYTES), None);
    let enc = hdr(MAJOR_BYTES, u64::MAX - 8);
    assert_eq!(Reader::new(&enc).str_bytes(MAJOR_BYTES), None);
}

#[test]
fn str_bytes_refuses_a_length_that_truncates_on_a_32_bit_usize() {
    // The one this suite was worth writing for. The module used to do
    // `len as usize`, which on the 32-bit target silently drops the high
    // word: a declared length of 0x1_0000_0004 becomes 4, and a payload
    // that must be refused is accepted as a short one instead.
    //
    // The host cannot reproduce that -- usize is 64 bits here, so the
    // same encoding fails the bounds check for the right reason and the
    // test passes either way. What makes this test carry its weight is
    // running it on a 32-bit target, where before the fix it fails.
    //
    // Rust bounds-checks the slice, so this was never memory unsafety.
    // It was the target accepting an encoding no test could see it
    // accept, which is the more durable kind of problem.
    let mut enc = hdr(MAJOR_BYTES, 0x1_0000_0004);
    enc.extend_from_slice(&[0xAA; 32]); // plenty of payload for len==4
    assert_eq!(
        Reader::new(&enc).str_bytes(MAJOR_BYTES),
        None,
        "a length above usize::MAX on a 32-bit target must be refused, not truncated"
    );

    // skip() takes the same path over a string payload.
    assert_eq!(Reader::new(&enc).skip(), None);

    // And the boundary itself: exactly 2^32 must not become 0.
    let mut enc = hdr(MAJOR_TEXT, 0x1_0000_0000);
    enc.extend_from_slice(&[0xBB; 8]);
    assert_eq!(
        Reader::new(&enc).str_bytes(MAJOR_TEXT),
        None,
        "2^32 truncated to an empty string"
    );
}

#[test]
fn a_zero_length_string_is_legal_and_empty() {
    let enc = bstr(b"");
    let mut r = Reader::new(&enc);
    assert_eq!(r.str_bytes(MAJOR_BYTES), Some(&[][..]));
    assert_eq!(r.position(), 1);
}

#[test]
fn take_is_bounded_by_the_buffer() {
    let buf = [0xAAu8, 0xBB, 0xCC];
    let mut r = Reader::new(&buf);
    assert_eq!(r.take(2), Some(&buf[0..2]));
    assert_eq!(r.take(2), None, "took more than remained");
    assert_eq!(r.take(1), Some(&buf[2..3]));
    assert_eq!(r.take(usize::MAX), None, "an overflowing take was allowed");
}

#[test]
fn position_tracks_a_sub_encoding_verbatim() {
    // The documented use: capture the raw bytes of one item so they can
    // be handed on without re-encoding. If position() disagreed with
    // what was consumed, the captured slice would be wrong.
    let inner = bstr(b"payload");
    let mut enc = hdr(MAJOR_ARRAY, 2);
    enc.extend_from_slice(&hdr(MAJOR_UINT, 7));
    let start_of_inner = enc.len();
    enc.extend_from_slice(&inner);

    let mut r = Reader::new(&enc);
    assert_eq!(r.array(), Some(2));
    assert_eq!(r.uint(), Some(7));
    let a = r.position();
    assert_eq!(a, start_of_inner);
    r.skip().expect("skip the byte string");
    let b = r.position();
    assert_eq!(
        &enc[a..b],
        &inner[..],
        "the captured sub-encoding is not verbatim"
    );
}

// ---------- skip ----------

#[test]
fn skip_consumes_exactly_one_scalar() {
    for enc in [
        hdr(MAJOR_UINT, 1),
        hdr(MAJOR_UINT, 1000),
        hdr(MAJOR_NINT, 5),
        hdr(MAJOR_SIMPLE, 21), // true
    ] {
        let mut r = Reader::new(&enc);
        assert_eq!(r.skip(), Some(()), "{enc:02x?}");
        assert_eq!(r.position(), enc.len(), "{enc:02x?} left bytes behind");
    }
}

#[test]
fn skip_consumes_a_strings_payload_too() {
    let enc = bstr(b"twelve bytes");
    let mut r = Reader::new(&enc);
    assert_eq!(r.skip(), Some(()));
    assert_eq!(r.position(), enc.len());
}

#[test]
fn skip_refuses_a_string_whose_payload_is_not_there() {
    let mut enc = hdr(MAJOR_BYTES, 64);
    enc.extend_from_slice(b"short");
    assert_eq!(Reader::new(&enc).skip(), None);
}

#[test]
fn skip_walks_a_whole_nested_structure() {
    // {1: [1, 2], 2: h'AABB', 3: {4: 5}}  then a trailing marker that
    // must survive: if skip over-consumes, the marker disappears.
    let mut enc = hdr(MAJOR_MAP, 3);
    enc.extend_from_slice(&hdr(MAJOR_UINT, 1));
    enc.extend_from_slice(&hdr(MAJOR_ARRAY, 2));
    enc.extend_from_slice(&hdr(MAJOR_UINT, 1));
    enc.extend_from_slice(&hdr(MAJOR_UINT, 2));
    enc.extend_from_slice(&hdr(MAJOR_UINT, 2));
    enc.extend_from_slice(&bstr(&[0xAA, 0xBB]));
    enc.extend_from_slice(&hdr(MAJOR_UINT, 3));
    enc.extend_from_slice(&hdr(MAJOR_MAP, 1));
    enc.extend_from_slice(&hdr(MAJOR_UINT, 4));
    enc.extend_from_slice(&hdr(MAJOR_UINT, 5));
    let end_of_map = enc.len();
    enc.extend_from_slice(&hdr(MAJOR_UINT, 99)); // the marker

    let mut r = Reader::new(&enc);
    assert_eq!(r.skip(), Some(()));
    assert_eq!(
        r.position(),
        end_of_map,
        "skip did not land on the map's end"
    );
    assert_eq!(r.uint(), Some(99), "the item after the map was eaten");
}

#[test]
fn skip_is_bounded_by_depth() {
    // The comment says 8 is generous because CTAP2 requests are two or
    // three deep. Confirm both edges: 8 nested arrays are fine, 9 are
    // refused rather than recursing. This is the check that keeps a
    // hostile request off the Non-secure guard page.
    let nest = |n: usize| {
        let mut v = Vec::new();
        for _ in 0..n {
            v.extend_from_slice(&hdr(MAJOR_ARRAY, 1));
        }
        v.extend_from_slice(&hdr(MAJOR_UINT, 0));
        v
    };
    assert_eq!(
        Reader::new(&nest(7)).skip(),
        Some(()),
        "7 levels should be fine"
    );
    assert_eq!(
        Reader::new(&nest(8)).skip(),
        None,
        "8 levels was not refused"
    );
    assert_eq!(
        Reader::new(&nest(64)).skip(),
        None,
        "64 levels was not refused"
    );
}

#[test]
fn skip_refuses_a_container_it_cannot_complete() {
    // An array header claiming more elements than were sent. Accepting
    // it would leave the cursor somewhere arbitrary with a success
    // return, which is worse than failing.
    let mut enc = hdr(MAJOR_ARRAY, 4);
    enc.extend_from_slice(&hdr(MAJOR_UINT, 1));
    assert_eq!(Reader::new(&enc).skip(), None);

    // ...and a map claiming a count it cannot honour, including the
    // odd case where the key is present but the value is not.
    let mut enc = hdr(MAJOR_MAP, 1);
    enc.extend_from_slice(&hdr(MAJOR_UINT, 1));
    assert_eq!(
        Reader::new(&enc).skip(),
        None,
        "a map with a key and no value was accepted"
    );
}

#[test]
fn a_huge_container_count_terminates_rather_than_hanging() {
    // `for _ in 0..arg` with arg from the wire. u64::MAX elements must
    // fail on the first missing one, not iterate.
    let enc = hdr(MAJOR_ARRAY, u64::MAX);
    assert_eq!(Reader::new(&enc).skip(), None);
    let enc = hdr(MAJOR_MAP, u64::MAX);
    assert_eq!(Reader::new(&enc).skip(), None);
}

#[test]
fn skip_refuses_reserved_and_indefinite_containers() {
    for ai in [28u8, 29, 30, 31] {
        let enc = [MAJOR_ARRAY << 5 | ai];
        assert_eq!(Reader::new(&enc).skip(), None, "array ai {ai}");
        let enc = [MAJOR_MAP << 5 | ai];
        assert_eq!(Reader::new(&enc).skip(), None, "map ai {ai}");
    }
}

// ---------- shapes the CTAP2 demux actually sees ----------

#[test]
fn a_realistic_make_credential_map_walks_field_by_field() {
    // The shape main.rs:705 parses: a map keyed by small uints, values
    // of mixed type, walked by reading each key then skipping or
    // taking the value. Anything that desynchronises here reads one
    // CTAP parameter as another.
    let mut enc = hdr(MAJOR_MAP, 3);
    enc.extend_from_slice(&hdr(MAJOR_UINT, 1)); // clientDataHash
    enc.extend_from_slice(&bstr(&[0x42; 32]));
    enc.extend_from_slice(&hdr(MAJOR_UINT, 2)); // rp
    enc.extend_from_slice(&hdr(MAJOR_MAP, 1));
    enc.extend_from_slice(&{
        let mut v = hdr(MAJOR_TEXT, 2);
        v.extend_from_slice(b"id");
        v
    });
    enc.extend_from_slice(&{
        let mut v = hdr(MAJOR_TEXT, 11);
        v.extend_from_slice(b"example.com");
        v
    });
    enc.extend_from_slice(&hdr(MAJOR_UINT, 3)); // options
    enc.extend_from_slice(&hdr(MAJOR_SIMPLE, 21));

    let mut r = Reader::new(&enc);
    assert_eq!(r.map(), Some(3));

    assert_eq!(r.uint(), Some(1));
    assert_eq!(r.str_bytes(MAJOR_BYTES), Some(&[0x42u8; 32][..]));

    assert_eq!(r.uint(), Some(2));
    assert_eq!(r.map(), Some(1));
    assert_eq!(r.str_bytes(MAJOR_TEXT), Some(&b"id"[..]));
    assert_eq!(r.str_bytes(MAJOR_TEXT), Some(&b"example.com"[..]));

    assert_eq!(r.uint(), Some(3));
    assert_eq!(r.header(), Some((MAJOR_SIMPLE, 21)));

    assert_eq!(
        r.position(),
        enc.len(),
        "the request did not consume exactly"
    );
}

#[test]
fn an_unknown_parameter_can_be_skipped_without_losing_the_next_one() {
    // Forward compatibility: a client sending a parameter this build
    // does not know must not cost the parameters after it.
    let mut enc = hdr(MAJOR_MAP, 2);
    enc.extend_from_slice(&hdr(MAJOR_UINT, 99)); // unknown key
    enc.extend_from_slice(&hdr(MAJOR_ARRAY, 2)); // ...with a compound value
    enc.extend_from_slice(&bstr(b"a"));
    enc.extend_from_slice(&hdr(MAJOR_MAP, 1));
    enc.extend_from_slice(&hdr(MAJOR_UINT, 1));
    enc.extend_from_slice(&hdr(MAJOR_UINT, 2));
    enc.extend_from_slice(&hdr(MAJOR_UINT, 4)); // the one we want
    enc.extend_from_slice(&bstr(b"kept"));

    let mut r = Reader::new(&enc);
    assert_eq!(r.map(), Some(2));
    assert_eq!(r.uint(), Some(99));
    r.skip().expect("skip the unknown value");
    assert_eq!(r.uint(), Some(4));
    assert_eq!(r.str_bytes(MAJOR_BYTES), Some(&b"kept"[..]));
}

#[test]
fn trailing_garbage_after_a_complete_item_is_the_callers_problem_not_a_crash() {
    // The reader does not enforce "exactly one item"; it just stops.
    // Pinned so a future change to that contract is a deliberate one.
    let mut enc = hdr(MAJOR_UINT, 1);
    enc.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    let mut r = Reader::new(&enc);
    assert_eq!(r.uint(), Some(1));
    assert_eq!(r.position(), 1);
    // 0xFF is major 7, additional info 31 -- indefinite, so rejected.
    assert_eq!(r.header(), None);
}

// ---------- the recursion bound ----------
//
// Found by mutation, not by reading: changing `depth - 1` to `depth - 0`
// in the map arm of `skip_depth` left every test in this file passing.
// That line is the only thing standing between attacker-controlled CBOR
// and a stack overflow in the Non-secure image -- the module comment
// says so -- and nothing here constrained it. The array arm was in the
// same position.
//
// A recursion guard has to be checked at its boundary. A test that only
// nests three deep passes whether the limit is 8, 800, or absent.

/// `{1: {1: ... 0 ...}}` nested `n` deep.
fn nested_map(n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(0xA1); // map(1)
        v.push(0x01); // key: 1
    }
    v.push(0x00); // innermost value: 0
    v
}

/// `[[[ ... 0 ... ]]]` nested `n` deep.
fn nested_array(n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(0x81); // array(1)
    }
    v.push(0x00);
    v
}

#[test]
fn nesting_within_the_bound_is_skipped() {
    // The accept half. A guard that refused everything would pass every
    // refusal test below and quietly break every real request -- CTAP2
    // requests are two or three levels deep and must go through.
    for n in 1..=7 {
        assert!(
            Reader::new(&nested_map(n)).skip().is_some(),
            "a {n}-deep map was refused, and real requests nest three deep"
        );
        assert!(
            Reader::new(&nested_array(n)).skip().is_some(),
            "a {n}-deep array was refused"
        );
    }
}

#[test]
fn nesting_past_the_bound_is_refused_rather_than_recursed() {
    // The refuse half, and the reason the file exists. Without this,
    // `skip` recurses once per level on a stack the Non-secure image
    // shares with everything else it does.
    for n in [8usize, 9, 16, 64, 256] {
        assert!(
            Reader::new(&nested_map(n)).skip().is_none(),
            "a {n}-deep map was walked -- the depth bound is not holding"
        );
        assert!(
            Reader::new(&nested_array(n)).skip().is_none(),
            "a {n}-deep array was walked"
        );
    }
}

#[test]
fn the_bound_falls_in_exactly_the_same_place_for_maps_and_arrays() {
    // Two arms, two hand-written `depth - 1`s. Pinning the boundary
    // itself rather than "deep is refused" is what makes an off-by-one
    // in one arm and not the other visible: 7 in, 8 out, both.
    assert!(
        Reader::new(&nested_map(7)).skip().is_some(),
        "map: 7 should be in"
    );
    assert!(
        Reader::new(&nested_map(8)).skip().is_none(),
        "map: 8 should be out"
    );
    assert!(
        Reader::new(&nested_array(7)).skip().is_some(),
        "array: 7 should be in"
    );
    assert!(
        Reader::new(&nested_array(8)).skip().is_none(),
        "array: 8 should be out"
    );
}

/// `{{{...}: 0}: 0}` -- nested `n` deep through map KEYS only.
fn key_nested_map(n: usize) -> Vec<u8> {
    let mut v = vec![0xA1u8; n]; // n map(1) headers
    v.push(0x00); // innermost key
    v.extend(core::iter::repeat(0x00).take(n)); // one value per level
    v
}

/// `{0: {0: {0: ...}}}` -- nested `n` deep through map VALUES only.
fn value_nested_map(n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(0xA1); // map(1)
        v.push(0x00); // key: 0
    }
    v.push(0x00); // innermost value
    v
}

#[test]
fn depth_hidden_in_map_keys_is_bounded() {
    // The map arm recurses twice per entry -- once for the key, once for
    // the value -- on two separate lines, and each carries its own
    // hand-written decrement. Descending through KEYS is what exercises
    // the first of them on its own.
    //
    // This is the mutant that survived the first fix: a test that
    // descends through arrays still runs out of depth in the array arm,
    // so the key arm's decrement can be missing and nothing notices. A
    // key is normally a small integer, which is exactly why an eye
    // skips over it.
    for n in 1..=7 {
        assert!(key_nested_map(n).len() > 0);
        assert!(
            Reader::new(&key_nested_map(n)).skip().is_some(),
            "a {n}-deep key nest was refused"
        );
    }
    for n in [8usize, 12, 32] {
        assert!(
            Reader::new(&key_nested_map(n)).skip().is_none(),
            "a {n}-deep nest hidden in map KEYS was walked -- the key \
             recursion is not losing depth"
        );
    }
}

#[test]
fn depth_hidden_in_map_values_is_bounded() {
    // The other line, isolated the same way.
    for n in 1..=7 {
        assert!(
            Reader::new(&value_nested_map(n)).skip().is_some(),
            "a {n}-deep value nest was refused"
        );
    }
    for n in [8usize, 12, 32] {
        assert!(
            Reader::new(&value_nested_map(n)).skip().is_none(),
            "a {n}-deep nest hidden in map VALUES was walked"
        );
    }
}
