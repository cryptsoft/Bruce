// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The largeBlobs command -- phase 5 of the CTAP2 surface.
//!
//! 412 lines. A device-wide byte array a relying party can read and
//! write, used to attach data to a passkey. Reads are unauthenticated by
//! design; writes need a token carrying `lbw` once a PIN exists.
//!
//! Two things make it worth testing carefully. The read path takes an
//! attacker-controlled length and offset with no authentication at all,
//! which is the only place on this device where that is true. And writes
//! arrive in fragments assembled across several transactions, so the
//! staging buffer is state a malformed sequence can steer.
//!
//! Requests are framed as CTAP 2.1 numbers them. That was not always
//! true: get, set and offset used to be rotated by one and the
//! pinUvAuth prefix was `0x0c 0x02` where the spec has `h'0c00'`, which
//! made the whole command unreachable by any client but our own.

use pqf_cbor::Value;
use pqf_firmware_hosttest as fw;

use fw::client_pin::{PERM_GET_ASSERTION, PERM_LARGE_BLOB_WRITE};
use fw::ctap2::{CTAP2_LARGE_BLOBS as LB, CTAP2_OK};
use fw::flash_store::MAX_LARGE_BLOB_LEN;
use fw::testclient::{auth_param, Device};

const ERR_INVALID_LENGTH: u8 = 0x03;
const ERR_LARGE_BLOB_STORAGE_FULL: u8 = 0x18;
const ERR_MISSING_PARAMETER: u8 = 0x14;
const ERR_PIN_AUTH_INVALID: u8 = 0x33;
const ERR_PUAT_REQUIRED: u8 = 0x36;

/// CTAP 2.1 sec. 6.10: 0x01 get, 0x02 set, 0x03 offset, 0x04 length,
/// 0x05 pinUvAuthParam, 0x06 pinUvAuthProtocol.
const F_GET: u64 = 0x01;
const F_SET: u64 = 0x02;
const F_OFFSET: u64 = 0x03;
const F_LENGTH: u64 = 0x04;
const F_AUTH: u64 = 0x05;
const F_PROTO: u64 = 0x06;

/// The CTAP 2.1 initial array: `0x80` then SHA-256(0x80)[..16].
fn initial_array() -> Vec<u8> {
    let mut v = vec![0x80u8];
    v.extend_from_slice(&fw::bc_crypto::sha256(&[0x80u8])[..16]);
    v
}

/// A well-formed array of `n` bytes: the marker, filler, and the
/// trailing 16 bytes a client checks. Only the length and the round trip
/// matter here -- the device does not validate the hash on write.
fn array_of(n: usize) -> Vec<u8> {
    assert!(n >= 17);
    let mut v = vec![0x80u8];
    v.extend(std::iter::repeat(0xA5).take(n - 17));
    v.extend_from_slice(&fw::bc_crypto::sha256(&v)[..16]);
    v
}

fn map(entries: Vec<(u64, Value)>) -> Value {
    let mut m: Vec<(Value, Value)> = entries
        .into_iter()
        .map(|(k, v)| (Value::Uint(k), v))
        .collect();
    m.sort_by_key(|(k, _)| if let Value::Uint(n) = k { *n } else { 0 });
    Value::Map(m)
}

/// The message a write's `pinUvAuthParam` covers, per CTAP 2.1 sec. 6.10:
/// `0xff * 32 || h'0c00' || uint32LE(offset) || SHA-256(fragment)`.
fn write_auth(token: &[u8], offset: u32, fragment: &[u8]) -> Vec<u8> {
    let mut msg = vec![0xffu8; 32];
    msg.push(0x0c);
    msg.push(0x00);
    msg.extend_from_slice(&offset.to_le_bytes());
    msg.extend_from_slice(&fw::bc_crypto::sha256(fragment));
    auth_param(token, &msg)
}

trait Blobs {
    fn get(&mut self, offset: u64, count: u64) -> Vec<u8>;
    fn read_all(&mut self, n: usize) -> Vec<u8>;
    fn write(&mut self, offset: u32, fragment: &[u8], total: Option<u64>) -> Vec<u8>;
}

impl Blobs for Device {
    fn get(&mut self, offset: u64, count: u64) -> Vec<u8> {
        self.send(
            LB,
            &map(vec![
                (F_OFFSET, Value::Uint(offset)),
                (F_GET, Value::Uint(count)),
            ]),
        )
    }

    /// The array bytes out of a successful read.
    fn read_all(&mut self, n: usize) -> Vec<u8> {
        let r = self.get(0, n as u64);
        assert_eq!(r[0], CTAP2_OK, "largeBlobs get returned {:#04x}", r[0]);
        match Device::field(&r, 0x01).expect("no config field") {
            Value::Bytes(b) => b,
            other => panic!("the config field is {other:?}"),
        }
    }

    fn write(&mut self, offset: u32, fragment: &[u8], total: Option<u64>) -> Vec<u8> {
        let mut e = vec![
            (F_OFFSET, Value::Uint(offset as u64)),
            (F_SET, Value::Bytes(fragment.to_vec())),
        ];
        if let Some(t) = total {
            e.push((F_LENGTH, Value::Uint(t)));
        }
        if !self.token.is_empty() {
            e.push((
                F_AUTH,
                Value::Bytes(write_auth(&self.token, offset, fragment)),
            ));
            e.push((F_PROTO, Value::Uint(1)));
        }
        self.send(LB, &map(e))
    }
}

fn writer() -> Device {
    Device::authenticated(PERM_LARGE_BLOB_WRITE as u64, None)
}

// ---- reading ----------------------------------------------------------

#[test]
fn a_fresh_device_serves_the_spec_initial_array() {
    // A client validates the trailing hash, so serving nothing reads as
    // a corrupt array rather than an empty one.
    let mut d = Device::bare();
    assert_eq!(d.read_all(17), initial_array());
}

#[test]
fn reading_needs_no_authentication() {
    // By design -- sec. 6.10 gates writes, not reads. Worth a test because
    // it is the one command on this device that answers a stranger.
    let mut d = Device::bare();
    assert!(d.token.is_empty(), "setup: this device should have no PIN");
    assert_eq!(d.get(0, 17)[0], CTAP2_OK);
}

#[test]
fn a_read_can_be_asked_for_more_than_exists_without_overrunning() {
    // `get` is an attacker-controlled u32 arriving with no
    // authentication, and `offset + get` wraps on the 32-bit target
    // where overflow checks are off. A plain add would slice with
    // start > end and panic -- a no-auth denial of service. The clamp is
    // what stops it, so it is checked at the values that would wrap.
    let mut d = Device::bare();
    let n = initial_array().len();
    for count in [n as u64 + 1, 1024, u32::MAX as u64, u64::from(u32::MAX) - 1] {
        let r = d.get(0, count);
        assert_eq!(
            r[0], CTAP2_OK,
            "a get of {count} was refused rather than clamped"
        );
        match Device::field(&r, 0x01) {
            Some(Value::Bytes(b)) => {
                assert_eq!(b.len(), n, "a get of {count} returned {} bytes", b.len())
            }
            other => panic!("the config field is {other:?}"),
        }
    }
}

#[test]
fn a_read_at_an_offset_past_the_end_is_refused() {
    let mut d = Device::bare();
    for offset in [1000u64, 9999, u32::MAX as u64] {
        assert_eq!(
            d.get(offset, 4)[0],
            ERR_INVALID_LENGTH,
            "a read at offset {offset} was not refused"
        );
    }
}

#[test]
fn a_read_at_the_exact_end_returns_nothing_rather_than_failing() {
    // offset == len is the boundary a client hits when it has already
    // read the whole array and asks for one more page.
    let mut d = Device::bare();
    let n = initial_array().len() as u64;
    let r = d.get(n, 16);
    assert_eq!(r[0], CTAP2_OK, "a read at the exact end was refused");
    match Device::field(&r, 0x01) {
        Some(Value::Bytes(b)) => assert!(
            b.is_empty(),
            "a read past the end returned {} bytes",
            b.len()
        ),
        other => panic!("the config field is {other:?}"),
    }
}

#[test]
fn a_request_that_is_neither_a_read_nor_a_write_is_refused() {
    let mut d = Device::bare();
    let r = d.send(LB, &map(vec![(F_OFFSET, Value::Uint(0))]));
    assert_eq!(
        r[0], ERR_MISSING_PARAMETER,
        "a request with no get and no set was served"
    );
}

// ---- writing ----------------------------------------------------------

#[test]
fn an_array_round_trips_through_a_single_fragment_write() {
    let mut d = writer();
    let blob = array_of(64);
    assert_eq!(
        d.write(0, &blob, Some(blob.len() as u64))[0],
        CTAP2_OK,
        "a single-fragment write failed"
    );
    assert_eq!(d.read_all(blob.len()), blob, "the array came back altered");
}

#[test]
fn a_write_assembles_across_fragments() {
    // The multi-fragment path sec. 6.10.3: `length` on the first fragment
    // only, then offsets. This is the flow a real client uses for
    // anything past maxFragmentLength.
    let mut d = writer();
    let blob = array_of(300);
    let (a, b, c) = (&blob[..100], &blob[100..200], &blob[200..]);
    assert_eq!(
        d.write(0, a, Some(blob.len() as u64))[0],
        CTAP2_OK,
        "fragment 1"
    );
    assert_eq!(d.write(100, b, None)[0], CTAP2_OK, "fragment 2");
    assert_eq!(d.write(200, c, None)[0], CTAP2_OK, "fragment 3");
    assert_eq!(
        d.read_all(blob.len()),
        blob,
        "the reassembled array is wrong"
    );
}

#[test]
fn a_partial_write_does_not_replace_what_is_already_stored() {
    // The commit happens on the last fragment. A client that starts a
    // write and stops must leave the previous array intact, or a dropped
    // connection destroys the user's data.
    let mut d = writer();
    let first = array_of(64);
    assert_eq!(d.write(0, &first, Some(first.len() as u64))[0], CTAP2_OK);

    let second = array_of(300);
    assert_eq!(
        d.write(0, &second[..100], Some(second.len() as u64))[0],
        CTAP2_OK
    );
    assert_eq!(
        d.read_all(first.len()),
        first,
        "an unfinished write replaced the stored array"
    );
}

#[test]
fn an_array_can_be_replaced_by_a_shorter_one() {
    // The case a bitwise-AND bug hides in: the tail of the old array is
    // still on the die, and a length that was not rewritten would hand
    // it back.
    let mut d = writer();
    let long = array_of(512);
    assert_eq!(d.write(0, &long, Some(long.len() as u64))[0], CTAP2_OK);
    let short = array_of(17);
    assert_eq!(d.write(0, &short, Some(short.len() as u64))[0], CTAP2_OK);
    assert_eq!(
        d.read_all(long.len()),
        short,
        "the array kept some of its old contents"
    );
}

#[test]
fn an_array_shorter_than_the_minimum_is_refused() {
    // 17 bytes is the smallest legal serialised array: an empty CBOR
    // array plus its 16-byte hash. Anything shorter cannot carry the
    // hash a client validates.
    let mut d = writer();
    for n in [0usize, 1, 8, 16] {
        let frag = vec![0x80u8; n];
        assert_eq!(
            d.write(0, &frag, Some(n as u64))[0],
            ERR_INVALID_LENGTH,
            "a {n}-byte array was accepted"
        );
    }
}

#[test]
fn an_array_larger_than_the_advertised_ceiling_is_storage_full_not_malformed() {
    // getInfo advertises maxSerializedLargeBlobArray. Accepting more
    // would either overrun the sector or truncate silently.
    //
    // The status distinguishes it from a malformed length, because a
    // client can act on the difference: too big to ever store is
    // answered by writing less, a bad length by fixing the request.
    // Both used to come back as 0x29, which is CTAP2_ERR_NOT_BUSY and
    // means neither.
    let mut d = writer();
    for n in [MAX_LARGE_BLOB_LEN + 1, MAX_LARGE_BLOB_LEN * 2, 65535] {
        assert_eq!(
            d.write(0, &array_of(64), Some(n as u64))[0],
            ERR_LARGE_BLOB_STORAGE_FULL,
            "a declared length of {n} was accepted"
        );
    }
}

#[test]
fn a_length_below_the_minimum_array_is_invalid_length_not_storage_full() {
    // The other side of the split. A 17-byte serialised array is the
    // smallest legal one; shorter is malformed, not too large.
    let mut d = writer();
    for n in [0u64, 1, 16] {
        assert_eq!(
            d.write(0, &array_of(64), Some(n))[0],
            ERR_INVALID_LENGTH,
            "a declared length of {n} gave the wrong status"
        );
    }
}

#[test]
fn an_array_of_exactly_the_advertised_ceiling_is_accepted() {
    let mut d = writer();
    let blob = array_of(MAX_LARGE_BLOB_LEN);
    assert_eq!(
        d.write(0, &blob, Some(blob.len() as u64))[0],
        CTAP2_OK,
        "an array of exactly the advertised maximum was refused"
    );
    assert_eq!(d.read_all(blob.len()).len(), MAX_LARGE_BLOB_LEN);
}

#[test]
fn a_first_fragment_without_a_declared_length_is_refused() {
    // sec. 6.10.3 makes `length` required at offset zero. Without it there
    // is no way to know when the array is complete, so a write could be
    // committed half-assembled.
    let mut d = writer();
    let blob = array_of(64);
    assert_ne!(
        d.write(0, &blob, None)[0],
        CTAP2_OK,
        "a write starting with no declared length was accepted"
    );
}

#[test]
fn a_continuation_fragment_with_no_write_in_progress_is_refused() {
    // Arriving at a non-zero offset with no staging buffer is either a
    // lost first fragment or an attempt to write into one that belongs
    // to someone else.
    let mut d = writer();
    let blob = array_of(300);
    assert_ne!(
        d.write(100, &blob[100..200], None)[0],
        CTAP2_OK,
        "a continuation fragment was accepted with nothing in flight"
    );
}

#[test]
fn a_fragment_at_the_wrong_offset_is_refused() {
    // The offsets have to run contiguously. A gap would leave
    // uninitialised staging bytes inside the committed array.
    let mut d = writer();
    let blob = array_of(300);
    assert_eq!(
        d.write(0, &blob[..100], Some(blob.len() as u64))[0],
        CTAP2_OK
    );
    for wrong in [50u32, 99, 101, 200] {
        assert_ne!(
            d.write(wrong, &blob[100..200], None)[0],
            CTAP2_OK,
            "a fragment at offset {wrong} was accepted after 100 bytes"
        );
    }
}

// ---- the write authentication gate -----------------------------------

#[test]
fn a_write_needs_a_token_once_a_pin_is_set() {
    let mut d = writer();
    let blob = array_of(64);
    let r = d.send(
        LB,
        &map(vec![
            (F_OFFSET, Value::Uint(0)),
            (F_SET, Value::Bytes(blob.clone())),
            (F_LENGTH, Value::Uint(blob.len() as u64)),
        ]),
    );
    assert_eq!(
        r[0], ERR_PUAT_REQUIRED,
        "an unauthenticated write was accepted"
    );
    assert_eq!(d.read_all(17), initial_array(), "the array changed anyway");
}

#[test]
fn a_write_needs_the_large_blob_permission_specifically() {
    // A browser's assertion token must not be able to overwrite the
    // device-wide array.
    let mut d = Device::authenticated(PERM_GET_ASSERTION as u64, None);
    let blob = array_of(64);
    let r = d.write(0, &blob, Some(blob.len() as u64));
    assert_eq!(
        r[0], ERR_PIN_AUTH_INVALID,
        "a token without lbw wrote the array"
    );
}

#[test]
fn a_write_with_a_forged_auth_param_is_refused() {
    let mut d = writer();
    let blob = array_of(64);
    for forged in [vec![0u8; 16], vec![0xff; 16], vec![], vec![0u8; 32]] {
        let r = d.send(
            LB,
            &map(vec![
                (F_OFFSET, Value::Uint(0)),
                (F_SET, Value::Bytes(blob.clone())),
                (F_LENGTH, Value::Uint(blob.len() as u64)),
                (F_AUTH, Value::Bytes(forged.clone())),
                (F_PROTO, Value::Uint(1)),
            ]),
        );
        assert_eq!(
            r[0], ERR_PIN_AUTH_INVALID,
            "auth param {forged:?} was accepted"
        );
    }
    assert_eq!(d.read_all(17), initial_array(), "the array changed anyway");
}

#[test]
fn a_write_is_bound_to_its_own_offset_and_contents() {
    // The signed message covers both, so a param captured from one
    // fragment must not authorise a different one. Otherwise an observer
    // could replay a write at an offset of their choosing.
    let mut d = writer();
    let blob = array_of(300);
    let good = write_auth(&d.token, 0, &blob[..100]);
    let r = d.send(
        LB,
        &map(vec![
            (F_OFFSET, Value::Uint(0)),
            (F_SET, Value::Bytes(blob[100..200].to_vec())),
            (F_LENGTH, Value::Uint(blob.len() as u64)),
            (F_AUTH, Value::Bytes(good)),
            (F_PROTO, Value::Uint(1)),
        ]),
    );
    assert_eq!(
        r[0], ERR_PIN_AUTH_INVALID,
        "a param for one fragment authorised another"
    );
}

#[test]
fn a_write_needs_no_token_on_a_device_with_no_pin() {
    // With no PIN and alwaysUv off there is no verification method to
    // demand, so sec. 6.10.4 leaves the write unauthenticated. Checked so
    // the gate's condition is pinned in both directions.
    let mut d = Device::bare();
    let blob = array_of(64);
    assert_eq!(
        d.write(0, &blob, Some(blob.len() as u64))[0],
        CTAP2_OK,
        "a PIN-less device refused a write it has no way to authenticate"
    );
    assert_eq!(d.read_all(blob.len()), blob);
}

#[test]
fn a_request_carrying_both_a_read_and_a_write_is_refused() {
    // sec. 6.10: get and set are mutually exclusive. Serving both would make
    // the response ambiguous about which one happened.
    let mut d = writer();
    let blob = array_of(64);
    let r = d.send(
        LB,
        &map(vec![
            (F_OFFSET, Value::Uint(0)),
            (F_GET, Value::Uint(17)),
            (F_SET, Value::Bytes(blob.clone())),
            (F_LENGTH, Value::Uint(blob.len() as u64)),
            (F_AUTH, Value::Bytes(write_auth(&d.token, 0, &blob))),
            (F_PROTO, Value::Uint(1)),
        ]),
    );
    assert_ne!(r[0], CTAP2_OK, "a request with both get and set was served");
}

#[test]
fn malformed_large_blob_bodies_are_refused_without_panicking() {
    let mut d = Device::bare();
    for body in [
        vec![],
        vec![0xff],
        vec![0xa1],
        vec![0xa1, 0x01],
        vec![0x81, 0x01],
        vec![0xff; 200],
    ] {
        let mut msg = vec![LB];
        msg.extend_from_slice(&body);
        let mut host = |_op: fw::ctap2::HostOp| true;
        let r = fw::ctap2::handle_cbor(
            &msg,
            &mut d.trng,
            &mut d.session,
            &mut d.store,
            &mut host,
            0,
            [0, 0, 0, 1],
        );
        assert!(!r.is_empty(), "an empty response to {body:?}");
        assert_ne!(r[0], CTAP2_OK, "{body:?} was accepted");
    }
}

// ---- reset abandons a half-written array ------------------------------

#[test]
fn a_reset_abandons_a_write_that_was_in_progress() {
    // authenticatorReset erases the stored array, but the staging buffer
    // for a multi-fragment write is a separate static and was not
    // touched. Only the FIRST fragment carries the pinUvAuthParam --
    // continuations are authenticated by being continuations -- so a
    // write begun before the reset could be completed after it and
    // committed, authenticated by a token the reset had destroyed.
    //
    // CTAP 2.1 sec. 6.6: a reset destroys all device data. A fragment
    // sitting in a buffer is device data.
    let body = array_of(64);
    let mut d = writer();

    // First fragment only: declares the total, writes half.
    let half = body.len() / 2;
    assert_eq!(
        d.write(0, &body[..half], Some(body.len() as u64))[0],
        CTAP2_OK,
        "the opening fragment was refused"
    );

    d.send(fw::ctap2::CTAP2_RESET_CMD, &Value::Map(vec![]));

    // The continuation must not be accepted into the abandoned write.
    let resp = d.write(half as u32, &body[half..], None);
    assert_ne!(
        resp[0], CTAP2_OK,
        "a fragment from before the reset completed a write afterwards"
    );
    assert_eq!(
        d.read_all(17),
        initial_array(),
        "the array is not the spec-initial one after a reset"
    );
}

#[test]
fn a_write_started_after_a_reset_still_works() {
    // The accept half: abandoning must not wedge the buffer.
    let body = array_of(64);
    let half = body.len() / 2;
    {
        let mut d = writer();
        assert_eq!(
            d.write(0, &body[..half], Some(body.len() as u64))[0],
            CTAP2_OK
        );
        d.send(fw::ctap2::CTAP2_RESET_CMD, &Value::Map(vec![]));
    } // the device lock is one at a time
    let mut d = writer(); // a reset destroys the token too
    assert_eq!(
        d.write(0, &body[..half], Some(body.len() as u64))[0],
        CTAP2_OK,
        "a fresh write after a reset was refused"
    );
    assert_eq!(d.write(half as u32, &body[half..], None)[0], CTAP2_OK);
    assert_eq!(d.read_all(body.len()), body, "the array did not round-trip");
}
