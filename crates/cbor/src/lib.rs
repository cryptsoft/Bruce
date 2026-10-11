// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `pqf-cbor` -- a CBOR codec for the Bruce firmware.
//!
//! Implements the subset of [RFC 8949] the CTAP 2.1 protocol uses,
//! plus the canonical-form encoding rules from sec. 4.2.1 of the same
//! document. The crate is `#![no_std]` + `alloc`, has no external
//! dependencies, and is small enough to fit in a single file
//! (~500 LOC including tests).
//!
//! [RFC 8949]: https://www.rfc-editor.org/rfc/rfc8949.html
//!
//! # Supported subset
//!
//! - Major types 0-6 in full (unsigned int, negative int, byte
//!   string, text string, array, map, tag).
//! - Major type 7 *simple values* `false` (20), `true` (21),
//!   `null` (22), and `undefined` (23).
//! - Definite-length encoding only.
//! - Shortest-form integer encoding on the writer side (per
//!   sec. 4.2.1). The reader accepts any well-formed length encoding.
//!
//! # Out of scope
//!
//! - Indefinite-length items (additional-info 31 under major types
//!   2/3/4/5) -- rejected as [`Error::Indefinite`].
//! - Floats (half / single / double -- additional-info 25/26/27 under
//!   major type 7) -- rejected as [`Error::Float`].
//! - Reserved simple values (24..=31 except the four named ones).
//! - Streaming decode -- the reader takes the whole input buffer at
//!   once and complains about trailing bytes.
//!
//! # Top-level surface
//!
//! Two free functions and one enum:
//!
//! - [`encode`] -- serialise a [`Value`] tree into a `Vec<u8>`.
//! - [`decode`] -- parse a `&[u8]` into a [`Value`].
//! - [`Value`] -- the in-memory representation.
//!
//! The [`cbor_map!`] / [`cbor_array!`] / [`cbor_int!`] / [`cbor_text!`]
//! / [`cbor_bytes!`] / [`cbor_bool!`] / [`cbor_null!`] / [`cbor_tag!`]
//! macros are convenience constructors so callers can write CBOR
//! literals inline.

// `no_std` for the firmware build; under `cargo test` we link `std`
// (default target overridden to the host) so the unit tests can run
// with an allocator + test harness. The library code only ever uses
// `core` + `alloc`, both of which `std` re-exports.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

// ---------- The Value enum ----------

/// One decoded CBOR data item.
///
/// Variant names mirror RFC 8949 sec. 3.1 terminology:
///
/// | Variant   | Major type | Notes                                          |
/// |-----------|------------|------------------------------------------------|
/// | `Uint`    | 0          | unsigned integer (0..=2^64-1).                  |
/// | `Nint`    | 1          | negative integer, stored as the already-       |
/// |           |            | decoded signed value (e.g. wire `-1 - 6 = -7`  |
/// |           |            | is `Nint(-7)`). Range `i64::MIN..=-1`.         |
/// | `Bytes`   | 2          | owned `Vec<u8>`.                               |
/// | `Text`    | 3          | owned UTF-8 `String`.                          |
/// | `Array`   | 4          | items in source/insertion order.               |
/// | `Map`     | 5          | entries in source/insertion order. The codec   |
/// |           |            | does *not* enforce canonical key ordering on   |
/// |           |            | the reader side; callers building maps for     |
/// |           |            | canonical output must arrange entries in the   |
/// |           |            | required order themselves before encoding.     |
/// | `Tag`     | 6          | `(tag-number, content)`.                       |
/// | `Bool`    | 7 (20/21)  | simple value `false` / `true`.                 |
/// | `Null`    | 7 (22)     | simple value `null`.                           |
/// | `Undef`   | 7 (23)     | simple value `undefined`.                      |
///
/// Negative integers in the wire range `[-2^64, i64::MIN - 1]` are
/// outside the CTAP 2.1 subset and the decoder rejects them as
/// [`Error::IntOverflow`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Nint(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Tag(u64, Box<Value>),
    Bool(bool),
    Null,
    Undef,
}

// ---------- Canonical CBOR ordering ----------
//
// CTAP 2.1 sec. 6 references RFC 7049 sec. 3.9 (now RFC 8949 sec. 4.2.1)
// canonical encoding, which requires map keys to be sorted by their
// serialised form: shorter encodings before longer, then lexicographic
// byte ordering within the same length. Chrome's WebAuthn stack
// validates this strictly on `attestationObject` and rejects responses
// where keys arrive in insertion order -- when that happens it falls
// back to the U2F (CTAP1) transport, producing `fmt="fido-u2f"`
// attestation statements that some servers don't accept.
//
// `#[derive(Ord)]` would give us variant-then-content ordering, which
// matches canonical CBOR for the *Uint* variant by accident but is
// **wrong** for `Nint`: derive sorts numerically (so `-256 < -25`),
// but per RFC 8949 sec. 3 the wire form encodes -1 as 0x20, -2 as 0x21,
// ..., -24 as 0x37 -- so canonically -1 < -2 < -3 (less-negative first
// within the 1-byte length class, then jumping to the 2-byte class
// at -25 -> 0x38 0x18, etc., still ordered shorter-encoding-first
// per sec. 4.2.1). The custom `Ord` below applies the sec. 4.2.1 rule
// per major type:
//
//   - `Uint(u64)`         -- numeric ascending (matches sec. 4.2.1
//                            length-first since shorter encodings
//                            already correspond to smaller u64
//                            values).
//   - `Nint(i64)`         -- numeric ascending then **reversed**,
//                            giving the less-negative-first order
//                            the wire form requires.
//   - `Bytes` / `Text`    -- length-first, then lexicographic byte
//                            order within the same length.
//   - `Array` / `Map`     -- length-first, then element-wise
//                            recursive cmp.
//   - `Tag(u64, ...)`       -- by tag number first, then inner value.
//   - simple values       -- `Bool(false) < Bool(true) < Null <
//                            Undef`, matching the simple-value
//                            slot bytes 20 / 21 / 22 / 23.
//
// `major_type()` (below) assigns each variant a distinct sort
// key so cross-variant comparisons fall through cleanly without a
// separate type-tag pass.

impl Ord for Value {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        let st = self.major_type();
        let ot = other.major_type();
        if st != ot {
            return st.cmp(&ot);
        }
        match (self, other) {
            (Value::Uint(a), Value::Uint(b)) => a.cmp(b),
            // Wire form: -1 -> 0x20, -2 -> 0x21, ... so the
            // less-negative value compares LOWER. Reverse the
            // numeric cmp to get canonical order.
            (Value::Nint(a), Value::Nint(b)) => a.cmp(b).reverse(),
            (Value::Bytes(a), Value::Bytes(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
            (Value::Text(a), Value::Text(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
            (Value::Array(a), Value::Array(b)) => a.len().cmp(&b.len()).then_with(|| {
                for (x, y) in a.iter().zip(b.iter()) {
                    match x.cmp(y) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                Ordering::Equal
            }),
            (Value::Map(a), Value::Map(b)) => a.len().cmp(&b.len()).then_with(|| {
                for ((ka, va), (kb, vb)) in a.iter().zip(b.iter()) {
                    match ka.cmp(kb).then_with(|| va.cmp(vb)) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                Ordering::Equal
            }),
            (Value::Tag(ta, ia), Value::Tag(tb, ib)) => ta.cmp(tb).then_with(|| ia.cmp(ib)),
            (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
            (Value::Null, Value::Null) | (Value::Undef, Value::Undef) => Ordering::Equal,
            // Cross-major-type comparison handled above by st/ot.
            // Within Bool/Null/Undef (all major 7), they're
            // distinguished by simple-value slot which we encode
            // into major_type's low bits via the `+ N` offsets.
            _ => Ordering::Equal,
        }
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Value {
    /// Major type for canonical-CBOR ordering. Mostly the 3-bit
    /// CBOR major type, but the three major-7 simple-value
    /// variants get distinct values so they sort among themselves
    /// (false < true < null < undefined matches the simple-value
    /// slot bytes 20/21/22/23).
    fn major_type(&self) -> u8 {
        match self {
            Value::Uint(_) => 0,
            Value::Nint(_) => 1,
            Value::Bytes(_) => 2,
            Value::Text(_) => 3,
            Value::Array(_) => 4,
            Value::Map(_) => 5,
            Value::Tag(_, _) => 6,
            // Major type 7, simple-value slots. Stable, distinct,
            // and in numeric order of their wire byte.
            Value::Bool(false) => 7 + 20 - 20, // = 7
            Value::Bool(true) => 7 + 21 - 20,  // = 8
            Value::Null => 7 + 22 - 20,        // = 9
            Value::Undef => 7 + 23 - 20,       // = 10
        }
    }
}

// ---------- Construction conveniences ----------

impl Value {
    /// Pick the appropriate variant (`Uint` or `Nint`) for a signed
    /// integer. Mirrors how integer literals get encoded on the wire.
    pub fn int(n: i64) -> Self {
        if n >= 0 {
            Value::Uint(n as u64)
        } else {
            Value::Nint(n)
        }
    }
}

// `From<T> for Value` impls drive the macro arguments via `.into()`.
// Numeric integer literals default to `i32` in Rust, so we cover the
// signed family + the unsigned family.

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::Uint(n)
    }
}
impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Value::Uint(n as u64)
    }
}
impl From<u16> for Value {
    fn from(n: u16) -> Self {
        Value::Uint(n as u64)
    }
}
impl From<u8> for Value {
    fn from(n: u8) -> Self {
        Value::Uint(n as u64)
    }
}
impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::int(n)
    }
}
impl From<i32> for Value {
    fn from(n: i32) -> Self {
        Value::int(n as i64)
    }
}
impl From<i16> for Value {
    fn from(n: i16) -> Self {
        Value::int(n as i64)
    }
}
impl From<i8> for Value {
    fn from(n: i8) -> Self {
        Value::int(n as i64)
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(String::from(s))
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s)
    }
}
impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value::Bytes(b)
    }
}
impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Self {
        Value::Bytes(b.to_vec())
    }
}

/// Trait used by the construction macros so map keys / array items
/// can be written as bare literals (`0x01`, `"foo"`, `true`, etc.).
/// Anything that's `Into<Value>` gets `IntoValue` for free.
pub trait IntoValue {
    fn into_value(self) -> Value;
}
impl<T> IntoValue for T
where
    Value: From<T>,
{
    fn into_value(self) -> Value {
        Value::from(self)
    }
}

// ---------- Macros ----------

/// `cbor_int!(n)` -- wrap an `i64` expression as a [`Value`]. Routes
/// positive values to [`Value::Uint`] and negative ones to
/// [`Value::Nint`].
#[macro_export]
macro_rules! cbor_int {
    ($n:expr) => {
        $crate::Value::int($n as i64)
    };
}

/// `cbor_uint!(n)` -- wrap a `u64` expression as [`Value::Uint`].
#[macro_export]
macro_rules! cbor_uint {
    ($n:expr) => {
        $crate::Value::Uint($n as u64)
    };
}

/// `cbor_text!(s)` -- anything `Into<String>` -> [`Value::Text`].
#[macro_export]
macro_rules! cbor_text {
    ($s:expr) => {
        $crate::Value::Text(($s).into())
    };
}

/// `cbor_bytes!(b)` -- wrap a `Vec<u8>` as [`Value::Bytes`]. Takes
/// ownership of the vector; clone the source first if you need it.
#[macro_export]
macro_rules! cbor_bytes {
    ($b:expr) => {
        $crate::Value::Bytes($b)
    };
}

/// `cbor_bool!(b)` -- wrap a `bool` as [`Value::Bool`].
#[macro_export]
macro_rules! cbor_bool {
    ($b:expr) => {
        $crate::Value::Bool($b)
    };
}

/// `cbor_null!()` -- produce a [`Value::Null`].
#[macro_export]
macro_rules! cbor_null {
    () => {
        $crate::Value::Null
    };
}

/// `cbor_array![v, v, ...]` -- build a [`Value::Array`] from a
/// comma-separated list of expressions. Each element runs through
/// [`IntoValue`] so bare literals work alongside already-built
/// [`Value`]s.
#[macro_export]
macro_rules! cbor_array {
    ($($v:expr),* $(,)?) => {{
        use $crate::IntoValue;
        $crate::Value::Array(::alloc::vec![$($v.into_value()),*])
    }};
}

/// `cbor_map! { k => v, k => v, ... }` -- build a [`Value::Map`]
/// from a brace-delimited list of `key => value` pairs. Keys and
/// values run through [`IntoValue`] so bare literals are accepted.
/// Entries preserve insertion order; callers needing canonical
/// output must order them themselves before invoking.
#[macro_export]
macro_rules! cbor_map {
    ($($k:expr => $v:expr),* $(,)?) => {{
        use $crate::IntoValue;
        $crate::Value::Map(::alloc::vec![
            $(($k.into_value(), $v.into_value())),*
        ])
    }};
}

/// `cbor_tag!(tag, value)` -- wrap a [`Value`] in a CBOR tag
/// (major type 6).
#[macro_export]
macro_rules! cbor_tag {
    ($tag:expr, $v:expr) => {
        $crate::Value::Tag($tag, ::alloc::boxed::Box::new($v))
    };
}

// ---------- Encoder ----------

/// Encode `value` and append the resulting CBOR bytes to `out`.
///
/// The encoding follows RFC 8949 sec. 3 with sec. 4.2.1's shortest-form
/// integer rule applied throughout (the "core deterministic"
/// canonical subset, minus key ordering -- which is the caller's
/// responsibility).
pub fn encode(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(n) => write_head(0, *n, out),
        Value::Nint(n) => {
            // Wire form: argument = -1 - n. Computed as the bitwise
            // complement of n-as-u64, which equals -1-n for every i64
            // (including i64::MIN) with no intermediate subtraction that
            // could panic under overflow-checks. e.g. n=-7 -> arg=6.
            let arg = (*n as u64) ^ u64::MAX;
            write_head(1, arg, out);
        }
        Value::Bytes(b) => {
            write_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            let bytes = s.as_bytes();
            write_head(3, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        Value::Array(items) => {
            write_head(4, items.len() as u64, out);
            for it in items {
                encode(it, out);
            }
        }
        Value::Map(entries) => {
            // CTAP 2.1 sec. 6 + WebAuthn require canonical-CBOR map
            // encoding (sorted keys, deduplicated). Chrome's
            // WebAuthn validates this on `attestationObject` and
            // rejects insertion-order maps -- when it does, it
            // falls back to the U2F transport, producing
            // `fmt="fido-u2f"` instead of `fmt="packed"`. We sort
            // a *copy* so callers' Vec isn't mutated, and the
            // sort uses the custom `Ord for Value` that matches
            // RFC 8949 sec. 4.2.1 canonical ordering (length-first,
            // then lexicographic byte order, with the Nint cmp
            // reversed -- see the `Ord` impl above).
            let mut sorted: Vec<(Value, Value)> = entries.clone();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            // Dedupe by key -- first occurrence wins. CTAP doesn't
            // emit duplicate keys in normal usage, but a buggy
            // caller would otherwise produce non-canonical output
            // by encoding the duplicate too.
            sorted.dedup_by(|a, b| a.0.eq(&b.0));
            write_head(5, sorted.len() as u64, out);
            for (k, v) in &sorted {
                encode(k, out);
                encode(v, out);
            }
        }
        Value::Tag(tag, inner) => {
            write_head(6, *tag, out);
            encode(inner, out);
        }
        Value::Bool(false) => out.push(0xf4), // major 7, simple 20
        Value::Bool(true) => out.push(0xf5),  // major 7, simple 21
        Value::Null => out.push(0xf6),        // major 7, simple 22
        Value::Undef => out.push(0xf7),       // major 7, simple 23
    }
}

/// Emit the initial byte (major type + additional info) plus the
/// length/argument bytes for `arg`, using the shortest form per
/// RFC 8949 sec. 4.2.1.
///
/// | range            | bytes | additional info | layout                                    |
/// | ---              | ---   | ---             | ---                                       |
/// | `0..=23`         | 1     | `arg` itself    | `(mt<<5) \| arg`                          |
/// | `24..=255`       | 2     | 24              | `(mt<<5) \| 24`, then `arg` as u8         |
/// | `256..=65535`    | 3     | 25              | `(mt<<5) \| 25`, then `arg` as BE u16     |
/// | `2^16..=2^32-1`    | 5     | 26              | `(mt<<5) \| 26`, then `arg` as BE u32     |
/// | else             | 9     | 27              | `(mt<<5) \| 27`, then `arg` as BE u64     |
fn write_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    debug_assert!(major < 8);
    let head = major << 5;
    if arg < 24 {
        out.push(head | (arg as u8));
    } else if arg < 0x100 {
        out.push(head | 24);
        out.push(arg as u8);
    } else if arg < 0x1_0000 {
        out.push(head | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg < 0x1_0000_0000 {
        out.push(head | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(head | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

// ---------- Decoder ----------

/// Errors the decoder can return.
///
/// Variants are split finely so test code can pinpoint failures, but
/// the firmware folds every one of them into a single
/// `CTAP2_ERR_INVALID_CBOR` at the dispatch layer -- exact-variant
/// distinctions don't drive control flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input ended mid-item.
    Truncated,
    /// Indefinite-length item -- additional-info 31 under a string,
    /// array, or map major type.
    Indefinite,
    /// Float -- additional-info 25 / 26 / 27 under major type 7.
    Float,
    /// Reserved simple-value slot (24..=31 minus the four named
    /// ones we accept).
    Reserved,
    /// A negative integer larger in magnitude than `i64::MIN` allows.
    /// Out of subset for CTAP 2.1.
    IntOverflow,
    /// A text-string field wasn't valid UTF-8.
    InvalidUtf8,
    /// Nesting depth exceeded [`MAX_DEPTH`].
    TooDeep,
    /// Bytes left over after a complete top-level item.
    Trailing,
    /// A map repeated a key. RFC 8949 sec. 5.6 / CTAP 2.1 sec. 6 require unique
    /// keys; silent first-match resolution would otherwise let a peer
    /// smuggle a second value past whichever layer reads the map.
    DuplicateKey,
}

/// Cap on nested array / map / tag recursion depth. With the
/// Cortex-M33's 16 KiB stack and our per-frame footprint, 128 leaves
/// comfortable headroom while still rejecting hostile inputs.
pub const MAX_DEPTH: usize = 128;

/// Decode exactly one CBOR data item from `input`. The whole buffer
/// must be consumed -- extra trailing bytes return [`Error::Trailing`].
pub fn decode(input: &[u8]) -> Result<Value, Error> {
    let mut c = Cursor { buf: input, pos: 0 };
    let v = decode_one(&mut c, 0)?;
    if c.pos != input.len() {
        return Err(Error::Trailing);
    }
    Ok(v)
}

/// Position-tracking view over a `&[u8]`. We don't use `std::io`
/// because the crate is `no_std`.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> Result<u8, Error> {
        let b = *self.buf.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        if end > self.buf.len() {
            return Err(Error::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
}

fn decode_one(c: &mut Cursor<'_>, depth: usize) -> Result<Value, Error> {
    if depth >= MAX_DEPTH {
        return Err(Error::TooDeep);
    }

    let initial = c.byte()?;
    let major = initial >> 5;
    let info = initial & 0x1f;

    // additional-info 31 means indefinite-length under string /
    // array / map / tag, or the "break" marker under simple. Both
    // are outside our subset.
    if info == 31 {
        return Err(Error::Indefinite);
    }

    // Major type 7 doesn't have an "argument" the same way 0-6 do
    // -- it's directly the simple-value slot (or a float, which we
    // reject).
    if major == 7 {
        return decode_simple(info);
    }

    let arg = decode_arg(info, c)?;
    decode_with_arg(major, arg, c, depth)
}

/// Parse the argument that follows the initial byte. `info` is the
/// low five bits of the initial byte.
fn decode_arg(info: u8, c: &mut Cursor<'_>) -> Result<u64, Error> {
    match info {
        0..=23 => Ok(info as u64),
        24 => Ok(c.byte()? as u64),
        25 => {
            let s = c.take(2)?;
            Ok(u16::from_be_bytes([s[0], s[1]]) as u64)
        }
        26 => {
            let s = c.take(4)?;
            Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64)
        }
        27 => {
            let s = c.take(8)?;
            Ok(u64::from_be_bytes([
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
            ]))
        }
        // 28..=30 are reserved for future use per RFC 8949 sec. 3 Table 1.
        // info == 31 is handled upstream as indefinite-length.
        _ => Err(Error::Reserved),
    }
}

fn decode_with_arg(major: u8, arg: u64, c: &mut Cursor<'_>, depth: usize) -> Result<Value, Error> {
    match major {
        // 0 -- unsigned. `arg` is the value.
        0 => Ok(Value::Uint(arg)),

        // 1 -- negative. Spec: `value = -1 - arg`. Subset constraint:
        // we only carry `i64` for the decoded value, so anything
        // with `arg > i64::MAX as u64` would overflow on the
        // -1 - arg cast. CTAP doesn't go anywhere near that range,
        // so reject.
        1 => {
            if arg > i64::MAX as u64 {
                return Err(Error::IntOverflow);
            }
            Ok(Value::Nint(-1i64 - arg as i64))
        }

        // 2 -- byte string of `arg` bytes.
        2 => {
            // `arg as usize` would silently truncate a 64-bit length on
            // the 32-bit target; reject anything that can't fit usize so
            // a giant declared length fails cleanly instead of reading a
            // wrapped-around count.
            let n = usize::try_from(arg).map_err(|_| Error::Truncated)?;
            let b = c.take(n)?;
            Ok(Value::Bytes(b.to_vec()))
        }

        // 3 -- text string of `arg` UTF-8 bytes.
        3 => {
            let n = usize::try_from(arg).map_err(|_| Error::Truncated)?;
            let b = c.take(n)?;
            let s = core::str::from_utf8(b).map_err(|_| Error::InvalidUtf8)?;
            Ok(Value::Text(String::from(s)))
        }

        // 4 -- array of `arg` items.
        4 => {
            // Never pre-allocate from the attacker-controlled count:
            // `arg` can be up to 2^64-1, and Value is tens of bytes, so a
            // tiny message could request a multi-gigabyte Vec the device
            // can't satisfy (alloc error -> panic=abort -> DoS). Each
            // element occupies >= 1 input byte, so the bytes still in the
            // buffer are a hard upper bound on the real element count.
            let cap = (arg as usize).min(c.buf.len() - c.pos);
            let mut items = Vec::with_capacity(cap);
            for _ in 0..arg {
                items.push(decode_one(c, depth + 1)?);
            }
            Ok(Value::Array(items))
        }

        // 5 -- map of `arg` key/value pairs.
        5 => {
            // Same bound as arrays, but each entry is a key + a value, so
            // it needs >= 2 input bytes.
            let cap = (arg as usize).min((c.buf.len() - c.pos) / 2 + 1);
            let mut entries = Vec::with_capacity(cap);
            for _ in 0..arg {
                let k = decode_one(c, depth + 1)?;
                let v = decode_one(c, depth + 1)?;
                // Reject duplicate keys (RFC 8949 sec. 5.6 / CTAP 2.1 sec. 6). The
                // maps CTAP uses are small, so the linear scan is cheap.
                if entries.iter().any(|(ek, _)| ek == &k) {
                    return Err(Error::DuplicateKey);
                }
                entries.push((k, v));
            }
            Ok(Value::Map(entries))
        }

        // 6 -- tagged value. `arg` is the tag number; the next item
        // is the tag content.
        6 => {
            let inner = decode_one(c, depth + 1)?;
            Ok(Value::Tag(arg, Box::new(inner)))
        }

        // 7 -- handled before we reach here.
        _ => Err(Error::Reserved),
    }
}

fn decode_simple(info: u8) -> Result<Value, Error> {
    match info {
        20 => Ok(Value::Bool(false)),
        21 => Ok(Value::Bool(true)),
        22 => Ok(Value::Null),
        23 => Ok(Value::Undef),
        // 0..=19 are unassigned simple values. 24 is the
        // 1-byte-extended simple form (not used by CTAP). 25/26/27
        // are floats. 28..=30 are reserved.
        25..=27 => Err(Error::Float),
        _ => Err(Error::Reserved),
    }
}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn enc(v: Value) -> Vec<u8> {
        let mut out = Vec::new();
        encode(&v, &mut out);
        out
    }

    // -- Encoder: shortest-form integer layout --

    #[test]
    fn uint_short_form() {
        // 0..=23 encode in one byte: `(0 << 5) | n`.
        assert_eq!(enc(Value::Uint(0)), vec![0x00]);
        assert_eq!(enc(Value::Uint(10)), vec![0x0a]);
        assert_eq!(enc(Value::Uint(23)), vec![0x17]);
    }

    #[test]
    fn uint_one_byte_form() {
        // 24..=255 use the 1-byte-arg form: 0x18, then the byte.
        assert_eq!(enc(Value::Uint(24)), vec![0x18, 0x18]);
        assert_eq!(enc(Value::Uint(255)), vec![0x18, 0xff]);
    }

    #[test]
    fn uint_two_byte_form() {
        // 256..=65535 use the 2-byte BE form.
        assert_eq!(enc(Value::Uint(256)), vec![0x19, 0x01, 0x00]);
        assert_eq!(enc(Value::Uint(65535)), vec![0x19, 0xff, 0xff]);
    }

    #[test]
    fn nint_layout() {
        // -1 -> mt 1, arg 0 -> 0x20.
        assert_eq!(enc(Value::Nint(-1)), vec![0x20]);
        // -7 -> mt 1, arg 6 -> 0x26. ES256 COSE alg.
        assert_eq!(enc(Value::Nint(-7)), vec![0x26]);
        // -50 -> mt 1, arg 49 -> 0x38 0x31. The pure ML-DSA-87 COSE alg.
        assert_eq!(enc(Value::Nint(-50)), vec![0x38, 0x31]);
    }

    #[test]
    fn bytes_layout() {
        assert_eq!(enc(Value::Bytes(vec![0xde, 0xad])), vec![0x42, 0xde, 0xad]);
    }

    #[test]
    fn text_layout() {
        assert_eq!(enc(Value::Text("a".to_string())), vec![0x61, b'a']);
        assert_eq!(
            enc(Value::Text("packed".to_string())),
            vec![0x66, b'p', b'a', b'c', b'k', b'e', b'd']
        );
    }

    #[test]
    fn small_map_layout() {
        // {1: "a"} -> A1 01 61 'a'
        let m = Value::Map(vec![(Value::Uint(1), Value::Text("a".to_string()))]);
        assert_eq!(enc(m), vec![0xa1, 0x01, 0x61, b'a']);
    }

    #[test]
    fn simples_layout() {
        assert_eq!(enc(Value::Bool(false)), vec![0xf4]);
        assert_eq!(enc(Value::Bool(true)), vec![0xf5]);
        assert_eq!(enc(Value::Null), vec![0xf6]);
        assert_eq!(enc(Value::Undef), vec![0xf7]);
    }

    // -- Round-trip --

    #[test]
    fn round_trip_uint() {
        for n in [0u64, 1, 23, 24, 100, 255, 256, 65535, 65536, 1u64 << 32] {
            let mut out = Vec::new();
            encode(&Value::Uint(n), &mut out);
            assert_eq!(decode(&out).unwrap(), Value::Uint(n));
        }
    }

    #[test]
    fn round_trip_nint() {
        for n in [-1i64, -7, -49, -50, -255, -256, -65536] {
            let mut out = Vec::new();
            encode(&Value::Nint(n), &mut out);
            assert_eq!(decode(&out).unwrap(), Value::Nint(n));
        }
    }

    #[test]
    fn canonical_map_sorts_keys() {
        // Insert in non-canonical order, expect canonical bytes out.
        // Canonical order for these keys per RFC 8949 sec. 4.2.1:
        //   1, 2, 3        (positive ints, low -> high)
        //   -1, -2, -3     (negative ints, less-negative first;
        //                  wire: 0x20, 0x21, 0x22)
        // So the sorted order is: 1, 2, 3, -1, -2, -3.
        let m = Value::Map(vec![
            (Value::Nint(-3), Value::Uint(99)),
            (Value::Uint(2), Value::Uint(20)),
            (Value::Nint(-1), Value::Uint(11)),
            (Value::Uint(3), Value::Uint(30)),
            (Value::Nint(-2), Value::Uint(22)),
            (Value::Uint(1), Value::Uint(10)),
        ]);
        let mut out = Vec::new();
        encode(&m, &mut out);
        // Map header: a6 (map, 6 entries)
        // Then: 01 0a 02 14 03 18 1e 20 0b 21 16 22 18 63
        //       (1->10, 2->20, 3->30, -1->11, -2->22, -3->99)
        let expected = vec![
            0xa6, // map(6)
            0x01, 0x0a, // 1 -> 10
            0x02, 0x14, // 2 -> 20
            0x03, 0x18, 0x1e, // 3 -> 30 (24-byte form)
            0x20, 0x0b, // -1 -> 11
            0x21, 0x16, // -2 -> 22
            0x22, 0x18, 0x63, // -3 -> 99
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn canonical_map_dedups_keys() {
        // Two entries with key=1, different values. After dedup,
        // first wins; resulting map has 2 entries, not 3.
        let m = Value::Map(vec![
            (Value::Uint(1), Value::Uint(10)),
            (Value::Uint(1), Value::Uint(99)),
            (Value::Uint(2), Value::Uint(20)),
        ]);
        let mut out = Vec::new();
        encode(&m, &mut out);
        // a2 (map(2)) 01 0a 02 14
        assert_eq!(out, vec![0xa2, 0x01, 0x0a, 0x02, 0x14]);
    }

    #[test]
    fn round_trip_nested() {
        // Map with mixed types -- sanity check the recursive path.
        let v = cbor_map! {
            0x01 => "FIDO_2_0",
            0x02 => cbor_array![1, 2, 3],
            0x03 => true,
            0x04 => Value::Null,
        };
        let mut out = Vec::new();
        encode(&v, &mut out);
        assert_eq!(decode(&out).unwrap(), v);
    }

    // -- Decoder: error paths --

    #[test]
    fn encodes_extreme_nint_without_panic() {
        // The old `-1 - n` encode form would panic under overflow-checks
        // for the extremes; the complement form must not, and both must
        // round-trip. -1 is the smallest-magnitude negint; i64::MIN the
        // most negative we carry.
        for n in [-1i64, -7i64, i64::MIN] {
            let v = Value::Nint(n);
            let mut out = Vec::new();
            encode(&v, &mut out);
            assert_eq!(decode(&out).unwrap(), v);
        }
    }

    #[test]
    fn rejects_indefinite() {
        // 0x9f starts an indefinite-length array.
        assert_eq!(decode(&[0x9f, 0x01, 0xff]).unwrap_err(), Error::Indefinite);
    }

    #[test]
    fn rejects_truncated_bytes() {
        // Byte string declared 4 bytes but only 1 provided.
        assert_eq!(decode(&[0x44, 0xde]).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn rejects_trailing() {
        // 0x00 decodes to Uint(0); the second 0x00 is unexpected.
        assert_eq!(decode(&[0x00, 0x00]).unwrap_err(), Error::Trailing);
    }

    #[test]
    fn rejects_duplicate_map_keys() {
        // 0xa2 = map(2) with entries {1: 1, 1: 2} -- key 1 repeated.
        assert_eq!(
            decode(&[0xa2, 0x01, 0x01, 0x01, 0x02]).unwrap_err(),
            Error::DuplicateKey
        );
        // A map with distinct keys still decodes.
        assert!(decode(&[0xa2, 0x01, 0x01, 0x02, 0x02]).is_ok());
    }

    #[test]
    fn rejects_huge_count_without_oom() {
        // H5: a tiny input that declares a 4-billion-element array/map
        // must NOT pre-allocate a Vec from that attacker-controlled count
        // (which would exhaust the heap and abort under panic=abort). The
        // reserve is clamped to the bytes actually left in the buffer, so
        // decoding fails fast with Truncated when the (absent) elements
        // are read instead of attempting a multi-gigabyte allocation.
        // 0x9a + u32 = array of 0xffffffff items, zero bytes of body.
        assert_eq!(
            decode(&[0x9a, 0xff, 0xff, 0xff, 0xff]).unwrap_err(),
            Error::Truncated
        );
        // 0xbb + u32 = map of 0xffffffff pairs, zero bytes of body.
        assert_eq!(
            decode(&[0xbb, 0xff, 0xff, 0xff, 0xff]).unwrap_err(),
            Error::Truncated
        );
    }

    #[test]
    fn rejects_float() {
        // 0xfa is mt 7 / info 26 -> single-precision float.
        assert_eq!(
            decode(&[0xfa, 0x00, 0x00, 0x00, 0x00]).unwrap_err(),
            Error::Float
        );
    }

    #[test]
    fn rejects_deep_nesting() {
        // 200 nested single-element arrays > MAX_DEPTH (128).
        let mut bytes = vec![0x81; 200];
        bytes.push(0x00);
        assert_eq!(decode(&bytes).unwrap_err(), Error::TooDeep);
    }

    #[test]
    fn cose_alg_neg50_decodes() {
        // -50 on the wire is 0x38 0x31. Should decode to Nint(-50).
        assert_eq!(decode(&[0x38, 0x31]).unwrap(), Value::Nint(-50));
    }

    // -- Macros + From impls --

    #[test]
    fn macros_accept_literals() {
        let m = cbor_map! {
            1 => "hi",
            2 => 42,
            3 => true,
            4 => vec![0xdeu8, 0xad],
        };
        let mut out = Vec::new();
        encode(&m, &mut out);
        assert_eq!(decode(&out).unwrap(), m);
    }

    #[test]
    fn cbor_int_picks_variant() {
        assert_eq!(cbor_int!(0), Value::Uint(0));
        assert_eq!(cbor_int!(42), Value::Uint(42));
        assert_eq!(cbor_int!(-1), Value::Nint(-1));
        assert_eq!(cbor_int!(-7), Value::Nint(-7));
    }

    #[test]
    fn cbor_tag_macro() {
        let t = cbor_tag!(24, Value::Uint(1));
        let mut out = Vec::new();
        encode(&t, &mut out);
        assert_eq!(decode(&out).unwrap(), t);
    }
}
