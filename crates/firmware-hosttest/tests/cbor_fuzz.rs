// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Fuzzing the CBOR decoders.
//!
//! The project had none. Every CBOR test in the tree is a case someone
//! thought of, which is exactly the coverage that misses the input
//! nobody imagined -- and CBOR is the format every byte a host sends
//! arrives in.
//!
//! Two things make this worth more than random bytes:
//!
//! **Structure-aware generation.** Uniform random bytes are rejected at
//! byte 0 essentially always, so they only ever test the first branch.
//! The generator here builds *valid* CBOR trees, encodes them, and then
//! corrupts the encoding -- truncating it, flipping bits, and rewriting
//! length fields. That puts pressure on the paths that run after a
//! header has already parsed, which is where a length is trusted.
//!
//! **A differential oracle.** There are two independent Rust decoders
//! in this tree, `pqf_cbor` (tree) and `fw-nonsecure`'s `cborr`
//! (streaming). They were written separately for different worlds. When
//! two implementations of one format disagree about the same bytes, one
//! of them is wrong -- the same reasoning that found bugs in both ports
//! when the CTAPHID suites were mirrored.
//!
//! Everything is driven by a seeded PRNG and the seed is printed on
//! failure, so any finding is reproducible by re-running one number
//! rather than by luck.

use pqf_cbor::{decode, encode, Value};
use pqf_firmware_hosttest::ns_cborr as cborr;

// ---------- a deterministic PRNG ----------
//
// xorshift64*. No external dependency, and a failing case is a seed
// rather than a story about what the machine happened to do.

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
}

/// How many cases each oracle runs.
///
/// Fixed by default so a green run means the same thing on every
/// machine and a failure is reproducible from its printed seed. The
/// whole suite costs about a fifth of a second at this size, so the
/// default is generous rather than token. Set `PQF_FUZZ_ITERS` to soak
/// it harder -- `PQF_FUZZ_ITERS=5000000` is a coffee break, and because
/// the seeds are just an integer range, a soak that finds something
/// reports a seed the default run can be pointed at directly.
fn iters(default: u64) -> u64 {
    match std::env::var("PQF_FUZZ_ITERS") {
        Ok(v) => v.parse().unwrap_or(default),
        Err(_) => default,
    }
}

// ---------- structure-aware generation ----------

/// Build a random CBOR value. `depth` bounds nesting so generation
/// terminates; the decoders' own limits are exercised separately by the
/// deep-nesting test below.
fn gen_value(rng: &mut Rng, depth: usize) -> Value {
    let leaf = depth == 0;
    let pick = rng.below(if leaf { 6 } else { 9 });
    match pick {
        0 => Value::Uint(match rng.below(4) {
            0 => rng.below(24) as u64,
            1 => rng.below(256) as u64,
            2 => rng.below(65536) as u64,
            _ => rng.next(),
        }),
        1 => Value::Nint(-1 - (rng.below(1 << 20) as i64)),
        2 => {
            let n = rng.below(40);
            Value::Bytes((0..n).map(|_| rng.byte()).collect())
        }
        3 => {
            // Valid UTF-8 only: the encoder takes a String, so invalid
            // sequences are produced by the mutators instead.
            let n = rng.below(20);
            Value::Text(
                (0..n)
                    .map(|_| (b'a' + (rng.below(26) as u8)) as char)
                    .collect(),
            )
        }
        4 => match rng.below(3) {
            0 => Value::Bool(rng.chance(2)),
            1 => Value::Null,
            _ => Value::Undef,
        },
        5 => Value::Uint(0),
        6 => {
            let n = rng.below(5);
            Value::Array((0..n).map(|_| gen_value(rng, depth - 1)).collect())
        }
        7 => {
            // Unique keys. The encoder deduplicates by key on purpose
            // (crates/cbor/src/lib.rs:463, canonical CBOR), so a
            // generated duplicate makes the round trip lossy by design
            // and reports as a failure that is not one.
            let n = rng.below(5);
            let mut kvs: Vec<(Value, Value)> = Vec::new();
            for _ in 0..n {
                let k = gen_value(rng, 0);
                if kvs.iter().any(|(existing, _)| *existing == k) {
                    continue;
                }
                kvs.push((k, gen_value(rng, depth - 1)));
            }
            Value::Map(kvs)
        }
        // Tags are deliberately absent from `cborr` -- CTAP2 canonical
        // CBOR forbids them -- so generating one produces a scope
        // difference rather than a finding. `gen_value_tagged` below
        // still emits them for the panic-safety tests, where the point
        // is that neither decoder falls over.
        _ => Value::Array(
            (0..rng.below(3))
                .map(|_| gen_value(rng, depth - 1))
                .collect(),
        ),
    }
}

/// As `gen_value`, but may emit tags. Used only where the property is
/// "does not panic" -- a tag is legal CBOR that this profile excludes,
/// and both decoders must survive one either way.
fn gen_value_tagged(rng: &mut Rng, depth: usize) -> Value {
    if depth > 0 && rng.chance(4) {
        Value::Tag(rng.next() % 64, Box::new(gen_value(rng, depth - 1)))
    } else {
        gen_value(rng, depth)
    }
}

/// Corrupt an encoding. These are the mutations that matter for a
/// length-prefixed format: a length that no longer matches its payload
/// is the classic way to walk a decoder off the end.
fn mutate(rng: &mut Rng, buf: &mut Vec<u8>) {
    if buf.is_empty() {
        return;
    }
    match rng.below(6) {
        0 => {
            // Bit flip.
            let i = rng.below(buf.len());
            buf[i] ^= 1 << rng.below(8);
        }
        1 => {
            // Truncate: the single most productive mutation, because it
            // hits every "read the next N bytes" site.
            let n = rng.below(buf.len());
            buf.truncate(n);
        }
        2 => {
            // Replace a byte outright.
            let i = rng.below(buf.len());
            buf[i] = rng.byte();
        }
        3 => {
            // Rewrite a header's additional-info to claim a much larger
            // argument than the payload provides.
            let i = rng.below(buf.len());
            buf[i] = (buf[i] & 0xE0) | (24 + rng.below(4) as u8);
        }
        4 => {
            // Splice in extra bytes -- trailing data, or a second item.
            let n = rng.below(8);
            for _ in 0..n {
                let b = rng.byte();
                buf.push(b);
            }
        }
        _ => {
            // Duplicate a slice, to make lengths and payloads disagree.
            if buf.len() > 2 {
                let a = rng.below(buf.len() - 1);
                let b = a + 1 + rng.below(buf.len() - a - 1);
                let chunk: Vec<u8> = buf[a..b].to_vec();
                buf.extend_from_slice(&chunk);
            }
        }
    }
}

// ---------- oracle 1: nothing may panic ----------

#[test]
fn no_input_makes_the_tree_decoder_panic() {
    // A panic in a decoder is a denial of service reachable by anyone
    // who can send bytes. On the firmware, panic = abort.
    for seed in 0..iters(60_000) {
        let mut rng = Rng::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xC0FF_EE);
        let v = gen_value_tagged(&mut rng, 3);
        let mut buf = Vec::new();
        encode(&v, &mut buf);
        for _ in 0..1 + rng.below(3) {
            mutate(&mut rng, &mut buf);
        }
        // The assertion is simply that this returns.
        let _ = decode(&buf);
    }
}

#[test]
fn no_input_makes_the_streaming_reader_panic() {
    for seed in 0..iters(60_000) {
        let mut rng = Rng::new(seed ^ 0xBEEF_1234_5678);
        let v = gen_value(&mut rng, 3);
        let mut buf = Vec::new();
        encode(&v, &mut buf);
        for _ in 0..1 + rng.below(3) {
            mutate(&mut rng, &mut buf);
        }
        let mut r = cborr::Reader::new(&buf);
        // Walk it the way the demux does: header, then skip.
        let _ = r.header();
        let mut r = cborr::Reader::new(&buf);
        let _ = r.skip();
        let mut r = cborr::Reader::new(&buf);
        let _ = r.map();
        let mut r = cborr::Reader::new(&buf);
        let _ = r.str_bytes(cborr::MAJOR_BYTES);
    }
}

#[test]
fn pure_random_bytes_are_survived() {
    // Structure-aware generation is the productive part, but pure noise
    // is free and covers the "rejected at byte 0" paths.
    for seed in 0..iters(60_000) {
        let mut rng = Rng::new(seed ^ 0xFACE_0FF);
        let n = rng.below(64);
        let buf: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
        let _ = decode(&buf);
        let mut r = cborr::Reader::new(&buf);
        let _ = r.skip();
    }
}

// ---------- oracle 2: the cursor never escapes the input ----------

#[test]
fn the_streaming_reader_never_reports_consuming_more_than_it_was_given() {
    // `position()` is used by the demux to capture a sub-encoding
    // verbatim. A cursor past the end would slice out of bounds at the
    // call site rather than here, so the bound is worth its own check.
    for seed in 0..iters(80_000) {
        let mut rng = Rng::new(seed ^ 0x5EED_5EED);
        let v = gen_value(&mut rng, 3);
        let mut buf = Vec::new();
        encode(&v, &mut buf);
        for _ in 0..1 + rng.below(3) {
            mutate(&mut rng, &mut buf);
        }
        let mut r = cborr::Reader::new(&buf);
        let _ = r.skip();
        assert!(
            r.position() <= buf.len(),
            "seed {seed}: cursor {} past end {} for {buf:02x?}",
            r.position(),
            buf.len()
        );
    }
}

// ---------- oracle 3: round trip, no second implementation needed ----------

/// Sort every map's entries by their encoded key, recursively.
///
/// The encoder emits canonical CBOR -- map keys sorted by serialised
/// form, per CTAP 2.1 sec. 6, which Chrome checks strictly on
/// `attestationObject`. So a decoded value legitimately comes back with
/// its maps in a different order than they went in, and comparing them
/// raw reports that as a round-trip failure. It is not one; it is the
/// canonicalisation doing its job. Both sides get normalised instead.
fn canonical(v: &Value) -> Value {
    match v {
        Value::Array(xs) => Value::Array(xs.iter().map(canonical).collect()),
        Value::Map(kvs) => {
            let mut out: Vec<(Value, Value)> = kvs
                .iter()
                .map(|(k, val)| (canonical(k), canonical(val)))
                .collect();
            out.sort_by_key(|(k, _)| {
                let mut b = Vec::new();
                encode(k, &mut b);
                b
            });
            Value::Map(out)
        }
        Value::Tag(t, inner) => Value::Tag(*t, Box::new(canonical(inner))),
        other => other.clone(),
    }
}

#[test]
fn every_generated_value_survives_an_encode_decode_round_trip() {
    // Uncorrupted, so this is a pure encoder/decoder agreement check.
    // A disagreement is unambiguous: the two halves of one crate do not
    // share a format.
    for seed in 0..iters(100_000) {
        let mut rng = Rng::new(seed ^ 0xA5A5_1234);
        let v = gen_value(&mut rng, 4);
        let mut buf = Vec::new();
        encode(&v, &mut buf);
        match decode(&buf) {
            Ok(back) => assert_eq!(
                canonical(&back),
                canonical(&v),
                "seed {seed}: round trip changed the value beyond canonical \
                 map ordering\n  bytes {buf:02x?}"
            ),
            Err(e) => {
                panic!("seed {seed}: our own encoder produced bytes we reject: {e:?}\n  {buf:02x?}")
            }
        }
    }
}

#[test]
fn decoding_yields_maps_already_in_canonical_order() {
    // Stronger than the round trip, and the property Chrome actually
    // depends on: what comes back out is already sorted, so a caller
    // that re-encodes it without thinking still emits canonical bytes.
    for seed in 0..iters(60_000) {
        let mut rng = Rng::new(seed ^ 0x7777_3333);
        let v = gen_value(&mut rng, 4);
        let mut buf = Vec::new();
        encode(&v, &mut buf);
        let Ok(back) = decode(&buf) else { continue };
        assert_eq!(
            back,
            canonical(&back),
            "seed {seed}: a decoded map was not in canonical key order"
        );
    }
}

#[test]
fn re_encoding_a_decoded_value_is_stable() {
    // decode -> encode -> decode -> encode must reach a fixed point.
    // If the second encoding differs from the first, the encoder is not
    // a function of the value alone, and canonical ordering -- which
    // Chrome checks strictly on attestationObject -- is not reliable.
    for seed in 0..iters(80_000) {
        let mut rng = Rng::new(seed ^ 0x1357_9BDF);
        let v = gen_value(&mut rng, 4);
        let mut once = Vec::new();
        encode(&v, &mut once);
        let Ok(d1) = decode(&once) else { continue };
        let mut twice = Vec::new();
        encode(&d1, &mut twice);
        assert_eq!(
            once, twice,
            "seed {seed}: re-encoding a decoded value produced different bytes"
        );
    }
}

// ---------- oracle 4: the two decoders must agree ----------

/// Does this value contain a CBOR tag anywhere?
fn contains_tag(v: &Value) -> bool {
    match v {
        Value::Tag(..) => true,
        Value::Array(xs) => xs.iter().any(contains_tag),
        Value::Map(kvs) => kvs
            .iter()
            .any(|(k, val)| contains_tag(k) || contains_tag(val)),
        _ => false,
    }
}

/// Walk `cborr` over a whole item the way `skip` does, and report
/// whether it consumed the entire input. This is the largest honest
/// comparison against the tree decoder: both answer "is this one
/// complete, well-formed item and nothing else".
fn cborr_accepts_whole(buf: &[u8]) -> bool {
    let mut r = cborr::Reader::new(buf);
    r.skip().is_some() && r.position() == buf.len()
}

#[test]
fn the_two_decoders_agree_on_what_is_a_complete_item() {
    // Where they legitimately differ, the difference is documented and
    // skipped rather than papered over:
    //
    //   * cborr has a depth limit of 8; pqf_cbor's is its own MAX_DEPTH.
    //     A value deeper than 8 is a real difference of scope, not a bug,
    //     so generation stays well under both.
    //   * pqf_cbor rejects floats and reserved simple values outright;
    //     cborr's `header` accepts a major-7 argument and leaves the
    //     meaning to the caller. Generation does not emit floats.
    //   * pqf_cbor validates UTF-8 in text strings; cborr does not look.
    //     A mutation can turn valid text invalid, so a disagreement of
    //     exactly that shape is excluded below.
    //   * TAGS. cborr has no MAJOR_TAG at all (cborr.rs:19-25 stops at
    //     MAJOR_SIMPLE) and `skip` refuses major type 6, while pqf_cbor
    //     has a `Value::Tag`. CTAP2 canonical CBOR forbids tags, so the
    //     streaming reader is the stricter and arguably more correct of
    //     the two -- found by this fuzzer on its first run. Generation
    //     avoids tags rather than excusing them, so a genuine
    //     tree-accepts/stream-rejects finding is still fatal below.
    let mut disagreements = 0;
    for seed in 0..iters(100_000) {
        let mut rng = Rng::new(seed ^ 0x2468_ACE0);
        let v = gen_value(&mut rng, 3);
        let mut buf = Vec::new();
        encode(&v, &mut buf);
        if rng.chance(2) {
            mutate(&mut rng, &mut buf);
        }

        let tree = decode(&buf);
        let stream = cborr_accepts_whole(&buf);

        match (&tree, stream) {
            (Ok(_), true) | (Err(_), false) => {}
            // A tag reached by mutation, not by generation: a single
            // byte flip turns anything into major type 6. cborr has no
            // MAJOR_TAG and refuses them, which for CTAP2 is correct;
            // pqf_cbor has Value::Tag. Excused by inspecting the value
            // rather than by not generating tags, because mutation will
            // always find them.
            (Ok(v), false) if contains_tag(v) => {}
            (Ok(_), false) => {
                disagreements += 1;
                panic!(
                    "seed {seed}: the tree decoder accepted bytes the streaming reader \
                     rejected -- one of them is wrong\n  {buf:02x?}"
                );
            }
            (Err(e), true) => {
                // The documented scope differences all live on this
                // side: cborr is more permissive because it does not
                // check UTF-8, floats, or canonical ordering.
                // pqf_cbor enforces CTAP2 canonical rules that the
                // streaming reader does not look at. DuplicateKey is the
                // notable one and was found by a 3M-case soak after
                // 740k came back clean: pqf_cbor refuses a map with a
                // repeated key, cborr takes whichever entry it walks
                // over. Note the asymmetry -- on tags cborr is the
                // STRICTER of the two, here it is the more permissive,
                // so neither is simply a subset of the other.
                let excused = matches!(
                    e,
                    pqf_cbor::Error::InvalidUtf8
                        | pqf_cbor::Error::Float
                        | pqf_cbor::Error::Reserved
                        | pqf_cbor::Error::IntOverflow
                        | pqf_cbor::Error::TooDeep
                        | pqf_cbor::Error::DuplicateKey
                );
                if !excused {
                    disagreements += 1;
                    panic!(
                        "seed {seed}: the streaming reader accepted bytes the tree decoder \
                         rejected with {e:?}, which is not a documented scope difference\n  \
                         {buf:02x?}"
                    );
                }
            }
        }
    }
    assert_eq!(disagreements, 0);
}

// ---------- oracle 5: bounded work ----------

#[test]
fn a_deeply_nested_input_is_refused_rather_than_recursed() {
    // The mutation that finds this in the wild is trivial to write by
    // hand: a thousand array headers. Both decoders must refuse rather
    // than recurse the stack, and refusing is not enough on its own --
    // it has to refuse without having already blown the stack, which is
    // what running it here checks.
    for depth in [8usize, 9, 64, 512, 4096] {
        let mut buf: Vec<u8> = (0..depth).map(|_| 0x81u8).collect(); // array(1)
        buf.push(0x00); // uint 0
        let mut r = cborr::Reader::new(&buf);
        let got = r.skip();
        if depth >= 8 {
            assert!(got.is_none(), "cborr accepted {depth} levels of nesting");
        }
        // The tree decoder must also return rather than recurse away.
        let _ = decode(&buf);
    }
}

#[test]
fn a_huge_declared_length_does_not_allocate_against_it() {
    // The classic: a byte string that claims 4 GiB with eight bytes of
    // payload. A decoder that reserves capacity from the declared
    // length before reading it is an out-of-memory abort waiting for a
    // hostile host -- and on a 520 KiB part, "hostile" is generous.
    for (label, hdr) in [
        ("2^32-1", vec![0x5Au8, 0xFF, 0xFF, 0xFF, 0xFF]),
        (
            "2^64-1",
            vec![0x5Bu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        ),
        ("2^31", vec![0x5Au8, 0x80, 0x00, 0x00, 0x00]),
    ] {
        let mut buf = hdr;
        buf.extend_from_slice(b"eight!!!");
        assert!(
            decode(&buf).is_err(),
            "{label}: an impossible length was accepted"
        );
        let mut r = cborr::Reader::new(&buf);
        assert!(
            r.str_bytes(cborr::MAJOR_BYTES).is_none(),
            "{label}: the streaming reader returned a payload it does not have"
        );
    }
}
