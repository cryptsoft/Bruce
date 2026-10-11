// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The QRNG driver and the entropy picker, against a scripted bus.
//!
//! The chip cannot be here, and that is the point: on hardware the driver
//! almost always sees a healthy part, so the paths that matter most -- a
//! bad header, a set health bit, a bus that dies half way through a draw,
//! a chip that answers but never readies -- are the ones silicon never
//! runs. `qrng::Bus` is implemented below as a model the test scripts, and
//! `Entropy` sits over the deterministic stub `Trng`, so "the TRNG was not
//! consulted" is a statement about bytes, not a belief.
//!
//! What is under test is the real `crates/firmware/src/qrng.rs` and the
//! real `crates/firmware/src/entropy.rs`.

use std::cell::RefCell;
use std::rc::Rc;

use pqf_firmware_hosttest as fw;

use fw::bc_crypto::sha256;
use fw::entropy::{self, Entropy};
use fw::qrng::{Bus, BusError, Qrng, HEADER_BYTE, PACKET_LEN, REG_PACKET, REG_STATUS};
use fw::trng::Trng;
use rand_core::RngCore;

/// The scripted bus, shared between the test (which sets the script and
/// reads the observations) and the driver (which owns the `Bus`).
#[derive(Default)]
struct Script {
    // script
    chip: bool,
    status_busy_reads: u32,
    bus_fail_after: Option<usize>,
    bus_fail_count: Option<u32>,
    bad_header: u64,
    bad_health: u64,
    // observations
    reads_status: u32,
    reads_packet: u32,
    fails_so_far: u32,
    packet_index: usize,
    releases: u32,
    pd_low: u32,
    pd_high: u32,
    delay_us: u64,
    next_raw: u8,
    /// The entropy bytes of every packet the driver ACCEPTED, in order.
    /// Hash k of the stream is SHA-256 over `good_raw[64k..64k+64]` as
    /// long as no draw was abandoned part way.
    good_raw: Vec<u8>,
}

impl Script {
    fn healthy() -> Rc<RefCell<Script>> {
        Rc::new(RefCell::new(Script {
            chip: true,
            next_raw: 1,
            ..Default::default()
        }))
    }
    fn hash(&self, k: usize) -> [u8; 32] {
        sha256(&self.good_raw[64 * k..64 * k + 64])
    }
}

struct FakeBus(Rc<RefCell<Script>>);

impl Bus for FakeBus {
    fn read_regs(&mut self, reg: u8, out: &mut [u8]) -> Result<(), BusError> {
        let mut m = self.0.borrow_mut();
        if !m.chip {
            return Err(BusError);
        }
        match reg {
            REG_STATUS => {
                m.reads_status += 1;
                if out.len() != 1 {
                    return Err(BusError);
                }
                if m.status_busy_reads > 0 {
                    m.status_busy_reads -= 1;
                    out[0] = 0x01;
                } else {
                    out[0] = 0x00;
                }
                Ok(())
            }
            REG_PACKET => {
                if out.len() != PACKET_LEN {
                    return Err(BusError);
                }
                let idx = m.packet_index;
                m.packet_index += 1;
                m.reads_packet += 1;
                if let Some(after) = m.bus_fail_after {
                    let still_failing = m.bus_fail_count.map_or(true, |n| m.fails_so_far < n);
                    if idx >= after && still_failing {
                        m.fails_so_far += 1;
                        return Err(BusError);
                    }
                }
                let bad_hdr = idx < 64 && (m.bad_header >> idx) & 1 == 1;
                let bad_hlt = idx < 64 && (m.bad_health >> idx) & 1 == 1;
                out[0] = if bad_hdr { 0x00 } else { HEADER_BYTE };
                out[1] = if bad_hlt { 0x04 } else { 0x00 };
                for b in out[2..].iter_mut() {
                    *b = m.next_raw;
                    m.next_raw = m.next_raw.wrapping_add(1);
                }
                if !bad_hdr && !bad_hlt {
                    let bytes = out[2..].to_vec();
                    m.good_raw.extend_from_slice(&bytes);
                }
                Ok(())
            }
            _ => Err(BusError),
        }
    }
    fn set_pd(&mut self, high: bool) {
        let mut m = self.0.borrow_mut();
        if high {
            m.pd_high += 1
        } else {
            m.pd_low += 1
        }
    }
    fn delay_us(&mut self, us: u32) {
        self.0.borrow_mut().delay_us += us as u64;
    }
    fn release(&mut self) {
        self.0.borrow_mut().releases += 1;
    }
}

fn probe(m: &Rc<RefCell<Script>>) -> Option<Qrng<FakeBus>> {
    Qrng::probe(FakeBus(Rc::clone(m)))
}

/// The stub TRNG's stream from a fresh instance: 1, 2, 3, ...
fn stub_stream(n: usize) -> Vec<u8> {
    let mut t = Trng::new_for_test();
    let mut v = vec![0u8; n];
    t.fill(&mut v);
    v
}

// ---- the driver ----------------------------------------------------------

#[test]
fn no_chip_means_none_and_the_pins_are_released() {
    let m = Script::healthy();
    m.borrow_mut().chip = false;
    assert!(probe(&m).is_none(), "an empty bus was reported as a chip");
    let s = m.borrow();
    assert_eq!(s.releases, 1, "pins not released after the miss");
    assert_eq!(
        s.pd_low + s.pd_high,
        0,
        "PD was toggled although nothing answered"
    );
    assert_eq!(
        s.reads_packet, 0,
        "a packet was requested from an absent chip"
    );
}

#[test]
fn a_chip_that_never_readies_is_treated_as_absent() {
    let m = Script::healthy();
    m.borrow_mut().status_busy_reads = 1_000_000;
    assert!(
        probe(&m).is_none(),
        "a chip that never reads ready was used"
    );
    let s = m.borrow();
    assert_eq!(
        (s.pd_low, s.pd_high),
        (1, 1),
        "no PD power-cycle although the chip ACKed"
    );
    assert_eq!(s.releases, 1, "pins not released");
    assert!(
        s.delay_us < 2_000_000,
        "the ready wait is not bounded ({} us)",
        s.delay_us
    );
}

#[test]
fn present_output_is_sha256_over_64_raw_bytes() {
    let m = Script::healthy();
    m.borrow_mut().status_busy_reads = 3; // ready on the 4th read: the wait is a wait
    let mut q = probe(&m).expect("chip not detected");
    assert!(q.present());
    {
        let s = m.borrow();
        assert_eq!(
            (s.pd_low, s.pd_high),
            (1, 1),
            "PD was not pulsed exactly once"
        );
        assert!(s.reads_status >= 4, "ready was not waited for");
    }
    let mut out = [0u8; 32];
    assert_eq!(q.fill(&mut out), 32);
    let s = m.borrow();
    assert_eq!(out, s.hash(0), "output is not SHA-256(first 64 raw bytes)");
    assert_eq!(
        s.reads_packet, 4,
        "a 32-byte request should read exactly 4 packets"
    );
    assert_eq!(q.stats().served, 32);
    // Framing dropped: hashing the packets WITH header + health must differ.
    let mut framed = Vec::new();
    for p in 0..4 {
        framed.push(HEADER_BYTE);
        framed.push(0);
        framed.extend_from_slice(&s.good_raw[p * 16..p * 16 + 16]);
    }
    assert_ne!(
        out,
        sha256(&framed),
        "framing bytes leaked into the conditioner input"
    );
}

#[test]
fn small_requests_drain_the_buffered_hash_once() {
    let m = Script::healthy();
    let mut q = probe(&m).unwrap();
    let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
    q.fill(&mut a);
    q.fill(&mut b);
    let s = m.borrow();
    let h = s.hash(0);
    assert_eq!(a, h[..16], "first half wrong");
    assert_eq!(
        b,
        h[16..],
        "second half did not continue where the first stopped"
    );
    assert_eq!(
        s.reads_packet, 4,
        "two 16-byte requests should cost one draw"
    );
    assert_ne!(a, b, "the two halves are identical -- bytes were re-served");
}

#[test]
fn a_request_spanning_two_draws_stays_in_order() {
    let m = Script::healthy();
    let mut q = probe(&m).unwrap();
    let mut got = [0u8; 40];
    q.fill(&mut got);
    let mut tail = [0u8; 24];
    q.fill(&mut tail);
    let s = m.borrow();
    let (h0, h1) = (s.hash(0), s.hash(1));
    assert_eq!(got[..32], h0);
    assert_eq!(
        got[32..],
        h1[..8],
        "bytes 32..40 are not the start of the next hash"
    );
    assert_eq!(
        tail,
        h1[8..],
        "the rest of the second hash was not what followed"
    );
    assert_eq!(
        s.reads_packet, 8,
        "40 + 24 bytes should be exactly two draws"
    );
}

#[test]
fn a_bad_header_packet_is_dropped_not_hashed() {
    let m = Script::healthy();
    m.borrow_mut().bad_header = 1 << 1;
    let mut q = probe(&m).unwrap();
    let mut out = [0u8; 32];
    assert_eq!(q.fill(&mut out), 32);
    let s = m.borrow();
    assert_eq!(
        out,
        s.hash(0),
        "the bad packet's bytes reached the conditioner"
    );
    assert_eq!(q.stats().header_err, 1);
    assert_eq!(
        s.reads_packet, 5,
        "dropping one packet should cost one extra read"
    );
}

#[test]
fn a_health_flagged_packet_is_dropped_not_hashed() {
    let m = Script::healthy();
    m.borrow_mut().bad_health = (1 << 0) | (1 << 3);
    let mut q = probe(&m).unwrap();
    let mut out = [0u8; 32];
    assert_eq!(q.fill(&mut out), 32);
    let s = m.borrow();
    assert_eq!(
        out,
        s.hash(0),
        "an unhealthy packet's bytes reached the conditioner"
    );
    assert_eq!(q.stats().health_err, 2);
    assert_eq!(s.reads_packet, 6);
}

#[test]
fn a_stream_of_rejects_gives_up_and_returns_short() {
    let m = Script::healthy();
    m.borrow_mut().bad_header = 0x1FF; // nine bad in a row
    let mut q = probe(&m).unwrap();
    let mut out = [0u8; 16];
    assert_eq!(q.fill(&mut out), 0, "nothing should have been served");
    assert_eq!(
        q.stats().header_err,
        9,
        "expected the draw to give up after the ninth reject"
    );
    assert_eq!(q.stats().short_requests, 1);
    assert!(
        q.present(),
        "one failed request must not write the chip off"
    );
}

#[test]
fn a_bus_error_mid_request_returns_the_good_prefix() {
    let m = Script::healthy();
    m.borrow_mut().bus_fail_after = Some(4); // first draw ok, then dead
    let mut q = probe(&m).unwrap();
    let status_before = m.borrow().reads_status;
    let mut out = [0u8; 64];
    assert_eq!(
        q.fill(&mut out),
        32,
        "the completed draw should have been kept"
    );
    let s = m.borrow();
    assert_eq!(out[..32], s.hash(0));
    assert_eq!(q.stats().bus_err, 4, "3 retries + the one that gave up");
    assert_eq!(q.stats().short_requests, 1);
    assert!(
        s.reads_status > status_before,
        "no ready check after the failure"
    );
    assert!(q.present());
}

#[test]
fn an_unplugged_chip_is_written_off_on_the_first_failed_request() {
    // The realistic loss: the cable comes out. The status read after the
    // failed draw gets no answer, and that is the whole verdict -- no
    // eight-request grace period, no ready-wait, the next byte is the
    // TRNG's.
    let m = Script::healthy();
    let mut q = probe(&m).unwrap();
    m.borrow_mut().chip = false;
    let mut b = [0u8; 8];
    assert_eq!(q.fill(&mut b), 0);
    assert!(!q.present(), "a chip that no longer answers was kept");
    assert!(q.stats().lost);
    assert_eq!(q.stats().short_requests, 1);
    assert_eq!(m.borrow().releases, 1, "the bus was not released");
    let s = m.borrow();
    let reads = s.reads_packet + s.reads_status;
    drop(s);
    assert_eq!(q.fill(&mut b), 0);
    let s = m.borrow();
    assert_eq!(
        s.reads_packet + s.reads_status,
        reads,
        "a written-off chip is still being asked"
    );
}

#[test]
fn a_transient_fault_costs_exactly_one_liveness_read() {
    let m = Script::healthy();
    m.borrow_mut().bus_fail_after = Some(0);
    let mut q = probe(&m).unwrap();
    let before = m.borrow().reads_status;
    let mut b = [0u8; 8];
    assert_eq!(q.fill(&mut b), 0);
    assert_eq!(
        m.borrow().reads_status,
        before + 1,
        "expected one status read after the failed draw"
    );
    assert!(
        q.present(),
        "a chip that still answers status must not be written off by one failure"
    );
}

#[test]
fn eight_consecutive_failures_write_the_chip_off() {
    let m = Script::healthy();
    m.borrow_mut().bus_fail_after = Some(0);
    let mut q = probe(&m).unwrap();
    let mut b = [0u8; 8];
    for _ in 0..7 {
        q.fill(&mut b);
    }
    assert!(q.present(), "written off too early (after 7)");
    q.fill(&mut b);
    assert!(!q.present(), "still present after 8 consecutive failures");
    assert!(q.stats().lost);
    assert_eq!(
        m.borrow().releases,
        1,
        "bus not released after being written off"
    );
    let reads = m.borrow().reads_packet;
    assert_eq!(q.fill(&mut b), 0);
    assert_eq!(
        m.borrow().reads_packet,
        reads,
        "a written-off chip is still being asked"
    );
}

#[test]
fn a_transient_failure_recovers_and_resets_the_counter() {
    let m = Script::healthy();
    {
        let mut s = m.borrow_mut();
        s.bus_fail_after = Some(4); // draw 1 fine; packets 4..9 fail; then fine
        s.bus_fail_count = Some(6);
    }
    let mut q = probe(&m).unwrap();
    let mut a = [0u8; 32];
    assert_eq!(q.fill(&mut a), 32);
    assert_eq!(q.fill(&mut a), 0, "4 failures -> short");
    assert_eq!(q.stats().short_requests, 1);
    let mut b = [0u8; 32];
    assert_eq!(
        q.fill(&mut b),
        32,
        "2 failures then 4 good packets -> complete"
    );
    assert_eq!(b, m.borrow().hash(1), "after recovery the output is wrong");
    assert!(q.present());
    // the consecutive-failure counter really reset: 7 more failures must
    // not write it off
    {
        let mut s = m.borrow_mut();
        s.bus_fail_after = Some(s.packet_index);
        s.bus_fail_count = None;
        s.fails_so_far = 0;
    }
    for _ in 0..7 {
        q.fill(&mut a);
    }
    assert!(
        q.present(),
        "the failure counter did not reset after a good request"
    );
}

#[test]
fn an_empty_request_touches_nothing() {
    let m = Script::healthy();
    let mut q = probe(&m).unwrap();
    assert_eq!(q.fill(&mut []), 0);
    assert_eq!(
        m.borrow().reads_packet,
        0,
        "a zero-length fill drew from the chip"
    );
}

// ---- the picker ------------------------------------------------------------

#[test]
fn with_a_chip_the_trng_is_not_consulted() {
    let m = Script::healthy();
    let mut e = Entropy::new(Trng::new_for_test(), probe(&m));
    assert!(e.qrng_present());
    assert_eq!(e.source_name(), "QRNG");
    let mut out = [0u8; 32];
    e.fill(&mut out);
    assert_eq!(out, m.borrow().hash(0));
    assert_eq!(e.split(), (32, 0));
    // Kill the chip and draw again: the bytes must be the stub TRNG's
    // FIRST bytes, proving it was never advanced while the QRNG served.
    m.borrow_mut().chip = false;
    let mut tail = [0u8; 8];
    e.fill(&mut tail);
    assert_eq!(
        tail.to_vec(),
        stub_stream(8),
        "the TRNG had been consumed while the QRNG served"
    );
    assert_eq!(e.split(), (32, 8));
}

#[test]
fn without_a_chip_every_byte_is_the_trng() {
    let m = Script::healthy();
    m.borrow_mut().chip = false;
    let mut e = Entropy::new(Trng::new_for_test(), probe(&m));
    assert!(!e.qrng_present());
    assert_eq!(e.source_name(), "TRNG");
    let mut out = [0u8; 20];
    e.fill(&mut out);
    assert_eq!(out.to_vec(), stub_stream(20));
    assert_eq!(e.split(), (0, 20));
    assert!(e.qrng_stats().is_none());
}

#[test]
fn a_short_qrng_draw_is_completed_by_the_trng() {
    let m = Script::healthy();
    m.borrow_mut().bus_fail_after = Some(4);
    let mut e = Entropy::new(Trng::new_for_test(), probe(&m));
    let mut out = [0u8; 64];
    e.fill(&mut out);
    assert_eq!(out[..32], m.borrow().hash(0), "the QRNG half is wrong");
    assert_eq!(
        out[32..].to_vec(),
        stub_stream(32),
        "the remainder did not come from the TRNG"
    );
    assert_eq!(e.split(), (32, 32));
    assert_eq!(e.qrng_stats().unwrap().short_requests, 1);
}

#[test]
fn once_written_off_the_name_and_the_bytes_say_trng() {
    let m = Script::healthy();
    m.borrow_mut().bus_fail_after = Some(0);
    let mut e = Entropy::new(Trng::new_for_test(), probe(&m));
    let mut b = [0u8; 8];
    for _ in 0..8 {
        e.fill(&mut b);
    }
    assert!(!e.qrng_present());
    assert_eq!(e.source_name(), "TRNG");
    assert!(e.qrng_stats().unwrap().lost);
    assert_eq!(e.split(), (0, 64));
}

#[test]
fn the_status_report_names_the_source_and_carries_the_counters() {
    let m = Script::healthy();
    let mut e = Entropy::new(Trng::new_for_test(), probe(&m));
    let mut out = [0u8; 40];
    e.fill(&mut out); // two draws: 40 bytes from the QRNG, 8 packets read
    let s = e.status_bytes();
    let word = |i: usize| u32::from_be_bytes(s[1 + 4 * i..5 + 4 * i].try_into().unwrap());
    assert_eq!(s.len(), entropy::STATUS_LEN);
    assert_eq!(s[0], entropy::SRC_QRNG);
    assert_eq!(word(0), 40, "qrng_bytes");
    assert_eq!(word(1), 0, "fallback_bytes");
    assert_eq!(word(2), 8, "packets");
    assert_eq!(
        (word(3), word(4), word(5), word(6)),
        (0, 0, 0, 0),
        "error counters"
    );

    // Pull the cable. The 24 conditioned bytes still buffered from the
    // second draw are served first -- they are good bytes -- and the
    // first request that actually has to touch the bus is short, the chip
    // is written off, and the report says so on that same request.
    m.borrow_mut().chip = false;
    let mut more = [0u8; 32];
    e.fill(&mut more);
    let s = e.status_bytes();
    let word = |i: usize| u32::from_be_bytes(s[1 + 4 * i..5 + 4 * i].try_into().unwrap());
    assert_eq!(s[0], entropy::SRC_QRNG_LOST);
    assert_eq!(
        word(0),
        64,
        "the buffered remainder of the second draw was still the QRNG's"
    );
    assert_eq!(
        word(1),
        8,
        "the eight bytes past the buffer came from the TRNG"
    );
    assert_eq!(word(6), 1, "one short request");

    // No chip at boot: TRNG, and nothing to count.
    let n: Entropy<FakeBus> = Entropy::new(Trng::new_for_test(), None);
    let s = n.status_bytes();
    assert_eq!(s[0], entropy::SRC_TRNG);
    assert!(s[1..].iter().all(|&b| b == 0));
}

#[test]
fn the_rng_core_impl_routes_through_the_picker() {
    let m = Script::healthy();
    let mut e = Entropy::new(Trng::new_for_test(), probe(&m));
    let a = e.next_u32();
    let b = e.next_u64();
    let mut c = [0u8; 20];
    e.fill_bytes(&mut c);
    let h = m.borrow().hash(0);
    assert_eq!(a, u32::from_le_bytes(h[..4].try_into().unwrap()));
    assert_eq!(b, u64::from_le_bytes(h[4..12].try_into().unwrap()));
    assert_eq!(c, h[12..32]);
    assert_eq!(e.split(), (32, 0));
}
