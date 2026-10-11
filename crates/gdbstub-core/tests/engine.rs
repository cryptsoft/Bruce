// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Protocol tests for the RSP engine.
//!
//! The C port's stub has had a host suite since GDB stub (`test_gdbstub.c`,
//! 73 checks); this is the Rust equivalent, and the section headings are
//! deliberately the same ones so the two can be compared line for line.
//! What differs is the split: the C stub is one file containing both the
//! protocol and the DEMCR/FPB pokes, so its suite fakes the registers.
//! Here the hardware lives in the firmware crate behind [`Target`], so
//! the sections about MON_STEP and FPB master-disable have no counterpart
//! -- those belong to `crates/firmware/src/gdbstub.rs` and can only be
//! judged on silicon.
//!
//! Run on the host, not the firmware target:
//!
//! ```text
//! cargo test -p pqf-gdbstub-core --target "$(rustc -vV | awk '/^host:/{print $2}')"
//! ```

use pqf_gdbstub_core::{Engine, StopReason, Target, Transport, MAX_BREAKPOINTS, REG_N};

/// Where the mock target's readable window starts. Anything outside is
/// refused, standing in for the firmware's address whitelist.
const MEM_BASE: u32 = 0x2000_0000;
const MEM_LEN: usize = 256;

/// A target that records what the engine asked of it.
struct Mock {
    mem: [u8; MEM_LEN],
    bp: [Option<u32>; MAX_BREAKPOINTS],
    halted: bool,
    halt_requests: usize,
    /// One entry per `resume`, holding the `step` flag it was given.
    resumes: Vec<bool>,
}

impl Mock {
    /// Starts *running*, which is the state a real target is in when GDB
    /// first connects -- the case the engine used to get wrong.
    fn running() -> Self {
        let mut mem = [0u8; MEM_LEN];
        for (i, b) in mem.iter_mut().enumerate() {
            *b = i as u8;
        }
        Self {
            mem,
            bp: [None; MAX_BREAKPOINTS],
            halted: false,
            halt_requests: 0,
            resumes: Vec::new(),
        }
    }

    fn halted() -> Self {
        let mut m = Self::running();
        m.halted = true;
        m
    }

    fn live_breakpoints(&self) -> usize {
        self.bp.iter().filter(|b| b.is_some()).count()
    }
}

impl Target for Mock {
    fn read_u8(&mut self, addr: u32) -> Option<u8> {
        let off = addr.checked_sub(MEM_BASE)? as usize;
        self.mem.get(off).copied()
    }
    fn write_u8(&mut self, addr: u32, val: u8) -> bool {
        match addr.checked_sub(MEM_BASE) {
            Some(off) if (off as usize) < MEM_LEN => {
                self.mem[off as usize] = val;
                true
            }
            _ => false,
        }
    }
    fn set_breakpoint(&mut self, slot: usize, addr: u32) {
        self.bp[slot] = Some(addr);
    }
    fn clear_breakpoint(&mut self, slot: usize) {
        self.bp[slot] = None;
    }
    fn resume(&mut self, step: bool) {
        self.resumes.push(step);
        self.halted = false;
    }
    fn is_halted(&self) -> bool {
        self.halted
    }
    fn request_halt(&mut self) {
        self.halt_requests += 1;
        // The firmware raises DEMCR.MON_PEND and stops at the next
        // controlled point; here that point is immediate.
        self.halted = true;
    }
}

/// Collects everything the engine wrote, acks included.
#[derive(Default)]
struct Wire {
    out: Vec<u8>,
}

impl Transport for Wire {
    fn read(&mut self, _buf: &mut [u8]) -> usize {
        0
    }
    fn write(&mut self, data: &[u8]) {
        self.out.extend_from_slice(data);
    }
}

/// A test session: engine, target and wire, driven a packet at a time.
struct Session {
    engine: Engine,
    target: Mock,
    wire: Wire,
}

impl Session {
    fn new(target: Mock) -> Self {
        Self {
            engine: Engine::new(),
            target,
            wire: Wire::default(),
        }
    }

    /// Frame `body` as `$body#xx` and feed it in. Returns whether the
    /// engine asked to resume.
    fn send(&mut self, body: &str) -> bool {
        self.send_raw(&frame(body))
    }

    /// Feed bytes exactly as given -- for framing tests that need to be
    /// wrong on purpose.
    fn send_raw(&mut self, bytes: &[u8]) -> bool {
        self.wire.out.clear();
        self.engine.feed(&mut self.wire, &mut self.target, bytes)
    }

    /// Everything written since the last packet, as a lossy string.
    fn wire_text(&self) -> String {
        String::from_utf8_lossy(&self.wire.out).into_owned()
    }

    /// The reply body, with the leading ack, the `$` and the `#xx`
    /// checksum stripped. Panics if no packet was sent.
    fn reply(&self) -> String {
        let text = self.wire_text();
        let start = text
            .find('$')
            .unwrap_or_else(|| panic!("no packet in {text:?}"));
        let rest = &text[start + 1..];
        let end = rest
            .rfind('#')
            .unwrap_or_else(|| panic!("unterminated packet in {text:?}"));
        rest[..end].to_string()
    }

    /// True when the engine sent a packet at all (an empty reply, `$#00`,
    /// still counts -- that is RSP for "unsupported").
    fn replied(&self) -> bool {
        self.wire_text().contains('$')
    }
}

/// `$body#<checksum>`, the checksum being the low byte of the sum.
fn frame(body: &str) -> Vec<u8> {
    let sum = body.bytes().fold(0u8, |a, b| a.wrapping_add(b));
    let mut v = Vec::with_capacity(body.len() + 4);
    v.push(b'$');
    v.extend_from_slice(body.as_bytes());
    v.push(b'#');
    v.extend_from_slice(format!("{sum:02x}").as_bytes());
    v
}

/// A register value as the `g`/`P` packets carry it: little-endian hex.
fn le_hex32(v: u32) -> String {
    v.to_le_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

// -- framing: ack, packet assembly, checksum swallow -------------------

#[test]
fn every_packet_is_acked_before_it_is_answered() {
    let mut s = Session::new(Mock::halted());
    s.send("qC");
    // The ack has to precede the reply: GDB retransmits without it.
    let text = s.wire_text();
    assert!(text.starts_with('+'), "expected leading ack, got {text:?}");
    assert_eq!(s.reply(), "QC1");
}

#[test]
fn bytes_outside_a_packet_are_ignored() {
    let mut s = Session::new(Mock::halted());
    // GDB's own acks and line noise arrive between packets.
    let mut bytes = b"+-\r\n".to_vec();
    bytes.extend_from_slice(&frame("qC"));
    s.send_raw(&bytes);
    assert_eq!(s.reply(), "QC1");
}

#[test]
fn a_packet_split_across_reads_still_arrives() {
    let mut s = Session::new(Mock::halted());
    let full = frame("qAttached");
    let (head, tail) = full.split_at(4);
    s.wire.out.clear();
    s.engine.feed(&mut s.wire, &mut s.target, head);
    assert!(!s.replied(), "answered a half-received packet");
    s.engine.feed(&mut s.wire, &mut s.target, tail);
    assert_eq!(s.reply(), "1");
}

#[test]
fn checksum_digits_are_swallowed_not_parsed_as_a_packet() {
    // The two hex digits after '#' must not be mistaken for the start of
    // the next packet, or every exchange desynchronises by two bytes.
    let mut s = Session::new(Mock::halted());
    let mut bytes = frame("qC");
    bytes.extend_from_slice(&frame("qAttached"));
    s.send_raw(&bytes);
    let text = s.wire_text();
    assert!(text.contains("QC1"), "first reply missing: {text:?}");
    assert!(text.contains("$1#"), "second reply missing: {text:?}");
}

// -- framing: }-escaped payload bytes decode ---------------------------

#[test]
fn escaped_bytes_decode_and_do_not_end_the_packet() {
    // `}` escapes the next byte with ^0x20. An escaped '#' (0x23 sent as
    // `}\x03`) must not terminate the packet. Here the escape encodes the
    // 'A' of "qA<tail>" so a successful decode is observable as a reply
    // to qAttached.
    let mut s = Session::new(Mock::halted());
    let body = b"qAttached";
    let sum = body.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    let mut bytes = vec![b'$', b'q', b'}'];
    bytes.push(b'A' ^ 0x20);
    bytes.extend_from_slice(&body[2..]);
    bytes.push(b'#');
    bytes.extend_from_slice(format!("{sum:02x}").as_bytes());
    s.send_raw(&bytes);
    assert_eq!(s.reply(), "1", "escaped byte did not decode to 'A'");
}

#[test]
fn an_escaped_hash_does_not_terminate_the_packet() {
    let mut s = Session::new(Mock::halted());
    // Body is "p#" -- a nonsense register number, but the point is that
    // the '#' inside it must reach the dispatcher rather than ending the
    // packet, so the answer is E01 and not a truncated "p".
    let mut bytes = vec![b'$', b'p', b'}'];
    bytes.push(b'#' ^ 0x20);
    bytes.extend_from_slice(b"#00");
    s.send_raw(&bytes);
    assert_eq!(s.reply(), "E01");
}

// -- running target: register access refused, '?' pends a halt ---------

#[test]
fn question_mark_on_a_running_target_asks_it_to_stop() {
    let mut s = Session::new(Mock::running());
    s.send("?");
    // No stop reply yet: the target has not stopped, and answering from
    // the previous stop's register file is exactly the bug this guards.
    assert!(
        !s.replied(),
        "answered '?' from stale state: {:?}",
        s.wire_text()
    );
    assert_eq!(s.target.halt_requests, 1, "no halt was requested");
    assert_eq!(s.engine.stop_reason, StopReason::Interrupt);
}

#[test]
fn question_mark_on_a_halted_target_answers_immediately() {
    let mut s = Session::new(Mock::halted());
    s.engine.stop_reason = StopReason::Trap;
    s.send("?");
    assert_eq!(s.reply(), "S05");
    assert_eq!(
        s.target.halt_requests, 0,
        "halted target should not be re-halted"
    );
}

#[test]
fn a_second_attach_does_not_replay_the_previous_stop() {
    // The regression that made a re-attach silently swallow the first
    // breakpoint hit: GDB believed the target sat at the address it last
    // trapped on, so it stepped over the breakpoint there on resume.
    let mut s = Session::new(Mock::halted());
    s.engine.regs[15] = 0x1000_7cf4;
    s.send("?");
    assert_eq!(s.reply(), "S05");

    // Session ends; target runs on.
    s.send("D");
    assert!(!s.target.halted, "detach left the target halted");

    // Fresh attach. The stale PC is still in the register file, so an
    // engine that answers from it would look identical to the working
    // case -- what separates them is that a halt must be requested.
    s.send("?");
    assert!(!s.replied(), "replayed the previous stop on re-attach");
    assert_eq!(s.target.halt_requests, 1);
}

#[test]
fn register_reads_are_refused_while_the_target_runs() {
    for packet in ["g", "p0"] {
        let mut s = Session::new(Mock::running());
        s.send(packet);
        assert_eq!(s.reply(), "E01", "{packet} answered from a running target");
    }
}

#[test]
fn register_writes_are_refused_while_the_target_runs() {
    let mut s = Session::new(Mock::running());
    s.send(&format!("P0={}", le_hex32(0xdead_beef)));
    assert_eq!(s.reply(), "E01");
    assert_eq!(s.engine.regs[0], 0, "write landed despite the refusal");

    let mut s = Session::new(Mock::running());
    let all: String = (0..REG_N).map(|_| le_hex32(0x1111_1111)).collect();
    s.send(&format!("G{all}"));
    assert_eq!(s.reply(), "E01");
    assert_eq!(s.engine.regs[0], 0);
}

#[test]
fn ctrl_c_stops_a_running_target() {
    // 0x03 arrives raw, outside any packet.
    let mut s = Session::new(Mock::running());
    s.send_raw(&[0x03]);
    assert_eq!(s.target.halt_requests, 1, "Ctrl-C did not stop the target");
    assert_eq!(s.engine.stop_reason, StopReason::Interrupt);
    assert!(s.engine.attached, "Ctrl-C should mark the session attached");
}

#[test]
fn ctrl_c_on_an_already_halted_target_is_not_a_second_halt() {
    let mut s = Session::new(Mock::halted());
    s.send_raw(&[0x03]);
    assert_eq!(s.target.halt_requests, 0);
    assert_eq!(s.engine.stop_reason, StopReason::Interrupt);
}

// -- halted: g/G/p/P round trip ----------------------------------------

#[test]
fn g_returns_all_seventeen_registers_little_endian() {
    let mut s = Session::new(Mock::halted());
    for i in 0..REG_N {
        s.engine.regs[i] = 0x1000_0000 + i as u32;
    }
    s.send("g");
    let reply = s.reply();
    assert_eq!(
        reply.len(),
        REG_N * 8,
        "GDB rejects any other length outright"
    );
    assert!(reply.starts_with(&le_hex32(0x1000_0000)));
    assert!(
        reply.ends_with(&le_hex32(0x1000_0010)),
        "xpsr must be register 16"
    );
}

#[test]
fn capital_g_writes_every_register() {
    let mut s = Session::new(Mock::halted());
    let all: String = (0..REG_N as u32)
        .map(|i| le_hex32(0xaa00_0000 + i))
        .collect();
    s.send(&format!("G{all}"));
    assert_eq!(s.reply(), "OK");
    assert_eq!(s.engine.regs[0], 0xaa00_0000);
    assert_eq!(s.engine.regs[REG_N - 1], 0xaa00_0000 + (REG_N as u32 - 1));
}

#[test]
fn capital_g_rejects_a_short_payload_without_writing_anything() {
    let mut s = Session::new(Mock::halted());
    s.engine.regs[0] = 0x1234_5678;
    s.send("G0011");
    assert_eq!(s.reply(), "E01");
    assert_eq!(
        s.engine.regs[0], 0x1234_5678,
        "partial write from a short G"
    );
}

#[test]
fn p_and_capital_p_round_trip_one_register() {
    let mut s = Session::new(Mock::halted());
    s.send(&format!("P5={}", le_hex32(0x5a5a_5a5a)));
    assert_eq!(s.reply(), "OK");
    assert_eq!(s.engine.regs[5], 0x5a5a_5a5a);
    s.send("p5");
    assert_eq!(s.reply(), le_hex32(0x5a5a_5a5a));
}

#[test]
fn register_numbers_past_the_end_are_refused() {
    let mut s = Session::new(Mock::halted());
    s.send(&format!("p{:x}", REG_N));
    assert_eq!(s.reply(), "E01");
    s.send(&format!("P{:x}={}", REG_N, le_hex32(1)));
    assert_eq!(s.reply(), "E01");
}

// -- memory: m/M and the region whitelist ------------------------------

#[test]
fn m_reads_memory_as_hex() {
    let mut s = Session::new(Mock::halted());
    s.send(&format!("m{MEM_BASE:x},4"));
    assert_eq!(
        s.reply(),
        "00010203",
        "mock memory is filled with its own offsets"
    );
}

#[test]
fn capital_m_writes_memory() {
    let mut s = Session::new(Mock::halted());
    s.send(&format!("M{:x},2:aabb", MEM_BASE + 8));
    assert_eq!(s.reply(), "OK");
    assert_eq!(s.target.mem[8], 0xaa);
    assert_eq!(s.target.mem[9], 0xbb);
}

#[test]
fn reads_outside_the_whitelist_are_refused() {
    let mut s = Session::new(Mock::halted());
    s.send("m00000000,4");
    assert_eq!(s.reply(), "E01");
}

#[test]
fn a_write_outside_the_whitelist_is_refused() {
    let mut s = Session::new(Mock::halted());
    s.send("M00000000,1:ff");
    assert_eq!(s.reply(), "E01");
}

#[test]
fn a_read_running_off_the_end_is_refused_rather_than_truncated() {
    // The last two bytes of the window plus two past it. A stub that
    // returned what it could would hand GDB a short reply it reads as
    // corrupt; refusing is the honest answer.
    let mut s = Session::new(Mock::halted());
    s.send(&format!("m{:x},4", MEM_BASE + MEM_LEN as u32 - 2));
    assert_eq!(s.reply(), "E01");
}

#[test]
fn a_write_with_a_short_payload_is_refused() {
    let mut s = Session::new(Mock::halted());
    let before = s.target.mem[0];
    s.send(&format!("M{MEM_BASE:x},4:aabb"));
    assert_eq!(s.reply(), "E01");
    assert_eq!(s.target.mem[0], before, "partial write from a short M");
}

#[test]
fn a_write_with_a_non_hex_payload_is_refused() {
    let mut s = Session::new(Mock::halted());
    s.send(&format!("M{MEM_BASE:x},1:zz"));
    assert_eq!(s.reply(), "E01");
}

// -- breakpoints: Z0/z0 onto target slots ------------------------------

#[test]
fn z0_sets_a_breakpoint_and_lowercase_z_clears_it() {
    let mut s = Session::new(Mock::halted());
    s.send("Z0,10000100,2");
    assert_eq!(s.reply(), "OK");
    assert_eq!(s.engine.breakpoint_count(), 1);
    assert_eq!(s.target.live_breakpoints(), 1, "engine and target disagree");

    s.send("z0,10000100,2");
    assert_eq!(s.reply(), "OK");
    assert_eq!(s.engine.breakpoint_count(), 0);
    assert_eq!(s.target.live_breakpoints(), 0);
}

#[test]
fn hardware_breakpoints_use_the_same_slots() {
    // Z1 is a hardware breakpoint; on this target both land on FPB
    // comparators, so the engine treats them identically.
    let mut s = Session::new(Mock::halted());
    s.send("Z1,10000200,2");
    assert_eq!(s.reply(), "OK");
    assert_eq!(s.target.live_breakpoints(), 1);
}

#[test]
fn setting_the_same_breakpoint_twice_succeeds_without_burning_a_slot() {
    // GDB re-sends every breakpoint on each continue. Answering E01 makes
    // it give up on the breakpoint entirely.
    let mut s = Session::new(Mock::halted());
    s.send("Z0,10000100,2");
    s.send("Z0,10000100,2");
    assert_eq!(s.reply(), "OK");
    assert_eq!(s.engine.breakpoint_count(), 1);
}

#[test]
fn slot_exhaustion_is_reported_rather_than_silently_dropped() {
    let mut s = Session::new(Mock::halted());
    for i in 0..MAX_BREAKPOINTS {
        s.send(&format!("Z0,{:x},2", 0x1000_0000 + i as u32 * 4));
        assert_eq!(s.reply(), "OK", "slot {i} should have been free");
    }
    s.send("Z0,20000000,2");
    assert_eq!(s.reply(), "E01", "a ninth breakpoint must fail loudly");
    assert_eq!(s.engine.breakpoint_count(), MAX_BREAKPOINTS);
}

#[test]
fn clearing_an_unknown_breakpoint_is_an_error() {
    let mut s = Session::new(Mock::halted());
    s.send("z0,deadbeef,2");
    assert_eq!(s.reply(), "E01");
}

#[test]
fn a_malformed_breakpoint_packet_is_refused() {
    let mut s = Session::new(Mock::halted());
    s.send("Z0,zzzz,2");
    assert_eq!(s.reply(), "E01");
    assert_eq!(s.engine.breakpoint_count(), 0);
}

// -- resume: c / s -----------------------------------------------------

#[test]
fn continue_resumes_without_stepping() {
    let mut s = Session::new(Mock::halted());
    assert!(s.send("c"), "c must tell the caller to resume");
    assert_eq!(s.target.resumes, vec![false]);
}

#[test]
fn continue_with_an_address_moves_the_pc() {
    let mut s = Session::new(Mock::halted());
    s.send("c10000200");
    assert_eq!(s.engine.regs[15], 0x1000_0200);
    assert_eq!(s.target.resumes, vec![false]);
}

#[test]
fn step_asks_for_a_single_instruction() {
    let mut s = Session::new(Mock::halted());
    assert!(s.send("s"));
    assert_eq!(s.target.resumes, vec![true]);
}

// -- stop reason -------------------------------------------------------

#[test]
fn stop_reason_distinguishes_a_trap_from_an_interrupt() {
    let mut s = Session::new(Mock::halted());
    s.engine.stop_reason = StopReason::Trap;
    s.wire.out.clear();
    s.engine.send_stop_reason(&mut s.wire);
    assert_eq!(s.reply(), "S05");

    s.engine.stop_reason = StopReason::Interrupt;
    s.wire.out.clear();
    s.engine.send_stop_reason(&mut s.wire);
    assert_eq!(s.reply(), "S02");
}

// -- detach: slots released, target runs free --------------------------

#[test]
fn detach_releases_every_breakpoint_and_resumes() {
    for packet in ["D", "k", "vKill"] {
        let mut s = Session::new(Mock::halted());
        s.send("Z0,10000100,2");
        s.send("Z0,10000200,2");
        assert_eq!(s.target.live_breakpoints(), 2);

        assert!(s.send(packet), "{packet} must resume the target");
        assert_eq!(s.reply(), "OK");
        assert_eq!(
            s.engine.breakpoint_count(),
            0,
            "{packet} left engine slots set"
        );
        assert_eq!(
            s.target.live_breakpoints(),
            0,
            "{packet} left comparators armed"
        );
        assert!(!s.engine.attached, "{packet} left the session attached");
        assert!(!s.target.halted, "{packet} left the target halted");
    }
}

// -- qSupported and friends --------------------------------------------

#[test]
fn qsupported_advertises_the_target_description() {
    // Without qXfer:features:read GDB assumes the legacy 26-register ARM
    // layout and rejects the 17-register `g` reply outright, after which
    // nothing in the session works.
    let mut s = Session::new(Mock::halted());
    s.send("qSupported:multiprocess+;xmlRegisters=arm");
    let reply = s.reply();
    assert!(reply.contains("qXfer:features:read+"), "got {reply:?}");
    assert!(reply.contains("PacketSize="), "got {reply:?}");
}

#[test]
fn qattached_reports_an_existing_process() {
    // 0 would make `quit` offer to kill the "process" instead of
    // detaching, which on a token means leaving it halted.
    let mut s = Session::new(Mock::halted());
    s.send("qAttached");
    assert_eq!(s.reply(), "1");
}

#[test]
fn thread_queries_describe_exactly_one_thread() {
    let mut s = Session::new(Mock::halted());
    s.send("qfThreadInfo");
    assert_eq!(s.reply(), "m1");
    s.send("qsThreadInfo");
    assert_eq!(s.reply(), "l", "the list has to terminate or GDB loops");
    s.send("qC");
    assert_eq!(s.reply(), "QC1");
}

#[test]
fn thread_select_and_alive_always_succeed() {
    let mut s = Session::new(Mock::halted());
    s.send("Hg0");
    assert_eq!(s.reply(), "OK");
    s.send("T1");
    assert_eq!(s.reply(), "OK");
}

#[test]
fn unsupported_packets_get_the_empty_reply() {
    // RSP for "not supported". GDB degrades gracefully; silence makes it
    // retransmit until it times out.
    for packet in ["qRcmd,68656c70", "vCont?", "X10000000,4:aaaa", "!"] {
        let mut s = Session::new(Mock::halted());
        s.send(packet);
        assert!(s.replied(), "{packet} got no reply at all");
        assert_eq!(
            s.reply(),
            "",
            "{packet} should be unsupported, got {:?}",
            s.reply()
        );
    }
}

// -- qXfer: target.xml served in GDB-sized chunks ----------------------

/// Read the description the way GDB does: repeated offset reads until a
/// chunk comes back prefixed `l`.
fn read_target_xml(chunk: usize) -> String {
    let mut s = Session::new(Mock::halted());
    let mut doc = String::new();
    let mut off = 0usize;
    loop {
        s.send(&format!("qXfer:features:read:target.xml:{off:x},{chunk:x}"));
        let reply = s.reply();
        let (tag, data) = reply.split_at(1);
        doc.push_str(data);
        off += data.len();
        if tag == "l" {
            break doc;
        }
        assert_eq!(tag, "m", "chunk tag must be 'm' or 'l'");
        assert!(
            !data.is_empty(),
            "an 'm' chunk with no data would loop forever"
        );
        assert!(off < 8192, "target.xml never terminated");
    }
}

#[test]
fn target_xml_reassembles_from_small_chunks() {
    let doc = read_target_xml(64);
    assert!(
        doc.starts_with("<?xml"),
        "got {:?}",
        &doc[..32.min(doc.len())]
    );
    assert!(doc.ends_with("</target>"), "document truncated");
    assert!(
        doc.contains("org.gnu.gdb.arm.m-profile"),
        "GDB needs this to treat the core as Cortex-M"
    );
    assert!(doc.contains("<architecture>arm</architecture>"));
}

#[test]
fn chunk_size_does_not_change_the_document() {
    assert_eq!(read_target_xml(16), read_target_xml(4096));
}

#[test]
fn target_xml_declares_exactly_the_registers_g_sends() {
    let doc = read_target_xml(4096);
    assert_eq!(
        doc.matches("<reg ").count(),
        REG_N,
        "the description and the `g` reply must agree, or GDB reports \
         'Truncated register 16 in remote g packet'"
    );
    // Order matters: GDB numbers them by position.
    let first = doc.find("name=\"r0\"").expect("r0 missing");
    let last = doc.find("name=\"xpsr\"").expect("xpsr missing");
    assert!(first < last, "xpsr must be the last register");
}

#[test]
fn reading_past_the_end_of_target_xml_terminates() {
    let mut s = Session::new(Mock::halted());
    s.send("qXfer:features:read:target.xml:ffff,100");
    assert_eq!(s.reply(), "l", "a bare 'l' is end-of-transfer");
}

// -- attach bookkeeping ------------------------------------------------

#[test]
fn any_packet_marks_the_session_attached() {
    let mut s = Session::new(Mock::halted());
    assert!(!s.engine.attached, "a fresh engine is not attached");
    s.send("qC");
    assert!(s.engine.attached);
}

#[test]
fn detach_clears_the_attached_flag() {
    // The firmware only pushes an unsolicited stop reply while attached;
    // leaving this set after a detach means writing into a dead session.
    let mut s = Session::new(Mock::halted());
    s.send("qC");
    s.send("D");
    assert!(!s.engine.attached);
}
