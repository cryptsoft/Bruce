// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! GDB remote-serial-protocol engine.
//!
//! Deliberately knows nothing about ARMv8-M, USB, or the RP2350. It
//! parses packets, marshals the register file, enforces the memory
//! whitelist and tracks breakpoint slots; everything that needs actual
//! silicon is behind [`Target`], and everything that needs a wire is
//! behind [`Transport`].
//!
//! That split is not tidiness for its own sake. The protocol is where
//! the bugs are, and this way it can be driven by a real
//! `arm-none-eabi-gdb` on a host with no board attached -- which is how
//! the C port's stub is tested, and how two firmware bugs in the Rust
//! one were caught only after a board became unavailable.

#![cfg_attr(not(feature = "std"), no_std)]

/// Registers GDB expects for m-profile: r0-r12, sp, lr, pc, xpsr.
pub const REG_N: usize = 17;
/// Breakpoint slots. Matches the RP2350's FPB comparator count.
pub const MAX_BREAKPOINTS: usize = 8;
/// Largest packet body we build. Advertised as PacketSize=800.
pub const PKT_MAX: usize = 1024;

/// Everything the engine needs from the machine underneath it.
pub trait Target {
    /// Read one byte, or None if the address is not permitted.
    fn read_u8(&mut self, addr: u32) -> Option<u8>;
    /// Write one byte; false if not permitted.
    fn write_u8(&mut self, addr: u32, val: u8) -> bool;
    /// Arm a hardware breakpoint in `slot`.
    fn set_breakpoint(&mut self, slot: usize, addr: u32);
    /// Release `slot`.
    fn clear_breakpoint(&mut self, slot: usize);
    /// Resume; `step` requests a single instruction.
    fn resume(&mut self, step: bool);
    /// True while the target is actually stopped and its registers are
    /// the ones GDB would be looking at.
    fn is_halted(&self) -> bool;
    /// Stop at the next controlled point. Called when GDB wants state
    /// from a target that is still running -- a Ctrl-C, or the `?` that
    /// opens every session. Without it the engine would answer from the
    /// register file it captured at the *previous* stop, and GDB would
    /// believe the target was sitting at an address it left long ago.
    fn request_halt(&mut self);
}

/// The byte pipe to GDB.
pub trait Transport {
    fn read(&mut self, buf: &mut [u8]) -> usize;
    /// Queue bytes. Implementations must NOT block: on the firmware the
    /// endpoint only drains when the USB device is polled, and that
    /// cannot happen from inside packet handling.
    fn write(&mut self, data: &[u8]);
}

/// Why the target stopped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StopReason {
    /// Breakpoint or step completion.
    Trap,
    /// Host asked (Ctrl-C).
    Interrupt,
}

/// The engine's own state: register file, breakpoints, packet assembly.
pub struct Engine {
    pub regs: [u32; REG_N],
    breakpoints: [Option<u32>; MAX_BREAKPOINTS],
    rx: [u8; PKT_MAX],
    rx_len: usize,
    in_packet: bool,
    /// Bytes of the trailing checksum still to swallow.
    skip: u8,
    /// A `}` has been seen and the next byte is escaped.
    escaped: bool,
    pub attached: bool,
    pub stop_reason: StopReason,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_hex(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 8 {
        return None;
    }
    let mut v: u32 = 0;
    for &b in s {
        v = (v << 4) | nibble(b)? as u32;
    }
    Some(v)
}

/// GDB sends register values little-endian as byte pairs.
fn parse_le_hex32(h: &[u8]) -> Option<u32> {
    if h.len() < 8 {
        return None;
    }
    let mut v = 0u32;
    for i in 0..4 {
        let hi = nibble(h[i * 2])?;
        let lo = nibble(h[i * 2 + 1])?;
        v |= (((hi << 4) | lo) as u32) << (i * 8);
    }
    Some(v)
}

fn put_hex8(out: &mut [u8], at: usize, v: u8) {
    out[at] = HEX[(v >> 4) as usize];
    out[at + 1] = HEX[(v & 0xf) as usize];
}

fn put_hex32(out: &mut [u8], at: usize, v: u32) {
    for i in 0..4 {
        put_hex8(out, at + i * 2, ((v >> (i * 8)) & 0xff) as u8);
    }
}

impl Engine {
    pub const fn new() -> Self {
        Self {
            regs: [0; REG_N],
            breakpoints: [None; MAX_BREAKPOINTS],
            rx: [0; PKT_MAX],
            rx_len: 0,
            in_packet: false,
            skip: 0,
            escaped: false,
            attached: false,
            stop_reason: StopReason::Trap,
        }
    }

    fn send<T: Transport>(&mut self, t: &mut T, body: &[u8]) {
        let mut sum: u8 = 0;
        for &b in body {
            sum = sum.wrapping_add(b);
        }
        t.write(b"$");
        t.write(body);
        let mut tail = [b'#', 0, 0];
        put_hex8(&mut tail, 1, sum);
        t.write(&tail);
    }

    fn ok<T: Transport>(&mut self, t: &mut T) {
        self.send(t, b"OK");
    }

    fn err<T: Transport>(&mut self, t: &mut T) {
        self.send(t, b"E01");
    }

    /// Tell GDB why we are stopped. `S05` is a trap, `S02` an interrupt.
    pub fn send_stop_reason<T: Transport>(&mut self, t: &mut T) {
        match self.stop_reason {
            StopReason::Trap => self.send(t, b"S05"),
            StopReason::Interrupt => self.send(t, b"S02"),
        }
    }

    /// Feed received bytes in. Returns true when the target should
    /// resume, having already handled every complete packet.
    pub fn feed<T: Transport, G: Target>(
        &mut self,
        t: &mut T,
        target: &mut G,
        data: &[u8],
    ) -> bool {
        let mut resume = false;
        for &b in data {
            if self.skip > 0 {
                self.skip -= 1;
                continue;
            }
            if !self.in_packet {
                match b {
                    b'$' => {
                        self.in_packet = true;
                        self.rx_len = 0;
                        self.escaped = false;
                    }
                    // Ctrl-C.
                    0x03 => {
                        self.stop_reason = StopReason::Interrupt;
                        self.attached = true;
                        if !target.is_halted() {
                            target.request_halt();
                        }
                    }
                    // '+'/'-' acks and stray bytes are not interesting.
                    _ => {}
                }
                continue;
            }
            // RSP escaping: `}` means "the next byte is XORed with 0x20".
            // This has to be resolved before the `#` test, or an escaped
            // `#` (sent as `}\x03`) would end the packet early. The C
            // port does the same; without it the two stubs disagree on
            // any payload containing `#`, `$`, `}` or `*`.
            if self.escaped {
                self.escaped = false;
                if self.rx_len < PKT_MAX {
                    self.rx[self.rx_len] = b ^ 0x20;
                    self.rx_len += 1;
                }
                continue;
            }
            if b == b'}' {
                self.escaped = true;
                continue;
            }
            if b == b'#' {
                self.in_packet = false;
                // Swallow the two checksum digits. USB and a pty are
                // both reliable; re-deriving the sum to reject a packet
                // we could not have received corrupt buys nothing.
                self.skip = 2;
                t.write(b"+");
                let len = self.rx_len;
                let mut body = [0u8; PKT_MAX];
                body[..len].copy_from_slice(&self.rx[..len]);
                if self.dispatch(t, target, &body[..len]) {
                    resume = true;
                }
                continue;
            }
            if self.rx_len < PKT_MAX {
                self.rx[self.rx_len] = b;
                self.rx_len += 1;
            }
        }
        resume
    }

    fn dispatch<T: Transport, G: Target>(
        &mut self,
        t: &mut T,
        target: &mut G,
        body: &[u8],
    ) -> bool {
        self.attached = true;
        let mut out = [0u8; PKT_MAX];
        match body.first().copied() {
            Some(b'?') => {
                if target.is_halted() {
                    self.send_stop_reason(t);
                } else {
                    // Running. Manufacture a real stop instead of
                    // replaying the last one: the target announces it
                    // once it gets there, with registers that are true.
                    self.stop_reason = StopReason::Interrupt;
                    target.request_halt();
                }
                false
            }
            Some(b'g') => {
                if !target.is_halted() {
                    self.err(t);
                    return false;
                }
                for i in 0..REG_N {
                    put_hex32(&mut out, i * 8, self.regs[i]);
                }
                self.send(t, &out[..REG_N * 8]);
                false
            }
            Some(b'G') => {
                if !target.is_halted() {
                    self.err(t);
                    return false;
                }
                let hex = &body[1..];
                if hex.len() < REG_N * 8 {
                    self.err(t);
                    return false;
                }
                for i in 0..REG_N {
                    if let Some(v) = parse_le_hex32(&hex[i * 8..]) {
                        self.regs[i] = v;
                    }
                }
                self.ok(t);
                false
            }
            Some(b'p') if !target.is_halted() => {
                self.err(t);
                false
            }
            Some(b'p') => match parse_hex(&body[1..]) {
                Some(n) if (n as usize) < REG_N => {
                    put_hex32(&mut out, 0, self.regs[n as usize]);
                    self.send(t, &out[..8]);
                    false
                }
                _ => {
                    self.err(t);
                    false
                }
            },
            Some(b'P') if !target.is_halted() => {
                self.err(t);
                false
            }
            Some(b'P') => {
                let mut it = body[1..].splitn(2, |&c| c == b'=');
                let n = it.next().and_then(parse_hex);
                let v = it.next().and_then(parse_le_hex32);
                match (n, v) {
                    (Some(n), Some(v)) if (n as usize) < REG_N => {
                        self.regs[n as usize] = v;
                        self.ok(t);
                    }
                    _ => self.err(t),
                }
                false
            }
            Some(b'm') => {
                let mut it = body[1..].splitn(2, |&c| c == b',');
                let addr = it.next().and_then(parse_hex);
                let len = it.next().and_then(parse_hex);
                match (addr, len) {
                    (Some(a), Some(l)) if (l as usize) * 2 <= PKT_MAX => {
                        for i in 0..l as usize {
                            match target.read_u8(a.wrapping_add(i as u32)) {
                                Some(b) => put_hex8(&mut out, i * 2, b),
                                None => {
                                    self.err(t);
                                    return false;
                                }
                            }
                        }
                        self.send(t, &out[..l as usize * 2]);
                    }
                    _ => self.err(t),
                }
                false
            }
            Some(b'M') => {
                let mut it = body[1..].splitn(2, |&c| c == b':');
                let head = it.next().unwrap_or(b"");
                let data = it.next().unwrap_or(b"");
                let mut hit = head.splitn(2, |&c| c == b',');
                let addr = hit.next().and_then(parse_hex);
                let len = hit.next().and_then(parse_hex);
                match (addr, len) {
                    (Some(a), Some(l)) if data.len() >= l as usize * 2 => {
                        for i in 0..l as usize {
                            match (nibble(data[i * 2]), nibble(data[i * 2 + 1])) {
                                (Some(h), Some(lo)) => {
                                    if !target.write_u8(a.wrapping_add(i as u32), (h << 4) | lo) {
                                        self.err(t);
                                        return false;
                                    }
                                }
                                _ => {
                                    self.err(t);
                                    return false;
                                }
                            }
                        }
                        self.ok(t);
                    }
                    _ => self.err(t),
                }
                false
            }
            Some(b'c') => {
                if let Some(a) = parse_hex(&body[1..]) {
                    self.regs[15] = a;
                }
                target.resume(false);
                true
            }
            Some(b's') => {
                target.resume(true);
                true
            }
            Some(b'Z') | Some(b'z') => {
                let set = body[0] == b'Z';
                let mut it = body[2..].splitn(3, |&c| c == b',');
                let _ = it.next();
                match it.next().and_then(parse_hex) {
                    Some(a) => {
                        let done = if set {
                            self.alloc_breakpoint(target, a)
                        } else {
                            self.free_breakpoint(target, a)
                        };
                        if done {
                            self.ok(t);
                        } else {
                            self.err(t);
                        }
                    }
                    None => self.err(t),
                }
                false
            }
            Some(b'D') | Some(b'k') => {
                self.ok(t);
                self.detach(target);
                true
            }
            Some(b'H') | Some(b'T') => {
                self.ok(t);
                false
            }
            Some(b'q') => {
                if body.starts_with(b"qSupported") {
                    // qXfer:features:read is not optional in practice.
                    // Without a target description GDB falls back to
                    // the legacy 26-register ARM layout and rejects our
                    // 17-register `g` reply outright: "Truncated
                    // register 16 in remote 'g' packet", after which
                    // nothing else in the session works.
                    self.send(t, b"PacketSize=800;qXfer:features:read+");
                } else if body.starts_with(b"qXfer:features:read:") {
                    self.send_target_xml(t, body);
                } else if body.starts_with(b"qAttached") {
                    // 1 so `quit` detaches rather than offering to kill.
                    self.send(t, b"1");
                } else if body.starts_with(b"qC") {
                    self.send(t, b"QC1");
                } else if body.starts_with(b"qfThreadInfo") {
                    self.send(t, b"m1");
                } else if body.starts_with(b"qsThreadInfo") {
                    self.send(t, b"l");
                } else {
                    self.send(t, b"");
                }
                false
            }
            Some(b'v') => {
                if body.starts_with(b"vKill") {
                    // Treated as a detach, exactly like `D` and `k`.
                    // Resuming without releasing the comparators would
                    // leave the token trapping into a monitor no
                    // debugger is listening to -- which halts it for
                    // good, and looks from outside like a dead token.
                    self.ok(t);
                    self.detach(target);
                    return true;
                }
                self.send(t, b"");
                false
            }
            // The empty reply is RSP for "not supported".
            _ => {
                self.send(t, b"");
                false
            }
        }
    }

    /// Serve `target.xml` in the chunks GDB asks for.
    ///
    /// The reply is `m<data>` while more follows and `l<data>` for the
    /// last piece; GDB reads until it sees `l`.
    fn send_target_xml<T: Transport>(&mut self, t: &mut T, body: &[u8]) {
        // qXfer:features:read:<annex>:<offset>,<length>
        let tail = &body[b"qXfer:features:read:".len()..];
        let mut parts = tail.splitn(2, |&c| c == b':');
        let _annex = parts.next().unwrap_or(b"");
        let range = parts.next().unwrap_or(b"");
        let mut rp = range.splitn(2, |&c| c == b',');
        let off = rp.next().and_then(parse_hex).unwrap_or(0) as usize;
        let len = rp.next().and_then(parse_hex).unwrap_or(0) as usize;

        let xml = TARGET_XML.as_bytes();
        if off >= xml.len() {
            self.send(t, b"l");
            return;
        }
        let end = core::cmp::min(xml.len(), off + len.min(PKT_MAX - 1));
        let mut out = [0u8; PKT_MAX];
        out[0] = if end < xml.len() { b'm' } else { b'l' };
        out[1..1 + (end - off)].copy_from_slice(&xml[off..end]);
        self.send(t, &out[..1 + (end - off)]);
    }

    /// End the session: release every comparator and let the target run.
    ///
    /// Shared by `D`, `k` and `vKill`, because a debugger that has gone
    /// away must not leave breakpoints armed whichever way it left.
    fn detach<G: Target>(&mut self, target: &mut G) {
        for i in 0..MAX_BREAKPOINTS {
            if self.breakpoints[i].is_some() {
                self.breakpoints[i] = None;
                target.clear_breakpoint(i);
            }
        }
        self.attached = false;
        target.resume(false);
    }

    fn alloc_breakpoint<G: Target>(&mut self, target: &mut G, addr: u32) -> bool {
        // Already set: GDB re-sends on every continue, and answering
        // E01 there makes it give up on the breakpoint entirely.
        if self.breakpoints.iter().any(|b| *b == Some(addr)) {
            return true;
        }
        for i in 0..MAX_BREAKPOINTS {
            if self.breakpoints[i].is_none() {
                self.breakpoints[i] = Some(addr);
                target.set_breakpoint(i, addr);
                return true;
            }
        }
        false
    }

    fn free_breakpoint<G: Target>(&mut self, target: &mut G, addr: u32) -> bool {
        for i in 0..MAX_BREAKPOINTS {
            if self.breakpoints[i] == Some(addr) {
                self.breakpoints[i] = None;
                target.clear_breakpoint(i);
                return true;
            }
        }
        false
    }

    /// How many breakpoint slots are in use. For tests and diagnostics.
    pub fn breakpoint_count(&self) -> usize {
        self.breakpoints.iter().filter(|b| b.is_some()).count()
    }
}

/// Target description for GDB.
///
/// Seventeen registers in the order the `g` packet sends them, so GDB
/// numbers them 0..16 and expects exactly the reply this engine builds.
/// `org.gnu.gdb.arm.m-profile` is what makes GDB treat the core as
/// Cortex-M rather than classic ARM.
const TARGET_XML: &str = concat!(
    "<?xml version=\"1.0\"?>",
    "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">",
    "<target>",
    "<architecture>arm</architecture>",
    "<feature name=\"org.gnu.gdb.arm.m-profile\">",
    "<reg name=\"r0\" bitsize=\"32\"/>",
    "<reg name=\"r1\" bitsize=\"32\"/>",
    "<reg name=\"r2\" bitsize=\"32\"/>",
    "<reg name=\"r3\" bitsize=\"32\"/>",
    "<reg name=\"r4\" bitsize=\"32\"/>",
    "<reg name=\"r5\" bitsize=\"32\"/>",
    "<reg name=\"r6\" bitsize=\"32\"/>",
    "<reg name=\"r7\" bitsize=\"32\"/>",
    "<reg name=\"r8\" bitsize=\"32\"/>",
    "<reg name=\"r9\" bitsize=\"32\"/>",
    "<reg name=\"r10\" bitsize=\"32\"/>",
    "<reg name=\"r11\" bitsize=\"32\"/>",
    "<reg name=\"r12\" bitsize=\"32\"/>",
    "<reg name=\"sp\" bitsize=\"32\" type=\"data_ptr\"/>",
    "<reg name=\"lr\" bitsize=\"32\"/>",
    "<reg name=\"pc\" bitsize=\"32\" type=\"code_ptr\"/>",
    "<reg name=\"xpsr\" bitsize=\"32\" regnum=\"25\"/>",
    "</feature>",
    "</target>",
);
