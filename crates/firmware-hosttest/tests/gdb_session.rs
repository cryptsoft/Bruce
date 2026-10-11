// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The GDB stub's TX queue.
//!
//! The GDB protocol itself lives in `pqf-gdbstub-core`, which has its
//! own 47 tests. What is left in `crates/firmware/src/gdbstub.rs` is
//! transport, and most of it is MMIO or exception context that cannot
//! run off silicon. The `Session` TX queue can, and it was the one
//! piece with a real defect in it.
//!
//! A GDB packet leaves the core as three separate `Transport::write`
//! calls -- `$`, the body, then `#checksum` (gdbstub-core lib.rs:153-157).
//! The queue used to copy byte by byte and simply stop when full:
//!
//!     for &b in data {
//!         if self.tx_len < self.tx.len() { ...push... }
//!     }
//!
//! so an overflow arriving between those writes left `$<body>` in the
//! buffer with no terminator. The host receives a packet that never
//! ends and waits for it forever -- GDB has no timeout on a partial
//! packet. Later replies then vanish silently behind it.
//!
//! The fix is all-or-nothing writes plus discarding the queue on
//! overflow: a lost reply is something GDB retries out of, a truncated
//! one is not.

use pqf_gdbstub_core::Transport;

/// A stand-in for `Session` with the same queue discipline, so the
/// property can be tested without a USB bus. Kept deliberately close to
/// the real one: same buffer size, same three fields, same rules.
/// `Session` itself needs a `UsbBusAllocator` and a `SerialPort`, and
/// `usbd_serial` is not a dependency here.
struct Queue {
    tx: [u8; pqf_gdbstub_core::PKT_MAX + 8],
    tx_len: usize,
    tx_overflow: bool,
    /// What the host actually received.
    sent: Vec<u8>,
    /// Whether the endpoint is draining. A host that has stopped
    /// reading is exactly the condition that fills the queue.
    draining: bool,
}

impl Queue {
    fn new() -> Self {
        Self {
            tx: [0; pqf_gdbstub_core::PKT_MAX + 8],
            tx_len: 0,
            tx_overflow: false,
            sent: Vec::new(),
            draining: false,
        }
    }

    fn flush(&mut self) {
        if self.tx_overflow {
            self.tx_len = 0;
            self.tx_overflow = false;
            return;
        }
        if !self.draining {
            return;
        }
        self.sent.extend_from_slice(&self.tx[..self.tx_len]);
        self.tx_len = 0;
    }
}

impl Transport for Queue {
    fn read(&mut self, _buf: &mut [u8]) -> usize {
        0
    }
    fn write(&mut self, data: &[u8]) {
        if self.tx_overflow || data.len() > self.tx.len() - self.tx_len {
            self.tx_overflow = true;
            return;
        }
        self.tx[self.tx_len..self.tx_len + data.len()].copy_from_slice(data);
        self.tx_len += data.len();
    }
}

/// Emit one packet the way gdbstub-core does: three writes.
fn packet(q: &mut Queue, body: &[u8]) {
    let sum = body.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    q.write(b"$");
    q.write(body);
    let tail = [b'#', hex(sum >> 4), hex(sum & 0xF)];
    q.write(&tail);
}

fn hex(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + n - 10
    }
}

/// Every `$` in the stream must have a `#` after it. This is the
/// property GDB depends on and the one the old code broke.
fn every_packet_is_terminated(s: &[u8]) -> bool {
    let mut i = 0;
    while let Some(d) = s[i..].iter().position(|&b| b == b'$') {
        let start = i + d;
        match s[start..].iter().position(|&b| b == b'#') {
            // A checksum needs two hex digits after the '#'.
            Some(h) if start + h + 2 < s.len() => i = start + h + 3,
            _ => return false,
        }
    }
    true
}

#[test]
fn a_packet_that_fits_is_delivered_whole() {
    let mut q = Queue::new();
    q.draining = true;
    packet(&mut q, b"OK");
    q.flush();
    assert_eq!(
        q.sent,
        b"$OK#9a".to_vec(),
        "a small reply did not round-trip"
    );
}

#[test]
fn a_stalled_host_never_receives_a_packet_without_a_checksum() {
    // The reported failure, reproduced: the host stops draining, four
    // large qXfer replies are queued, then it starts reading again.
    // Before the fix this delivered one complete packet followed by a
    // second cut off mid-body -- and GDB waits on that forever.
    let mut q = Queue::new();
    q.draining = false;
    let big = vec![b'a'; 400];
    for _ in 0..4 {
        packet(&mut q, &big);
        q.flush(); // the host is not reading; nothing moves
    }
    q.draining = true;
    q.flush();

    assert!(
        every_packet_is_terminated(&q.sent),
        "a packet was delivered without a terminating checksum: {:?}",
        String::from_utf8_lossy(&q.sent)
    );
}

#[test]
fn an_overflow_drops_the_reply_rather_than_half_of_it() {
    let mut q = Queue::new();
    q.draining = false;
    // Fill past capacity in one packet.
    let huge = vec![b'x'; pqf_gdbstub_core::PKT_MAX + 16];
    packet(&mut q, &huge);
    assert!(q.tx_overflow, "an oversized packet did not latch overflow");

    q.draining = true;
    q.flush();
    assert!(
        q.sent.is_empty(),
        "part of an oversized packet was still sent"
    );
    assert!(!q.tx_overflow, "flush did not clear the overflow latch");
}

#[test]
fn the_queue_recovers_after_an_overflow() {
    // A dropped reply must not poison the connection: the next packet
    // has to go out normally, which is what makes GDB's retry work.
    let mut q = Queue::new();
    q.draining = false;
    packet(&mut q, &vec![b'x'; pqf_gdbstub_core::PKT_MAX + 16]);
    q.draining = true;
    q.flush();
    assert!(q.sent.is_empty());

    packet(&mut q, b"OK");
    q.flush();
    assert_eq!(q.sent, b"$OK#9a".to_vec(), "the queue did not recover");
}

#[test]
fn once_overflowed_nothing_further_is_appended_before_the_flush() {
    // Otherwise a later small write would slip in ahead of the dropped
    // packet's bytes and the stream would be reordered, not merely
    // lossy.
    let mut q = Queue::new();
    q.draining = false;
    packet(&mut q, &vec![b'x'; pqf_gdbstub_core::PKT_MAX + 16]);
    let len_after_overflow = q.tx_len;
    packet(&mut q, b"OK");
    assert_eq!(
        q.tx_len, len_after_overflow,
        "a write was accepted after the queue overflowed"
    );
}

#[test]
fn a_packet_exactly_filling_the_buffer_is_still_delivered() {
    // The boundary: the largest reply that genuinely fits must not be
    // rejected by an off-by-one in the capacity check.
    let mut q = Queue::new();
    q.draining = true;
    // 1 for '$', 3 for "#xx" -- so the body may be capacity minus 4.
    let body = vec![b'y'; q.tx.len() - 4];
    packet(&mut q, &body);
    assert!(!q.tx_overflow, "a reply that exactly fits was rejected");
    q.flush();
    assert_eq!(
        q.sent.len(),
        q.tx.len(),
        "the exact-fit reply was not delivered whole"
    );
    assert!(every_packet_is_terminated(&q.sent));
}

#[test]
fn one_byte_over_the_boundary_is_refused_cleanly() {
    let mut q = Queue::new();
    q.draining = true;
    let body = vec![b'y'; q.tx.len() - 3];
    packet(&mut q, &body);
    assert!(q.tx_overflow, "a reply one byte too long was accepted");
    q.flush();
    assert!(
        q.sent.is_empty(),
        "part of an over-long reply was delivered"
    );
}
