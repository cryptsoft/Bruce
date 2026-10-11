// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Minimal CBOR writer for the Secure world's CTAP2 responses.
//!
//! The Secure image has no allocator, so this writes into a caller-owned
//! slice and reports overflow rather than growing. It encodes only the
//! shapes CTAP2 responses actually use -- there is no general-purpose
//! encoder here, and deliberately no *decoder*: request parsing stays
//! Non-secure (see docs/TRUSTZONE.md, "Why the CBOR parser stayed
//! Non-secure").
//!
//! Every method is a no-op once `overflow` is set, so a caller can write
//! a whole structure and check once at the end.

pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    overflow: bool,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            overflow: false,
        }
    }

    /// Bytes written, or None if anything did not fit.
    pub fn finish(self) -> Option<usize> {
        if self.overflow {
            None
        } else {
            Some(self.pos)
        }
    }

    fn put(&mut self, b: u8) {
        if self.pos < self.buf.len() {
            self.buf[self.pos] = b;
            self.pos += 1;
        } else {
            self.overflow = true;
        }
    }

    pub fn raw(&mut self, data: &[u8]) {
        for &b in data {
            self.put(b);
        }
    }

    /// Major type in the top 3 bits, argument in the low 5 (with the
    /// 24/25/26 escapes for larger values).
    fn header(&mut self, major: u8, arg: u64) {
        let m = major << 5;
        if arg < 24 {
            self.put(m | arg as u8);
        } else if arg < 0x100 {
            self.put(m | 24);
            self.put(arg as u8);
        } else if arg < 0x1_0000 {
            self.put(m | 25);
            self.put((arg >> 8) as u8);
            self.put(arg as u8);
        } else {
            self.put(m | 26);
            self.put((arg >> 24) as u8);
            self.put((arg >> 16) as u8);
            self.put((arg >> 8) as u8);
            self.put(arg as u8);
        }
    }

    pub fn uint(&mut self, v: u64) {
        self.header(0, v);
    }

    /// Negative integers encode as -(n+1), so -7 is major type 1 with
    /// argument 6.
    pub fn nint(&mut self, v: i64) {
        debug_assert!(v < 0);
        self.header(1, (-1 - v) as u64);
    }

    pub fn bytes(&mut self, data: &[u8]) {
        self.header(2, data.len() as u64);
        self.raw(data);
    }

    pub fn text(&mut self, s: &str) {
        self.header(3, s.len() as u64);
        self.raw(s.as_bytes());
    }

    pub fn array(&mut self, n: usize) {
        self.header(4, n as u64);
    }

    pub fn map(&mut self, n: usize) {
        self.header(5, n as u64);
    }
}
