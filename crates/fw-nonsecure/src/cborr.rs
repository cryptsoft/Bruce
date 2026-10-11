// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Minimal CBOR reader for CTAP2 requests.
//!
//! This is the Non-secure world's job on purpose. Parsing
//! attacker-controlled CBOR is the historical CVE surface in this class
//! of device, so it runs where a bug cannot reach a key: everything it
//! extracts is copied into a fixed-layout struct and handed to Secure by
//! value (see docs/TRUSTZONE.md).
//!
//! Only what CTAP2 requests need. Indefinite-length items are rejected
//! rather than supported -- CTAP2 canonical CBOR forbids them, and
//! accepting them would mean a second length model to get wrong.

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// Major types, per RFC 8949.
pub const MAJOR_UINT: u8 = 0;
pub const MAJOR_NINT: u8 = 1;
pub const MAJOR_BYTES: u8 = 2;
pub const MAJOR_TEXT: u8 = 3;
pub const MAJOR_ARRAY: u8 = 4;
pub const MAJOR_MAP: u8 = 5;
pub const MAJOR_SIMPLE: u8 = 7;

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Current offset, so a caller can capture a sub-encoding verbatim.
    pub fn position(&self) -> usize {
        self.pos
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// Read one item header: (major type, argument).
    pub fn header(&mut self) -> Option<(u8, u64)> {
        let b = self.byte()?;
        let major = b >> 5;
        let arg = match b & 0x1f {
            n @ 0..=23 => n as u64,
            24 => self.byte()? as u64,
            25 => {
                let hi = self.byte()? as u64;
                (hi << 8) | self.byte()? as u64
            }
            26 => {
                let mut v = 0u64;
                for _ in 0..4 {
                    v = (v << 8) | self.byte()? as u64;
                }
                v
            }
            27 => {
                let mut v = 0u64;
                for _ in 0..8 {
                    v = (v << 8) | self.byte()? as u64;
                }
                v
            }
            // 28..30 reserved; 31 is indefinite length.
            _ => return None,
        };
        Some((major, arg))
    }

    /// Read a map header, returning the entry count.
    pub fn map(&mut self) -> Option<u64> {
        match self.header()? {
            (MAJOR_MAP, n) => Some(n),
            _ => None,
        }
    }

    /// Read an array header, returning the element count.
    pub fn array(&mut self) -> Option<u64> {
        match self.header()? {
            (MAJOR_ARRAY, n) => Some(n),
            _ => None,
        }
    }

    /// Read an unsigned integer.
    pub fn uint(&mut self) -> Option<u64> {
        match self.header()? {
            (MAJOR_UINT, n) => Some(n),
            _ => None,
        }
    }

    /// Borrow a byte or text string's contents.
    pub fn str_bytes(&mut self, want: u8) -> Option<&'a [u8]> {
        let (major, len) = self.header()?;
        if major != want {
            return None;
        }
        // `as usize` would TRUNCATE on the 32-bit target: a declared
        // length of 0x1_0000_0004 becomes 4, and a payload that should
        // be refused is accepted as a short one. The host, where usize
        // is 64 bits, rejects the same encoding -- so no host test can
        // see it. Convert instead of casting.
        let len = usize::try_from(len).ok()?;
        let end = self.pos.checked_add(len)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    /// Consume `len` raw bytes -- the payload of a header already read.
    pub fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    /// Skip one complete item, however nested.
    ///
    /// Bounded by `depth` so a deeply nested request cannot recurse the
    /// NS stack into the guard page -- CTAP2 requests are two or three
    /// levels deep, so 8 is generous.
    pub fn skip(&mut self) -> Option<()> {
        self.skip_depth(8)
    }

    fn skip_depth(&mut self, depth: u32) -> Option<()> {
        if depth == 0 {
            return None;
        }
        let (major, arg) = self.header()?;
        match major {
            MAJOR_UINT | MAJOR_NINT | MAJOR_SIMPLE => Some(()),
            MAJOR_BYTES | MAJOR_TEXT => {
                // Same truncation trap as `str_bytes`; same fix.
                let end = self.pos.checked_add(usize::try_from(arg).ok()?)?;
                if end > self.buf.len() {
                    return None;
                }
                self.pos = end;
                Some(())
            }
            MAJOR_ARRAY => {
                for _ in 0..arg {
                    self.skip_depth(depth - 1)?;
                }
                Some(())
            }
            MAJOR_MAP => {
                for _ in 0..arg {
                    self.skip_depth(depth - 1)?;
                    self.skip_depth(depth - 1)?;
                }
                Some(())
            }
            _ => None,
        }
    }
}
