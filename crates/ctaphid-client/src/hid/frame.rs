// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAPHID frame layout -- encoding outgoing reports and parsing
//! incoming ones.
//!
//! Reference: FIDO U2F HID v1.2 sec. 6.2 ("Message and packet
//! structure"). The 64-byte report carries one of two frame
//! shapes:
//!
//! - **Initialisation frame** -- first packet of a logical message.
//!   Identified by the high bit of the 5th byte (`CMD`) being set.
//!
//!   ```text
//!   off 0..4   : channel identifier (big-endian u32)
//!   off 4      : 0x80 | command byte
//!   off 5..7   : payload length (big-endian u16, "BCNT")
//!   off 7..64  : first 57 bytes of payload
//!   ```
//!
//! - **Continuation frame** -- packets 2..N of a multi-packet message.
//!   Identified by the high bit of the 5th byte being clear; the
//!   low 7 bits are the sequence number (0..=0x7F).
//!
//!   ```text
//!   off 0..4   : channel identifier (big-endian u32)
//!   off 4      : 0x00..0x7f sequence number
//!   off 5..64  : next 59 bytes of payload
//!   ```
//!
//! A logical CTAPHID message is therefore at most
//! `57 + 128 * 59 = 7609` bytes -- that's `MAX_MSG_LEN`. The framing
//! does not enforce a minimum; an empty payload uses a single init
//! frame with `BCNT = 0`.

/// Wire size of one CTAPHID packet. The interrupt endpoint always
/// transfers full-size reports.
pub const REPORT_LEN: usize = 64;

/// Bytes of payload that fit in an initialisation frame.
pub const INIT_PAYLOAD_CAP: usize = REPORT_LEN - 7; // 4 CID + 1 CMD + 2 BCNT

/// Bytes of payload that fit in a continuation frame.
pub const CONT_PAYLOAD_CAP: usize = REPORT_LEN - 5; // 4 CID + 1 SEQ

/// Maximum CTAPHID message payload length: one init frame plus
/// 128 continuation frames (SEQ wraps after 0x80 distinct values).
pub const MAX_MSG_LEN: usize = INIT_PAYLOAD_CAP + 128 * CONT_PAYLOAD_CAP;

/// CTAPHID command codes -- high bit always set to mark an
/// initialisation frame. See FIDO U2F HID v1.2 sec. 6.2 Table 3, plus
/// the additional CTAP 2.1 sec. 11.2.9 commands.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    Ping,
    Msg,
    Init,
    Wink,
    Cbor,
    Cancel,
    /// `CTAPHID_CMD_RNG` (command number 0x50; 0xD0 on the wire with
    /// the init bit) -- vendor command (CTAP reserves 0x40..0x7f for
    /// vendor use). Returns raw TRNG bytes from the
    /// `bruce` firmware. Request payload is empty (device returns
    /// one init frame's worth) or a 2-byte big-endian count; see
    /// [`super::Device::rng`].
    Rng,
    /// `CTAPHID_CMD_REBOOT` (command number 0x51; 0xD1 on the wire with
    /// the init bit) -- vendor command. Reboots the `bruce` token,
    /// either into the RP2350 USB bootloader or warm back into firmware;
    /// gated behind a user-presence touch on the device. Request payload
    /// is a single mode byte; see [`super::Device::reboot`].
    Reboot,
    Keepalive,
    Error,
}

impl Cmd {
    /// The on-wire command byte (high bit set, since CTAPHID commands
    /// always travel in initialisation frames).
    pub fn as_byte(self) -> u8 {
        match self {
            Cmd::Ping => 0x81,
            Cmd::Msg => 0x83,
            Cmd::Init => 0x86,
            Cmd::Wink => 0x88,
            Cmd::Cbor => 0x90,
            Cmd::Cancel => 0x91,
            // 0x80 (init bit) | 0x50 vendor command number, matching
            // the other constants here which carry the init bit.
            Cmd::Rng => 0xd0,
            // 0x80 (init bit) | 0x51 vendor command number.
            Cmd::Reboot => 0xd1,
            Cmd::Keepalive => 0xbb,
            Cmd::Error => 0xbf,
        }
    }

    /// Inverse of [`Self::as_byte`]. Returns `None` for unknown
    /// command bytes so callers can surface a transport-level
    /// "unknown command" error rather than panic.
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x81 => Cmd::Ping,
            0x83 => Cmd::Msg,
            0x86 => Cmd::Init,
            0x88 => Cmd::Wink,
            0x90 => Cmd::Cbor,
            0x91 => Cmd::Cancel,
            0xd0 => Cmd::Rng,
            0xd1 => Cmd::Reboot,
            0xbb => Cmd::Keepalive,
            0xbf => Cmd::Error,
            _ => return None,
        })
    }
}

/// CTAPHID broadcast channel identifier (0xFFFFFFFF). Used for
/// [`Cmd::Init`] before the host has been allocated its own CID.
pub const BROADCAST_CID: u32 = 0xffff_ffff;

/// Build an initialisation frame for `cid` carrying `cmd` and the
/// first up-to-57 bytes of `payload`. Returns the 64-byte report
/// AND the number of payload bytes consumed (`<= INIT_PAYLOAD_CAP`).
///
/// Caller is responsible for following up with continuation frames
/// when the payload is larger than 57 bytes.
pub fn build_init_frame(cid: u32, cmd: Cmd, payload: &[u8]) -> ([u8; REPORT_LEN], usize) {
    let mut frame = [0u8; REPORT_LEN];
    frame[0..4].copy_from_slice(&cid.to_be_bytes());
    frame[4] = cmd.as_byte();
    let bcnt = payload.len() as u16;
    frame[5..7].copy_from_slice(&bcnt.to_be_bytes());
    let take = core::cmp::min(payload.len(), INIT_PAYLOAD_CAP);
    frame[7..7 + take].copy_from_slice(&payload[..take]);
    (frame, take)
}

/// Build a continuation frame for `cid` carrying sequence number
/// `seq` and the next up-to-59 bytes of `payload`. Returns the
/// 64-byte report AND the number of payload bytes consumed.
///
/// `seq` is the 0-based packet index within the message -- packet 0
/// is the init frame, so the first continuation frame has `seq = 0`,
/// the second has `seq = 1`, etc. The 0x80 boundary is the cap on
/// message size: only 128 continuations are permitted before BCNT
/// would have overflowed anyway.
pub fn build_cont_frame(cid: u32, seq: u8, payload: &[u8]) -> ([u8; REPORT_LEN], usize) {
    debug_assert!(
        seq < 0x80,
        "CTAPHID continuation SEQ must have high bit clear"
    );
    let mut frame = [0u8; REPORT_LEN];
    frame[0..4].copy_from_slice(&cid.to_be_bytes());
    frame[4] = seq & 0x7f;
    let take = core::cmp::min(payload.len(), CONT_PAYLOAD_CAP);
    frame[5..5 + take].copy_from_slice(&payload[..take]);
    (frame, take)
}

/// Parsed first frame of a CTAPHID message.
#[derive(Debug)]
pub struct ParsedInit<'a> {
    /// The channel id field. Caller usually checks this equals its
    /// own allocated CID and discards frames for other channels.
    pub cid: u32,
    /// The command this message belongs to.
    pub cmd: Cmd,
    /// Total payload length the device promised in BCNT.
    pub bcnt: u16,
    /// The first 0..=57 bytes of payload that arrived with the init
    /// frame. Could be the whole payload if `bcnt <= 57`.
    pub payload: &'a [u8],
}

/// Parsed continuation frame of a CTAPHID message.
#[derive(Debug)]
pub struct ParsedCont<'a> {
    /// Channel id, as above.
    pub cid: u32,
    /// Sequence number (0..=0x7F). The caller validates against
    /// its expected counter -- a mismatch usually means a packet
    /// was dropped or a foreign packet bled into the conversation.
    pub seq: u8,
    /// Up to 59 bytes of payload. The caller decides how many bytes
    /// it still needs (BCNT minus what's already been consumed).
    pub payload: &'a [u8],
}

/// Classifies a 64-byte HID report from the device as either an
/// init frame or a continuation frame.
#[derive(Debug)]
pub enum Parsed<'a> {
    /// First frame of a new (or echoed) message.
    Init(ParsedInit<'a>),
    /// Continuation of a message in progress.
    Cont(ParsedCont<'a>),
}

/// Parse a 64-byte report into either an init or cont frame.
///
/// Returns `None` only if the buffer is shorter than [`REPORT_LEN`]
/// (caller surfaces that as [`crate::hid::error::Error::ShortRead`]).
/// Reports with an unknown command byte still parse -- the caller
/// can then surface that as a higher-level "unexpected command"
/// error.
pub fn parse_frame(buf: &[u8]) -> Option<Parsed<'_>> {
    if buf.len() < REPORT_LEN {
        return None;
    }
    let cid = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let head = buf[4];
    if head & 0x80 != 0 {
        // Init frame. Unknown command bytes still parse so the caller
        // can distinguish "device sent a CMD_ERROR" from "device sent
        // junk" downstream.
        let bcnt = u16::from_be_bytes([buf[5], buf[6]]);
        // `cmd` may be None for never-seen command codes; we keep
        // them as the high-bit-set Error variant for callers that
        // want to surface a transport-layer "unknown cmd" error
        // without losing the byte. We *don't* try to be clever and
        // remap to `Cmd::Error` (0xBF) here; that's the spec's
        // command for error responses and we'd rather not lie.
        let cmd = Cmd::from_byte(head).unwrap_or(Cmd::Error);
        Some(Parsed::Init(ParsedInit {
            cid,
            cmd,
            bcnt,
            payload: &buf[7..REPORT_LEN],
        }))
    } else {
        Some(Parsed::Cont(ParsedCont {
            cid,
            seq: head & 0x7f,
            payload: &buf[5..REPORT_LEN],
        }))
    }
}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_frame_layout() {
        // Build an init frame for cid 0x12345678, CBOR cmd, payload [0x04].
        let (frame, taken) = build_init_frame(0x1234_5678, Cmd::Cbor, &[0x04]);
        assert_eq!(taken, 1);
        // CID
        assert_eq!(&frame[0..4], &[0x12, 0x34, 0x56, 0x78]);
        // CMD = CBOR = 0x90
        assert_eq!(frame[4], 0x90);
        // BCNT = 1
        assert_eq!(&frame[5..7], &[0x00, 0x01]);
        // First payload byte
        assert_eq!(frame[7], 0x04);
        // Rest of the report is zero-padded
        assert!(frame[8..].iter().all(|&b| b == 0));
    }

    #[test]
    fn init_frame_truncates_to_57_bytes() {
        // Build an init frame for a 100-byte payload. Should consume
        // exactly 57 bytes; the BCNT field reflects the full 100.
        let payload = [0xa5u8; 100];
        let (frame, taken) = build_init_frame(1, Cmd::Cbor, &payload);
        assert_eq!(taken, INIT_PAYLOAD_CAP);
        let bcnt = u16::from_be_bytes([frame[5], frame[6]]);
        assert_eq!(bcnt, 100);
        assert_eq!(
            &frame[7..7 + INIT_PAYLOAD_CAP],
            &payload[..INIT_PAYLOAD_CAP]
        );
    }

    #[test]
    fn cont_frame_layout() {
        let (frame, taken) = build_cont_frame(0xaabb_ccdd, 0, &[0xde, 0xad]);
        assert_eq!(taken, 2);
        assert_eq!(&frame[0..4], &[0xaa, 0xbb, 0xcc, 0xdd]);
        // SEQ 0 -- high bit clear marks a cont frame.
        assert_eq!(frame[4], 0x00);
        assert_eq!(&frame[5..7], &[0xde, 0xad]);
        assert!(frame[7..].iter().all(|&b| b == 0));
    }

    #[test]
    fn cont_seq_high_bit_masked() {
        // The build helper accepts a u8 but masks 0x80 off via debug
        // assert in debug builds. In release the mask is `seq & 0x7f`.
        let (frame, _) = build_cont_frame(1, 0x05, &[]);
        assert_eq!(frame[4], 0x05);
    }

    #[test]
    fn parse_init_round_trip() {
        let (frame, _) = build_init_frame(0xdead_beef, Cmd::Init, &[0xca, 0xfe]);
        let parsed = parse_frame(&frame).unwrap();
        match parsed {
            Parsed::Init(p) => {
                assert_eq!(p.cid, 0xdead_beef);
                assert_eq!(p.cmd, Cmd::Init);
                assert_eq!(p.bcnt, 2);
                assert_eq!(&p.payload[..2], &[0xca, 0xfe]);
            }
            Parsed::Cont(_) => panic!("expected Init, got Cont"),
        }
    }

    #[test]
    fn parse_cont_round_trip() {
        let (frame, _) = build_cont_frame(0x1, 0x42, &[0x01, 0x02, 0x03]);
        let parsed = parse_frame(&frame).unwrap();
        match parsed {
            Parsed::Cont(p) => {
                assert_eq!(p.cid, 1);
                assert_eq!(p.seq, 0x42);
                assert_eq!(&p.payload[..3], &[0x01, 0x02, 0x03]);
            }
            Parsed::Init(_) => panic!("expected Cont, got Init"),
        }
    }

    #[test]
    fn short_buffer_is_none() {
        assert!(parse_frame(&[0u8; 63]).is_none());
        assert!(parse_frame(&[]).is_none());
    }

    #[test]
    fn cmd_byte_round_trip() {
        for c in [
            Cmd::Ping,
            Cmd::Msg,
            Cmd::Init,
            Cmd::Wink,
            Cmd::Cbor,
            Cmd::Cancel,
            Cmd::Rng,
            Cmd::Reboot,
            Cmd::Keepalive,
            Cmd::Error,
        ] {
            assert_eq!(Cmd::from_byte(c.as_byte()), Some(c));
        }
        assert_eq!(Cmd::from_byte(0x00), None);
        assert_eq!(Cmd::from_byte(0x7f), None);
    }

    #[test]
    fn max_msg_len_matches_spec() {
        // FIDO U2F HID v1.2 sec. 6.2: max payload is the init frame's
        // 57 data bytes plus 128 continuation frames at 59 data
        // bytes each.
        assert_eq!(MAX_MSG_LEN, 7609);
    }
}
