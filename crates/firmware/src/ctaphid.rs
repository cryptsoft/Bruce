// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAP HID framing + command dispatch, transport-agnostic.
//!
//! Wraps a 64-byte frame in/out interface (our `FidoHidClass`) and
//! implements the subset of CTAP HID commands needed to pass
//! `fido2-token -L` / `fido2-token -I`:
//!
//!   - INIT  (0x86) -- allocate channel, return capabilities
//!   - PING  (0x81) -- echo
//!   - WINK  (0x88) -- blink LED, empty response
//!   - CBOR  (0x90) -- stub for Day 1; Day 2 wires it to OpenSK's CTAP2
//!   - CANCEL (0x91)
//!
//! Multi-frame messages (cont frames) are supported up to 7609 bytes
//! payload (1 init + 128 cont = CTAP HID max).

extern crate alloc;

const FRAME_LEN: usize = 64;
const INIT_DATA: usize = FRAME_LEN - 7; // 4 CID + 1 CMD + 2 BCNT
const CONT_DATA: usize = FRAME_LEN - 5; // 4 CID + 1 SEQ

const BROADCAST_CID: u32 = 0xffff_ffff;

pub const CMD_PING: u8 = 0x81;
pub const CMD_MSG: u8 = 0x83;
pub const CMD_INIT: u8 = 0x86;
/// CTAPHID_WINK. Stored WITH the 0x80 init-packet bit (the value that
/// actually appears in `frame[4]`), like every other command constant,
/// so the dispatch match compares against the raw head byte. The spec
/// command number is 0x08; on the wire an init frame carries 0x88. The
/// old 0x08 never matched `head`, so advertised WINK was dead.
pub const CMD_WINK: u8 = 0x88;
pub const CMD_CBOR: u8 = 0x90;
pub const CMD_CANCEL: u8 = 0x91;
/// Vendor command (CTAP HID reserves 0x40..0x7f for vendor use; spec
/// number 0x50, so 0xD0 with the init-packet bit): return raw TRNG
/// output. Request payload is empty (57 bytes back -- one init frame's
/// worth) or a 2-byte big-endian count of 1..=RNG_MAX. Response payload
/// is exactly that many random bytes. No authentication and no
/// user-presence gesture -- the entropy is not a secret; the host mixes
/// it into its own pool (PKCS#11 C_GenerateRandom, `openssl rand`).
/// Wire-compatible with the C port's CTAPHID_CMD_RNG.
pub const CMD_RNG: u8 = 0xD0;
pub const RNG_MAX: usize = 1024;
pub const RNG_DEFAULT: usize = 57;
/// Vendor command (spec number 0x52, 0xD2 with the init-packet bit):
/// which entropy source CMD_RNG and every key draw are served from,
/// with the picker's counters -- the answer a host cannot get from the
/// bytes (QRNG and TRNG output are indistinguishable) and should not
/// have to infer from a stopwatch. Empty request payload; the response
/// is `entropy::STATUS_LEN` bytes laid out by `Entropy::status_bytes`
/// (source byte, then seven big-endian u32 counters). Wire-compatible
/// with the C port's `CTAPHID_CMD_RNG_STATUS`.
pub const CMD_RNG_STATUS: u8 = 0xD2;

/// Vendor command: reboot the token. Payload is exactly one mode byte --
/// [`REBOOT_WARM`] (0x00) restarts the firmware, [`REBOOT_BOOTSEL`]
/// (0x01) enters the RP2350 USB bootloader (mass storage / DFU). Both
/// are gated behind a test of user presence by the caller (auto-confirms
/// on buttonless builds); on success the device re-enumerates, so no
/// response frame is sent. 0xD1 = spec number 0x51 with the init-packet
/// bit. Wire-compatible with the C port's `CTAPHID_CMD_REBOOT`.
pub const CMD_REBOOT: u8 = 0xD1;
pub const REBOOT_WARM: u8 = 0x00;
pub const REBOOT_BOOTSEL: u8 = 0x01;
/// User-presence timeout for CMD_REBOOT, in microseconds (mirrors the C
/// port's CTAPHID_REBOOT_UP_TIMEOUT_US and ctap2's UP_TIMEOUT_US).
pub const REBOOT_UP_TIMEOUT_US: u64 = 10_000_000;
pub const CMD_KEEPALIVE: u8 = 0xBB;
pub const CMD_ERROR: u8 = 0xBF;

/// KEEPALIVE status codes per CTAP HID spec sec. 11.2.9.1.7.
pub const KEEPALIVE_PROCESSING: u8 = 0x01;
pub const KEEPALIVE_UPNEEDED: u8 = 0x02;

/// Build a single 64-byte CTAP HID KEEPALIVE frame. The host resets
/// its command timeout whenever it sees one of these, so we can
/// emit one before a long-running operation (e.g. ML-DSA keygen)
/// to buy ourselves the few-hundred-ms it actually takes.
pub fn keepalive_frame(cid: u32, status: u8) -> [u8; FRAME_LEN] {
    let mut frame = [0u8; FRAME_LEN];
    frame[..4].copy_from_slice(&cid.to_be_bytes());
    frame[4] = CMD_KEEPALIVE;
    frame[5..7].copy_from_slice(&1u16.to_be_bytes());
    frame[7] = status;
    frame
}

pub const ERR_INVALID_CMD: u8 = 0x01;
/// A command parameter was out of range (CTAP HID sec. 11.2.9.1.6) -- e.g.
/// a CMD_RNG count of 0 or beyond RNG_MAX.
pub const ERR_INVALID_PARAMETER: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
/// A multi-frame transaction stalled mid-assembly: no further frame
/// arrived within `MSG_TIMEOUT_US` of the last one (CTAP HID sec. 11.2.5.2).
/// We drop the partial reassembly and report this to the owning CID so
/// the single global reassembly slot can't be wedged forever.
pub const ERR_MSG_TIMEOUT: u8 = 0x05;
/// A frame arrived on a channel other than the one with an in-progress
/// transaction (CTAP HID sec. 11.2.4).
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
/// CID 0, or a non-INIT command on the broadcast channel (sec. 11.2.4).
pub const ERR_INVALID_CHANNEL: u8 = 0x0B;
/// Generic "other" error (CTAP HID sec. 8.1.9.1.6). Used by CMD_REBOOT when
/// the user-presence gate is declined or times out. Mirrors the C
/// port's CTAPHID_ERR_OTHER.
pub const ERR_OTHER: u8 = 0x7f;

/// Max CTAP HID message payload (1 init.57 + 128 cont.59 = 7609 bytes).
pub const MAX_MSG_LEN: usize = INIT_DATA + 128 * CONT_DATA;

/// Inactivity window for an in-progress multi-frame reassembly, in
/// microseconds. CTAP HID sec. 11.2.5.2 specifies a transaction timeout
/// on the order of 500 ms; once `now - last_frame_us` exceeds this we
/// abort the partial message with ERR_MSG_TIMEOUT and free the slot.
/// The time source is the caller's monotonic microsecond counter
/// (`hal::Timer`), threaded in through `handle_frame` / `poll_timeout`.
pub const MSG_TIMEOUT_US: u64 = 500_000;

/// Reassembly state for an inbound CTAP HID message. The payload
/// buffer is heap-allocated to keep the per-channel state cost
/// proportional to the actual message size -- a 7.6 KB inline buffer
/// on the stack would push us past the stack envelope when combined
/// with the ml-dsa keygen working set.
struct InboundMsg {
    cid: u32,
    cmd: u8,
    total_len: u16,
    expected_seq: u8,
    buf: alloc::vec::Vec<u8>,
    /// Monotonic timestamp (microseconds) of the most recent frame
    /// that advanced this reassembly. Refreshed on the INIT frame and
    /// every continuation; `poll_timeout` aborts the message once the
    /// gap to "now" exceeds `MSG_TIMEOUT_US`.
    last_frame_us: u64,
}

/// Outbound response -- assembled in full on the heap, then handed
/// back one frame at a time via `next_frame`.
pub struct Response {
    cid: u32,
    cmd: u8,
    payload: alloc::vec::Vec<u8>,
    sent: usize,
    seq: u8,
    init_sent: bool,
}

impl Response {
    fn new(cid: u32, cmd: u8, data: &[u8]) -> Self {
        let n = core::cmp::min(data.len(), MAX_MSG_LEN);
        Self {
            cid,
            cmd,
            payload: data[..n].to_vec(),
            sent: 0,
            seq: 0,
            init_sent: false,
        }
    }

    /// Produce the next 64-byte frame to send. Returns None when the
    /// whole response has been transmitted.
    pub fn next_frame(&mut self) -> Option<[u8; FRAME_LEN]> {
        let payload_len = self.payload.len();
        if !self.init_sent {
            self.init_sent = true;
            let mut frame = [0u8; FRAME_LEN];
            frame[..4].copy_from_slice(&self.cid.to_be_bytes());
            frame[4] = self.cmd;
            frame[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
            let take = core::cmp::min(payload_len, INIT_DATA);
            frame[7..7 + take].copy_from_slice(&self.payload[..take]);
            self.sent = take;
            return Some(frame);
        }
        if self.sent >= payload_len {
            return None;
        }
        let mut frame = [0u8; FRAME_LEN];
        frame[..4].copy_from_slice(&self.cid.to_be_bytes());
        frame[4] = self.seq & 0x7f;
        let take = core::cmp::min(payload_len - self.sent, CONT_DATA);
        frame[5..5 + take].copy_from_slice(&self.payload[self.sent..self.sent + take]);
        self.sent += take;
        self.seq = self.seq.wrapping_add(1);
        Some(frame)
    }
}

pub struct CtapHid {
    rx: Option<InboundMsg>,
    /// Next channel ID handed out via INIT. 0 and 0xffffffff are
    /// reserved; we skip them.
    next_cid: u32,
}

/// What `handle_frame` decided to do with this frame.
pub enum FrameOutcome {
    /// Frame consumed (mid-message or ignored). Caller does nothing.
    Idle,
    /// Send this response back to the host immediately.
    Reply(Response),
    /// The host sent a complete CMD_CBOR (0x90) message; caller
    /// should run the CTAP2 layer and then call `build_response`.
    CborMessage {
        cid: u32,
        payload: alloc::vec::Vec<u8>,
    },
    /// The host sent a complete CMD_MSG (0x83) message -- a CTAP1 /
    /// U2F APDU. Caller should run the U2F layer ([`crate::u2f`])
    /// and then call `build_response` with the resulting body.
    /// Phase 11b.
    ///
    /// Only present when the `u2f` feature is enabled. The default
    /// build has no U2F layer (CMD_MSG is refused with
    /// ERR_INVALID_CMD in `complete`), so this variant is never
    /// constructed there and is compiled out entirely.
    #[cfg(feature = "u2f")]
    U2fMessage {
        cid: u32,
        payload: alloc::vec::Vec<u8>,
    },
    /// The host sent a validated CMD_RNG (vendor) request; caller
    /// should draw `count` bytes from the TRNG and call
    /// `build_response(cid, CMD_RNG, bytes)`. Routed out of this
    /// layer like CBOR/MSG because the transport struct doesn't own
    /// the TRNG.
    RngRequest { cid: u32, count: usize },
    /// The host sent a validated CMD_RNG_STATUS (vendor) request; caller
    /// should answer with `build_response(cid, CMD_RNG_STATUS,
    /// &entropy.status_bytes())`. Routed out for the same reason as RNG.
    RngStatusRequest { cid: u32 },
    /// The host sent a validated CMD_REBOOT (vendor) request; caller
    /// should run the user-presence gate and, if confirmed, reboot
    /// (`mode` is [`REBOOT_WARM`] or [`REBOOT_BOOTSEL`]). Routed out of
    /// this layer like CBOR/RNG because the transport struct owns
    /// neither the presence gate nor the reset ROM call. On success the
    /// device disappears, so no response is expected.
    RebootRequest { cid: u32, mode: u8 },
}

impl CtapHid {
    pub const fn new() -> Self {
        Self {
            rx: None,
            next_cid: 1,
        }
    }

    /// Feed one inbound 64-byte frame. Returns:
    /// - `Idle` if mid-message or the frame was ignored.
    /// - `Reply(r)` if a complete CTAP HID command was dispatched
    ///   entirely within this layer (INIT, PING, WINK, ...).
    /// - `CborMessage` if a complete CMD_CBOR (0x90) message was
    ///   assembled and should be handed to the CTAP2 layer.
    pub fn handle_frame(
        &mut self,
        frame: &[u8; FRAME_LEN],
        // Monotonic microsecond timestamp for this frame, used to stamp
        // the reassembly so `poll_timeout` can detect a stalled host.
        now_us: u64,
        wink_cb: &mut dyn FnMut(),
    ) -> FrameOutcome {
        let cid = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        let head = frame[4];
        let is_init = head & 0x80 != 0;

        // Channel validation (sec. 11.2.4): CID 0 is reserved, and the
        // broadcast channel only ever carries CTAPHID_INIT.
        if cid == 0 {
            return FrameOutcome::Reply(self.error_response(cid, ERR_INVALID_CHANNEL));
        }
        if cid == BROADCAST_CID && head != CMD_INIT {
            return FrameOutcome::Reply(self.error_response(cid, ERR_INVALID_CHANNEL));
        }

        // Channel arbitration (sec. 11.2.4): one transaction at a time. While
        // a reassembly is in progress, an *init* frame on any other
        // channel is answered ERR_CHANNEL_BUSY and the in-flight
        // transaction is left intact. The sole exception is a broadcast
        // INIT, which only allocates a channel and starts no transaction
        // of its own.
        //
        // Continuation frames are deliberately not covered here. A
        // continuation on a channel with nothing in flight is a spurious
        // continuation, and sec. 11.2.5.4 is specific about those: they "will
        // be ignored". Answering them CHANNEL_BUSY instead is what made
        // this port disagree with the C one, which was following the more
        // specific rule.
        if is_init {
            if let Some(active) = self.rx.as_ref() {
                if active.cid != cid && cid != BROADCAST_CID {
                    return FrameOutcome::Reply(self.error_response(cid, ERR_CHANNEL_BUSY));
                }
            }
        }

        if is_init {
            let cmd = head;
            let bcnt = u16::from_be_bytes([frame[5], frame[6]]);
            if bcnt as usize > MAX_MSG_LEN {
                return FrameOutcome::Reply(self.error_response(cid, ERR_INVALID_LEN));
            }
            let take = core::cmp::min(bcnt as usize, INIT_DATA);
            let mut buf = alloc::vec::Vec::with_capacity(bcnt as usize);
            buf.extend_from_slice(&frame[7..7 + take]);
            if buf.len() as u16 == bcnt {
                // Drop a partial reassembly only if THIS channel owns it
                // (an INIT on its own active channel is a resync). A
                // broadcast INIT must not disturb another channel's
                // in-flight transaction.
                if self.rx.as_ref().map_or(false, |m| m.cid == cid) {
                    self.rx = None;
                }
                return self.complete(cid, cmd, &buf, wink_cb);
            }
            self.rx = Some(InboundMsg {
                cid,
                cmd,
                total_len: bcnt,
                expected_seq: 0,
                buf,
                last_frame_us: now_us,
            });
            return FrameOutcome::Idle;
        }

        let seq = head;
        // CTAP HID sec. 11.2.5.4: "Spurious continuation packets appearing
        // without a prior initialization packet will be ignored." That
        // covers two cases, and neither may disturb a message already in
        // flight -- taking the slot first and asking questions after let
        // any host drop another channel's transaction with one frame.
        let mut msg = match self.rx.as_ref() {
            // Nothing in flight at all: spurious, ignore in silence.
            None => return FrameOutcome::Idle,
            // Something in flight, but on a different channel: spurious
            // for *this* channel. Ignore it, and leave the other
            // channel's message alone -- taking the slot before checking
            // whose it was would let any host drop any other host's
            // transaction with a single frame.
            Some(m) if m.cid != cid => return FrameOutcome::Idle,
            // Our channel, wrong sequence number: a frame was lost, so
            // the message can no longer be assembled. Abandon it and say
            // so -- the host has to start again either way.
            Some(m) if m.expected_seq != seq => {
                self.rx = None;
                return FrameOutcome::Reply(self.error_response(cid, ERR_INVALID_SEQ));
            }
            Some(_) => self.rx.take().unwrap(),
        };
        let remaining = msg.total_len as usize - msg.buf.len();
        let take = core::cmp::min(remaining, CONT_DATA);
        msg.buf.extend_from_slice(&frame[5..5 + take]);
        msg.expected_seq = seq.wrapping_add(1) & 0x7f;
        // Refresh the inactivity timer: progress was made, so the host
        // is alive and the timeout window restarts from this frame.
        msg.last_frame_us = now_us;

        if msg.buf.len() as u16 == msg.total_len {
            self.complete(cid, msg.cmd, &msg.buf, wink_cb)
        } else {
            self.rx = Some(msg);
            FrameOutcome::Idle
        }
    }

    /// Sweep the in-progress reassembly (if any) for a stalled host.
    /// Called from the main loop with the current monotonic timestamp.
    /// If a multi-frame transaction has seen no progress for longer
    /// than `MSG_TIMEOUT_US`, the partial message is dropped and an
    /// ERR_MSG_TIMEOUT reply is returned for the owning channel --
    /// freeing the single global reassembly slot that a stalled host
    /// would otherwise wedge forever (CTAP HID sec. 11.2.5.2). Returns
    /// `None` when there is nothing to time out.
    pub fn poll_timeout(&mut self, now_us: u64) -> Option<Response> {
        let stalled = self.rx.as_ref().map_or(false, |m| {
            now_us.saturating_sub(m.last_frame_us) >= MSG_TIMEOUT_US
        });
        if stalled {
            // `take` is safe: we only reach here when `rx` is `Some`.
            let cid = self.rx.take().map(|m| m.cid).unwrap_or(0);
            return Some(self.error_response(cid, ERR_MSG_TIMEOUT));
        }
        None
    }

    /// React to a dropped inbound frame reported by the transport
    /// (the RX ring overflowed). A gap in the frame stream would
    /// desynchronise sequence numbers and corrupt any in-flight
    /// reassembly, so we drop the partial message and answer the
    /// owning channel ERR_CHANNEL_BUSY, prompting the host to retry
    /// the transaction cleanly. Returns `None` if nothing was being
    /// reassembled (the lost frame was a complete single-frame
    /// command the host can simply resend).
    pub fn poll_overflow(&mut self) -> Option<Response> {
        let cid = self.rx.take().map(|m| m.cid)?;
        Some(self.error_response(cid, ERR_CHANNEL_BUSY))
    }

    /// Build a CTAP HID response frame stream for a precomputed payload.
    /// Used by the CTAP2 layer to wrap its CBOR response.
    pub fn build_response(&self, cid: u32, cmd: u8, data: &[u8]) -> Response {
        Response::new(cid, cmd, data)
    }

    fn complete(
        &mut self,
        cid: u32,
        cmd: u8,
        data: &[u8],
        wink_cb: &mut dyn FnMut(),
    ) -> FrameOutcome {
        if cmd == CMD_CANCEL {
            // CTAP HID sec. 11.2.9.1.4: CANCEL aborts the outstanding
            // transaction on this channel and itself produces NO direct
            // reply (the cancelled command answers CTAP2_ERR_KEEPALIVE_
            // CANCEL). Drop any partial reassembly. A CANCEL that lands
            // mid-sign never reaches here -- it's caught earlier on the
            // KEEPALIVE pump path (see ctap2::opensk_hybrid_sign), which
            // consumes it from the rx ring -- so reaching this point means
            // there is no synchronous CBOR op in flight to interrupt.
            self.rx = None;
            return FrameOutcome::Idle;
        }
        if cmd == CMD_CBOR {
            // Hand off the (already-assembled) CBOR payload to the
            // caller for CTAP2 dispatch. Heap-owned so the buffer
            // doesn't sit on the stack while we run multi-second
            // ML-DSA-65 keygen.
            let payload = data.to_vec();
            return FrameOutcome::CborMessage { cid, payload };
        }
        if cmd == CMD_RNG {
            // Vendor RNG request (constant's doc comment above). Empty
            // payload = default count; 2-byte big-endian payload = an
            // explicit count; anything else is malformed. Validated
            // here, filled by the caller who owns the TRNG.
            let count = match data.len() {
                0 => RNG_DEFAULT,
                2 => u16::from_be_bytes([data[0], data[1]]) as usize,
                _ => return FrameOutcome::Reply(self.error_response(cid, ERR_INVALID_LEN)),
            };
            if count == 0 || count > RNG_MAX {
                return FrameOutcome::Reply(self.error_response(cid, ERR_INVALID_PARAMETER));
            }
            return FrameOutcome::RngRequest { cid, count };
        }
        if cmd == CMD_RNG_STATUS {
            // Vendor RNG status request (constant's doc comment above):
            // no payload; the caller owns the picker and its counters.
            if !data.is_empty() {
                return FrameOutcome::Reply(self.error_response(cid, ERR_INVALID_LEN));
            }
            return FrameOutcome::RngStatusRequest { cid };
        }
        if cmd == CMD_REBOOT {
            // Vendor reboot request (constant's doc comment above).
            // Exactly one mode byte; validated here, gated (user
            // presence) and executed by the caller who owns the reset.
            let mode = match data {
                [m] if *m == REBOOT_WARM || *m == REBOOT_BOOTSEL => *m,
                [_] => return FrameOutcome::Reply(self.error_response(cid, ERR_INVALID_PARAMETER)),
                _ => return FrameOutcome::Reply(self.error_response(cid, ERR_INVALID_LEN)),
            };
            return FrameOutcome::RebootRequest { cid, mode };
        }
        if cmd == CMD_MSG {
            // CTAP1 / U2F APDU. We advertise CAPABILITY_NMSG (see the
            // INIT response builder below) -- "device does NOT support
            // CTAPHID_MSG" -- but some browser implementations probe
            // CMD_MSG anyway. If we silently dispatched to the U2F
            // layer (which we used to do in Phase 11b via
            // `FrameOutcome::U2fMessage`), the browser would observe a
            // valid U2F Register / Authenticate response, conclude
            // U2F works regardless of NMSG, and pin all future
            // WebAuthn calls onto the U2F transport. The resulting
            // attestation comes back to the RP as `fmt="fido-u2f"`
            // instead of `"packed"`, which a PQC-aware RP may not
            // accept.
            //
            // Honour our own NMSG advertisement: refuse CMD_MSG with
            // ERR_INVALID_CMD. The browser then has no choice but to
            // fall through to CMD_CBOR (CTAP2 MakeCredential /
            // GetAssertion), which emits `fmt="packed"`.
            //
            // With the `u2f` feature on, that refusal is exactly what
            // has to be lifted: the whole point of the feature is U2F
            // interop testing on a dev device, and `main.rs` already
            // carries a `U2fMessage` arm that nothing could reach while
            // this returned unconditionally. Compiled out of, and so
            // unchanged for, every default (shipping) build.
            #[cfg(feature = "u2f")]
            {
                return FrameOutcome::U2fMessage {
                    cid,
                    payload: data.to_vec(),
                };
            }
            #[cfg(not(feature = "u2f"))]
            return FrameOutcome::Reply(self.error_response(cid, ERR_INVALID_CMD));
        }
        FrameOutcome::Reply(self.dispatch(cid, cmd, data, wink_cb))
    }

    fn dispatch(&mut self, cid: u32, cmd: u8, data: &[u8], wink_cb: &mut dyn FnMut()) -> Response {
        match cmd {
            CMD_INIT => {
                if data.len() != 8 {
                    return self.error_response(cid, ERR_INVALID_LEN);
                }
                let new_cid = if cid == BROADCAST_CID {
                    let allocated = self.next_cid;
                    self.next_cid = self.next_cid.wrapping_add(1);
                    if self.next_cid == BROADCAST_CID || self.next_cid == 0 {
                        self.next_cid = 1;
                    }
                    allocated
                } else {
                    cid
                };
                let mut buf = [0u8; 17];
                buf[..8].copy_from_slice(data);
                buf[8..12].copy_from_slice(&new_cid.to_be_bytes());
                buf[12] = 2; // CTAPHID protocol version
                buf[13] = 0; // dev major
                buf[14] = 1; // dev minor
                buf[15] = 0; // dev build
                             // CAPABILITY_WINK (0x01) | CAPABILITY_CBOR (0x04) |
                             // CAPABILITY_NMSG (0x08).
                             //
                             // NMSG = "device does NOT support CTAPHID_MSG (U2F)".
                             // We're FIDO2 / CTAP2 only -- the firmware deliberately
                             // does not implement the legacy U2F transport. With
                             // NMSG advertised, browsers skip U2F entirely and use
                             // CTAP2 MakeCredential / GetAssertion, which emit
                             // standard WebAuthn responses (`fmt = "packed"` rather
                             // than `fmt = "fido-u2f"`). Without NMSG set, Chrome
                             // / Firefox / Safari all prefer U2F for plain
                             // ES256-only registrations because it's a simpler
                             // one-round-trip protocol than CTAP2.
                             //
                             // WINK is the cosmetic "blink me, RP wants to
                             // identify the device" command -- structurally
                             // supported via the `CMD_WINK` arm below, so
                             // advertising the bit is free.
                             // With the `u2f` feature on, NMSG must be DROPPED: the
                             // bit is a promise that CMD_MSG will be refused, and a
                             // U2F build honours CMD_MSG instead. Leaving it set made
                             // the feature untestable -- a U2F client reads the
                             // capability and declines before sending anything
                             // ("device does not offer CTAP1 (NMSG set)"). Default
                             // builds are unchanged and keep NMSG.
                #[cfg(feature = "u2f")]
                {
                    buf[16] = 0x01 | 0x04;
                }
                #[cfg(not(feature = "u2f"))]
                {
                    buf[16] = 0x01 | 0x04 | 0x08;
                }
                Response::new(cid, CMD_INIT, &buf)
            }
            CMD_PING => Response::new(cid, CMD_PING, data),
            CMD_WINK => {
                wink_cb();
                Response::new(cid, CMD_WINK | 0x80, &[])
            }
            // CMD_CANCEL, CMD_CBOR and CMD_MSG are handled before
            // reaching this match (see `complete`): CANCEL produces no
            // reply, and CBOR/MSG get dispatched off this layer to the
            // CTAP2 / U2F layers respectively, which need access to
            // TRNG + CredStore that this struct doesn't own.
            _ => self.error_response(cid, ERR_INVALID_CMD),
        }
    }

    fn error_response(&mut self, cid: u32, code: u8) -> Response {
        Response::new(cid, CMD_ERROR, &[code])
    }
}
