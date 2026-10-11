// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAPHID framing: channel allocation, reassembly, and the errors.
//!
//! This is the layer every byte from the host passes through before
//! anything else looks at it, and it is reachable by anyone who can send
//! USB frames -- no PIN, no user presence, nothing. The conformance suite
//! exercises it only as a side effect of doing real CTAP2 operations, so the
//! malformed and hostile cases have never been covered.
//!
//! The C port has had `test_ctap2.c` and friends since Phase C-11. This
//! is the Rust half for the transport layer.

use pqf_firmware_hosttest as fw;

use fw::ctaphid::{
    keepalive_frame, CtapHid, FrameOutcome, CMD_CANCEL, CMD_CBOR, CMD_ERROR, CMD_INIT, CMD_MSG,
    CMD_PING, CMD_REBOOT, CMD_RNG, CMD_RNG_STATUS, CMD_WINK, ERR_CHANNEL_BUSY, ERR_INVALID_CHANNEL,
    ERR_INVALID_CMD, ERR_INVALID_LEN, ERR_INVALID_PARAMETER, ERR_INVALID_SEQ, ERR_MSG_TIMEOUT,
    KEEPALIVE_PROCESSING, MAX_MSG_LEN, MSG_TIMEOUT_US, REBOOT_BOOTSEL, RNG_MAX,
};

const FRAME_LEN: usize = 64;
const BROADCAST: u32 = 0xffff_ffff;

fn init_frame(cid: u32, cmd: u8, payload: &[u8]) -> [u8; FRAME_LEN] {
    init_frame_len(cid, cmd, payload, payload.len() as u16)
}

/// An init frame whose declared length may differ from what it carries --
/// which is how a multi-frame message starts, and also how a hostile one
/// lies.
fn init_frame_len(cid: u32, cmd: u8, payload: &[u8], declared: u16) -> [u8; FRAME_LEN] {
    let mut f = [0u8; FRAME_LEN];
    f[..4].copy_from_slice(&cid.to_be_bytes());
    f[4] = cmd;
    f[5..7].copy_from_slice(&declared.to_be_bytes());
    let n = payload.len().min(FRAME_LEN - 7);
    f[7..7 + n].copy_from_slice(&payload[..n]);
    f
}

fn cont_frame(cid: u32, seq: u8, payload: &[u8]) -> [u8; FRAME_LEN] {
    let mut f = [0u8; FRAME_LEN];
    f[..4].copy_from_slice(&cid.to_be_bytes());
    f[4] = seq;
    let n = payload.len().min(FRAME_LEN - 5);
    f[5..5 + n].copy_from_slice(&payload[..n]);
    f
}

fn feed(h: &mut CtapHid, f: &[u8; FRAME_LEN]) -> FrameOutcome {
    h.handle_frame(f, 0, &mut || {})
}

fn feed_at(h: &mut CtapHid, f: &[u8; FRAME_LEN], now_us: u64) -> FrameOutcome {
    h.handle_frame(f, now_us, &mut || {})
}

/// Drain a response into the payload it carries, and the command byte.
fn drain(mut r: fw::ctaphid::Response) -> (u8, Vec<u8>) {
    let mut cmd = 0u8;
    let mut out = Vec::new();
    let mut total = 0usize;
    let mut first = true;
    while let Some(f) = r.next_frame() {
        if first {
            cmd = f[4];
            total = u16::from_be_bytes([f[5], f[6]]) as usize;
            out.extend_from_slice(&f[7..]);
            first = false;
        } else {
            out.extend_from_slice(&f[5..]);
        }
    }
    out.truncate(total);
    (cmd, out)
}

fn expect_reply(o: FrameOutcome) -> (u8, Vec<u8>) {
    match o {
        FrameOutcome::Reply(r) => drain(r),
        _ => panic!("expected a reply frame"),
    }
}

fn expect_error(o: FrameOutcome) -> u8 {
    let (cmd, body) = expect_reply(o);
    assert_eq!(
        cmd, CMD_ERROR,
        "expected an error reply, got command {cmd:#04x}"
    );
    assert_eq!(body.len(), 1, "an error reply carries exactly one byte");
    body[0]
}

/// Allocate a channel the way a real client does, and return its CID.
fn allocate(h: &mut CtapHid) -> u32 {
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let (cmd, body) = expect_reply(feed(h, &init_frame(BROADCAST, CMD_INIT, &nonce)));
    assert_eq!(cmd, CMD_INIT);
    assert_eq!(&body[..8], &nonce, "INIT must echo the nonce");
    u32::from_be_bytes([body[8], body[9], body[10], body[11]])
}

// ---- channel allocation ---------------------------------------------

#[test]
fn init_echoes_the_nonce_and_hands_out_a_usable_channel() {
    // The nonce echo is how a client tells its own INIT response apart
    // from someone else's on the broadcast channel. Getting it wrong
    // means two clients can steal each other's channels.
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    assert_ne!(cid, 0, "channel 0 is reserved");
    assert_ne!(cid, BROADCAST, "the broadcast channel is reserved");
}

#[test]
fn every_channel_allocation_is_distinct() {
    let mut h = CtapHid::new();
    let mut seen = std::collections::HashSet::new();
    for i in 0..64 {
        let cid = allocate(&mut h);
        assert!(
            seen.insert(cid),
            "channel {cid:#x} handed out twice (round {i})"
        );
        assert_ne!(cid, 0);
        assert_ne!(cid, BROADCAST);
    }
}

#[test]
fn an_unallocated_channel_is_honoured_rather_than_refused() {
    // Deliberate, and worth pinning so it is not "fixed" by accident.
    // Neither port tracks which CIDs it has handed out -- the C port has
    // no ERR_INVALID_CHANNEL path at all, and the Rust one rejects only
    // CID 0 and a non-INIT broadcast. A strict reading of CTAP HID
    // 11.2.4 would have the authenticator refuse a CID it never issued.
    //
    // The simplification costs little here because arbitration is by the
    // *active* CID and there is one transaction slot, so an invented CID
    // cannot corrupt another channel's reassembly -- it gets
    // ERR_CHANNEL_BUSY like anyone else. And it buys something real: a
    // client that remembers its CID across a device reboot keeps
    // working, which on a token that reboots as often as this one does
    // is the common case rather than the exception.
    let mut h = CtapHid::new();
    let _ = allocate(&mut h);
    let (cmd, body) = expect_reply(feed(&mut h, &init_frame(0xdead_beef, CMD_PING, b"hi")));
    assert_eq!(cmd, CMD_PING);
    assert_eq!(body, b"hi");
}

#[test]
fn channel_zero_is_refused() {
    let mut h = CtapHid::new();
    let e = expect_error(feed(&mut h, &init_frame(0, CMD_PING, b"hi")));
    assert_eq!(e, ERR_INVALID_CHANNEL);
}

#[test]
fn only_init_is_accepted_on_the_broadcast_channel() {
    let mut h = CtapHid::new();
    let e = expect_error(feed(&mut h, &init_frame(BROADCAST, CMD_PING, b"hi")));
    assert_eq!(e, ERR_INVALID_CHANNEL);
}

// ---- PING and the simple commands -----------------------------------

#[test]
fn ping_echoes_its_payload_exactly() {
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    let payload: Vec<u8> = (0..40u8).collect();
    let (cmd, body) = expect_reply(feed(&mut h, &init_frame(cid, CMD_PING, &payload)));
    assert_eq!(cmd, CMD_PING);
    assert_eq!(body, payload, "PING did not echo verbatim");
}

#[test]
fn an_empty_ping_is_answered() {
    // Zero-length is legal and a client uses it as a liveness probe.
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    let (cmd, body) = expect_reply(feed(&mut h, &init_frame(cid, CMD_PING, &[])));
    assert_eq!(cmd, CMD_PING);
    assert!(body.is_empty());
}

#[test]
fn wink_runs_the_callback_once() {
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    let mut winks = 0;
    let f = init_frame(cid, CMD_WINK, &[]);
    let out = h.handle_frame(&f, 0, &mut || winks += 1);
    assert!(matches!(out, FrameOutcome::Reply(_)));
    assert_eq!(winks, 1, "WINK did not run its callback exactly once");
}

#[test]
fn an_unknown_command_is_refused() {
    // The command byte must have bit 7 set; without it the frame is a
    // *continuation*, not a command, which is a different rejection.
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    let e = expect_error(feed(&mut h, &init_frame(cid, 0xbe, &[])));
    assert_eq!(e, ERR_INVALID_CMD);
}

#[test]
fn u2f_is_refused_unless_the_feature_is_built_in() {
    // The default build has no U2F layer. Advertising NMSG while
    // silently accepting CMD_MSG would be worse than refusing it.
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    let out = feed(&mut h, &init_frame(cid, CMD_MSG, &[0, 1, 2, 3]));
    if cfg!(feature = "u2f") {
        assert!(
            !matches!(out, FrameOutcome::Reply(_)),
            "u2f build should route out"
        );
    } else {
        assert_eq!(expect_error(out), ERR_INVALID_CMD);
    }
}

// ---- reassembly ------------------------------------------------------

#[test]
fn a_multi_frame_message_reassembles_in_order() {
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    let payload: Vec<u8> = (0..200u16).map(|i| i as u8).collect();

    let mut out = feed(
        &mut h,
        &init_frame_len(cid, CMD_PING, &payload[..57], payload.len() as u16),
    );
    assert!(
        matches!(out, FrameOutcome::Idle),
        "an incomplete message replied early"
    );
    let mut off = 57;
    let mut seq = 0u8;
    while off < payload.len() {
        let end = (off + 59).min(payload.len());
        out = feed(&mut h, &cont_frame(cid, seq, &payload[off..end]));
        off = end;
        seq += 1;
    }
    let (cmd, body) = expect_reply(out);
    assert_eq!(cmd, CMD_PING);
    assert_eq!(body, payload, "a reassembled message came back altered");
}

#[test]
fn an_out_of_order_continuation_is_refused() {
    // Sequence numbers are the only thing keeping a reassembly honest.
    // Accepting a wrong one lets a host place bytes wherever it likes in
    // the buffer.
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    feed(&mut h, &init_frame_len(cid, CMD_PING, &[0u8; 57], 200));
    let e = expect_error(feed(&mut h, &cont_frame(cid, 5, &[0u8; 59])));
    assert_eq!(e, ERR_INVALID_SEQ);
}

#[test]
fn a_continuation_with_no_message_in_progress_is_ignored() {
    // CTAP HID sec. 11.2.5.4: "Spurious continuation packets appearing
    // without a prior initialization packet will be ignored."
    //
    // This port used to answer ERR_INVALID_SEQ, and the note here used
    // to claim both ports did. They did not -- the C port ignored them,
    // correctly, and that only came out when the C port got a mirror of
    // this suite and the two disagreed. Two implementations of one wire
    // format disagreeing means one is wrong; here it was this one.
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    let out = feed(&mut h, &cont_frame(cid, 0, &[1, 2, 3, 4]));
    assert!(
        matches!(out, FrameOutcome::Idle),
        "a spurious continuation drew a reply"
    );
}

#[test]
fn another_channels_frame_does_not_disturb_a_message_in_flight() {
    // Arbitration (sec. 11.2.4) catches this before the continuation path
    // does: a frame on any other channel while a reassembly is running
    // is answered ERR_CHANNEL_BUSY, and -- the part worth testing -- the
    // in-flight message is left alone. Without that, any host could drop
    // any other host's transaction with a single frame, on a transport
    // with no authentication at all.
    let mut h = CtapHid::new();
    let a = allocate(&mut h);
    let b = allocate(&mut h);
    assert_ne!(a, b, "setup: two distinct channels");

    let payload: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
    let out = feed(
        &mut h,
        &init_frame_len(a, CMD_PING, &payload[..57], payload.len() as u16),
    );
    assert!(
        matches!(out, FrameOutcome::Idle),
        "setup: A's message is in flight"
    );

    // B interferes, both ways it can. Its continuation is spurious --
    // B has nothing in flight -- so sec. 11.2.5.4 says ignore it; its init
    // frame is a competing transaction, so arbitration refuses it.
    let out = feed(&mut h, &cont_frame(b, 0, &[0xff; 8]));
    assert!(
        matches!(out, FrameOutcome::Idle),
        "B's spurious continuation drew a reply"
    );
    let (cmd, body) = expect_reply(feed(&mut h, &init_frame(b, CMD_PING, &[1, 2, 3])));
    assert_eq!(cmd, CMD_ERROR);
    assert_eq!(
        body[0], ERR_CHANNEL_BUSY,
        "B's init frame was not refused as busy"
    );

    // A's message still completes, unaltered.
    let mut off = 57;
    let mut seq = 0u8;
    let mut last = FrameOutcome::Idle;
    while off < payload.len() {
        let end = (off + 59).min(payload.len());
        last = feed(&mut h, &cont_frame(a, seq, &payload[off..end]));
        off = end;
        seq += 1;
    }
    let (cmd, body) = expect_reply(last);
    assert_eq!(cmd, CMD_PING, "channel A's message did not complete");
    assert_eq!(
        body, payload,
        "channel A's message was corrupted by channel B's frames"
    );
}

#[test]
fn a_second_channel_is_told_the_device_is_busy() {
    // One transaction at a time. Without this, two hosts interleaving
    // frames would corrupt each other's reassembly.
    let mut h = CtapHid::new();
    let a = allocate(&mut h);
    let b = allocate(&mut h);
    feed(&mut h, &init_frame_len(a, CMD_PING, &[0u8; 57], 200));
    let e = expect_error(feed(&mut h, &init_frame(b, CMD_PING, b"hello")));
    assert_eq!(e, ERR_CHANNEL_BUSY);
}

#[test]
fn a_declared_length_past_the_maximum_is_refused() {
    // MAX_MSG_LEN is 7609 and the length field is 16 bits, so a host can
    // declare far more than the device will ever accept. Refusing at the
    // declaration is what stops a large allocation on someone's say-so.
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    let e = expect_error(feed(
        &mut h,
        &init_frame_len(cid, CMD_PING, &[0u8; 57], u16::MAX),
    ));
    assert_eq!(e, ERR_INVALID_LEN);
    assert!(MAX_MSG_LEN < u16::MAX as usize);
}

#[test]
fn a_message_of_exactly_the_maximum_length_is_accepted() {
    // The boundary in the other direction: 7609 must work, or the
    // advertised maxMsgSize is a lie and large credentials fail.
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    let payload = vec![0xABu8; MAX_MSG_LEN];
    let mut out = feed(
        &mut h,
        &init_frame_len(cid, CMD_CBOR, &payload[..57], MAX_MSG_LEN as u16),
    );
    let mut off = 57;
    let mut seq = 0u8;
    while off < payload.len() {
        let end = (off + 59).min(payload.len());
        out = feed(&mut h, &cont_frame(cid, seq, &payload[off..end]));
        off = end;
        seq = seq.wrapping_add(1);
    }
    match out {
        FrameOutcome::CborMessage { cid: c, payload: p } => {
            assert_eq!(c, cid);
            assert_eq!(
                p.len(),
                MAX_MSG_LEN,
                "the largest legal message was truncated"
            );
        }
        _ => panic!("a maximum-length CBOR message was not delivered"),
    }
}

#[test]
fn a_stalled_reassembly_times_out_and_frees_the_channel() {
    // A host that starts a message and goes away must not hold the
    // device forever -- that is a one-frame denial of service.
    let mut h = CtapHid::new();
    let a = allocate(&mut h);
    let b = allocate(&mut h);
    feed_at(&mut h, &init_frame_len(a, CMD_PING, &[0u8; 57], 200), 1_000);

    assert!(
        h.poll_timeout(1_000 + MSG_TIMEOUT_US / 2).is_none(),
        "timed out early"
    );
    let r = h
        .poll_timeout(1_000 + MSG_TIMEOUT_US + 1)
        .expect("a stalled reassembly never timed out");
    let (cmd, body) = drain(r);
    assert_eq!(cmd, CMD_ERROR);
    assert_eq!(body[0], ERR_MSG_TIMEOUT);

    // And the channel is free again.
    let (cmd, _) = expect_reply(feed(&mut h, &init_frame(b, CMD_PING, b"x")));
    assert_eq!(cmd, CMD_PING);
}

#[test]
fn a_new_init_on_the_same_channel_abandons_a_partial_message() {
    // CTAP HID says INIT resynchronises a channel. A client that lost
    // track has to be able to start over without waiting out the
    // timeout.
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    feed(&mut h, &init_frame_len(cid, CMD_PING, &[0u8; 57], 200));
    let (cmd, _) = expect_reply(feed(&mut h, &init_frame(cid, CMD_INIT, &[9u8; 8])));
    assert_eq!(cmd, CMD_INIT);
    // The abandoned message did not leave the channel busy.
    let (cmd, body) = expect_reply(feed(&mut h, &init_frame(cid, CMD_PING, b"back")));
    assert_eq!(cmd, CMD_PING);
    assert_eq!(body, b"back");
}

// ---- the vendor commands --------------------------------------------

#[test]
fn a_cbor_message_is_routed_out_rather_than_answered_here() {
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    match feed(&mut h, &init_frame(cid, CMD_CBOR, &[0x04])) {
        FrameOutcome::CborMessage { cid: c, payload } => {
            assert_eq!(c, cid);
            assert_eq!(payload, vec![0x04]);
        }
        _ => panic!("CMD_CBOR was not routed to the CTAP2 layer"),
    }
}

#[test]
fn the_rng_command_bounds_what_it_will_be_asked_for() {
    // Vendor CMD_RNG takes a count from the host. Unbounded, it is an
    // allocation of the host's choosing.
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    match feed(&mut h, &init_frame(cid, CMD_RNG, &[0x00, 0x20])) {
        FrameOutcome::RngRequest { count, .. } => assert_eq!(count, 32),
        _ => panic!("a valid RNG request was not routed"),
    }
    // Over the cap and zero are both refused, as a bad parameter rather
    // than a bad length -- the frame was well formed, the number in it
    // was not.
    let too_big = ((RNG_MAX + 1) as u16).to_be_bytes();
    let e = expect_error(feed(&mut h, &init_frame(cid, CMD_RNG, &too_big)));
    assert_eq!(
        e, ERR_INVALID_PARAMETER,
        "an oversized RNG request was accepted"
    );
    let e = expect_error(feed(&mut h, &init_frame(cid, CMD_RNG, &[0, 0])));
    assert_eq!(
        e, ERR_INVALID_PARAMETER,
        "a zero-length RNG request was accepted"
    );
    // A malformed payload length is a length error.
    let e = expect_error(feed(&mut h, &init_frame(cid, CMD_RNG, &[0, 0, 0])));
    assert_eq!(e, ERR_INVALID_LEN);
}

#[test]
fn the_rng_status_command_takes_no_payload_and_routes_out() {
    // CMD_RNG_STATUS carries no arguments: an empty frame is routed to
    // the owner of the picker, anything else is a length error rather
    // than being silently ignored.
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    match feed(&mut h, &init_frame(cid, CMD_RNG_STATUS, &[])) {
        FrameOutcome::RngStatusRequest { cid: c } => assert_eq!(c, cid),
        _ => panic!("a valid RNG status request was not routed"),
    }
    let e = expect_error(feed(&mut h, &init_frame(cid, CMD_RNG_STATUS, &[0])));
    assert_eq!(
        e, ERR_INVALID_LEN,
        "a status request with a payload was accepted"
    );
}

#[test]
fn the_reboot_command_validates_its_mode_byte() {
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    match feed(&mut h, &init_frame(cid, CMD_REBOOT, &[REBOOT_BOOTSEL])) {
        FrameOutcome::RebootRequest { mode, .. } => assert_eq!(mode, REBOOT_BOOTSEL),
        _ => panic!("a valid reboot request was not routed"),
    }
    let e = expect_error(feed(&mut h, &init_frame(cid, CMD_REBOOT, &[0x7f])));
    assert_eq!(
        e, ERR_INVALID_PARAMETER,
        "an unknown reboot mode was accepted"
    );
    let e = expect_error(feed(&mut h, &init_frame(cid, CMD_REBOOT, &[])));
    assert_eq!(
        e, ERR_INVALID_LEN,
        "a reboot with no mode byte was accepted"
    );
}

#[test]
fn cancel_is_accepted_and_does_not_reply() {
    // CTAP HID 11.2.9.4: CANCEL is fire-and-forget. A reply would be
    // mistaken for the response to the command being cancelled.
    let mut h = CtapHid::new();
    let cid = allocate(&mut h);
    let out = feed(&mut h, &init_frame(cid, CMD_CANCEL, &[]));
    assert!(matches!(out, FrameOutcome::Idle), "CANCEL drew a reply");
}

// ---- keepalive -------------------------------------------------------

#[test]
fn a_keepalive_frame_is_well_formed() {
    // Sent while a long operation runs. A malformed one makes a client
    // give up mid-ceremony, which on this token means during an ML-DSA
    // signature.
    let f = keepalive_frame(0x1234_5678, KEEPALIVE_PROCESSING);
    assert_eq!(u32::from_be_bytes([f[0], f[1], f[2], f[3]]), 0x1234_5678);
    assert_eq!(f[4], fw::ctaphid::CMD_KEEPALIVE);
    assert_eq!(
        u16::from_be_bytes([f[5], f[6]]),
        1,
        "keepalive carries one byte"
    );
    assert_eq!(f[7], KEEPALIVE_PROCESSING);
}
