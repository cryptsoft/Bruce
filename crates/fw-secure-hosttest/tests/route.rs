// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAPHID routing in the Non-secure image.
//!
//! `crates/fw-nonsecure/src/main.rs` had 274 lines of `handle_message`
//! that no test could reach: every arm ends in a call across the
//! TrustZone boundary, and the function is generic over a `UsbBus`, so
//! reaching it meant standing up USB and the Secure gateway. The
//! parsers underneath it (`ctapreq`) and the transport above it
//! (`fido_hid`) were both covered; the routing between them was not.
//!
//! That is the wrong gap to have, because the routing is where the
//! presence gate lives. `route` now decides it, so these tests can ask
//! the question directly -- and the important one is not "does
//! makeCredential need a touch", which everybody remembers, but "is
//! there any command that reaches a signing path without one", which is
//! the failure nobody notices.

use pqf_fw_secure_hosttest::route::{
    route, Ctap, Route, BROADCAST_CID, CMD_CBOR, CMD_INIT, CMD_PING, CMD_WINK, ERR_INVALID_CHANNEL,
    ERR_INVALID_LEN, RESERVED_CID,
};

const CID: u32 = 0x1234_5678;
const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

// ---------- the presence gate ----------

#[test]
fn the_two_signing_commands_require_a_gesture() {
    // The whole point of the device. If either of these ever answers
    // false, the token signs whatever it is asked to, silently, with no
    // human in the loop -- and nothing else in the system would notice,
    // because Secure trusts this decision.
    assert!(
        Ctap::MakeCredential.needs_presence(),
        "makeCredential would sign untouched"
    );
    assert!(
        Ctap::GetAssertion.needs_presence(),
        "getAssertion would sign untouched"
    );
}

#[test]
fn selection_requires_a_gesture_because_it_is_the_gesture() {
    // CTAP 2.1 sec. 6.7: authenticatorSelection exists to let a platform ask
    // "is a human at this one". Answering without asking makes every
    // connected authenticator claim to be the chosen one.
    assert!(Ctap::Selection.needs_presence());
}

#[test]
fn the_ungated_commands_are_ungated_on_purpose() {
    // Each of these would be a denial of service if gated, and the
    // reasoning is in route.rs. Pinned here so that "add a touch, it can
    // only be safer" is a test failure and a conversation rather than a
    // quiet regression: getInfo is sent unprompted by every client on
    // enumeration, and clientPin covers reading the retry counter.
    for c in [Ctap::GetInfo, Ctap::ClientPin, Ctap::GetNextAssertion] {
        assert!(!c.needs_presence(), "{c:?} became gated -- see route.rs");
    }
}

#[test]
fn the_token_gated_commands_are_not_also_touch_gated() {
    // credentialManagement and config are gated by a pinUvAuthToken,
    // checked in Secure where the token lives. A touch here would be an
    // extra prompt rather than a replacement for that check.
    assert!(!Ctap::CredMgmt.needs_presence());
    assert!(!Ctap::Config.needs_presence());
}

#[test]
fn every_ctap2_command_is_classified_deliberately() {
    // The test that earns this file. Walk all 256 possible command
    // bytes; every one must be a command this image knows about, or
    // Unknown. An arm added to `from_byte` without a decision about its
    // gate shows up here as a byte that is neither.
    //
    // The gated set is written out rather than derived, so widening it
    // by accident is a failure. Three commands sign or attest presence;
    // everything else must not be able to reach one of those paths.
    let gated: &[u8] = &[
        0x01, // makeCredential
        0x02, // getAssertion
        0x0b, // selection
    ];
    for b in 0..=255u8 {
        let c = Ctap::from_byte(b);
        let want = gated.contains(&b);
        assert_eq!(
            c.needs_presence(),
            want,
            "command {b:#04x} routes to {c:?} with presence={} -- expected {want}. \
             A new command must be added to the gated list above deliberately, \
             or shown not to sign.",
            c.needs_presence()
        );
    }
}

#[test]
fn an_unknown_command_never_prompts_for_a_touch() {
    // A refused command that first burns ten seconds waiting for a
    // finger is a way to make a token useless from software.
    for b in [0x00u8, 0x03, 0x05, 0x07, 0x09, 0x0c, 0x40, 0x7f, 0xff] {
        let c = Ctap::from_byte(b);
        assert_eq!(c, Ctap::Unknown, "{b:#04x} unexpectedly known");
        assert!(!c.needs_presence(), "{b:#04x} is refused but still prompts");
    }
}

#[test]
fn the_preview_cred_mgmt_command_routes_like_the_real_one() {
    // 0x41 is the vendor-preview alias every shipping client still
    // sends. Routing it differently from 0x0a would give two clients
    // two different authenticators.
    assert_eq!(Ctap::from_byte(0x41), Ctap::CredMgmt);
    assert_eq!(Ctap::from_byte(0x0a), Ctap::CredMgmt);
    assert_eq!(
        Ctap::from_byte(0x41).needs_presence(),
        Ctap::from_byte(0x0a).needs_presence()
    );
}

// ---------- routing carries the gate, so the caller cannot forget ----------

#[test]
fn routing_resolves_the_gate_rather_than_leaving_it_to_the_caller() {
    // The old shape was a match arm per command, each with its own
    // hand-written `if !await_user_presence(..)`. Adding an arm and
    // forgetting the paste was an ungated signing command that looked
    // exactly like the ones around it. Now the answer comes back with
    // the route.
    match route(CID, CMD_CBOR, &[0x01]) {
        Route::Cbor { cmd, presence } => {
            assert_eq!(cmd, Ctap::MakeCredential);
            assert!(presence, "routing did not carry the gate");
        }
        r => panic!("makeCredential routed to {r:?}"),
    }
    match route(CID, CMD_CBOR, &[0x04]) {
        Route::Cbor { cmd, presence } => {
            assert_eq!(cmd, Ctap::GetInfo);
            assert!(!presence);
        }
        r => panic!("getInfo routed to {r:?}"),
    }
}

#[test]
fn the_gate_is_decided_by_the_command_byte_and_nothing_else() {
    // Trailing bytes are the request's parameters. If any of them could
    // move the gate, a host would choose whether it needs to touch.
    for extra in [vec![], vec![0xa0], vec![0xff; 64], vec![0x00; 300]] {
        let mut msg = vec![0x01u8];
        msg.extend_from_slice(&extra);
        match route(CID, CMD_CBOR, &msg) {
            Route::Cbor { presence, .. } => {
                assert!(
                    presence,
                    "makeCredential lost its gate with {} trailing bytes",
                    extra.len()
                )
            }
            r => panic!("routed to {r:?}"),
        }
    }
}

// ---------- reserved channels (CTAP 2.1 sec. 11.2.3) ----------

#[test]
fn a_transaction_on_a_reserved_channel_is_refused() {
    // CID 0 and the broadcast CID are shared by every host that has not
    // been allocated a channel. Serving a transaction on one runs it on
    // a channel with no owner: two hosts interleave with no arbitration
    // and the response goes to whoever else is listening. The C port
    // has refused this since it was written; the Non-secure image
    // served it.
    for cid in [RESERVED_CID, BROADCAST_CID] {
        for (cmd, msg) in [
            (CMD_CBOR, vec![0x04u8]),
            (CMD_CBOR, vec![0x01u8]),
            (CMD_PING, vec![0xAAu8; 8]),
        ] {
            assert_eq!(
                route(cid, cmd, &msg),
                Route::Error(ERR_INVALID_CHANNEL),
                "cmd {cmd:#04x} was served on reserved channel {cid:#x}"
            );
        }
    }
}

#[test]
fn a_reserved_channel_cannot_reach_a_signing_path() {
    // The consequence, stated as itself: makeCredential on the broadcast
    // channel must not become a gesture prompt whose result is delivered
    // to an unowned channel.
    assert!(matches!(
        route(BROADCAST_CID, CMD_CBOR, &[0x01]),
        Route::Error(_)
    ));
    assert!(matches!(
        route(RESERVED_CID, CMD_CBOR, &[0x02]),
        Route::Error(_)
    ));
}

#[test]
fn init_is_the_one_command_a_reserved_channel_may_carry() {
    // Because asking for a channel is what the broadcast CID is for.
    assert_eq!(
        route(BROADCAST_CID, CMD_INIT, &NONCE),
        Route::Init { fresh: true }
    );
}

// ---------- INIT (CTAP 2.1 sec. 11.2.9.1.3) ----------

#[test]
fn init_on_an_allocated_channel_is_answered() {
    // sec. 11.2.9.1.3's other half: on an allocated CID, INIT resynchronises
    // that channel. It is what a host sends when it has lost track of a
    // transaction -- the recovery move. The Non-secure image used to
    // require the broadcast CID and drop this on the floor, so a wedged
    // channel stayed wedged: the host's one recourse got no answer and
    // it timed out instead.
    assert_eq!(route(CID, CMD_INIT, &NONCE), Route::Init { fresh: false });
    assert_eq!(route(1, CMD_INIT, &NONCE), Route::Init { fresh: false });
}

#[test]
fn init_takes_exactly_eight_bytes_of_nonce() {
    // A longer payload would have eight bytes of whatever followed
    // echoed back as the host's nonce -- and the nonce is how a host
    // matches the reply to its own request when several are in flight.
    assert_eq!(
        route(BROADCAST_CID, CMD_INIT, &NONCE),
        Route::Init { fresh: true }
    );
    for len in [0usize, 1, 7, 9, 16, 64] {
        let msg = vec![0xABu8; len];
        assert_eq!(
            route(BROADCAST_CID, CMD_INIT, &msg),
            Route::Error(ERR_INVALID_LEN),
            "INIT accepted a {len}-byte payload"
        );
    }
}

#[test]
fn a_short_init_is_refused_before_the_nonce_is_read() {
    // handle_message copies msg[0..8] unconditionally in the Init arm.
    // That is only sound because routing has already rejected anything
    // shorter -- this test is what makes the slice safe.
    for len in 0..8usize {
        assert!(
            matches!(
                route(BROADCAST_CID, CMD_INIT, &vec![0u8; len]),
                Route::Error(_)
            ),
            "a {len}-byte INIT reached the Init arm, which would slice msg[0..8]"
        );
    }
}

// ---------- PING and CBOR ----------

#[test]
fn ping_routes_on_an_allocated_channel_at_any_length() {
    for len in [0usize, 1, 57, 58, 59, 1024, 7609] {
        assert_eq!(
            route(CID, CMD_PING, &vec![0x5Au8; len]),
            Route::Ping,
            "len {len}"
        );
    }
}

#[test]
fn an_empty_cbor_message_is_refused_rather_than_ignored() {
    // No command byte to demux on. Ignoring it -- which is what the old
    // code did, by falling through its `if !msg.is_empty()` guard to the
    // catch-all -- leaves the host waiting for a reply that never comes,
    // when the answer is one error frame.
    assert_eq!(route(CID, CMD_CBOR, &[]), Route::Error(ERR_INVALID_LEN));
}

#[test]
fn an_unknown_ctaphid_command_is_left_to_the_vendor_arm() {
    // Routing does not know which vendor commands a build has; that
    // depends on `dev-escape`. Its job is only to say that nothing above
    // claimed the message.
    for cmd in [0xc0u8, 0xc1, 0xc5, 0xd1, 0xbb, 0x83, 0x00] {
        assert_eq!(route(CID, cmd, &[0u8; 4]), Route::Other, "cmd {cmd:#04x}");
    }
}

#[test]
fn the_ctaphid_command_bytes_carry_the_init_frame_bit() {
    // Every one of these is compared against byte 4 of an init frame,
    // which always has 0x80 set. A constant written without it matches
    // nothing at all, and the symptom is a command that is simply never
    // served.
    for (name, cmd) in [("PING", CMD_PING), ("INIT", CMD_INIT), ("CBOR", CMD_CBOR)] {
        assert_eq!(
            cmd & 0x80,
            0x80,
            "{name} constant is missing the init-frame bit"
        );
    }
    assert_eq!(CMD_PING, 0x81);
    assert_eq!(CMD_INIT, 0x86);
    assert_eq!(CMD_CBOR, 0x90);
}

#[test]
fn the_error_codes_match_the_c_port() {
    // Same wire, same numbers. c/firmware/src/ctaphid.h.
    assert_eq!(ERR_INVALID_LEN, 0x03);
    assert_eq!(ERR_INVALID_CHANNEL, 0x0b);
}

#[test]
fn init_on_the_broadcast_channel_allocates_and_on_an_allocated_one_does_not() {
    // sec. 11.2.9.1.3 has two halves and they differ in exactly this bit: a
    // broadcast INIT asks for a channel, an allocated-CID INIT asks for
    // the channel it arrived on to be reset and answered as itself.
    assert_eq!(
        route(BROADCAST_CID, CMD_INIT, &NONCE),
        Route::Init { fresh: true }
    );
    assert_eq!(route(CID, CMD_INIT, &NONCE), Route::Init { fresh: false });
}

#[test]
fn wink_is_answered_not_ignored() {
    // CAPS advertises WINK. Advertising it and answering nothing reads
    // to a host as a hung device.
    assert_eq!(route(CID, CMD_WINK, &[]), Route::Wink);
    assert_eq!(route(CID, CMD_WINK, &[1, 2, 3]), Route::Wink);
    // ...but never on a reserved channel.
    assert!(matches!(
        route(BROADCAST_CID, CMD_WINK, &[]),
        Route::Error(_)
    ));
}
