// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! What a fully-reassembled CTAPHID message resolves to.
//!
//! `handle_message` used to decide this inline, in a 274-line match
//! that could only run with a USB bus and the Secure gateway both
//! present -- so the routing was the one part of the Non-secure image
//! that no host test could reach, while its parsers (`ctapreq`) and its
//! transport (`fido_hid`) were both covered.
//!
//! That is the wrong thing to leave uncovered, because the routing is
//! where the presence gate lives. Whether a command needs a touch is
//! decided here and nowhere else: `handle_message` asks, and Secure
//! trusts the answer. A command added to the CBOR match without a
//! gesture is a signing operation that never asks anyone -- and the
//! shape of the old code, a `match` where the gated arms each carried
//! their own hand-written `if !await_user_presence(..)` block, made
//! exactly that omission easy and invisible.
//!
//! So the decision is a function over one byte, and
//! `every_ctap2_command_is_classified_deliberately` in the test suite
//! enumerates all 256 of them. Adding a command without deciding its
//! gate is now a test failure rather than a silent one.
//!
//! Nothing here touches USB, the gateway, or any buffer.

use crate::ctapreq::{
    CTAP2_CLIENT_PIN, CTAP2_CONFIG, CTAP2_CRED_MGMT, CTAP2_CRED_MGMT_PRE, CTAP2_GET_ASSERTION,
    CTAP2_GET_INFO, CTAP2_GET_NEXT_ASSERTION, CTAP2_MAKE_CREDENTIAL, CTAP2_SELECTION,
};

// CTAPHID commands, with the init-frame bit already set (CTAP 2.1 sec. 11.2).
pub const CMD_PING: u8 = 0x81;
pub const CMD_INIT: u8 = 0x86;
pub const CMD_WINK: u8 = 0x88;
pub const CMD_CBOR: u8 = 0x90;

/// Reserved channel ids (CTAP 2.1 sec. 11.2.3).
pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;
pub const RESERVED_CID: u32 = 0;

// CTAPHID error codes, matching c/firmware/src/ctaphid.h.
pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_CHANNEL: u8 = 0x0b;

/// CTAPHID_INIT's payload is a fixed 8-byte nonce (sec. 11.2.9.1.3).
pub const INIT_NONCE_LEN: usize = 8;

/// The CTAP2 commands this image demuxes.
///
/// `Unknown` is a variant rather than an `Option` so that
/// `needs_presence` is total: there is no way to ask about a command
/// and get no answer, and the unknown case answers `false` only because
/// it is refused before anything runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ctap {
    MakeCredential,
    GetAssertion,
    GetNextAssertion,
    GetInfo,
    ClientPin,
    Selection,
    Config,
    CredMgmt,
    Unknown,
}

impl Ctap {
    pub const fn from_byte(b: u8) -> Self {
        match b {
            CTAP2_MAKE_CREDENTIAL => Ctap::MakeCredential,
            CTAP2_GET_ASSERTION => Ctap::GetAssertion,
            CTAP2_GET_NEXT_ASSERTION => Ctap::GetNextAssertion,
            CTAP2_GET_INFO => Ctap::GetInfo,
            CTAP2_CLIENT_PIN => Ctap::ClientPin,
            CTAP2_SELECTION => Ctap::Selection,
            CTAP2_CONFIG => Ctap::Config,
            CTAP2_CRED_MGMT | CTAP2_CRED_MGMT_PRE => Ctap::CredMgmt,
            _ => Ctap::Unknown,
        }
    }

    /// Must a user gesture be confirmed before this command runs?
    ///
    /// The list is short and each absence is deliberate:
    ///
    /// - **makeCredential, getAssertion** -- the two that sign. CTAP 2.1
    ///   sec. 6.1.2 and sec. 6.2.2 both require user presence when `up` is set,
    ///   which this image always treats as set.
    /// - **selection** -- sec. 6.7 is the command whose entire purpose is
    ///   "prove a human is at this authenticator", so the gate is the
    ///   whole command.
    /// - **clientPin** -- deliberately not gated. sec. 6.5 does not require
    ///   presence, and demanding a touch to read `getPinRetries` would
    ///   make the retry counter unreadable by a client trying to tell
    ///   the user how many attempts remain: a denial of service built
    ///   out of a security control.
    /// - **getInfo, getNextAssertion** -- sec. 6.4 and sec. 6.3. getInfo is the
    ///   discovery command every client sends unprompted; gating it
    ///   would mean a touch to enumerate the device. getNextAssertion
    ///   continues an assertion whose gesture was already collected, and
    ///   asking again would mean one touch per credential.
    /// - **credentialManagement, config** -- sec. 6.8 and sec. 6.11 are gated by
    ///   a pinUvAuthToken instead, checked in the Secure world. A touch
    ///   here would be an additional prompt, not a replacement for that
    ///   check, and Secure is where the decision belongs because Secure
    ///   holds the token.
    /// - **Unknown** -- refused before it runs, so the answer is moot;
    ///   `false` keeps a rejected command from prompting for a touch it
    ///   has no use for.
    pub const fn needs_presence(self) -> bool {
        matches!(
            self,
            Ctap::MakeCredential | Ctap::GetAssertion | Ctap::Selection
        )
    }
}

/// What to do with one fully-reassembled message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Route {
    /// Reply to INIT with the nonce echoed back. `fresh` says whether to
    /// allocate a channel: true on the broadcast CID, false on an
    /// allocated one, where sec. 11.2.9.1.3 has the response carry the SAME
    /// CID -- the host is resynchronising that channel, not asking for
    /// another. Both this image and the C port used to hand back a fresh
    /// CID either way, quietly moving a recovering host to a new channel.
    Init { fresh: bool },
    /// Echo the payload through the Secure gateway.
    Ping,
    /// WINK: acknowledge with an empty WINK frame. This image advertised
    /// the capability and answered nothing, which a host reads as a hung
    /// device.
    Wink,
    /// A CTAP2 command; `presence` is `Ctap::needs_presence`, resolved
    /// here so the caller cannot forget to ask.
    Cbor { cmd: Ctap, presence: bool },
    /// Reply with a CTAPHID error frame carrying this code.
    Error(u8),
    /// A vendor command (`cmd`), or one this image does not serve.
    /// Which vendor commands exist depends on `dev-escape`, so the
    /// caller matches on the byte; routing's job is only to say that
    /// nothing above claimed it.
    Other,
}

/// Route one message. Pure: no USB, no gateway, no buffers.
///
/// The channel rules come first because they are unconditional. CTAP 2.1
/// sec. 11.2.3 reserves CID 0 and the broadcast CID, and both are shared by
/// every host that has not been allocated a channel yet. Serving a
/// transaction on one runs it on a channel with no owner: two hosts
/// interleave with no arbitration and a response goes to whoever else
/// is listening. INIT is the sole exception, because requesting a
/// channel is what the broadcast CID is *for*.
pub fn route(cid: u32, cmd: u8, msg: &[u8]) -> Route {
    if cmd == CMD_INIT {
        // sec. 11.2.9.1.3: the payload is exactly an 8-byte nonce. Accepting
        // a longer one would echo eight bytes of whatever followed and
        // call it the host's nonce.
        if msg.len() != INIT_NONCE_LEN {
            return Route::Error(ERR_INVALID_LEN);
        }
        // Valid on any channel: on the broadcast CID it allocates, and
        // on an allocated one it resynchronises a channel whose state
        // the host has lost. Refusing the second is why a wedged
        // channel used to stay wedged -- the host's recovery move got
        // no answer at all.
        return Route::Init {
            fresh: cid == BROADCAST_CID,
        };
    }

    if cid == RESERVED_CID || cid == BROADCAST_CID {
        return Route::Error(ERR_INVALID_CHANNEL);
    }

    match cmd {
        CMD_PING => Route::Ping,
        CMD_WINK => Route::Wink,
        // An empty CBOR message has no command byte to demux on.
        // sec. 11.2.9.1.2 gives it a length of at least one.
        CMD_CBOR if msg.is_empty() => Route::Error(ERR_INVALID_LEN),
        CMD_CBOR => {
            let cmd = Ctap::from_byte(msg[0]);
            Route::Cbor {
                cmd,
                presence: cmd.needs_presence(),
            }
        }
        _ => Route::Other,
    }
}
