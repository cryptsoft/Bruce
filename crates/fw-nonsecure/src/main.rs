// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Non-secure image -- Milestone 3 of the TrustZone-M split.
//! See `docs/TRUSTZONE.md`.
//!
//! Launched by the Secure image via BXNS, with no access to keys, the
//! TRNG, or flash. It runs the USB + FIDO HID + CTAPHID transport and
//! now **demuxes CTAP2 CBOR commands** (M3): the CBOR command byte is
//! read Non-secure -- the historical parser attack surface is
//! unprivileged -- and dispatched to a Secure command gateway.
//! `authenticatorGetInfo` (0x04) -> `sg_get_info`; PING still echoes
//! through `sg_echo`. This is the command-flow pattern M4 extends to
//! MakeCredential/GetAssertion (which will actually touch Secure keys).
//!
//! Scope: single-frame CTAPHID only (payload <= 57 bytes) -- getInfo's
//! response fits one frame. Multi-frame reassembly + the full CTAP2
//! surface come with M4. USB is polled, no IRQ.

#![no_std]
#![no_main]

mod fido_hid;

use cortex_m_rt::entry;
use fido_hid::{FidoHidClass, FIDO_HID_FRAME_LEN};
use panic_halt as _;
use rp235x_hal as hal;
mod cborr;
mod ctapreq;
mod route;
use crate::ctapreq::*;

use usb_device::bus::UsbBusAllocator;
use usb_device::device::{StringDescriptors, UsbDeviceBuilder, UsbVidPid};
// Only the dev-escape check-in looks at the enumeration state.
#[cfg(feature = "dev-escape")]
use usb_device::device::UsbDeviceState;
use usb_device::LangID;

extern "C" {
    /// Secure gateway: echo a buffer (NS->Secure->NS). See `fw-secure`.
    fn sg_echo(in_ptr: *const u8, in_len: usize, out_ptr: *mut u8, out_cap: usize) -> usize;
    /// Secure gateway: authenticatorGetInfo -- writes the response bytes
    /// (status + CBOR) into the NS buffer, returns the length.
    fn sg_get_info(out_ptr: *mut u8, out_cap: usize) -> usize;

    /// M4f: the composite PQ/T algorithm id is NOT hardcoded here. NS
    /// reads it out of getInfo at boot, so the Non-secure and Secure
    /// images cannot disagree about which ML-DSA level this build is --
    /// a mismatch would otherwise be silent and issue credentials under
    /// an algorithm the client never offered.
    ///
    /// M4e: CTAP2 MakeCredential / GetAssertion. Both take the same
    /// fixed-layout request buffer and return status byte + CBOR.
    fn sg_ctap_make_credential(
        req: *const u8,
        req_len: usize,
        out: *mut u8,
        out_cap: usize,
    ) -> usize;
    /// CTAP2 GetNextAssertion. No user-presence wait: the gesture that
    /// started the sequence authorised the whole of it.
    fn sg_ctap_get_next_assertion(out: *mut u8, out_cap: usize) -> usize;

    /// CTAP2 authenticatorCredentialManagement.
    fn sg_ctap_cred_mgmt(req: *const u8, req_len: usize, out: *mut u8, out_cap: usize) -> usize;

    /// CTAP2 authenticatorSelection: presence only, no payload.
    fn sg_ctap_selection(out: *mut u8, out_cap: usize) -> usize;

    /// CTAP2 authenticatorConfig (setMinPINLength).
    fn sg_ctap_config(req: *const u8, req_len: usize, out: *mut u8, out_cap: usize) -> usize;

    /// CTAP2 authenticatorClientPIN. Fixed-layout request, status byte
    /// plus CBOR back.
    fn sg_ctap_client_pin(req: *const u8, req_len: usize, out: *mut u8, out_cap: usize) -> usize;

    fn sg_ctap_get_assertion(req: *const u8, req_len: usize, out: *mut u8, out_cap: usize)
        -> usize;

    /// M4g: user presence. NS drives the timing only -- it opens a
    /// window and polls while pumping USB, because the wait is seconds
    /// long and the host needs KEEPALIVE meanwhile. The decision is
    /// entirely Secure's; all NS can do by lying is deny itself service.
    /// Does the Secure world already hold this credential for this
    /// relying party? Needed for the excludeList check, which CTAP2
    /// makes a MUST.
    fn sg_cred_is_ours(rp_id: *const u8, rp_id_len: usize, cred_id: *const u8) -> u8;

    fn sg_up_begin();
    fn sg_up_poll() -> u8;
    /// Test-only one-shot simulated gesture.
    #[cfg(feature = "dev-escape")]
    fn sg_up_inject(mode: u8);
    /// Test-only: raw button state, no gesture logic.
    #[cfg(feature = "dev-escape")]
    fn sg_up_raw() -> u8;
    #[cfg(feature = "dev-escape")]
    fn sg_up_probe() -> u32;

    /// Dev escape hatch: reboot to BOOTSEL. Never returns.
    #[cfg(feature = "dev-escape")]
    fn sg_reboot_bootsel();

    /// M4c: create a credential. In rp_id_hash[32], client_data_hash[32];
    /// out credential_id[64] || public_key[64] || signature[64].
    #[cfg(feature = "dev-escape")]
    fn sg_make_credential(rp_id_hash: *const u8, cdh: *const u8, out: *mut u8) -> usize;

    /// M4c: assert a credential. In rp_id_hash[32], client_data_hash[32],
    /// credential_id[64]; out signature[64].
    #[cfg(feature = "dev-escape")]
    fn sg_get_assertion(
        rp_id_hash: *const u8,
        cdh: *const u8,
        cred_id: *const u8,
        out: *mut u8,
    ) -> usize;

    /// Dev escape hatch: disarm the Secure dead-man's switch. Must be
    /// called once USB is up, or the Secure world will conclude this
    /// image is broken and drop to BOOTSEL after a few resets.
    #[cfg(feature = "dev-escape")]
    fn sg_healthy();
}

// CTAPHID constants (CTAP 2.1 sec. 11.2). They live in `route`, next to the
// rules that use them, so the dispatch below and the routing decision
// cannot end up disagreeing about what a command byte means.
use crate::route::{
    route, Ctap, Route, BROADCAST_CID, CMD_CBOR, CMD_INIT, CMD_PING, CMD_WINK, ERR_INVALID_CMD,
    ERR_INVALID_LEN,
};
/// Vendor reboot, same id and payload as the main firmware's CMD_REBOOT
/// (0x51 | 0x80) so the existing host reboot tooling drives this image
/// unmodified. Payload: one mode byte, 0x01 = BOOTSEL.
#[cfg(feature = "dev-escape")]
const CMD_REBOOT: u8 = 0xd1;
#[cfg(feature = "dev-escape")]
const REBOOT_BOOTSEL: u8 = 0x01;
const CAPS: u8 = 0x01 | 0x04 | 0x08; // WINK | CBOR | NMSG (matches the FIDO firmware)

/// M4c vendor commands. Raw binary rather than CBOR: the Secure world
/// has no allocator and no CBOR encoder yet, so the CTAP2 wrapper is
/// still to come. What these prove is the boundary property -- the
/// signing key is derived, used and destroyed inside Secure, and NS
/// never sees key material.
#[cfg(feature = "dev-escape")]
const CMD_MAKE_CRED: u8 = 0xc0; // 0x40 | 0x80
/// Test-only: queue a simulated touch. Vendor command, dev builds only.
#[cfg(feature = "dev-escape")]
const CMD_UP_INJECT: u8 = 0xc2; // 0x42 | 0x80
#[cfg(feature = "dev-escape")]
const CMD_UP_RAW: u8 = 0xc3; // 0x43 | 0x80
#[cfg(feature = "dev-escape")]
const CMD_UP_PROBE: u8 = 0xc4; // 0x44 | 0x80
/// Test-only: echo the last CBOR request this image received.
///
/// Earned its place immediately: CredentialManagement was failing with
/// INVALID_CBOR and three plausible theories all proved wrong. The
/// bytes settled it in one flash cycle.
///
/// The gap this fills: a parse failure surfaces as one status byte, and
/// a status byte cannot tell you which field of which encoding the
/// parser tripped over. Guessing at that from the spec costs a flash
/// cycle per hypothesis.
#[cfg(feature = "dev-escape")]
const CMD_LAST_CBOR: u8 = 0xc5; // 0x45 | 0x80

/// Last CBOR request, captured for CMD_LAST_CBOR.
#[cfg(feature = "dev-escape")]
static mut LAST_CBOR: [u8; 128] = [0u8; 128];
#[cfg(feature = "dev-escape")]
static mut LAST_CBOR_LEN: usize = 0;
/// CTAPHID KEEPALIVE, and the status that tells the host to prompt for
/// a touch rather than assume the device has hung.
const CMD_KEEPALIVE: u8 = 0xbb; // 0x3b | 0x80
const KEEPALIVE_UPNEEDED: u8 = 0x02;
const UP_CONFIRMED: u8 = 1;
const UP_TIMEOUT: u8 = 2;
const CTAP2_ERR_UP_REQUIRED: u8 = 0x27;
#[cfg(feature = "dev-escape")]
const CMD_GET_ASSERT: u8 = 0xc1; // 0x41 | 0x80
#[cfg(feature = "dev-escape")]
const HASH_LEN: usize = 32;
#[cfg(feature = "dev-escape")]
const CRED_ID_LEN: usize = 64;
#[cfg(feature = "dev-escape")]
const MAKE_RESP_LEN: usize = CRED_ID_LEN + 64 + 64; // id || pubkey || sig
#[cfg(feature = "dev-escape")]
const SIG_LEN: usize = 64;

/// CTAPHID error frame. The codes it can carry live in `route`.
const CMD_ERROR: u8 = 0xbf; // 0x3f | 0x80

/// Largest CTAP message NS will reassemble (M4a).
///
/// NS owns the transport, so the reassembly buffer is Non-secure by
/// design: it holds a message the host sent in the clear, and every
/// Secure gateway copies the arguments it needs out of it under an
/// `ns_readable` check. Nothing secret is ever staged here.
///
/// 7609, matching `ctap::MAX_MSG_SIZE` in the Secure image, which is
/// what getInfo advertises. Raised from 2048 for M4f: an ML-DSA-87
/// assertion is a 4627-byte signature plus the ECDSA DER, and the
/// attestation object carries a 2592-byte public key.
///
/// The buffers this sizes are statics, not stack locals. At this size
/// three of them on a 64 KiB Non-secure stack is not obviously safe,
/// and "probably fits" is not a good property for the thing that
/// overflows into a guard page. NS SRAM is 256 KiB, so this is
/// cheap; it is capped only to keep a hostile host from claiming a
/// length NS would spend the whole boot collecting.
const MAX_MSG: usize = 7609;

/// CTAPHID continuation frames carry 59 payload bytes; init frames 57.
const CONT_PAYLOAD: usize = FIDO_HID_FRAME_LEN - 5;
const INIT_PAYLOAD: usize = FIDO_HID_FRAME_LEN - 7;

/// In-progress reassembly of one multi-frame CTAPHID message.
///
/// Single-channel: this image serves one transaction at a time, so a
/// frame for a different CID while a message is in flight is dropped
/// rather than interleaved. The real firmware arbitrates channels; that
/// is transport policy and stays Non-secure either way.
/// Reassembly state and the response staging buffer, both static.
static mut REASM: Reassembly = Reassembly::new();
static mut OUT_BUF: [u8; MAX_MSG] = [0u8; MAX_MSG];

struct Reassembly {
    active: bool,
    cid: u32,
    cmd: u8,
    total: usize,
    got: usize,
    next_seq: u8,
    buf: [u8; MAX_MSG],
}

impl Reassembly {
    const fn new() -> Self {
        Self {
            active: false,
            cid: 0,
            cmd: 0,
            total: 0,
            got: 0,
            next_seq: 0,
            buf: [0u8; MAX_MSG],
        }
    }

    /// Start a message from an init frame. Returns false if the host
    /// declared a length we will not buffer.
    fn begin(&mut self, cid: u32, cmd: u8, total: usize, first: &[u8]) -> bool {
        if total > MAX_MSG {
            self.active = false;
            return false;
        }
        self.active = true;
        self.cid = cid;
        self.cmd = cmd;
        self.total = total;
        self.next_seq = 0;
        let n = first.len().min(total);
        self.buf[..n].copy_from_slice(&first[..n]);
        self.got = n;
        true
    }

    /// Absorb a continuation frame. Out-of-order sequence numbers abort
    /// the message: silently accepting them would let a host splice
    /// frames into a half-built request.
    fn cont(&mut self, cid: u32, seq: u8, data: &[u8]) -> bool {
        if !self.active || cid != self.cid || seq != self.next_seq {
            return false;
        }
        self.next_seq = self.next_seq.wrapping_add(1);
        let want = (self.total - self.got).min(data.len());
        self.buf[self.got..self.got + want].copy_from_slice(&data[..want]);
        self.got += want;
        true
    }

    fn complete(&self) -> bool {
        self.active && self.got >= self.total
    }

    fn message(&self) -> &[u8] {
        &self.buf[..self.total]
    }
}

/// Send a CTAPHID response of any length, splitting into an init frame
/// plus continuation frames.
fn send_message<B: usb_device::bus::UsbBus>(
    usb_dev: &mut usb_device::device::UsbDevice<B>,
    hid: &mut FidoHidClass<B>,
    cid: u32,
    cmd: u8,
    payload: &[u8],
) {
    let mut frame = [0u8; FIDO_HID_FRAME_LEN];
    frame[0..4].copy_from_slice(&cid.to_be_bytes());
    frame[4] = cmd;
    frame[5] = (payload.len() >> 8) as u8;
    frame[6] = payload.len() as u8;
    let first = payload.len().min(INIT_PAYLOAD);
    frame[7..7 + first].copy_from_slice(&payload[..first]);
    push_frame(usb_dev, hid, &frame);

    let mut off = first;
    let mut seq: u8 = 0;
    while off < payload.len() {
        let n = (payload.len() - off).min(CONT_PAYLOAD);
        frame = [0u8; FIDO_HID_FRAME_LEN];
        frame[0..4].copy_from_slice(&cid.to_be_bytes());
        frame[4] = seq; // bit 7 clear marks a continuation frame
        frame[5..5 + n].copy_from_slice(&payload[off..off + n]);
        push_frame(usb_dev, hid, &frame);
        off += n;
        seq = seq.wrapping_add(1);
    }
}

/// Write one frame, pumping USB so the IN endpoint drains.
fn push_frame<B: usb_device::bus::UsbBus>(
    usb_dev: &mut usb_device::device::UsbDevice<B>,
    hid: &mut FidoHidClass<B>,
    frame: &[u8; FIDO_HID_FRAME_LEN],
) {
    loop {
        match hid.send_frame(frame) {
            Ok(_) => break,
            Err(usb_device::UsbError::WouldBlock) => {
                usb_dev.poll(&mut [hid]);
            }
            Err(_) => break,
        }
    }
}

/// M5 negative self-test: the gateway must REFUSE a Secure pointer.
///
/// Every SAU region configured by the Secure image marks NS space
/// explicitly (NS flash from 0x1010_0000, NS RAM from 0x2007_0000), so
/// anything below those is Secure. Handing such an address to a veneer
/// is precisely the attack the M5 range checks exist to stop: without
/// them, `sg_echo` is an arbitrary Secure read *and* write, and
/// `sg_get_info` an arbitrary Secure write, both executed with Secure
/// privilege on NS's behalf.
///
/// Fail CLOSED. If a veneer accepts a Secure address this returns
/// false and `main` refuses to bring USB up, so a token that enumerates
/// is a token whose gateway rejected the probe. A self-test that only
/// logged would be worthless -- nobody reads logs from a FIDO key.
fn gateway_rejects_secure_pointers() -> bool {
    const SECURE_RAM: usize = 0x2000_0000; // NS RAM starts at 0x2007_0000
    const SECURE_FLASH: usize = 0x1000_0000; // NS flash starts at 0x1010_0000
    let mut ns_buf = [0u8; 32]; // exactly one hash argument

    unsafe {
        // Secure SOURCE: would leak Secure memory out to NS.
        if sg_echo(
            SECURE_RAM as *const u8,
            32,
            ns_buf.as_mut_ptr(),
            ns_buf.len(),
        ) != 0
        {
            return false;
        }
        // Secure DESTINATION: would let NS scribble on Secure memory.
        if sg_echo(ns_buf.as_ptr(), 32, SECURE_RAM as *mut u8, 32) != 0 {
            return false;
        }
        if sg_get_info(SECURE_FLASH as *mut u8, 64) != 0 {
            return false;
        }
        // M4c veneers. The design note is explicit that the range check
        // is not per-veneer boilerplate but the boundary's only defence,
        // and that one veneer forgetting it reopens the whole hole -- so
        // every gateway gets probed here as it is added.
        //
        // These two exist only in dev builds: they are a test protocol
        // for the boundary and, unlike the CTAP2 path, are not
        // presence-gated, so a production image does not carry them and
        // there is nothing here to probe.
        #[cfg(feature = "dev-escape")]
        {
            let cred = [0u8; 64];
            let mut out = [0u8; 192];
            // Secure SOURCE for each input in turn.
            if sg_make_credential(SECURE_RAM as *const u8, ns_buf.as_ptr(), out.as_mut_ptr()) != 0 {
                return false;
            }
            if sg_make_credential(ns_buf.as_ptr(), SECURE_RAM as *const u8, out.as_mut_ptr()) != 0 {
                return false;
            }
            // Secure DESTINATION: would let NS have Secure write to itself.
            if sg_make_credential(ns_buf.as_ptr(), ns_buf.as_ptr(), SECURE_RAM as *mut u8) != 0 {
                return false;
            }
            if sg_get_assertion(
                SECURE_RAM as *const u8,
                ns_buf.as_ptr(),
                cred.as_ptr(),
                out.as_mut_ptr(),
            ) != 0
            {
                return false;
            }
            if sg_get_assertion(
                ns_buf.as_ptr(),
                ns_buf.as_ptr(),
                SECURE_RAM as *const u8,
                out.as_mut_ptr(),
            ) != 0
            {
                return false;
            }
            if sg_get_assertion(
                ns_buf.as_ptr(),
                ns_buf.as_ptr(),
                cred.as_ptr(),
                SECURE_RAM as *mut u8,
            ) != 0
            {
                return false;
            }
        }

        // M4e veneers, same treatment.
        let mut req = [0u8; REQ_LEN];
        let mut big = [0u8; 512];
        // Zeroed requests for the command gateways: each is structurally
        // invalid, which is what we want -- the probes are about pointer
        // range checks, and a valid request would run a keygen on every
        // boot.
        let cm_req = [0u8; CM_REQ_LEN];
        let cfg_req = [0u8; CONFIG_REQ_LEN];
        let pin_req = [0u8; PIN_REQ_LEN];
        if sg_ctap_make_credential(
            SECURE_RAM as *const u8,
            REQ_LEN,
            big.as_mut_ptr(),
            big.len(),
        ) != 0
        {
            return false;
        }
        if sg_ctap_make_credential(req.as_ptr(), REQ_LEN, SECURE_RAM as *mut u8, 512) != 0 {
            return false;
        }
        if sg_ctap_get_assertion(
            SECURE_RAM as *const u8,
            REQ_LEN,
            big.as_mut_ptr(),
            big.len(),
        ) != 0
        {
            return false;
        }
        if sg_ctap_get_assertion(req.as_ptr(), REQ_LEN, SECURE_RAM as *mut u8, 512) != 0 {
            return false;
        }
        // A wrong length must be refused too -- Secure sizes its own
        // copy from this, so a short buffer accepted here would read
        // past what NS actually owns.
        if sg_ctap_make_credential(req.as_ptr(), REQ_LEN - 1, big.as_mut_ptr(), big.len()) != 0 {
            return false;
        }
        // Positive control: `req` is all zeros, so rp_id_len is 0 and
        // the request is invalid -- but the veneer must still be
        // reachable and answer with a one-byte error status. Returning
        // 0 here would mean the probes above passed only because the
        // gateway does nothing at all. Deliberately not a valid request:
        // that would run a keygen on every boot.
        req[REQ_OFF_RP_LEN] = 0;
        if sg_ctap_make_credential(req.as_ptr(), REQ_LEN, big.as_mut_ptr(), big.len()) != 1 {
            return false;
        }
        if sg_ctap_get_assertion(req.as_ptr(), REQ_LEN, big.as_mut_ptr(), big.len()) != 1 {
            return false;
        }

        // The CTAP2 command gateways added after M4f. The comment above
        // says every gateway is probed as it is added, and for a while
        // that was untrue of six of them: cred_mgmt, config, client_pin,
        // selection, get_next_assertion and cred_is_ours all took
        // pointers and none was covered. Deleting a range check from any
        // of them left this self-test passing and the token enumerating
        // normally, which is precisely the outcome it exists to prevent.
        //
        // Each is probed with a Secure destination, and the ones that
        // take a request with a Secure source as well.
        if sg_ctap_cred_mgmt(cm_req.as_ptr(), CM_REQ_LEN, SECURE_RAM as *mut u8, 64) != 0 {
            return false;
        }
        if sg_ctap_cred_mgmt(
            SECURE_FLASH as *const u8,
            CM_REQ_LEN,
            big.as_mut_ptr(),
            big.len(),
        ) != 0
        {
            return false;
        }
        if sg_ctap_config(cfg_req.as_ptr(), CONFIG_REQ_LEN, SECURE_RAM as *mut u8, 64) != 0 {
            return false;
        }
        if sg_ctap_config(
            SECURE_FLASH as *const u8,
            CONFIG_REQ_LEN,
            big.as_mut_ptr(),
            big.len(),
        ) != 0
        {
            return false;
        }
        if sg_ctap_client_pin(pin_req.as_ptr(), PIN_REQ_LEN, SECURE_RAM as *mut u8, 64) != 0 {
            return false;
        }
        if sg_ctap_client_pin(
            SECURE_FLASH as *const u8,
            PIN_REQ_LEN,
            big.as_mut_ptr(),
            big.len(),
        ) != 0
        {
            return false;
        }
        if sg_ctap_selection(SECURE_RAM as *mut u8, 64) != 0 {
            return false;
        }
        if sg_ctap_get_next_assertion(SECURE_RAM as *mut u8, 64) != 0 {
            return false;
        }
        // cred_is_ours answers a bool, so 0 is both "refused" and "not
        // ours" -- the length probe below is what distinguishes them.
        if sg_cred_is_ours(SECURE_FLASH as *const u8, 11, ns_buf.as_ptr()) != 0 {
            return false;
        }
        if sg_cred_is_ours(ns_buf.as_ptr(), ns_buf.len(), SECURE_FLASH as *const u8) != 0 {
            return false;
        }

        // ...and the legitimate case must still work, or the check is
        // just breaking the gateway rather than securing it.
        if sg_get_info(ns_buf.as_mut_ptr(), ns_buf.len()) == 0 {
            return false;
        }
        // Same for the six above: a wholly NS-owned call to each must
        // come back non-zero, or every probe there passed merely because
        // the gateway does nothing. All four requests are zeroed, so
        // each is invalid and answers a one-byte error status -- which
        // is a reply, and a reply is what proves reachability.
        if sg_ctap_cred_mgmt(cm_req.as_ptr(), CM_REQ_LEN, big.as_mut_ptr(), big.len()) == 0 {
            return false;
        }
        if sg_ctap_config(
            cfg_req.as_ptr(),
            CONFIG_REQ_LEN,
            big.as_mut_ptr(),
            big.len(),
        ) == 0
        {
            return false;
        }
        if sg_ctap_client_pin(pin_req.as_ptr(), PIN_REQ_LEN, big.as_mut_ptr(), big.len()) == 0 {
            return false;
        }
        if sg_ctap_selection(big.as_mut_ptr(), big.len()) == 0 {
            return false;
        }
        // Same for M4c: a wholly NS-owned call must succeed, or the
        // probes above would pass simply by everything being broken.
        #[cfg(feature = "dev-escape")]
        {
            let cred_ok = [0u8; 32];
            let mut out_ok = [0u8; 192];
            if sg_make_credential(cred_ok.as_ptr(), cred_ok.as_ptr(), out_ok.as_mut_ptr()) == 0 {
                return false;
            }
        }
    }
    true
}

#[entry]
fn main() -> ! {
    if !gateway_rejects_secure_pointers() {
        // Do not enumerate. A gateway that honours Secure pointers is
        // worse than a dead token.
        loop {
            cortex_m::asm::wfi();
        }
    }

    let mut pac = hal::pac::Peripherals::take().unwrap();
    let clocks = hal::clocks::ClocksManager::new(pac.CLOCKS);
    let usb_bus = UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    ));

    let mut hid = FidoHidClass::new(&usb_bus);
    // The placeholder vendor id every image in this tree uses, with a
    // product id of its own so this image is never mistaken for the
    // production firmware (0xF1D0).
    let mut usb_dev = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0xcafe, 0xF1DC))
        .strings(&[StringDescriptors::new(LangID::EN_US)
            .manufacturer("Bruce")
            .product("Bruce TZ-NS (M3)")])
        .unwrap()
        .build();

    let mut next_cid: u32 = 1;

    // Dev escape: not yet checked in with the Secure world.
    #[cfg(all(feature = "dev-escape", not(feature = "test-no-checkin")))]
    let mut reported_healthy = false;

    // Ask the Secure world which composite algorithm this build speaks.
    let hybrid_alg = discover_hybrid_alg();

    // SAFETY: single-threaded, and the only reference taken. Static
    // rather than a local so a 7609-byte buffer is not on the stack.
    let reasm: &mut Reassembly = unsafe { &mut *(&raw mut REASM) };

    loop {
        // Reaching Configured means the host has enumerated us, so the
        // NS image is alive enough to be driven -- and specifically
        // alive enough to accept the CMD_REBOOT escape. Disarm the
        // dead-man's switch. Deliberately gated on Configured rather
        // than on simply reaching the loop: a build that runs but never
        // enumerates is exactly the case recovery exists for.
        #[cfg(all(feature = "dev-escape", not(feature = "test-no-checkin")))]
        if !reported_healthy && usb_dev.state() == UsbDeviceState::Configured {
            // SAFETY: FFI to the Secure gateway; takes no pointers.
            unsafe { sg_healthy() };
            reported_healthy = true;
        }

        if usb_dev.poll(&mut [&mut hid]) {
            // A dropped frame makes any in-flight reassembly wrong. Abort
            // it explicitly and tell the host, rather than letting the
            // gap surface later as a sequence mismatch that reads like a
            // host bug. The ring can overrun here because two paths poll
            // USB without draining it -- await_user_presence for up to
            // ten seconds, and push_frame while emitting a long response.
            if hid.take_overflow() && reasm.active {
                let rcid = reasm.cid;
                reasm.active = false;
                send_message(&mut usb_dev, &mut hid, rcid, CMD_ERROR, &[ERR_INVALID_LEN]);
            }
            while let Some(frame) = hid.recv_frame() {
                let cid = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
                let b4 = frame[4];

                // M4a: CTAPHID is a framed transport, and NS owns it.
                // Bit 7 of byte 4 distinguishes an init frame (command)
                // from a continuation frame (sequence number).
                if b4 & 0x80 == 0 {
                    if reasm.cont(cid, b4, &frame[5..]) && reasm.complete() {
                        let (rcid, rcmd) = (reasm.cid, reasm.cmd);
                        handle_message(
                            &mut usb_dev,
                            &mut hid,
                            &mut next_cid,
                            hybrid_alg,
                            rcid,
                            rcmd,
                            reasm.message(),
                        );
                        reasm.active = false;
                    }
                    continue;
                }

                let bcnt = ((frame[5] as usize) << 8) | frame[6] as usize;
                if !reasm.begin(cid, b4, bcnt, &frame[7..]) {
                    // Declared longer than we will buffer.
                    send_message(&mut usb_dev, &mut hid, cid, CMD_ERROR, &[ERR_INVALID_LEN]);
                    continue;
                }
                if reasm.complete() {
                    let (rcid, rcmd) = (reasm.cid, reasm.cmd);
                    handle_message(
                        &mut usb_dev,
                        &mut hid,
                        &mut next_cid,
                        hybrid_alg,
                        rcid,
                        rcmd,
                        reasm.message(),
                    );
                    reasm.active = false;
                }
            }
        }
    }
}

/// Parse an `authenticatorMakeCredential` request into the fixed layout
/// the Secure gateway accepts.
///
/// Returns Err(status) rather than a bare None so the host learns why.
/// Only the fields that reach a Secure decision are extracted:
/// clientDataHash (1), rp.id (2), pubKeyCredParams (4) to confirm ES256
/// is offered, and options (7) for `uv`. Everything else is skipped --
/// this image has no PIN, no exclude list and no extensions, and
/// pretending otherwise would be worse than not answering.

/// Read the composite PQ/T algorithm id out of getInfo.
///
/// Deliberately discovered rather than hardcoded. The id depends on the
/// ML-DSA level the *Secure* image was built with (-54/-55/-56 for
/// 44/65/87 today, still provisional), and duplicating that choice in a Non-secure constant
/// would let the two images disagree silently -- NS would accept an
/// algorithm the Secure world does not implement, or refuse one it
/// does. Asking the authority for the answer makes a mismatch
/// impossible by construction rather than merely detectable.
///
/// Returns the first advertised algorithm that is not ES256.
fn discover_hybrid_alg() -> Option<i64> {
    let mut buf = [0u8; 256];
    // SAFETY: FFI to the Secure gateway; NS-owned buffer.
    let n = unsafe { sg_get_info(buf.as_mut_ptr(), buf.len()) };
    if n < 2 || buf[0] != 0 {
        return None;
    }
    let mut r = cborr::Reader::new(&buf[1..n]);
    let entries = r.map()?;
    for _ in 0..entries {
        let key = r.uint()?;
        if key != 0x0a {
            r.skip()?;
            continue;
        }
        let count = r.array()?;
        for _ in 0..count {
            let m = r.map()?;
            let mut alg: Option<i64> = None;
            for _ in 0..m {
                let k = r.str_bytes(cborr::MAJOR_TEXT)?;
                if k == b"alg" {
                    match r.header()? {
                        (cborr::MAJOR_NINT, arg) => alg = Some(-1 - (arg as i64)),
                        _ => return None,
                    }
                } else {
                    r.skip()?;
                }
            }
            match alg {
                Some(a) if a != -7 => return Some(a),
                _ => {}
            }
        }
        return None;
    }
    None
}

/// Wait for the Secure world to confirm a user gesture.
///
/// Returns false on timeout. USB is pumped every iteration -- that is
/// the whole reason the gate is split in two rather than blocking
/// inside the veneer -- and a KEEPALIVE goes out periodically so the
/// host prompts for a touch instead of concluding the device has hung.
///
/// The pacing counter is iterations, not microseconds: TIMER0 is not in
/// ACCESSCTRL's NS allow-list, so the Non-secure world has no clock of
/// its own here. Secure rate-limits the actual button sampling, so
/// spinning fast costs nothing but power.
fn await_user_presence<B: usb_device::bus::UsbBus>(
    usb_dev: &mut usb_device::device::UsbDevice<B>,
    hid: &mut FidoHidClass<B>,
    cid: u32,
) -> bool {
    // SAFETY: FFI to the Secure gateway; takes no pointers.
    unsafe { sg_up_begin() };
    let mut spins: u32 = 0;
    loop {
        usb_dev.poll(&mut [&mut *hid]);
        // SAFETY: as above.
        match unsafe { sg_up_poll() } {
            UP_CONFIRMED => return true,
            UP_TIMEOUT => return false,
            _ => {}
        }
        spins = spins.wrapping_add(1);
        if spins % 20_000 == 0 {
            let mut frame = [0u8; FIDO_HID_FRAME_LEN];
            frame[0..4].copy_from_slice(&cid.to_be_bytes());
            frame[4] = CMD_KEEPALIVE;
            frame[6] = 1;
            frame[7] = KEEPALIVE_UPNEEDED;
            let _ = hid.send_frame(&frame);
        }
    }
}

/// Act on one fully-reassembled CTAPHID message.
///
/// Split out of the poll loop because M4a made messages multi-frame:
/// the loop's job is now reassembly, and this is where a *message* --
/// not a frame -- is served.
///
/// The decision of *what* to serve is `route::route`, which is pure and
/// tested; this function is the part that cannot be, because every arm
/// ends in a call across the TrustZone boundary. Keeping the split sharp
/// is deliberate: the presence gate below is one `if`, applied to
/// whatever routing says needs it, rather than a copy of the same three
/// lines in each signing arm. The old shape made adding an ungated
/// signing command a matter of forgetting to paste something.
fn handle_message<B: usb_device::bus::UsbBus>(
    usb_dev: &mut usb_device::device::UsbDevice<B>,
    hid: &mut FidoHidClass<B>,
    next_cid: &mut u32,
    hybrid_alg: Option<i64>,
    cid: u32,
    cmd: u8,
    msg: &[u8],
) {
    match route(cid, cmd, msg) {
        // sec. 11.2.3's reserved channels and sec. 11.2.9.1's length rules.
        // Answering rather than ignoring is the point: a host that sends
        // INIT on a channel it has lost track of is trying to recover,
        // and silence is the one response it cannot act on.
        Route::Error(code) => {
            send_message(usb_dev, hid, cid, CMD_ERROR, &[code]);
        }

        Route::Init { fresh } => {
            // Reply nonce + CID + versions + caps, on the CID the request
            // arrived on. A fresh channel is allocated only for the
            // broadcast CID; a resynchronising host gets its own CID back.
            let new_cid = if fresh {
                let c = *next_cid;
                *next_cid = next_cid.wrapping_add(1);
                if *next_cid == 0 || *next_cid == BROADCAST_CID {
                    *next_cid = 1;
                }
                c
            } else {
                cid
            };
            let mut resp = [0u8; 17];
            resp[0..8].copy_from_slice(&msg[0..8]); // echo nonce
            resp[8..12].copy_from_slice(&new_cid.to_be_bytes());
            resp[12] = 2; // CTAPHID protocol version
            resp[13] = 0; // device major
            resp[14] = 1; // device minor
            resp[15] = 0; // device build
            resp[16] = CAPS;
            send_message(usb_dev, hid, cid, CMD_INIT, &resp);
        }

        Route::Wink => {
            // The other ports blink an LED here; the protocol obligation
            // is the acknowledgement, and that is what was missing.
            send_message(usb_dev, hid, cid, CMD_WINK, &[]);
        }

        Route::Ping => {
            // Echo through the Secure gateway in 256-byte chunks (the
            // gateway's scratch buffer). Proves the NS->Secure->NS round
            // trip still holds for a message longer than one frame.
            // SAFETY: single-threaded; one message is served at a time.
            let out: &mut [u8; MAX_MSG] = unsafe { &mut *(&raw mut OUT_BUF) };
            let mut done = 0usize;
            while done < msg.len() {
                let n = (msg.len() - done).min(256);
                // SAFETY: FFI to the Secure gateway; both spans are
                // NS-owned and within their buffers.
                let got = unsafe {
                    sg_echo(
                        msg[done..].as_ptr(),
                        n,
                        out[done..].as_mut_ptr(),
                        out.len() - done,
                    )
                };
                if got == 0 {
                    break;
                }
                done += got;
            }
            send_message(usb_dev, hid, cid, CMD_PING, &out[..done]);
        }

        Route::Cbor {
            cmd: ctap,
            presence,
        } => {
            #[cfg(feature = "dev-escape")]
            {
                // SAFETY: single-threaded; one transaction at a time.
                unsafe {
                    let n = msg.len().min(128);
                    (&mut *(&raw mut LAST_CBOR))[..n].copy_from_slice(&msg[..n]);
                    LAST_CBOR_LEN = n;
                }
            }

            // SAFETY: single-threaded; one message is served at a time.
            let out: &mut [u8; MAX_MSG] = unsafe { &mut *(&raw mut OUT_BUF) };

            // The gate, once, for whatever `route` said needs it. Before
            // any parsing: a request that will be refused for want of a
            // gesture should not have had its CBOR walked first, and the
            // ten-second window is a side effect no `match` guard should
            // be hiding.
            if presence && !await_user_presence(usb_dev, hid, cid) {
                out[0] = CTAP2_ERR_UP_REQUIRED;
                send_message(usb_dev, hid, cid, CMD_CBOR, &out[..1]);
                return;
            }

            // NS demuxes the CTAP2 command and calls the matching Secure
            // command gateway. The CBOR *parsing* -- the historical risk
            // surface -- stays Non-secure; the handler that could touch
            // secrets is Secure, and takes its arguments as copied values
            // rather than pointers into this buffer, so there is nothing
            // for NS to mutate underneath it.
            let n = match ctap {
                Ctap::CredMgmt => {
                    let mut req = [0u8; CM_REQ_LEN];
                    match parse_cred_mgmt(msg, &mut req) {
                        Err(status) => {
                            out[0] = status;
                            1
                        }
                        // SAFETY: both spans NS-owned; Secure re-checks.
                        Ok(()) => unsafe {
                            sg_ctap_cred_mgmt(req.as_ptr(), CM_REQ_LEN, out.as_mut_ptr(), out.len())
                        },
                    }
                }
                // SAFETY: NS-owned buffer, bounded length.
                Ctap::Selection => unsafe { sg_ctap_selection(out.as_mut_ptr(), out.len()) },
                Ctap::Config => {
                    let mut req = [0u8; CONFIG_REQ_LEN];
                    match parse_config(msg, &mut req) {
                        Err(status) => {
                            out[0] = status;
                            1
                        }
                        // SAFETY: both spans NS-owned; Secure re-checks.
                        Ok(()) => unsafe {
                            sg_ctap_config(
                                req.as_ptr(),
                                CONFIG_REQ_LEN,
                                out.as_mut_ptr(),
                                out.len(),
                            )
                        },
                    }
                }
                Ctap::ClientPin => {
                    let mut req = [0u8; PIN_REQ_LEN];
                    match parse_client_pin(msg, &mut req) {
                        Err(status) => {
                            out[0] = status;
                            1
                        }
                        // SAFETY: both spans NS-owned; Secure re-checks
                        // each and copies the request before parsing.
                        Ok(()) => unsafe {
                            sg_ctap_client_pin(
                                req.as_ptr(),
                                PIN_REQ_LEN,
                                out.as_mut_ptr(),
                                out.len(),
                            )
                        },
                    }
                }
                // SAFETY: NS-owned buffer, bounded length.
                Ctap::GetNextAssertion => unsafe {
                    sg_ctap_get_next_assertion(out.as_mut_ptr(), out.len())
                },
                // SAFETY: as above.
                Ctap::GetInfo => unsafe { sg_get_info(out.as_mut_ptr(), out.len()) },
                Ctap::MakeCredential => {
                    let mut req = [0u8; REQ_LEN];
                    match parse_make_credential(msg, hybrid_alg, &mut req, &mut |rp, id| {
                        // SAFETY: FFI to the Secure gateway; both spans
                        // NS-owned and re-checked there.
                        unsafe { sg_cred_is_ours(rp.as_ptr(), rp.len(), id.as_ptr()) != 0 }
                    }) {
                        Err(status) => {
                            out[0] = status;
                            1
                        }
                        // SAFETY: both spans NS-owned; Secure re-checks
                        // each one and re-reads the request into its own
                        // memory before parsing it.
                        Ok(()) => unsafe {
                            sg_ctap_make_credential(
                                req.as_ptr(),
                                REQ_LEN,
                                out.as_mut_ptr(),
                                out.len(),
                            )
                        },
                    }
                }
                Ctap::GetAssertion => {
                    let mut req = [0u8; REQ_LEN];
                    match parse_get_assertion(msg, &mut req, &mut |rp, id| {
                        // SAFETY: FFI to the Secure gateway; both spans
                        // NS-owned and re-checked there. 0 = not ours,
                        // else 1 + credProtect level.
                        unsafe { sg_cred_is_ours(rp.as_ptr(), rp.len(), id.as_ptr()) }
                    }) {
                        Err(status) => {
                            out[0] = status;
                            1
                        }
                        // SAFETY: as above.
                        Ok(()) => unsafe {
                            sg_ctap_get_assertion(
                                req.as_ptr(),
                                REQ_LEN,
                                out.as_mut_ptr(),
                                out.len(),
                            )
                        },
                    }
                }
                Ctap::Unknown => {
                    out[0] = CTAP2_ERR_INVALID_COMMAND;
                    1
                }
            };
            send_message(usb_dev, hid, cid, CMD_CBOR, &out[..n]);
        }

        // Vendor commands. All of them are dev-escape only, so on a
        // shipping build this arm is `_ => {}` and nothing here exists.
        Route::Other => match cmd {
            #[cfg(feature = "dev-escape")]
            CMD_MAKE_CRED if msg.len() >= 2 * HASH_LEN => {
                let mut out = [0u8; MAKE_RESP_LEN];
                // SAFETY: FFI to the Secure gateway. All three spans are
                // NS-owned; Secure re-checks every one before touching it.
                let n = unsafe {
                    sg_make_credential(
                        msg[..HASH_LEN].as_ptr(),
                        msg[HASH_LEN..2 * HASH_LEN].as_ptr(),
                        out.as_mut_ptr(),
                    )
                };
                send_message(usb_dev, hid, cid, CMD_MAKE_CRED, &out[..n]);
            }
            #[cfg(feature = "dev-escape")]
            CMD_GET_ASSERT if msg.len() >= 2 * HASH_LEN + CRED_ID_LEN => {
                let mut out = [0u8; SIG_LEN];
                // SAFETY: as above; a credential id Secure did not issue
                // for this relying party simply returns 0 bytes.
                let n = unsafe {
                    sg_get_assertion(
                        msg[..HASH_LEN].as_ptr(),
                        msg[HASH_LEN..2 * HASH_LEN].as_ptr(),
                        msg[2 * HASH_LEN..2 * HASH_LEN + CRED_ID_LEN].as_ptr(),
                        out.as_mut_ptr(),
                    )
                };
                send_message(usb_dev, hid, cid, CMD_GET_ASSERT, &out[..n]);
            }
            #[cfg(feature = "dev-escape")]
            CMD_LAST_CBOR => {
                // SAFETY: single-threaded; one transaction at a time.
                let (buf, n) = unsafe { (&*(&raw const LAST_CBOR), LAST_CBOR_LEN) };
                send_message(usb_dev, hid, cid, CMD_LAST_CBOR, &buf[..n]);
            }
            #[cfg(feature = "dev-escape")]
            CMD_UP_PROBE => {
                // SAFETY: FFI to the Secure gateway; takes no pointers.
                let v = unsafe { sg_up_probe() };
                send_message(usb_dev, hid, cid, CMD_UP_PROBE, &v.to_le_bytes());
            }
            #[cfg(feature = "dev-escape")]
            CMD_UP_RAW => {
                // SAFETY: FFI to the Secure gateway; takes no pointers.
                let v = unsafe { sg_up_raw() };
                send_message(usb_dev, hid, cid, CMD_UP_RAW, &[v]);
            }
            #[cfg(feature = "dev-escape")]
            CMD_UP_INJECT => {
                // SAFETY: FFI to the Secure gateway; takes no pointers.
                let mode = if msg.is_empty() { 0 } else { msg[0] };
                unsafe { sg_up_inject(mode) };
                send_message(usb_dev, hid, cid, CMD_UP_INJECT, &[0]);
            }
            #[cfg(feature = "dev-escape")]
            CMD_REBOOT if !msg.is_empty() && msg[0] == REBOOT_BOOTSEL => {
                // No response: the chip re-enumerates as PICOBOOT before
                // a reply could be read. Host tooling already expects it.
                // SAFETY: FFI to the Secure gateway; takes no pointers.
                unsafe { sg_reboot_bootsel() };
            }
            // An unrecognised command gets ERR_INVALID_CMD, as in both
            // other ports. Silence here left the host waiting out a
            // timeout on every command this image does not implement.
            _ => send_message(usb_dev, hid, cid, CMD_ERROR, &[ERR_INVALID_CMD]),
        },
    }
}
