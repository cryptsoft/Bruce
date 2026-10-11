// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! USB HID class for the FIDO Alliance CTAP HID transport.
//!
//! The standard `usbd-hid` macro doesn't expose a clean way to declare
//! the FIDO usage page (0xF1D0) with the 64-byte input/output reports
//! the CTAP HID spec mandates, so we implement the class trait directly.
//! See CTAP HID spec, sec. 11.2 (Report descriptor) and sec. 11.3 (Frame
//! protocol). Matches what OpenSK and Yubico's references emit.
//!
//! This file is intentionally transport-only: it exposes a 64-byte
//! `recv_frame` / `send_frame` API to the rest of the firmware, and
//! the CTAP HID command logic (INIT / PING / CBOR / etc.) lives one
//! layer up in `src/ctaphid.rs`.

use usb_device::class_prelude::*;
use usb_device::Result;

/// HID 1.11 descriptor type.
const DESC_TYPE_HID: u8 = 0x21;
/// HID 1.11 report descriptor type.
const DESC_TYPE_REPORT: u8 = 0x22;

/// CTAP HID report descriptor. Tagged as FIDO usage page (0xF1D0),
/// usage CTAPHID (0x01), with two 64-byte data reports (input + output).
/// Byte-for-byte identical to the example in the CTAP HID spec.
#[rustfmt::skip]
const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance, 0xF1D0)
    0x09, 0x01,       // Usage (CTAPHID)
    0xA1, 0x01,       // Collection (Application)

    0x09, 0x20,       //   Usage (Input Report Data)
    0x15, 0x00,       //   Logical Min (0)
    0x26, 0xFF, 0x00, //   Logical Max (255)
    0x75, 0x08,       //   Report Size (8 bits)
    0x95, 0x40,       //   Report Count (64 bytes)
    0x81, 0x02,       //   Input (Data,Var,Abs)

    0x09, 0x21,       //   Usage (Output Report Data)
    0x15, 0x00,       //   Logical Min (0)
    0x26, 0xFF, 0x00, //   Logical Max (255)
    0x75, 0x08,       //   Report Size (8 bits)
    0x95, 0x40,       //   Report Count (64 bytes)
    0x91, 0x02,       //   Output (Data,Var,Abs)

    0xC0,             // End Collection
];

/// HID 1.11 class descriptor that follows the interface descriptor.
/// 9 bytes: bLength=9, bDescriptorType=0x21, bcdHID=0x0111,
/// bCountryCode=0 (none), bNumDescriptors=1, bDescriptorType=0x22 (REPORT),
/// wDescriptorLength = length of FIDO_REPORT_DESCRIPTOR.
const HID_CLASS_DESCRIPTOR_LEN: usize = 9;

const FIDO_HID_FRAME_LEN: usize = 64;

/// Depth of the inbound-frame ring (number of 64-byte frames it can
/// hold before back-pressure). The OUT endpoint can deliver a frame
/// every USB microframe while the main loop drains exactly one frame
/// per iteration; during a synchronous CBOR/crypto stretch several
/// frames can arrive before the loop comes back round. A short ring
/// absorbs that burst so a streamed multi-frame message isn't torn
/// apart by a dropped continuation. 8 frames = 512 bytes of static
/// state -- cheap, and more than the host's typical in-flight window.
const RX_RING_LEN: usize = 8;

/// HID class request codes (USB HID 1.11 sec. 7).
const REQ_GET_REPORT: u8 = 0x01;
const REQ_SET_REPORT: u8 = 0x09;
const REQ_GET_IDLE: u8 = 0x02;
const REQ_SET_IDLE: u8 = 0x0A;
const REQ_GET_PROTOCOL: u8 = 0x03;
const REQ_SET_PROTOCOL: u8 = 0x0B;

/// FIDO HID class. Owns one interrupt IN and one interrupt OUT endpoint,
/// each 64 bytes, polled at 5 ms intervals (typical authenticator).
pub struct FidoHidClass<'a, B: UsbBus> {
    iface: InterfaceNumber,
    iface_str: StringIndex,
    ep_in: EndpointIn<'a, B>,
    ep_out: EndpointOut<'a, B>,

    /// Bounded ring of pending host->device frames. The OUT endpoint
    /// (and the SET_REPORT control path) hand us exactly 64 bytes per
    /// packet; we enqueue here and the higher layer drains one per
    /// `recv_frame`. A ring rather than a single slot so a burst of
    /// continuation frames arriving while the main loop is busy in
    /// synchronous crypto isn't silently dropped, which would tear a
    /// multi-frame CBOR message apart (the next continuation would
    /// then mismatch `expected_seq` and the transport would abort with
    /// ERR_INVALID_SEQ).
    rx_ring: [[u8; FIDO_HID_FRAME_LEN]; RX_RING_LEN],
    /// Index of the next frame to dequeue.
    rx_head: usize,
    /// Number of frames currently queued (0..=RX_RING_LEN).
    rx_len: usize,
    /// Set when a frame had to be dropped because the ring was full.
    /// The transport layer reads this via `take_overflow` and resets
    /// the affected channel with an explicit error rather than letting
    /// the gap corrupt an in-flight reassembly.
    rx_overflow: bool,
    /// Saved idle rate (HID Set_Idle); we don't actually use it but
    /// some hosts insist on round-tripping the value.
    idle_rate_4ms: u8,
}

impl<'a, B: UsbBus> FidoHidClass<'a, B> {
    pub fn new(alloc: &'a UsbBusAllocator<B>) -> Self {
        Self {
            iface: alloc.interface(),
            iface_str: alloc.string(),
            ep_in: alloc.interrupt(FIDO_HID_FRAME_LEN as u16, 5),
            ep_out: alloc.interrupt(FIDO_HID_FRAME_LEN as u16, 5),
            rx_ring: [[0u8; FIDO_HID_FRAME_LEN]; RX_RING_LEN],
            rx_head: 0,
            rx_len: 0,
            rx_overflow: false,
            idle_rate_4ms: 0,
        }
    }

    /// Enqueue one inbound 64-byte frame. On a full ring the frame is
    /// dropped and the overflow flag is latched (see `take_overflow`)
    /// -- we drop-with-error rather than overwrite a queued frame,
    /// which would silently corrupt an in-flight reassembly.
    fn rx_push(&mut self, frame: [u8; FIDO_HID_FRAME_LEN]) {
        if self.rx_len >= RX_RING_LEN {
            self.rx_overflow = true;
            return;
        }
        let tail = (self.rx_head + self.rx_len) % RX_RING_LEN;
        self.rx_ring[tail] = frame;
        self.rx_len += 1;
    }

    /// Returns one received CTAP HID frame (exactly 64 bytes), if the
    /// host has sent one since the last call. `None` if no data is
    /// waiting. The caller is expected to poll this each main-loop
    /// iteration; frames queued while the loop was busy are returned
    /// in arrival order from the ring.
    pub fn recv_frame(&mut self) -> Option<[u8; FIDO_HID_FRAME_LEN]> {
        if self.rx_len == 0 {
            return None;
        }
        let frame = self.rx_ring[self.rx_head];
        self.rx_head = (self.rx_head + 1) % RX_RING_LEN;
        self.rx_len -= 1;
        Some(frame)
    }

    /// Returns and clears the RX-overflow flag: `true` if at least one
    /// inbound frame was dropped because the ring was full since the
    /// last call. The transport layer uses this to abort the affected
    /// reassembly with an explicit error instead of letting the gap
    /// silently desynchronise sequence numbers.
    pub fn take_overflow(&mut self) -> bool {
        let overflowed = self.rx_overflow;
        self.rx_overflow = false;
        overflowed
    }

    /// Scan the inbound ring for a CTAPHID init frame on `cid` carrying
    /// `cancel_cmd`, removing the first match and returning `true`. Used
    /// by the KEEPALIVE pump during a multi-second hybrid sign so a host
    /// that dismisses the WebAuthn prompt (CTAPHID_CANCEL) can abort the
    /// in-flight operation (L15). Only the matching frame is consumed;
    /// any other queued frames keep their arrival order, so a following
    /// transaction is left intact.
    ///
    /// CTAPHID frame layout (CTAP 2.1 sec. 11.2.4): bytes 0..4 = channel id
    /// (big-endian), byte 4 = command byte (init packets carry bit 7).
    pub fn take_cancel(&mut self, cid: u32, cancel_cmd: u8) -> bool {
        let cid_be = cid.to_be_bytes();
        let mut i = 0;
        while i < self.rx_len {
            let idx = (self.rx_head + i) % RX_RING_LEN;
            let f = &self.rx_ring[idx];
            if f[..4] == cid_be[..] && f[4] == cancel_cmd {
                // Remove logical element `i`: shift later frames one
                // slot earlier, then drop the (now duplicate) tail.
                let mut j = i;
                while j + 1 < self.rx_len {
                    let a = (self.rx_head + j) % RX_RING_LEN;
                    let b = (self.rx_head + j + 1) % RX_RING_LEN;
                    self.rx_ring[a] = self.rx_ring[b];
                    j += 1;
                }
                self.rx_len -= 1;
                return true;
            }
            i += 1;
        }
        false
    }

    /// Push a 64-byte CTAP HID frame to the host's IN endpoint. Returns
    /// `WouldBlock` if the previous frame hasn't been polled yet --
    /// callers retry next tick. Returns `Ok(64)` on success.
    pub fn send_frame(&mut self, frame: &[u8; FIDO_HID_FRAME_LEN]) -> Result<usize> {
        self.ep_in.write(frame)
    }
}

impl<'a, B: UsbBus> UsbClass<B> for FidoHidClass<'a, B> {
    fn get_configuration_descriptors(&self, w: &mut DescriptorWriter) -> Result<()> {
        // Interface: HID class 0x03, subclass 0 (None), protocol 0 (None).
        w.interface_alt(self.iface, 0, 0x03, 0x00, 0x00, Some(self.iface_str))?;

        // HID 1.11 class descriptor (9 bytes, written raw).
        let report_len = (FIDO_REPORT_DESCRIPTOR.len() as u16).to_le_bytes();
        let hid_desc: [u8; HID_CLASS_DESCRIPTOR_LEN] = [
            HID_CLASS_DESCRIPTOR_LEN as u8, // bLength
            DESC_TYPE_HID,                  // bDescriptorType = HID
            0x11,
            0x01,             // bcdHID = 1.11
            0x00,             // bCountryCode
            0x01,             // bNumDescriptors
            DESC_TYPE_REPORT, // bDescriptorType
            report_len[0],
            report_len[1],
        ];
        w.write(DESC_TYPE_HID, &hid_desc[2..])?;

        // Endpoint descriptors: interrupt IN and OUT, 64 bytes, 5 ms.
        w.endpoint(&self.ep_in)?;
        w.endpoint(&self.ep_out)?;
        Ok(())
    }

    fn get_string(&self, index: StringIndex, _lang: usb_device::LangID) -> Option<&str> {
        if index == self.iface_str {
            Some("FIDO HID")
        } else {
            None
        }
    }

    fn control_in(&mut self, xfer: ControlIn<B>) {
        let req = *xfer.request();
        // Standard GET_DESCRIPTOR(Interface) -- host asks for the
        // report or HID descriptor. We only care if it's addressed
        // at our interface.
        if req.request_type == control::RequestType::Standard
            && req.recipient == control::Recipient::Interface
            && req.index as u8 == u8::from(self.iface)
            && req.request == control::Request::GET_DESCRIPTOR
        {
            let desc_type = (req.value >> 8) as u8;
            match desc_type {
                DESC_TYPE_REPORT => {
                    xfer.accept_with_static(FIDO_REPORT_DESCRIPTOR).ok();
                    return;
                }
                DESC_TYPE_HID => {
                    let report_len = (FIDO_REPORT_DESCRIPTOR.len() as u16).to_le_bytes();
                    let hid_desc: [u8; HID_CLASS_DESCRIPTOR_LEN] = [
                        HID_CLASS_DESCRIPTOR_LEN as u8,
                        DESC_TYPE_HID,
                        0x11,
                        0x01,
                        0x00,
                        0x01,
                        DESC_TYPE_REPORT,
                        report_len[0],
                        report_len[1],
                    ];
                    // accept_with_static needs &'static [u8]; we'd
                    // need a static for this. Use accept() which
                    // copies -- simpler and the request is rare.
                    xfer.accept(|buf| {
                        let n = core::cmp::min(buf.len(), hid_desc.len());
                        buf[..n].copy_from_slice(&hid_desc[..n]);
                        Ok(n)
                    })
                    .ok();
                    return;
                }
                _ => {}
            }
        }

        // HID class IN requests.
        if req.request_type == control::RequestType::Class
            && req.recipient == control::Recipient::Interface
            && req.index as u8 == u8::from(self.iface)
        {
            match req.request {
                REQ_GET_IDLE => {
                    let v = [self.idle_rate_4ms];
                    xfer.accept(|buf| {
                        if buf.is_empty() {
                            Err(UsbError::BufferOverflow)
                        } else {
                            buf[0] = v[0];
                            Ok(1)
                        }
                    })
                    .ok();
                    return;
                }
                REQ_GET_PROTOCOL => {
                    // Report protocol = 1, the only one we support.
                    xfer.accept(|buf| {
                        if buf.is_empty() {
                            Err(UsbError::BufferOverflow)
                        } else {
                            buf[0] = 1;
                            Ok(1)
                        }
                    })
                    .ok();
                    return;
                }
                REQ_GET_REPORT => {
                    // The host should be using interrupt IN, not
                    // GET_REPORT, for normal data flow. Some debug
                    // tools poke this anyway; return zeros.
                    xfer.accept(|buf| {
                        let n = core::cmp::min(buf.len(), FIDO_HID_FRAME_LEN);
                        for b in &mut buf[..n] {
                            *b = 0;
                        }
                        Ok(n)
                    })
                    .ok();
                    return;
                }
                _ => {}
            }
        }
    }

    fn control_out(&mut self, xfer: ControlOut<B>) {
        let req = *xfer.request();
        if req.request_type == control::RequestType::Class
            && req.recipient == control::Recipient::Interface
            && req.index as u8 == u8::from(self.iface)
        {
            match req.request {
                REQ_SET_IDLE => {
                    self.idle_rate_4ms = (req.value >> 8) as u8;
                    xfer.accept().ok();
                    return;
                }
                REQ_SET_PROTOCOL => {
                    // We only ever do report protocol. Accept.
                    xfer.accept().ok();
                    return;
                }
                REQ_SET_REPORT => {
                    // The host can also send frames via SET_REPORT
                    // (output report on EP0). Enqueue onto the RX ring;
                    // `rx_push` latches the overflow flag if it's full.
                    if xfer.data().len() == FIDO_HID_FRAME_LEN {
                        let mut buf = [0u8; FIDO_HID_FRAME_LEN];
                        buf.copy_from_slice(xfer.data());
                        self.rx_push(buf);
                    }
                    xfer.accept().ok();
                    return;
                }
                _ => {}
            }
        }
    }

    fn endpoint_out(&mut self, addr: EndpointAddress) {
        if addr != self.ep_out.address() {
            return;
        }
        // OUT endpoint received a packet. Enqueue a full 64-byte frame
        // onto the RX ring; `rx_push` latches the overflow flag if the
        // ring is full so the transport layer can abort cleanly.
        let mut buf = [0u8; FIDO_HID_FRAME_LEN];
        match self.ep_out.read(&mut buf) {
            Ok(n) if n == FIDO_HID_FRAME_LEN => {
                self.rx_push(buf);
            }
            _ => { /* drop short frames; CTAP HID is strict 64B */ }
        }
    }
}
