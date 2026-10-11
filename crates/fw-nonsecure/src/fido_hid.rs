// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! USB HID class for the FIDO Alliance CTAP HID transport -- the
//! Non-secure side of the TrustZone split (M2b-2).
//!
//! Ported from the FIDO firmware's `crates/firmware/src/fido_hid.rs`
//! (transport-only: a 64-byte `recv_frame`/`send_frame` API over one
//! interrupt IN + one interrupt OUT endpoint on the FIDO usage page
//! 0xF1D0). Trimmed for M2b-2 relative to the full firmware class: no
//! CANCEL scan, since nothing here runs long enough to need one. It DOES
//! keep the overflow latch -- the "single-frame PING" scope that once
//! justified dropping it is long gone, and multi-frame requests reach
//! this ring. The CTAPHID command logic lives in `main.rs`.

use usb_device::class_prelude::*;
use usb_device::Result;

const DESC_TYPE_HID: u8 = 0x21;
const DESC_TYPE_REPORT: u8 = 0x22;

/// CTAP HID report descriptor -- FIDO usage page (0xF1D0), usage
/// CTAPHID (0x01), two 64-byte data reports. Byte-for-byte the CTAP HID
/// spec example.
#[rustfmt::skip]
const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01,
    0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
    0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02,
    0xC0,
];

const HID_CLASS_DESCRIPTOR_LEN: usize = 9;
pub const FIDO_HID_FRAME_LEN: usize = 64;
const RX_RING_LEN: usize = 8;

const REQ_GET_REPORT: u8 = 0x01;
const REQ_SET_REPORT: u8 = 0x09;
const REQ_GET_IDLE: u8 = 0x02;
const REQ_SET_IDLE: u8 = 0x0A;
const REQ_GET_PROTOCOL: u8 = 0x03;
const REQ_SET_PROTOCOL: u8 = 0x0B;

pub struct FidoHidClass<'a, B: UsbBus> {
    iface: InterfaceNumber,
    iface_str: StringIndex,
    ep_in: EndpointIn<'a, B>,
    ep_out: EndpointOut<'a, B>,
    rx_ring: [[u8; FIDO_HID_FRAME_LEN]; RX_RING_LEN],
    /// Set when a frame was dropped because the ring was full. Read and
    /// cleared by `take_overflow`.
    rx_overflow: bool,
    rx_head: usize,
    rx_len: usize,
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
            rx_overflow: false,
            rx_head: 0,
            rx_len: 0,
            idle_rate_4ms: 0,
        }
    }

    fn rx_push(&mut self, frame: [u8; FIDO_HID_FRAME_LEN]) {
        if self.rx_len >= RX_RING_LEN {
            // Drop, but LATCH. The comment that used to sit here said a
            // single-frame PING never fills the ring, and that was true
            // when this file was written for M2b-2. It is not true now:
            // MAX_MSG is 7609 with a 59-byte continuation payload, so a
            // request can be 128 frames into a ring of 8, and two paths
            // poll USB without draining it -- await_user_presence for up
            // to ten seconds, and push_frame while it emits a long
            // response. Without the latch those frames vanish with no
            // trace, and the failure surfaces later as a sequence
            // mismatch in the reassembler, which points at the host.
            self.rx_overflow = true;
            return;
        }
        let tail = (self.rx_head + self.rx_len) % RX_RING_LEN;
        self.rx_ring[tail] = frame;
        self.rx_len += 1;
    }

    /// Returns and clears the RX-overflow flag: true if at least one
    /// inbound frame was dropped since the last call. The caller must
    /// abort any in-flight reassembly rather than let the gap surface
    /// as a sequence error.
    pub fn take_overflow(&mut self) -> bool {
        let o = self.rx_overflow;
        self.rx_overflow = false;
        o
    }

    /// Dequeue one received 64-byte CTAP HID frame, if any.
    pub fn recv_frame(&mut self) -> Option<[u8; FIDO_HID_FRAME_LEN]> {
        if self.rx_len == 0 {
            return None;
        }
        let frame = self.rx_ring[self.rx_head];
        self.rx_head = (self.rx_head + 1) % RX_RING_LEN;
        self.rx_len -= 1;
        Some(frame)
    }

    /// Push a 64-byte frame to the host IN endpoint. `WouldBlock` if the
    /// previous frame hasn't been polled yet.
    pub fn send_frame(&mut self, frame: &[u8; FIDO_HID_FRAME_LEN]) -> Result<usize> {
        self.ep_in.write(frame)
    }
}

impl<'a, B: UsbBus> UsbClass<B> for FidoHidClass<'a, B> {
    fn get_configuration_descriptors(&self, w: &mut DescriptorWriter) -> Result<()> {
        w.interface_alt(self.iface, 0, 0x03, 0x00, 0x00, Some(self.iface_str))?;
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
        w.write(DESC_TYPE_HID, &hid_desc[2..])?;
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
        if req.request_type == control::RequestType::Class
            && req.recipient == control::Recipient::Interface
            && req.index as u8 == u8::from(self.iface)
        {
            match req.request {
                REQ_GET_IDLE => {
                    let v = self.idle_rate_4ms;
                    xfer.accept(|buf| {
                        if buf.is_empty() {
                            Err(UsbError::BufferOverflow)
                        } else {
                            buf[0] = v;
                            Ok(1)
                        }
                    })
                    .ok();
                    return;
                }
                REQ_GET_PROTOCOL => {
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
                    xfer.accept().ok();
                    return;
                }
                REQ_SET_REPORT => {
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
        let mut buf = [0u8; FIDO_HID_FRAME_LEN];
        match self.ep_out.read(&mut buf) {
            Ok(n) if n == FIDO_HID_FRAME_LEN => self.rx_push(buf),
            _ => {}
        }
    }
}
