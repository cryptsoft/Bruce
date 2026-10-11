// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! USB DFU 1.1 *runtime* interface -- the half of the C port's
//! `PQF_BOOTLOADER` option that the Rust side never had.
//!
//! The link half already exists: `PQF_APP_OFFSET=1` relocates this
//! image into the DFU bootloader's app slot at `0x10021000`
//! (`build.rs`), and `main.rs` already stands down the bootloader's
//! launch guard once the host enumerates us. What was missing is the
//! interface that lets `dfu-util -D` reach a *running* token: without
//! it a Rust app boots fine under the bootloader but can only be
//! updated by getting into DFU mode some other way.
//!
//! This is deliberately not a DFU *implementation*. The bootloader owns
//! the actual download; all this interface does is say "I am DFU-aware"
//! in the configuration descriptor and accept `DFU_DETACH`, after which
//! the app reboots with the handshake the bootloader watches for. Three
//! bytes of state and no endpoints.
//!
//! `usb-device` ships no DFU class, so the descriptor is written by
//! hand. It must match what the C port emits byte for byte apart from
//! the interface and string indices, which `usb-device` allocates
//! sequentially rather than at the fixed numbers the C port assigns --
//! so those two come from the allocator and are never literals here.

use usb_device::class_prelude::*;
use usb_device::control;
use usb_device::Result;

/// USB Application-Specific class, DFU subclass, runtime protocol.
/// (`TUSB_CLASS_APPLICATION_SPECIFIC` / `APP_SUBCLASS_DFU_RUNTIME` /
/// `DFU_PROTOCOL_RT` in TinyUSB terms.)
const USB_CLASS_APP_SPECIFIC: u8 = 0xFE;
const USB_SUBCLASS_DFU: u8 = 0x01;
const USB_PROTOCOL_DFU_RUNTIME: u8 = 0x01;

/// DFU functional descriptor, `bDescriptorType`.
const DESC_TYPE_DFU_FUNCTIONAL: u8 = 0x21;

/// `bmAttributes`: CAN_DOWNLOAD | WILL_DETACH. WILL_DETACH is the
/// honest answer -- we reboot ourselves rather than waiting for the host
/// to issue a USB reset. Matches the C runtime interface. (The
/// bootloader's DFU-*mode* descriptor differs deliberately: it sets
/// MANIFESTATION_TOLERANT instead, because it is the side that performs
/// the download.)
const DFU_ATTR_CAN_DOWNLOAD: u8 = 1 << 0;
const DFU_ATTR_WILL_DETACH: u8 = 1 << 3;

/// Class requests we answer. Everything else stalls.
const DFU_REQ_DETACH: u8 = 0;
const DFU_REQ_GETSTATUS: u8 = 3;

/// `wDetachTimeOut` (ms) and `wTransferSize`, both mirroring the C
/// runtime descriptor. The transfer size must agree with the
/// bootloader's DFU-mode descriptor (`CFG_TUD_DFU_XFER_BUFSIZE`), which
/// is what `dfu-util` reports as "Device returned transfer size 4096".
const DETACH_TIMEOUT_MS: u16 = 1000;
const TRANSFER_SIZE: u16 = 4096;

/// `bcdDFUVersion`. 0x0101 is what TinyUSB emits and what the
/// bootloader answers with, so it is what `dfu-util` expects to see on
/// both halves of the pair.
const BCD_DFU: u16 = 0x0101;

/// `DFU_GETSTATUS` response: six bytes, all zero -- bStatus = OK,
/// bwPollTimeout = 0, bState = appIDLE, iString = 0. A runtime
/// interface has no meaningful status to report; it exists so that a
/// host which probes before detaching gets an answer instead of a
/// stall.
const GETSTATUS_APP_IDLE: [u8; 6] = [0; 6];

pub struct DfuRuntimeClass {
    iface: InterfaceNumber,
    iface_str: StringIndex,
    detach: bool,
}

impl DfuRuntimeClass {
    pub fn new<B: UsbBus>(alloc: &UsbBusAllocator<B>) -> Self {
        Self {
            iface: alloc.interface(),
            iface_str: alloc.string(),
            detach: false,
        }
    }

    /// True once the host has asked us to detach into DFU mode.
    ///
    /// Deliberately a poll rather than a callback: rebooting inside the
    /// control handler would cut the transfer's status stage off, and
    /// the host would report a failed detach for a detach that actually
    /// worked. The caller is expected to let the USB stack finish, then
    /// reboot.
    pub fn detach_requested(&self) -> bool {
        self.detach
    }
}

impl<B: UsbBus> UsbClass<B> for DfuRuntimeClass {
    fn get_configuration_descriptors(&self, w: &mut DescriptorWriter) -> Result<()> {
        // No endpoints: DFU runtime is control-transfer only, so
        // `interface_alt` leaves bNumEndpoints at 0 and nothing here
        // increments it.
        w.interface_alt(
            self.iface,
            0,
            USB_CLASS_APP_SPECIFIC,
            USB_SUBCLASS_DFU,
            USB_PROTOCOL_DFU_RUNTIME,
            Some(self.iface_str),
        )?;

        // The 9-byte DFU functional descriptor. `write` prepends
        // bLength and bDescriptorType itself, so only the seven payload
        // bytes go here -- passing all nine would emit an 11-byte
        // descriptor with a length nobody agrees with.
        let detach = DETACH_TIMEOUT_MS.to_le_bytes();
        let xfer = TRANSFER_SIZE.to_le_bytes();
        let bcd = BCD_DFU.to_le_bytes();
        w.write(
            DESC_TYPE_DFU_FUNCTIONAL,
            &[
                DFU_ATTR_CAN_DOWNLOAD | DFU_ATTR_WILL_DETACH,
                detach[0],
                detach[1],
                xfer[0],
                xfer[1],
                bcd[0],
                bcd[1],
            ],
        )?;
        Ok(())
    }

    fn get_string(&self, index: StringIndex, _lang: usb_device::LangID) -> Option<&str> {
        if index == self.iface_str {
            // Matches the C port's string so `dfu-util -l` reads the
            // same on both ports.
            Some("Bruce DFU runtime")
        } else {
            None
        }
    }

    fn control_in(&mut self, xfer: ControlIn<B>) {
        let req = *xfer.request();
        if !self.addressed_to_us(&req) {
            return;
        }
        if req.request_type == control::RequestType::Class && req.request == DFU_REQ_GETSTATUS {
            xfer.accept_with(&GETSTATUS_APP_IDLE).ok();
        }
    }

    fn control_out(&mut self, xfer: ControlOut<B>) {
        let req = *xfer.request();
        if !self.addressed_to_us(&req) {
            return;
        }

        // A host claims the interface with SET_INTERFACE before issuing
        // DFU requests. `usb-device` does not answer it for us, and an
        // unanswered one stalls the pipe before DETACH is ever sent.
        if req.request_type == control::RequestType::Standard
            && req.request == control::Request::SET_INTERFACE
        {
            xfer.accept().ok();
            return;
        }

        if req.request_type == control::RequestType::Class && req.request == DFU_REQ_DETACH {
            // ACK first, reboot later. The flag is read by the main
            // loop, which gives the status stage time to complete --
            // see `detach_requested`.
            self.detach = true;
            xfer.accept().ok();
        }
    }

    fn reset(&mut self) {
        // A bus reset that is not the one we asked for means the host
        // changed its mind; do not carry a stale detach across it.
        self.detach = false;
    }
}

impl DfuRuntimeClass {
    fn addressed_to_us(&self, req: &control::Request) -> bool {
        req.recipient == control::Recipient::Interface && req.index as u8 == u8::from(self.iface)
    }
}
