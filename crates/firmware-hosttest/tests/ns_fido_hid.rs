// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The Non-secure world's HID class.
//!
//! I previously argued this was a strict subset of the firmware class
//! and not worth a suite. The first half is true and the second was
//! wrong, for a reason worth stating: **the subset relation holds
//! between the two classes, not between the two images.**
//!
//! The firmware drains its ring every main-loop iteration. The
//! Non-secure image has two paths that poll USB without draining --
//! `await_user_presence`, whose window is ten seconds, and `push_frame`,
//! which spins while emitting a response that can run to dozens of
//! frames. Same ring, same depth of eight, entirely different driver,
//! and the driver is what decides whether the ring ever fills.
//!
//! It fills. `MAX_MSG` is 7609 with a 59-byte continuation payload, so
//! a request can be 128 frames. The class used to drop silently on a
//! full ring, justified by a header comment saying a "single-frame
//! PING" could never fill it -- true for M2b-2, untrue since the
//! reassembler landed. These tests pin the latch that replaced it.

use pqf_firmware_hosttest::ns_fido_hid::FidoHidClass;
use usb_device::device::{StringDescriptors, UsbDeviceBuilder, UsbVidPid};
use usb_device::prelude::*;

mod usbmock;
use usbmock::{setup_packet, Host, HostSide, MockBus};

const FRAME: usize = 64;
const RING: usize = 8;

const IN_STD_DEVICE: u8 = 0b1000_0000;
const IN_STD_IFACE: u8 = 0b1000_0001;
const REQ_GET_DESCRIPTOR: u8 = 6;
const DESC_CONFIGURATION: u16 = 0x0200;
const DESC_REPORT: u16 = 0x2200;

fn rig() -> (
    Host,
    FidoHidClass<'static, MockBus>,
    UsbDevice<'static, MockBus>,
) {
    let (alloc, host) = MockBus::new();
    let alloc: &'static _ = Box::leak(Box::new(alloc));
    let hid = FidoHidClass::new(alloc);
    let dev = UsbDeviceBuilder::new(alloc, UsbVidPid(0xcafe, 0xF1D0))
        .strings(&[StringDescriptors::default().manufacturer("t").product("t")])
        .unwrap()
        .build();
    (host, hid, dev)
}

fn pump(dev: &mut UsbDevice<'static, MockBus>, hid: &mut FidoHidClass<'static, MockBus>) {
    for _ in 0..8 {
        dev.poll(&mut [hid]);
    }
}

fn frame(cid: u32, b4: u8, tag: u8) -> [u8; FRAME] {
    let mut f = [0u8; FRAME];
    f[..4].copy_from_slice(&cid.to_be_bytes());
    f[4] = b4;
    f[5] = tag;
    f
}

fn deliver(
    host: &Host,
    dev: &mut UsbDevice<'static, MockBus>,
    hid: &mut FidoHidClass<'static, MockBus>,
    frames: &[[u8; FRAME]],
) {
    for f in frames {
        host.host_writes(1, f);
        pump(dev, hid);
    }
}

// ---------- the overflow latch: the reason this file exists ----------

#[test]
fn a_dropped_frame_is_latched_rather_than_lost_silently() {
    // The defect this replaced: past the eighth frame everything
    // vanished with no trace, and the gap surfaced much later as a
    // sequence mismatch in the reassembler -- which points the finger
    // at the host.
    let (host, mut hid, mut dev) = rig();
    let full: Vec<_> = (0..RING).map(|i| frame(1, 0x83, i as u8)).collect();
    deliver(&host, &mut dev, &mut hid, &full);
    assert!(!hid.take_overflow(), "latched at exactly capacity");

    deliver(&host, &mut dev, &mut hid, &[frame(1, 0x83, 0xFF)]);
    assert!(hid.take_overflow(), "a dropped frame was not latched");
    assert!(
        !hid.take_overflow(),
        "take_overflow did not clear the latch"
    );
}

#[test]
fn a_long_request_overruns_the_ring_and_says_so() {
    // Concretely what a real multi-frame request does here. MAX_MSG is
    // 7609 over a 59-byte continuation payload, so a large CBOR request
    // is well over a hundred frames into a ring of eight. Nothing in
    // this image can hold that, and the only correct behaviour is to
    // notice.
    let (host, mut hid, mut dev) = rig();
    let init = frame(0x1234, 0x90, 0);
    let mut all = vec![init];
    for seq in 0..40u8 {
        all.push(frame(0x1234, seq, seq));
    }
    deliver(&host, &mut dev, &mut hid, &all);
    assert!(
        hid.take_overflow(),
        "a 41-frame request did not report dropping anything into an 8-deep ring"
    );
}

#[test]
fn the_frames_that_did_fit_are_the_early_ones_in_order() {
    // Drop-newest, not overwrite-oldest. Overwriting would corrupt a
    // reassembly already in progress instead of merely truncating it.
    let (host, mut hid, mut dev) = rig();
    let keep: Vec<_> = (0..RING).map(|i| frame(1, 0x83, i as u8)).collect();
    deliver(&host, &mut dev, &mut hid, &keep);
    deliver(&host, &mut dev, &mut hid, &[frame(1, 0x83, 0xEE)]);
    for (i, want) in keep.iter().enumerate() {
        let got = hid.recv_frame().expect("a frame that fitted went missing");
        assert_eq!(&got[..], &want[..], "queued frame {i} was overwritten");
    }
    assert!(
        hid.recv_frame().is_none(),
        "the dropped frame was queued after all"
    );
}

#[test]
fn the_latch_clears_and_the_ring_keeps_working() {
    // A single overrun must not wedge the transport: after the caller
    // has taken the flag and drained, the next request has to work.
    let (host, mut hid, mut dev) = rig();
    let over: Vec<_> = (0..RING + 3).map(|i| frame(1, 0x83, i as u8)).collect();
    deliver(&host, &mut dev, &mut hid, &over);
    assert!(hid.take_overflow());
    while hid.recv_frame().is_some() {}

    let next = frame(2, 0x83, 99);
    deliver(&host, &mut dev, &mut hid, &[next]);
    assert!(!hid.take_overflow(), "the latch came back on its own");
    assert_eq!(
        &hid.recv_frame().expect("the ring stopped accepting frames")[..],
        &next[..]
    );
}

// ---------- the ring itself, under this image's access pattern ----------

#[test]
fn frames_survive_a_wrap_under_repeated_fill_and_drain() {
    // Same arithmetic as the firmware copy, but exercised here because
    // this image reaches the boundary in normal operation rather than
    // only under load.
    let (host, mut hid, mut dev) = rig();
    let mut tag = 0u8;
    for _ in 0..5 {
        let batch: Vec<_> = (0..RING - 1)
            .map(|_| {
                tag = tag.wrapping_add(1);
                frame(1, 0x83, tag)
            })
            .collect();
        deliver(&host, &mut dev, &mut hid, &batch);
        for want in &batch {
            assert_eq!(
                &hid.recv_frame().expect("frame lost across a wrap")[..],
                &want[..]
            );
        }
    }
}

#[test]
fn an_empty_ring_returns_none_rather_than_stale_bytes() {
    let (_host, mut hid, _dev) = rig();
    assert!(hid.recv_frame().is_none());
    assert!(!hid.take_overflow());
}

// ---------- descriptors: this image must look like the others ----------

fn descriptor(value: u16, bm: u8) -> Vec<u8> {
    let (host, mut hid, mut dev) = rig();
    host.setup(&setup_packet(bm, REQ_GET_DESCRIPTOR, value, 0, 256));
    pump(&mut dev, &mut hid);
    host.host_reads(0)
}

#[test]
fn the_report_descriptor_is_the_same_ctap_one() {
    // The cross-port drift test compares the source arrays; this checks
    // what this class actually emits over the wire, which is a
    // different question -- a descriptor writer can be wrong about an
    // array that is right.
    let d = descriptor(DESC_REPORT, IN_STD_IFACE);
    assert_eq!(d.len(), 34, "the emitted report descriptor is not 34 bytes");
    assert_eq!(
        &d[..4],
        &[0x06, 0xD0, 0xF1, 0x09],
        "emitted descriptor does not start with the FIDO usage page"
    );
}

#[test]
fn the_interface_is_hid_with_both_endpoints() {
    let cfg = descriptor(DESC_CONFIGURATION, IN_STD_DEVICE);
    let iface = cfg
        .windows(9)
        .find(|w| w[0] == 0x09 && w[1] == 0x04)
        .expect("no interface descriptor");
    assert_eq!(iface[5], 0x03, "bInterfaceClass must be HID");
    assert_eq!(iface[4], 0x02, "FIDO HID needs two endpoints");
    let eps: Vec<u8> = cfg
        .windows(7)
        .filter(|w| w[0] == 0x07 && w[1] == 0x05)
        .map(|w| w[2])
        .collect();
    assert_eq!(eps.len(), 2, "expected two endpoints, got {eps:?}");
    assert!(eps.iter().any(|a| a & 0x80 != 0), "no IN endpoint");
    assert!(eps.iter().any(|a| a & 0x80 == 0), "no OUT endpoint");
}
