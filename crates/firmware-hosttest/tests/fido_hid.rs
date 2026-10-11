// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The FIDO HID class: the RX ring, the cancel scan, and the
//! descriptors.
//!
//! Every byte a host sends arrives through this, and none of it had
//! ever been executed off silicon. Two parts are worth the attention:
//!
//! The **ring** is what keeps a multi-frame CBOR message from tearing
//! while the main loop is stuck in a multi-second ML-DSA signature.
//! Frames arriving during that window queue up; if one were dropped or
//! reordered the next continuation would mismatch `expected_seq` and
//! the transport would abort a perfectly good request. It is modular
//! arithmetic over a wrapping buffer, which is exactly the kind of code
//! that works until the head wraps past the tail.
//!
//! The **cancel scan** is the L15 abort path: a host that dismisses the
//! WebAuthn prompt sends CTAPHID_CANCEL mid-operation, and the scan has
//! to pull that one frame out of the middle of the queue while leaving
//! everything else in arrival order. A scan that disturbed the order
//! would corrupt the next transaction rather than the cancelled one.

mod usbmock;

use pqf_firmware_hosttest::fido_hid::FidoHidClass;
use usb_device::device::{StringDescriptors, UsbDeviceBuilder, UsbVidPid};
use usb_device::prelude::*;
use usbmock::{setup_packet, Host, HostSide, MockBus};

const FRAME: usize = 64;
const RING: usize = 8;
const CMD_CANCEL: u8 = 0x91;

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
    let fido = FidoHidClass::new(alloc);
    let dev = UsbDeviceBuilder::new(alloc, UsbVidPid(0xcafe, 0xF1D0))
        .strings(&[StringDescriptors::default().manufacturer("t").product("t")])
        .unwrap()
        .build();
    (host, fido, dev)
}

fn pump(dev: &mut UsbDevice<'static, MockBus>, fido: &mut FidoHidClass<'static, MockBus>) {
    for _ in 0..8 {
        dev.poll(&mut [fido]);
    }
}

/// A frame tagged so its identity survives the ring.
fn frame(cid: u32, cmd: u8, tag: u8) -> [u8; FRAME] {
    let mut f = [0u8; FRAME];
    f[..4].copy_from_slice(&cid.to_be_bytes());
    f[4] = cmd;
    f[5] = tag;
    f
}

/// Deliver frames to the class the way the bus does.
fn deliver(
    host: &Host,
    dev: &mut UsbDevice<'static, MockBus>,
    fido: &mut FidoHidClass<'static, MockBus>,
    frames: &[[u8; FRAME]],
) {
    for f in frames {
        host.host_writes(1, f);
        pump(dev, fido);
    }
}

// ---------- the RX ring ----------

#[test]
fn frames_come_back_in_arrival_order() {
    let (host, mut fido, mut dev) = rig();
    let sent: Vec<_> = (0..5).map(|i| frame(0xAABBCCDD, 0x83, i)).collect();
    deliver(&host, &mut dev, &mut fido, &sent);
    for (i, want) in sent.iter().enumerate() {
        let got = fido.recv_frame().expect("frame missing");
        assert_eq!(&got[..], &want[..], "frame {i} out of order or altered");
    }
    assert!(
        fido.recv_frame().is_none(),
        "ring returned more than was sent"
    );
}

#[test]
fn the_ring_wraps_without_corrupting_anything() {
    // Fill, drain, refill several times so head and tail both pass the
    // modulus. A ring whose arithmetic is subtly wrong survives a
    // single pass and fails here.
    let (host, mut fido, mut dev) = rig();
    let mut tag = 0u8;
    for _round in 0..5 {
        let batch: Vec<_> = (0..RING - 1)
            .map(|_| {
                tag = tag.wrapping_add(1);
                frame(1, 0x83, tag)
            })
            .collect();
        deliver(&host, &mut dev, &mut fido, &batch);
        for want in &batch {
            let got = fido.recv_frame().expect("frame lost after a wrap");
            assert_eq!(&got[..], &want[..], "frame corrupted after a wrap");
        }
    }
    assert!(
        !fido.take_overflow(),
        "overflow latched when the ring never filled"
    );
}

#[test]
fn a_full_ring_drops_and_latches_rather_than_overwriting() {
    // Overwriting a queued frame would silently corrupt an in-flight
    // reassembly; dropping and latching lets the transport abort that
    // channel with an explicit error instead.
    let (host, mut fido, mut dev) = rig();
    let keep: Vec<_> = (0..RING).map(|i| frame(1, 0x83, i as u8)).collect();
    deliver(&host, &mut dev, &mut fido, &keep);
    assert!(
        !fido.take_overflow(),
        "overflow latched at exactly capacity"
    );

    deliver(&host, &mut dev, &mut fido, &[frame(1, 0x83, 0xFF)]);
    assert!(
        fido.take_overflow(),
        "an overrun did not latch the overflow flag"
    );
    assert!(
        !fido.take_overflow(),
        "take_overflow did not clear the flag"
    );

    // The queued frames must be the ORIGINAL eight, not the newcomer.
    for (i, want) in keep.iter().enumerate() {
        let got = fido.recv_frame().expect("a queued frame went missing");
        assert_eq!(
            &got[..],
            &want[..],
            "queued frame {i} was overwritten by the drop"
        );
    }
}

// ---------- the L15 cancel scan ----------

#[test]
fn cancel_is_plucked_from_the_middle_and_order_is_preserved() {
    let (host, mut fido, mut dev) = rig();
    let a = frame(7, 0x83, 1);
    let c = frame(7, CMD_CANCEL, 2);
    let b = frame(7, 0x83, 3);
    let d = frame(7, 0x83, 4);
    deliver(&host, &mut dev, &mut fido, &[a, c, b, d]);

    assert!(fido.take_cancel(7, CMD_CANCEL), "cancel not found");
    assert_eq!(
        &fido.recv_frame().unwrap()[..],
        &a[..],
        "frame before the cancel was disturbed"
    );
    assert_eq!(
        &fido.recv_frame().unwrap()[..],
        &b[..],
        "order after the cancel changed"
    );
    assert_eq!(
        &fido.recv_frame().unwrap()[..],
        &d[..],
        "order after the cancel changed"
    );
    assert!(
        fido.recv_frame().is_none(),
        "the cancel frame was left in the ring"
    );
}

#[test]
fn cancel_only_matches_its_own_channel() {
    // A cancel for someone else's transaction must not abort ours --
    // and must not be consumed, since its owner still needs it.
    let (host, mut fido, mut dev) = rig();
    let other = frame(0xDEAD, CMD_CANCEL, 1);
    deliver(&host, &mut dev, &mut fido, &[other]);
    assert!(
        !fido.take_cancel(7, CMD_CANCEL),
        "a cancel on another channel matched"
    );
    assert_eq!(
        &fido.recv_frame().unwrap()[..],
        &other[..],
        "another channel's cancel was eaten"
    );
}

#[test]
fn cancel_only_matches_the_cancel_command() {
    let (host, mut fido, mut dev) = rig();
    let ping = frame(7, 0x81, 1);
    deliver(&host, &mut dev, &mut fido, &[ping]);
    assert!(
        !fido.take_cancel(7, CMD_CANCEL),
        "a PING was taken for a CANCEL"
    );
    assert!(
        fido.recv_frame().is_some(),
        "the PING was consumed by the scan"
    );
}

#[test]
fn cancel_on_an_empty_ring_is_simply_false() {
    let (_host, mut fido, _dev) = rig();
    assert!(!fido.take_cancel(7, CMD_CANCEL));
}

#[test]
fn only_the_first_cancel_is_taken() {
    // Two cancels queued; one call must consume exactly one, so a
    // second operation on the same channel is not aborted by a stale
    // frame from the first.
    let (host, mut fido, mut dev) = rig();
    let c1 = frame(7, CMD_CANCEL, 1);
    let c2 = frame(7, CMD_CANCEL, 2);
    deliver(&host, &mut dev, &mut fido, &[c1, c2]);
    assert!(fido.take_cancel(7, CMD_CANCEL));
    assert!(
        fido.take_cancel(7, CMD_CANCEL),
        "the second cancel vanished"
    );
    assert!(
        !fido.take_cancel(7, CMD_CANCEL),
        "a third cancel appeared from nowhere"
    );
}

#[test]
fn a_cancel_at_the_tail_after_a_wrap_is_still_found() {
    // The scan indexes modulo the ring. Put the cancel where head+i
    // wraps, which is where an off-by-one in that arithmetic shows up.
    let (host, mut fido, mut dev) = rig();
    // Advance head most of the way round first.
    let filler: Vec<_> = (0..RING - 1).map(|i| frame(1, 0x83, i as u8)).collect();
    deliver(&host, &mut dev, &mut fido, &filler);
    for _ in 0..RING - 1 {
        fido.recv_frame().unwrap();
    }
    let pre = frame(7, 0x83, 200);
    let can = frame(7, CMD_CANCEL, 201);
    deliver(&host, &mut dev, &mut fido, &[pre, can]);
    assert!(
        fido.take_cancel(7, CMD_CANCEL),
        "cancel not found across the wrap"
    );
    assert_eq!(&fido.recv_frame().unwrap()[..], &pre[..]);
    assert!(fido.recv_frame().is_none());
}

// ---------- descriptors ----------

fn descriptor(value: u16, bm: u8) -> Vec<u8> {
    let (host, mut fido, mut dev) = rig();
    host.setup(&setup_packet(bm, REQ_GET_DESCRIPTOR, value, 0, 256));
    pump(&mut dev, &mut fido);
    host.host_reads(0)
}

#[test]
fn the_report_descriptor_is_the_ctap_one() {
    // The FIDO usage page is 0xF1D0 and the usage is 0x01. A host that
    // does not see those does not treat the device as an authenticator
    // at all -- it enumerates as a nondescript HID device and nothing
    // works, with no error anywhere.
    let d = descriptor(DESC_REPORT, IN_STD_IFACE);
    assert!(!d.is_empty(), "no report descriptor returned");
    assert_eq!(
        &d[..4],
        &[0x06, 0xD0, 0xF1, 0x09],
        "report descriptor does not start with usage page 0xF1D0"
    );
    assert_eq!(d.len(), 34, "the CTAP HID report descriptor is 34 bytes");
    // Report sizes: 8 bits, 64 count, on both input and output.
    assert!(
        d.windows(2).any(|w| w == [0x95, 0x40]),
        "report count is not 64 -- CTAPHID frames are 64 bytes"
    );
}

#[test]
fn the_interface_is_hid_with_two_interrupt_endpoints() {
    let cfg = descriptor(DESC_CONFIGURATION, IN_STD_DEVICE);
    assert!(!cfg.is_empty(), "no configuration descriptor");
    let iface = cfg
        .windows(9)
        .find(|w| w[0] == 0x09 && w[1] == 0x04)
        .expect("no interface descriptor");
    assert_eq!(iface[5], 0x03, "bInterfaceClass must be HID");
    assert_eq!(iface[4], 0x02, "FIDO HID needs exactly two endpoints");

    // Endpoint descriptors: bLength 7, type 5. One IN (0x80 bit), one OUT.
    let eps: Vec<u8> = cfg
        .windows(7)
        .filter(|w| w[0] == 0x07 && w[1] == 0x05)
        .map(|w| w[2])
        .collect();
    assert_eq!(
        eps.len(),
        2,
        "expected two endpoint descriptors, got {eps:?}"
    );
    assert!(eps.iter().any(|a| a & 0x80 != 0), "no IN endpoint");
    assert!(eps.iter().any(|a| a & 0x80 == 0), "no OUT endpoint");

    // The HID class descriptor must declare the report length the
    // report descriptor actually is.
    let hid = cfg
        .windows(9)
        .find(|w| w[0] == 0x09 && w[1] == 0x21)
        .expect("no HID class descriptor");
    let declared = u16::from_le_bytes([hid[7], hid[8]]);
    assert_eq!(
        declared, 34,
        "HID descriptor declares the wrong report length"
    );
}

// ---------- the two ports must not drift ----------

#[test]
fn all_three_report_descriptors_are_the_same_bytes() {
    // The C firmware, the Rust firmware and the Non-secure image each
    // carry their own copy of this array. They are the token's identity
    // to a host; one drifting would make that image stop being
    // recognised as an authenticator, and nothing else would notice.
    //
    // Comments are stripped FIRST. A naive extractor reads a phantom
    // 0xF1 out of the words "0xF1D0" where they appear in prose -- the
    // same false alarm trng_no_drift.rs guards against.
    fn bytes_of(src: &str, marker: &str) -> Vec<u8> {
        let start = src
            .find(marker)
            .unwrap_or_else(|| panic!("{marker} not found"));
        let tail = &src[start..];
        // The EARLIER of the two openers. `.or_else` would take a `{`
        // from a function further down the file whenever the array
        // itself uses `[`, and then read bytes from somewhere else
        // entirely.
        let open = [tail.find('{'), tail.find('[')]
            .into_iter()
            .flatten()
            .min()
            .expect("no array opener");
        // Strip BOTH comment styles before scanning for hex. The C
        // file writes `/* Usage Page (FIDO Alliance, 0xF1D0) */`, and
        // an extractor that only handles `//` reads a phantom 0xF1 out
        // of that prose -- the same false alarm trng_no_drift.rs guards
        // against, and the reason this is worth spelling out.
        let body: String = tail[open..]
            .lines()
            .map(|l| {
                let l = match l.find("//") {
                    Some(i) => &l[..i],
                    None => l,
                };
                match l.find("/*") {
                    Some(i) => &l[..i],
                    None => l,
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let end = [body.find("};"), body.find("];")]
            .into_iter()
            .flatten()
            .min()
            .expect("no array close");
        let body = &body[..end];
        let mut out = Vec::new();
        let mut rest = body;
        while let Some(i) = rest.find("0x") {
            rest = &rest[i + 2..];
            let hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if !hex.is_empty() && hex.len() <= 2 {
                out.push(u8::from_str_radix(&hex, 16).unwrap());
            }
        }
        out
    }

    let rust_fw = bytes_of(
        include_str!("../../firmware/src/fido_hid.rs"),
        "FIDO_REPORT_DESCRIPTOR",
    );
    let rust_ns = bytes_of(
        include_str!("../../fw-nonsecure/src/fido_hid.rs"),
        "FIDO_REPORT_DESCRIPTOR",
    );
    let c_fw = bytes_of(
        include_str!("../../../c/firmware/src/usb_descriptors.c"),
        "pqf_hid_report_desc",
    );

    for (name, d) in [
        ("rust firmware", &rust_fw),
        ("rust non-secure", &rust_ns),
        ("c firmware", &c_fw),
    ] {
        assert_eq!(
            d.len(),
            34,
            "{name} report descriptor is {} bytes, not 34",
            d.len()
        );
    }
    assert_eq!(
        rust_fw, rust_ns,
        "the Rust firmware and Non-secure report descriptors have drifted"
    );
    assert_eq!(
        rust_fw, c_fw,
        "the Rust and C report descriptors have drifted"
    );
}
