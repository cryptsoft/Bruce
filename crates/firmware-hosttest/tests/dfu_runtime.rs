// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The USB DFU runtime interface.
//!
//! Silicon-proven -- a Rust app detached itself and installed the next
//! image through this interface -- but with no host coverage, and the
//! descriptor is the kind of thing that breaks silently. A wrong byte
//! there does not crash: the interface simply stops being recognised as
//! DFU, and the only symptom is `dfu-util` not listing it, on hardware,
//! after a flash.
//!
//! Everything runs through `UsbDevice::poll()` against the mock bus
//! rather than calling the class directly, because `DescriptorWriter`
//! and the control transfer types are `pub(crate)` in `usb-device`.
//! That is the better test anyway: it is the path a real host takes.

mod usbmock;

use pqf_firmware_hosttest::dfu_runtime::DfuRuntimeClass;
use usb_device::device::{StringDescriptors, UsbDeviceBuilder, UsbVidPid};
use usb_device::prelude::*;
use usbmock::{setup_packet, HostSide, MockBus};

/// bmRequestType values.
const OUT_CLASS_IFACE: u8 = 0b0010_0001;
const IN_CLASS_IFACE: u8 = 0b1010_0001;
const IN_STD_DEVICE: u8 = 0b1000_0000;
const OUT_STD_IFACE: u8 = 0b0000_0001;

const REQ_GET_DESCRIPTOR: u8 = 6;
const REQ_SET_INTERFACE: u8 = 11;
const DFU_DETACH: u8 = 0;
const DFU_GETSTATUS: u8 = 3;
const DFU_GETSTATE: u8 = 5;
const DFU_ABORT: u8 = 6;

const DESC_CONFIGURATION: u16 = 0x0200;

/// Bring up a device with just the DFU class, drive one control
/// transfer, and hand back what the host saw.
struct Rig {
    host: usbmock::Host,
}

impl Rig {
    fn new() -> (Self, DfuRuntimeClass, UsbDevice<'static, MockBus>) {
        let (alloc, host) = MockBus::new();
        let alloc: &'static _ = Box::leak(Box::new(alloc));
        let dfu = DfuRuntimeClass::new(alloc);
        let dev = UsbDeviceBuilder::new(alloc, UsbVidPid(0xcafe, 0xF1D0))
            .strings(&[StringDescriptors::default()
                .manufacturer("test")
                .product("test")])
            .unwrap()
            .build();
        (Rig { host }, dfu, dev)
    }
}

/// Run the device until the control transfer settles.
fn pump(dev: &mut UsbDevice<'static, MockBus>, dfu: &mut DfuRuntimeClass) {
    for _ in 0..8 {
        dev.poll(&mut [dfu]);
    }
}

fn config_descriptor() -> Vec<u8> {
    let (rig, mut dfu, mut dev) = Rig::new();
    rig.host.setup(&setup_packet(
        IN_STD_DEVICE,
        REQ_GET_DESCRIPTOR,
        DESC_CONFIGURATION,
        0,
        256,
    ));
    pump(&mut dev, &mut dfu);
    rig.host.host_reads(0)
}

// ---------- the descriptor ----------

#[test]
fn the_dfu_functional_descriptor_is_byte_exact() {
    // The nine bytes the C port emits via TUD_DFU_RT_DESCRIPTOR, which
    // is what `dfu-util` parses to decide this is a DFU runtime
    // interface at all. Written out rather than computed, so that a
    // change to the constants in dfu_runtime.rs has to be deliberate.
    //
    //   09    bLength
    //   21    bDescriptorType = DFU FUNCTIONAL
    //   09    bmAttributes = CAN_DOWNLOAD | WILL_DETACH
    //   E8 03 wDetachTimeOut = 1000 ms
    //   00 10 wTransferSize  = 4096
    //   01 01 bcdDFUVersion  = 1.1
    let want: [u8; 9] = [0x09, 0x21, 0x09, 0xE8, 0x03, 0x00, 0x10, 0x01, 0x01];
    let cfg = config_descriptor();
    assert!(!cfg.is_empty(), "no configuration descriptor came back");
    let found = cfg.windows(9).any(|w| w == want);
    assert!(
        found,
        "DFU functional descriptor not found or not byte-exact.\n \
         wanted: {want:02x?}\n got config: {cfg:02x?}"
    );
}

#[test]
fn the_interface_is_application_specific_dfu_runtime() {
    // Class 0xFE / subclass 0x01 / protocol 0x01. Protocol 0x02 would
    // be DFU *mode* -- claiming that on a running app would have the
    // host try to download to us instead of asking us to detach.
    let cfg = config_descriptor();
    let iface = cfg
        .windows(9)
        .find(|w| w[0] == 0x09 && w[1] == 0x04 && w[5] == 0xFE)
        .expect("no application-specific interface descriptor");
    assert_eq!(iface[6], 0x01, "bInterfaceSubClass must be DFU");
    assert_eq!(
        iface[7], 0x01,
        "bInterfaceProtocol must be RUNTIME, not DFU mode"
    );
    assert_eq!(
        iface[4], 0x00,
        "the runtime interface must declare zero endpoints"
    );
    assert_ne!(iface[8], 0x00, "iInterface must reference a string");
}

#[test]
fn the_interface_number_comes_from_the_allocator_not_a_literal() {
    // usb-device allocates sequentially; the C port pins DFU to
    // interface 3. Copying that literal would emit a descriptor
    // referring to an interface the device does not have -- it would
    // enumerate and then answer nothing.
    let cfg = config_descriptor();
    let iface = cfg
        .windows(9)
        .find(|w| w[0] == 0x09 && w[1] == 0x04 && w[5] == 0xFE)
        .expect("no DFU interface");
    assert_eq!(
        iface[2], 0,
        "as the only class here it must be interface 0, proving the number is allocated"
    );
}

// ---------- control requests ----------

/// Issue a class request to the DFU interface and report whether it was
/// accepted (no stall on EP0).
fn class_request(bm: u8, req: u8, w_len: u16) -> (bool, Vec<u8>, bool) {
    let (rig, mut dfu, mut dev) = Rig::new();
    rig.host.setup(&setup_packet(bm, req, 0, 0, w_len));
    pump(&mut dev, &mut dfu);
    let data = rig.host.host_reads(0);
    (!rig.host.stalled(0), data, dfu.detach_requested())
}

#[test]
fn getstatus_answers_six_bytes_of_appidle() {
    // A host may probe before detaching. Six zeros is bStatus = OK,
    // bwPollTimeout = 0, bState = appIDLE, iString = 0. dfu-util prints
    // exactly this as "state(0) = appIDLE" before it sends DETACH.
    let (accepted, data, _) = class_request(IN_CLASS_IFACE, DFU_GETSTATUS, 6);
    assert!(accepted, "GETSTATUS was stalled");
    assert_eq!(data.len(), 6, "GETSTATUS must return exactly six bytes");
    assert_eq!(
        data,
        vec![0u8; 6],
        "GETSTATUS must report appIDLE with no error"
    );
}

#[test]
fn detach_is_accepted_and_raises_the_flag() {
    let (accepted, _, detach) = class_request(OUT_CLASS_IFACE, DFU_DETACH, 0);
    assert!(
        accepted,
        "DETACH was stalled -- the host would report a failed detach"
    );
    assert!(
        detach,
        "DETACH did not raise the flag the main loop reboots on"
    );
}

#[test]
fn detach_is_not_raised_before_the_host_asks() {
    let (_, _, detach) = class_request(IN_CLASS_IFACE, DFU_GETSTATUS, 6);
    assert!(!detach, "merely reading status armed a reboot");
}

#[test]
fn set_interface_is_answered() {
    // dfu-util claims the interface with SET_INTERFACE before any DFU
    // request. usb-device does not answer it for a class, and an
    // unanswered one stalls the pipe before DETACH is ever sent -- so
    // the detach would fail for a reason that looks nothing like the
    // cause.
    let (accepted, _, _) = class_request(OUT_STD_IFACE, REQ_SET_INTERFACE, 0);
    assert!(accepted, "SET_INTERFACE was stalled");
}

#[test]
fn unknown_class_requests_are_refused_rather_than_silently_accepted() {
    // GETSTATE and ABORT are real DFU requests this runtime interface
    // deliberately does not implement. Answering them with whatever
    // happens to be in a buffer would be worse than stalling.
    for req in [DFU_GETSTATE, DFU_ABORT, 0x42] {
        let (accepted, data, detach) = class_request(IN_CLASS_IFACE, req, 8);
        assert!(
            !accepted || data.is_empty(),
            "class request {req:#04x} was answered with data it should not have"
        );
        assert!(!detach, "class request {req:#04x} armed a reboot");
    }
}

#[test]
fn a_request_aimed_at_another_interface_is_ignored() {
    // The class must check the recipient index. One that answered every
    // interface's requests would corrupt a composite device -- and the
    // shipping firmware IS composite when gdb_stub is on.
    let (rig, mut dfu, mut dev) = Rig::new();
    rig.host
        .setup(&setup_packet(OUT_CLASS_IFACE, DFU_DETACH, 0, 7, 0));
    pump(&mut dev, &mut dfu);
    assert!(
        !dfu.detach_requested(),
        "a DETACH addressed to interface 7 armed our reboot"
    );
}

#[test]
fn a_bus_reset_clears_a_pending_detach() {
    // If the host changes its mind, a stale flag would reboot the token
    // into DFU mode for no reason the user can see.
    let (rig, mut dfu, mut dev) = Rig::new();
    rig.host
        .setup(&setup_packet(OUT_CLASS_IFACE, DFU_DETACH, 0, 0, 0));
    pump(&mut dev, &mut dfu);
    assert!(dfu.detach_requested(), "precondition: detach was armed");

    usb_device::class::UsbClass::<MockBus>::reset(&mut dfu);
    assert!(!dfu.detach_requested(), "a bus reset left the detach armed");
}
