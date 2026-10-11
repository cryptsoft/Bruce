// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! A mock `UsbBus`, so the firmware's USB classes can be driven off
//! silicon.
//!
//! `usb-device` keeps `DescriptorWriter::new`, `ControlIn::new` and
//! `ControlOut::new` all `pub(crate)`, so a test cannot call
//! `get_configuration_descriptors` or `control_in`/`control_out`
//! directly. Everything has to go through `UsbDevice::poll()` with a
//! mock EP0 -- which is the better test anyway, since it exercises the
//! same path a host does rather than the class in isolation.
//!
//! **The one rule that matters.** `alloc_ep` must return the requested
//! address verbatim when the caller asks for a specific one, and
//! allocate from index 1 when it does not. `UsbDevice::build` allocates
//! EP0 *after* the classes have taken theirs, and `UsbDevice::poll`
//! hardcodes bit 0 as EP0. A mock that ignores `ep_addr` and hands out
//! sequential numbers puts the control pipe on EP2, and then every
//! descriptor and control assertion in every suite silently does
//! nothing -- no failure, no panic, just tests that pass without
//! testing. That failure mode is why this is a shared module rather
//! than copied per suite.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use usb_device::bus::{PollResult, UsbBus, UsbBusAllocator};
use usb_device::endpoint::{EndpointAddress, EndpointType};
use usb_device::{Result, UsbDirection, UsbError};

const NUM_EP: usize = 8;

#[derive(Default)]
struct EpState {
    allocated: bool,
    stalled: bool,
    /// Data the device has written, waiting for the host to read.
    to_host: Vec<u8>,
    /// Data the host has written, waiting for the device to read.
    to_device: Vec<u8>,
}

struct State {
    ep_in: Vec<EpState>,
    ep_out: Vec<EpState>,
    /// Set by `setup()`; cleared once the device consumes it.
    setup_pending: bool,
    next_in: usize,
    next_out: usize,
}

/// Shared between the bus and the test. The allocator takes ownership
/// of the `MockBus`, so the host side needs its own handle to the same
/// state rather than trying to reach back through the allocator.
#[derive(Clone)]
pub struct Host(Arc<Mutex<State>>);

pub struct MockBus {
    st: Arc<Mutex<State>>,
}

impl MockBus {
    /// Returns the allocator the classes are built against, plus the
    /// host-side handle for driving control transfers.
    pub fn new() -> (UsbBusAllocator<MockBus>, Host) {
        let mut ep_in = Vec::new();
        let mut ep_out = Vec::new();
        for _ in 0..NUM_EP {
            ep_in.push(EpState::default());
            ep_out.push(EpState::default());
        }
        let st = Arc::new(Mutex::new(State {
            ep_in,
            ep_out,
            setup_pending: false,
            next_in: 1,
            next_out: 1,
        }));
        let host = Host(Arc::clone(&st));
        (UsbBusAllocator::new(MockBus { st }), host)
    }
}

impl UsbBus for MockBus {
    fn alloc_ep(
        &mut self,
        dir: UsbDirection,
        addr: Option<EndpointAddress>,
        _kind: EndpointType,
        _max_packet_size: u16,
        _interval: u8,
    ) -> Result<EndpointAddress> {
        let mut guard = self.st.lock().unwrap();
        let st = &mut *guard;
        // Honour an explicit request. EP0 is asked for by name, and
        // giving it anything else silently disables every control test.
        if let Some(a) = addr {
            let idx = a.index();
            if idx >= NUM_EP {
                return Err(UsbError::EndpointOverflow);
            }
            let slot = if a.is_in() {
                &mut st.ep_in[idx]
            } else {
                &mut st.ep_out[idx]
            };
            slot.allocated = true;
            return Ok(a);
        }
        // Otherwise allocate from 1: index 0 is reserved for control.
        let (next, table) = match dir {
            UsbDirection::In => (&mut st.next_in, &mut st.ep_in),
            UsbDirection::Out => (&mut st.next_out, &mut st.ep_out),
        };
        while *next < NUM_EP && table[*next].allocated {
            *next += 1;
        }
        if *next >= NUM_EP {
            return Err(UsbError::EndpointOverflow);
        }
        table[*next].allocated = true;
        Ok(EndpointAddress::from_parts(*next, dir))
    }

    fn enable(&mut self) {}

    fn reset(&self) {
        let mut st = self.st.lock().unwrap();
        for e in st.ep_in.iter_mut() {
            e.stalled = false;
            e.to_host.clear();
            e.to_device.clear();
        }
        for e in st.ep_out.iter_mut() {
            e.stalled = false;
            e.to_host.clear();
            e.to_device.clear();
        }
        st.setup_pending = false;
    }

    fn set_device_address(&self, _addr: u8) {}

    fn write(&self, ep_addr: EndpointAddress, buf: &[u8]) -> Result<usize> {
        let mut st = self.st.lock().unwrap();
        let e = &mut st.ep_in[ep_addr.index()];
        if !e.allocated {
            return Err(UsbError::InvalidEndpoint);
        }
        e.to_host.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn read(&self, ep_addr: EndpointAddress, buf: &mut [u8]) -> Result<usize> {
        let mut st = self.st.lock().unwrap();
        let e = &mut st.ep_out[ep_addr.index()];
        if !e.allocated {
            return Err(UsbError::InvalidEndpoint);
        }
        if e.to_device.is_empty() {
            return Err(UsbError::WouldBlock);
        }
        let n = e.to_device.len().min(buf.len());
        buf[..n].copy_from_slice(&e.to_device[..n]);
        e.to_device.drain(..n);
        Ok(n)
    }

    fn set_stalled(&self, ep_addr: EndpointAddress, stalled: bool) {
        let mut st = self.st.lock().unwrap();
        let e = if ep_addr.is_in() {
            &mut st.ep_in[ep_addr.index()]
        } else {
            &mut st.ep_out[ep_addr.index()]
        };
        e.stalled = stalled;
    }

    fn is_stalled(&self, ep_addr: EndpointAddress) -> bool {
        let st = self.st.lock().unwrap();
        if ep_addr.is_in() {
            st.ep_in[ep_addr.index()].stalled
        } else {
            st.ep_out[ep_addr.index()].stalled
        }
    }

    fn suspend(&self) {}
    fn resume(&self) {}

    fn poll(&self) -> PollResult {
        let st = self.st.lock().unwrap();
        let mut ep_out = 0u16;
        let mut ep_in_complete = 0u16;
        for (i, e) in st.ep_out.iter().enumerate() {
            if !e.to_device.is_empty() {
                ep_out |= 1 << i;
            }
        }
        // Report every allocated IN endpoint as drained, so a class that
        // waits for completion makes progress.
        for (i, e) in st.ep_in.iter().enumerate() {
            if e.allocated {
                ep_in_complete |= 1 << i;
            }
        }
        if st.setup_pending || ep_out != 0 || ep_in_complete != 0 {
            PollResult::Data {
                ep_out,
                ep_in_complete,
                ep_setup: if st.setup_pending { 1 } else { 0 },
            }
        } else {
            PollResult::None
        }
    }
}

/// Host-side helpers. These are the "what the host did" half; the
/// `UsbBus` impl above is the "what the device sees" half.
pub trait HostSide {
    /// Queue a SETUP packet on EP0 and mark it pending.
    fn setup(&self, pkt: &[u8; 8]);
    /// Queue an OUT data payload on an endpoint.
    fn host_writes(&self, ep: u8, data: &[u8]);
    /// Take everything the device has written to an IN endpoint.
    fn host_reads(&self, ep: u8) -> Vec<u8>;
    /// Was the endpoint stalled? A stall is how a class refuses.
    fn stalled(&self, ep: u8) -> bool;
    fn clear_stall(&self, ep: u8);
}

impl HostSide for Host {
    fn setup(&self, pkt: &[u8; 8]) {
        let mut st = self.0.lock().unwrap();
        st.ep_out[0].to_device.clear();
        st.ep_out[0].to_device.extend_from_slice(pkt);
        st.ep_in[0].to_host.clear();
        st.ep_in[0].stalled = false;
        st.ep_out[0].stalled = false;
        st.setup_pending = true;
    }

    fn host_writes(&self, ep: u8, data: &[u8]) {
        let mut st = self.0.lock().unwrap();
        st.ep_out[ep as usize].to_device.extend_from_slice(data);
    }

    fn host_reads(&self, ep: u8) -> Vec<u8> {
        let mut st = self.0.lock().unwrap();
        std::mem::take(&mut st.ep_in[ep as usize].to_host)
    }

    fn stalled(&self, ep: u8) -> bool {
        let st = self.0.lock().unwrap();
        st.ep_in[ep as usize].stalled || st.ep_out[ep as usize].stalled
    }

    fn clear_stall(&self, ep: u8) {
        let mut st = self.0.lock().unwrap();
        st.ep_in[ep as usize].stalled = false;
        st.ep_out[ep as usize].stalled = false;
    }
}

/// Build a standard control SETUP packet.
pub fn setup_packet(
    bm_request_type: u8,
    b_request: u8,
    w_value: u16,
    w_index: u16,
    w_length: u16,
) -> [u8; 8] {
    let v = w_value.to_le_bytes();
    let i = w_index.to_le_bytes();
    let l = w_length.to_le_bytes();
    [
        bm_request_type,
        b_request,
        v[0],
        v[1],
        i[0],
        i[1],
        l[0],
        l[1],
    ]
}
