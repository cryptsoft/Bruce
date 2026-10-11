// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Serve the GDB stub on a pty, with no board attached.
//!
//! The Rust equivalent of the C port's `test_gdbstub --pty`. It stands
//! up a simulated target -- flash and SRAM backed by plain arrays, a
//! synthesized exception frame -- and serves the real protocol engine
//! over a pty, so `arm-none-eabi-gdb` can drive the same code the
//! firmware links.
//!
//! This exists because the protocol layer is where the bugs are and it
//! does not need silicon to exercise. What it cannot cover is the part
//! that genuinely does: the DebugMonitor trampoline, the FPB and DEMCR
//! writes, and USB. Those still want a token.
//!
//!   cargo run --example pty --features std
//!   arm-none-eabi-gdb -ex 'target remote /dev/ttysNNN'

use pqf_gdbstub_core::{Engine, StopReason, Target, Transport};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};

/// Simulated address map, matching the real one closely enough that a
/// GDB session behaves the same way.
const FLASH_BASE: u32 = 0x1000_0000;
const FLASH_LEN: usize = 64 * 1024;
const SRAM_BASE: u32 = 0x2000_0000;
const SRAM_LEN: usize = 64 * 1024;

struct SimTarget {
    flash: Vec<u8>,
    sram: Vec<u8>,
    breakpoints: [Option<u32>; pqf_gdbstub_core::MAX_BREAKPOINTS],
    resumed: bool,
    stepped: bool,
    /// Mirrors the firmware's IN_MONITOR: false means running, so the
    /// `?` that opens a session has to ask for a stop rather than being
    /// answered from a stale register file.
    halted: bool,
    stop_pending: bool,
}

impl SimTarget {
    fn new() -> Self {
        Self {
            flash: vec![0; FLASH_LEN],
            sram: vec![0; SRAM_LEN],
            breakpoints: [None; pqf_gdbstub_core::MAX_BREAKPOINTS],
            resumed: false,
            stepped: false,
            halted: false,
            stop_pending: false,
        }
    }

    fn slot(&mut self, addr: u32) -> Option<(&mut [u8], usize)> {
        if addr >= FLASH_BASE && ((addr - FLASH_BASE) as usize) < FLASH_LEN {
            let i = (addr - FLASH_BASE) as usize;
            Some((&mut self.flash, i))
        } else if addr >= SRAM_BASE && ((addr - SRAM_BASE) as usize) < SRAM_LEN {
            let i = (addr - SRAM_BASE) as usize;
            Some((&mut self.sram, i))
        } else {
            None
        }
    }
}

impl Target for SimTarget {
    fn read_u8(&mut self, addr: u32) -> Option<u8> {
        let (buf, i) = self.slot(addr)?;
        Some(buf[i])
    }
    fn write_u8(&mut self, addr: u32, val: u8) -> bool {
        match self.slot(addr) {
            Some((buf, i)) => {
                buf[i] = val;
                true
            }
            None => false,
        }
    }
    fn set_breakpoint(&mut self, slot: usize, addr: u32) {
        self.breakpoints[slot] = Some(addr);
    }
    fn clear_breakpoint(&mut self, slot: usize) {
        self.breakpoints[slot] = None;
    }
    fn resume(&mut self, step: bool) {
        self.resumed = true;
        self.stepped = step;
        self.halted = false;
    }
    fn is_halted(&self) -> bool {
        self.halted
    }
    fn request_halt(&mut self) {
        // The firmware raises DEMCR.MON_PEND and stops at the next
        // controlled point. Here that point is immediate.
        self.halted = true;
        self.stop_pending = true;
    }
}

struct PtyTransport {
    file: std::fs::File,
    pending: Vec<u8>,
}

impl Transport for PtyTransport {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        match self.file.read(buf) {
            Ok(n) => n,
            Err(_) => 0,
        }
    }
    fn write(&mut self, data: &[u8]) {
        // Queued then flushed, mirroring the firmware, where a blocking
        // write inside packet handling deadlocks against the USB poll.
        self.pending.extend_from_slice(data);
    }
}

impl PtyTransport {
    fn flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let _ = self.file.write_all(&self.pending);
        let _ = self.file.flush();
        self.pending.clear();
    }
}

fn main() {
    // openpty(3): a master we serve and a slave GDB connects to.
    let mut master: libc::c_int = 0;
    let mut slave: libc::c_int = 0;
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        eprintln!("openpty failed");
        std::process::exit(1);
    }
    let name = unsafe {
        let p = libc::ttyname(slave);
        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
    };
    println!("gdbstub pty ready: {name}");
    println!("  arm-none-eabi-gdb -ex 'target remote {name}'");

    let file = unsafe { std::fs::File::from_raw_fd(master) };
    // Non-blocking so the serve loop can poll rather than wedge.
    unsafe {
        let fl = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(file.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
    }

    let mut transport = PtyTransport {
        file,
        pending: Vec::new(),
    };
    let mut target = SimTarget::new();
    let mut engine = Engine::new();

    // A plausible halted context: PC in flash, SP in SRAM, and a
    // recognisable pattern in the low registers so a `g` reply is
    // obviously right or obviously wrong.
    for i in 0..13 {
        engine.regs[i] = 0x1000_0000 + i as u32;
    }
    engine.regs[13] = SRAM_BASE + 0x8000; // sp
    engine.regs[14] = 0xFFFF_FFF9; // lr (EXC_RETURN)
    engine.regs[15] = FLASH_BASE + 0x100; // pc
    engine.regs[16] = 0x0100_0000; // xpsr, Thumb bit set
    engine.stop_reason = StopReason::Trap;

    let mut buf = [0u8; 256];
    loop {
        let n = transport.read(&mut buf);
        if n > 0 {
            let data: Vec<u8> = buf[..n].to_vec();
            if engine.feed(&mut transport, &mut target, &data) {
                // A real target would run here. The simulation reports
                // an immediate trap, which is what a breakpoint at the
                // resume address would do anyway.
                engine.stop_reason = StopReason::Trap;
                target.halted = true;
                if engine.attached {
                    engine.send_stop_reason(&mut transport);
                }
            }
            // A halt the engine asked for announces itself, exactly as
            // the monitor does through REPORT_STOP.
            if target.stop_pending {
                target.stop_pending = false;
                if engine.attached {
                    engine.send_stop_reason(&mut transport);
                }
            }
            transport.flush();
        } else {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}
