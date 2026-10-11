// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! On-token GDB stub for the Rust port, over a second USB CDC
//! interface.
//!
//! The Rust equivalent of the C port's GDB stub stub
//! (`c/firmware/src/gdbstub.c`, documented in docs/GDB_DEBUG.md), and
//! built the same way, because the mechanism is dictated by the
//! hardware rather than the language.
//!
//! ## Monitor-mode debug
//!
//! With `DEMCR.MON_EN` set, debug events raise the **DebugMonitor
//! exception** instead of halting the core. The handler *is* the
//! debugger: it captures the interrupted context, spins servicing GDB
//! packets, and returns to resume. "Halted" here means "spinning inside
//! DebugMonitor", so USB keeps running underneath and the token stays
//! enumerated while stopped -- which is the whole reason this works on
//! a sealed device with no SWD.
//!
//! Consequences worth stating:
//!
//!   - The DebugMonitor runs at priority 0, so it can preempt the USB
//!     interrupt but nothing masks it.
//!   - Single-step is `DEMCR.MON_STEP`: return from the monitor with it
//!     set and the core executes one instruction, then re-enters.
//!   - A host-requested halt (Ctrl-C) sets `DEMCR.MON_PEND` from the
//!     poll path, so the stop happens at a controlled point rather than
//!     wherever the USB IRQ landed.
//!   - Breakpoints are FPB comparators, not patched instructions --
//!     nothing is written to flash, and the stub cannot trip over its
//!     own breakpoints because the FPB is disabled while inside the
//!     monitor.
//!
//! ## Not in a production image
//!
//! Feature-gated and default off. A debugger reachable over USB with no
//! authentication is an arbitrary read, write and execute primitive on
//! a device holding credential keys.

use core::sync::atomic::{AtomicBool, Ordering};

// --- Debug and breakpoint unit registers (ARMv8-M) ---
const SCB_DEMCR: u32 = 0xE000_EDFC;
const DEMCR_MON_EN: u32 = 1 << 16;
const DEMCR_MON_PEND: u32 = 1 << 17;
const DEMCR_MON_STEP: u32 = 1 << 18;

const FP_CTRL: u32 = 0xE000_2000;
const FP_CTRL_KEY: u32 = 1 << 1;
const FP_CTRL_ENABLE: u32 = 1 << 0;
const FP_COMP0: u32 = 0xE000_2008;
/// FPB comparators available for breakpoints. The RP2350's unit has
/// eight; using fewer would only shrink what GDB can set at once.
const FP_COMPS: usize = 8;

/// Exception-frame offsets, in words: r0 r1 r2 r3 r12 lr pc xpsr.
const FRAME_R0: usize = 0;
const FRAME_R12: usize = 4;
const FRAME_LR: usize = 5;
const FRAME_PC: usize = 6;
const FRAME_XPSR: usize = 7;

static ENABLED: AtomicBool = AtomicBool::new(false);
static IN_MONITOR: AtomicBool = AtomicBool::new(false);
static HALT_REQ: AtomicBool = AtomicBool::new(false);
/// The engine has asked for a halt but we have not raised MON_PEND yet.
///
/// The delay is the point. MON_PEND fires the moment it is written, and
/// the monitor reaches USB by calling straight back into packet
/// handling -- so raising it from inside `feed` would re-enter the
/// engine while the outer call still held it. The request is recorded
/// here and acted on once packet handling has returned.
static HALT_PENDING: AtomicBool = AtomicBool::new(false);
static STEP_REQ: AtomicBool = AtomicBool::new(false);

/// The debug-unit registers, behind a seam.
///
/// Everything below this line is architected Cortex-M debug hardware --
/// DEMCR and the FPB comparators -- and none of it existed off silicon,
/// so the breakpoint programming, the MON_STEP handling and the DEMCR
/// read-modify-writes had no coverage of any kind. The C port solved
/// the same problem the same way (`GDB_REG32` in
/// `c/firmware/test/gdbstub_host.h`); this is its Rust counterpart.
///
/// Split on `target_arch`, which is the discriminator `flash_store.rs`
/// and `ramfunc.rs` already use, rather than a trait: `monitor_entry`
/// is reached by `bl` from a naked trampoline with a fixed ABI, so it
/// can take neither a generic parameter nor an extra argument, and a
/// trait would have to live in a `static mut` -- reintroducing one
/// immediately after this change removes two.
///
/// On target this compiles to the same volatile accesses as before.
/// Not literally the same bytes: building thumbv8m three ways shows the
/// two inlined `for i in 0..FP_COMPS` loops come out with a different
/// induction variable choice. Same work, no calls, no indirection --
/// but "identical code" would be an overclaim and it was measured.
#[cfg(any(target_arch = "arm", target_arch = "riscv32"))]
pub mod mmio {
    #[inline(always)]
    pub fn read32(addr: u32) -> u32 {
        // SAFETY: architected debug registers, always mapped.
        unsafe { (addr as *const u32).read_volatile() }
    }
    #[inline(always)]
    pub fn write32(addr: u32, val: u32) {
        // SAFETY: as above.
        unsafe { (addr as *mut u32).write_volatile(val) }
    }
    #[inline(always)]
    pub fn barrier() {
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
}

/// Host stand-in: a small address-keyed register file.
///
/// `barrier()` being a no-op here is not cosmetic. `cortex_m::asm::dsb`
/// does not merely fail to execute off-target -- it does not LINK.
/// cortex-m only ships its static archive for `thumb*`, so anywhere
/// else the call expands to an `extern "C"` declaration with nothing to
/// resolve, and the failure names cortex-m rather than anything here.
#[cfg(not(any(target_arch = "arm", target_arch = "riscv32")))]
pub mod mmio {
    use core::sync::atomic::{AtomicU32, Ordering};

    const SLOTS: usize = 32;
    static KEYS: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];
    static VALS: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];

    /// Index for `addr`, allocating on first use. The last slot is a
    /// shared scratch cell so an unexpected address lands somewhere
    /// rather than panicking -- the same discipline as the C seam.
    fn slot(addr: u32) -> usize {
        for i in 0..SLOTS - 1 {
            let k = KEYS[i].load(Ordering::Relaxed);
            if k == addr {
                return i;
            }
            if k == 0 {
                KEYS[i].store(addr, Ordering::Relaxed);
                return i;
            }
        }
        SLOTS - 1
    }

    pub fn read32(addr: u32) -> u32 {
        VALS[slot(addr)].load(Ordering::Relaxed)
    }
    pub fn write32(addr: u32, val: u32) {
        VALS[slot(addr)].store(val, Ordering::Relaxed);
    }
    pub fn barrier() {}

    /// Clear the register file between tests.
    pub fn reset() {
        for i in 0..SLOTS {
            KEYS[i].store(0, Ordering::Relaxed);
            VALS[i].store(0, Ordering::Relaxed);
        }
    }
}

#[inline(always)]
fn dsb_isb() {
    mmio::barrier();
}

/// Bring up monitor-mode debug. Safe to call when no debugger is
/// present: nothing happens until GDB speaks.
pub fn init() {
    // SAFETY: architected debug registers, single write during bring-up.
    unsafe {
        // Enable the FPB with its key bit; comparators stay empty. The
        // engine owns which slot holds what.
        mmio::write32(FP_CTRL, FP_CTRL_KEY | FP_CTRL_ENABLE);
        for i in 0..FP_COMPS {
            mmio::write32(FP_COMP0 + 4 * i as u32, 0);
        }
        // Monitor mode on. From here a BKPT or an FPB match enters
        // DebugMonitor rather than locking the core up.
        let demcr = mmio::read32(SCB_DEMCR);
        mmio::write32(SCB_DEMCR, demcr | DEMCR_MON_EN);
    }
    dsb_isb();
    ENABLED.store(true, Ordering::Release);
}

/// Ask for a halt at the next controlled point.
///
/// Used for a host Ctrl-C. Setting MON_PEND rather than halting inline
/// means the stop lands where the core can be inspected coherently,
/// not part-way through the USB interrupt that delivered the request.
pub fn request_halt() {
    HALT_REQ.store(true, Ordering::Release);
    let demcr = mmio::read32(SCB_DEMCR);
    mmio::write32(SCB_DEMCR, demcr | DEMCR_MON_PEND);
    dsb_isb();
}

/// Disable and re-enable the FPB around the monitor, so a breakpoint
/// inside the stub itself cannot recurse.
pub fn fpb_enable(on: bool) {
    // SAFETY: architected register.
    unsafe {
        mmio::write32(FP_CTRL, FP_CTRL_KEY | if on { FP_CTRL_ENABLE } else { 0 });
    }
    dsb_isb();
}

/// Memory GDB is allowed to touch.
///
/// A debugger is an arbitrary read/write primitive by design, but
/// reading a reserved peripheral window can fault and take the token
/// down mid-session, which is worse than refusing. Flash, SRAM and the
/// peripheral/PPB windows are permitted; everything else is not.
pub fn addr_ok(addr: u32, len: u32) -> bool {
    let end = match addr.checked_add(len) {
        Some(e) => e,
        None => return false,
    };
    const RANGES: [(u32, u32); 4] = [
        (0x1000_0000, 0x1020_0000), // XIP flash
        (0x2000_0000, 0x2008_2000), // SRAM
        (0x4000_0000, 0x5020_0000), // peripherals
        (0xE000_0000, 0xE010_0000), // PPB
    ];
    RANGES.iter().any(|(lo, hi)| addr >= *lo && end <= *hi)
}

/// The CDC pipe to GDB.
///
/// Replies are queued, never written inline: the endpoint only drains
/// when the USB device is polled, and the device cannot be polled from
/// inside packet handling. Writing inline deadlocks -- it did.
pub struct Session<'a, B: usb_device::bus::UsbBus> {
    serial: usbd_serial::SerialPort<'a, B>,
    tx: [u8; pqf_gdbstub_core::PKT_MAX + 8],
    tx_len: usize,
    tx_off: usize,
    /// Set when a write did not fit. The queue is then inconsistent --
    /// see `write` and `flush`.
    tx_overflow: bool,
}

impl<'a, B: usb_device::bus::UsbBus> Session<'a, B> {
    pub fn new(alloc: &'a usb_device::bus::UsbBusAllocator<B>) -> Self {
        Self {
            serial: usbd_serial::SerialPort::new(alloc),
            tx: [0; pqf_gdbstub_core::PKT_MAX + 8],
            tx_len: 0,
            tx_off: 0,
            tx_overflow: false,
        }
    }

    pub fn class(&mut self) -> &mut usbd_serial::SerialPort<'a, B> {
        &mut self.serial
    }

    /// Push queued bytes at the endpoint. Call after `usb_dev.poll`,
    /// which is what actually moves them.
    ///
    /// If anything overflowed since the last flush the whole queue is
    /// discarded instead of sent. A GDB packet is emitted as three
    /// writes -- `$`, the body, then `#checksum` -- so an overflow that
    /// falls between them leaves a packet with no terminating checksum
    /// in the buffer. Sending that hangs GDB forever, because it waits
    /// for a terminator that will never arrive. Sending nothing makes
    /// GDB time out and retry, which it recovers from.
    pub fn flush(&mut self) {
        if self.tx_overflow {
            self.tx_off = 0;
            self.tx_len = 0;
            self.tx_overflow = false;
            return;
        }
        while self.tx_off < self.tx_len {
            match self.serial.write(&self.tx[self.tx_off..self.tx_len]) {
                Ok(n) if n > 0 => self.tx_off += n,
                _ => return,
            }
        }
        self.tx_off = 0;
        self.tx_len = 0;
    }

    /// Whether a reply was dropped because the queue was full. Reading
    /// clears it.
    pub fn take_tx_overflow(&mut self) -> bool {
        let o = self.tx_overflow;
        self.tx_overflow = false;
        o
    }
}

impl<B: usb_device::bus::UsbBus> pqf_gdbstub_core::Transport for Session<'_, B> {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        self.serial.read(buf).unwrap_or(0)
    }
    fn write(&mut self, data: &[u8]) {
        // All or nothing. The previous version copied byte by byte and
        // simply stopped when the buffer filled, which truncated a
        // packet in the middle -- the host then had a `$...` with no
        // `#checksum` and waited for a terminator that was never
        // coming. Refusing the whole write and latching keeps the
        // damage to "a reply was lost", which GDB retries out of.
        if self.tx_overflow || data.len() > self.tx.len() - self.tx_len {
            self.tx_overflow = true;
            return;
        }
        self.tx[self.tx_len..self.tx_len + data.len()].copy_from_slice(data);
        self.tx_len += data.len();
    }
}

/// The real machine: memory behind the whitelist, FPB comparators, and
/// the DEMCR bits that make a resume a step.
pub struct Hw;

impl pqf_gdbstub_core::Target for Hw {
    fn read_u8(&mut self, addr: u32) -> Option<u8> {
        if !addr_ok(addr, 1) {
            return None;
        }
        // SAFETY: the address passed the whitelist.
        Some(unsafe { (addr as *const u8).read_volatile() })
    }
    fn write_u8(&mut self, addr: u32, val: u8) -> bool {
        if !addr_ok(addr, 1) {
            return false;
        }
        // SAFETY: the address passed the whitelist.
        unsafe { (addr as *mut u8).write_volatile(val) };
        true
    }
    fn set_breakpoint(&mut self, slot: usize, addr: u32) {
        if slot < FP_COMPS {
            // SAFETY: architected register.
            mmio::write32(FP_COMP0 + 4 * slot as u32, addr | 1);
            dsb_isb();
        }
    }
    fn clear_breakpoint(&mut self, slot: usize) {
        if slot < FP_COMPS {
            // SAFETY: architected register.
            mmio::write32(FP_COMP0 + 4 * slot as u32, 0);
            dsb_isb();
        }
    }
    fn resume(&mut self, step: bool) {
        STEP_REQ.store(step, Ordering::Release);
    }
    fn is_halted(&self) -> bool {
        IN_MONITOR.load(Ordering::Acquire)
    }
    fn request_halt(&mut self) {
        HALT_PENDING.store(true, Ordering::Release);
    }
}

/// The engine, shared with the host harness so the protocol that ships
/// is the protocol that was tested.
static mut ENGINE: pqf_gdbstub_core::Engine = pqf_gdbstub_core::Engine::new();

/// A trap happened and GDB has not been told yet.
///
/// The monitor cannot send it directly -- the CDC session lives with
/// the USB device, not in exception context -- so it raises this and
/// the next service call delivers it. Without this a `continue` never
/// returns: the target dutifully stops and nobody says so.
static REPORT_STOP: AtomicBool = AtomicBool::new(false);

/// Read whatever the host has sent and act on complete packets.
///
/// Returns true when the target should resume. Used from the normal
/// poll loop and from inside the monitor's halted spin -- the same
/// call, because the engine does not care which context it is in.
pub fn service<B: usb_device::bus::UsbBus>(session: &mut Session<'_, B>) -> bool {
    // SAFETY: single-threaded.
    let engine = unsafe { &mut *(&raw mut ENGINE) };
    if REPORT_STOP.swap(false, Ordering::AcqRel) && engine.attached {
        engine.send_stop_reason(session);
    }
    let mut chunk = [0u8; 64];
    let n = {
        use pqf_gdbstub_core::Transport;
        session.read(&mut chunk)
    };
    if n == 0 {
        return false;
    }
    // SAFETY: single-threaded; the monitor and the poll loop never run
    // at the same time (the monitor preempts thread mode).
    let engine = unsafe { &mut *(&raw mut ENGINE) };
    engine.feed(session, &mut Hw, &chunk[..n])
}

/// Called from the firmware's main loop. Cheap with no debugger
/// attached: it drains the CDC endpoint and returns.
pub fn poll<B: usb_device::bus::UsbBus>(session: &mut Session<'_, B>) {
    if !ENABLED.load(Ordering::Acquire) || IN_MONITOR.load(Ordering::Acquire) {
        return;
    }
    service(session);
    // Now that packet handling has returned, it is safe to actually
    // stop: the monitor is about to call back in through the USB pump.
    if HALT_PENDING.swap(false, Ordering::AcqRel) {
        request_halt();
    }
}

/// How the monitor reaches USB while the rest of the firmware is
/// suspended.
///
/// This is the crux of the whole design and the easiest thing to get
/// wrong. When DebugMonitor fires it preempts thread mode, so `main` --
/// which owns the `UsbDevice` and the CDC session -- is *not running*.
/// A halted loop written in `main` can therefore never execute, and the
/// monitor would spin forever on the first breakpoint anyone set.
///
/// So the firmware registers a callback that services USB and the GDB
/// session, and the monitor calls it directly. The C port solves the
/// same problem by calling `tud_task()` from inside the handler; this
/// is the same shape, expressed as a function pointer because the USB
/// device is a local in `main` rather than a global.
///
/// Returns true once a continue or step arrived.
static mut PUMP: Option<fn() -> bool> = None;

/// Register the service callback. Called once from `main`.
///
/// # Safety
/// `f` must be safe to call from exception context: it will run with
/// the rest of the firmware suspended.
pub unsafe fn set_pump(f: fn() -> bool) {
    // SAFETY: single write during bring-up, before any debug event.
    unsafe { PUMP = Some(f) };
}

/// The monitor loop: where "halted" actually happens.
///
/// Entered from the DebugMonitor exception with the interrupted context
/// already captured. Spins servicing GDB, pumping USB as it goes, until
/// a continue or step arrives.
///
/// # Safety
/// Called only from the DebugMonitor trampoline, with `frame` pointing
/// at the stacked exception frame and `callee` at the pushed r4-r11.
pub unsafe fn monitor_entry(frame: *mut u32, callee: *mut u32) {
    if IN_MONITOR.swap(true, Ordering::AcqRel) {
        // Re-entry: a fault inside the stub. Returning is the least bad
        // option -- recursing would exhaust the stack.
        return;
    }
    fpb_enable(false);

    // Capture the interrupted context.
    // SAFETY: the caller guarantees both pointers.
    unsafe {
        let regs = &mut (&mut *(&raw mut ENGINE)).regs;
        for i in 0..4 {
            regs[i] = frame.add(FRAME_R0 + i).read_volatile();
        }
        for i in 0..8 {
            regs[4 + i] = callee.add(i).read_volatile();
        }
        regs[12] = frame.add(FRAME_R12).read_volatile();
        // SP as the interrupted code saw it: the frame sits on its
        // stack, so add the frame back.
        regs[13] = frame as u32 + 32;
        regs[14] = frame.add(FRAME_LR).read_volatile();
        regs[15] = frame.add(FRAME_PC).read_volatile();
        regs[16] = frame.add(FRAME_XPSR).read_volatile();
    }

    // Clear any pending halt request now that we have stopped.
    // SAFETY: architected register.
    unsafe {
        let demcr = mmio::read32(SCB_DEMCR);
        mmio::write32(SCB_DEMCR, demcr & !(DEMCR_MON_PEND | DEMCR_MON_STEP));
    }

    HALTED.store(true, Ordering::Release);
    // Say why, then tell GDB via the next service call. Without this the
    // reason is whatever the last stop set, so one Ctrl-C would make
    // every later breakpoint report itself as an interrupt.
    // SAFETY: single-threaded; the poll loop cannot run while we are in
    // the monitor.
    unsafe {
        (&mut *(&raw mut ENGINE)).stop_reason = if HALT_REQ.load(Ordering::Acquire) {
            pqf_gdbstub_core::StopReason::Interrupt
        } else {
            pqf_gdbstub_core::StopReason::Trap
        };
    }
    REPORT_STOP.store(true, Ordering::Release);
    // Service USB from right here. `main` is suspended underneath us,
    // so nothing else can.
    // SAFETY: single-threaded; set once during bring-up.
    let pump = unsafe { PUMP };
    match pump {
        Some(f) => {
            while HALTED.load(Ordering::Acquire) {
                if f() {
                    HALTED.store(false, Ordering::Release);
                }
            }
        }
        // No callback registered: resuming immediately is the only
        // option that does not hang the token.
        None => HALTED.store(false, Ordering::Release),
    }

    // Push any register writes back into the stacked frame, or a
    // `set $pc` would change GDB's copy and nothing else -- the target
    // would resume exactly where it trapped, silently ignoring the
    // debugger. Callee-saved r4-r11 go back to the trampoline's push,
    // which `pop {r4-r11, pc}` will restore.
    // SAFETY: both pointers are the trampoline's, valid until it
    // returns, and we are the only writer while halted.
    unsafe {
        let regs = &(&*(&raw const ENGINE)).regs;
        for i in 0..4 {
            frame.add(FRAME_R0 + i).write_volatile(regs[i]);
        }
        for i in 0..8 {
            callee.add(i).write_volatile(regs[4 + i]);
        }
        frame.add(FRAME_R12).write_volatile(regs[12]);
        frame.add(FRAME_LR).write_volatile(regs[14]);
        frame.add(FRAME_PC).write_volatile(regs[15]);
        // xPSR is deliberately NOT written back: clearing the Thumb bit
        // there faults the core on return, and nothing GDB legitimately
        // does needs it.
    }

    // Resume. A step returns with MON_STEP set so the core executes one
    // instruction and comes straight back.
    if STEP_REQ.swap(false, Ordering::AcqRel) {
        // SAFETY: architected register.
        unsafe {
            let demcr = mmio::read32(SCB_DEMCR);
            mmio::write32(SCB_DEMCR, demcr | DEMCR_MON_STEP);
        }
    }
    HALT_REQ.store(false, Ordering::Release);
    fpb_enable(true);
    IN_MONITOR.store(false, Ordering::Release);
}

/// Set while the monitor is waiting for GDB; cleared to resume.
static HALTED: AtomicBool = AtomicBool::new(false);

/// DebugMonitor entry trampoline.
///
/// Naked so the stacked frame is still exactly where the hardware left
/// it: a normal function prologue would move SP before we could read
/// it. Pushes r4-r11 (which the hardware does not stack) and hands both
/// pointers to [`monitor_entry`].
///
/// # Safety
/// Installed as the DebugMonitor vector; never called directly.
#[cfg(all(target_arch = "arm", feature = "gdb_stub"))]
#[no_mangle]
#[unsafe(naked)]
pub unsafe extern "C" fn DebugMonitor() {
    core::arch::naked_asm!(
        // EXC_RETURN bit 2 selects which stack was in use.
        "tst   lr, #4",
        "ite   eq",
        "mrseq r0, msp",
        "mrsne r0, psp",
        "push  {{r4-r11, lr}}",
        "mov   r1, sp",
        "bl    {entry}",
        "pop   {{r4-r11, pc}}",
        entry = sym monitor_entry_shim,
    )
}

/// Thin shim so the trampoline can `bl` a plain C-ABI symbol.
///
/// # Safety
/// Called only from the trampoline above.
#[cfg(all(target_arch = "arm", feature = "gdb_stub"))]
#[no_mangle]
pub unsafe extern "C" fn monitor_entry_shim(frame: *mut u32, callee: *mut u32) {
    // SAFETY: forwarded from the trampoline, which guarantees both.
    unsafe { monitor_entry(frame, callee) }
}
