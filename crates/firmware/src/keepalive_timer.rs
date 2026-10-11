// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Timer-driven CTAPHID `KEEPALIVE` for the single-core build.
//!
//! The dual-core firmware keeps the host's watchdog quiet by having core 0
//! pump USB and a `KEEPALIVE` frame every ~50 ms while core 1 signs. With
//! `single_core` the sign runs on core 0 itself, inside a bc-rust call that
//! offers no yield point, so nothing in the main context can pump. This
//! module does it from a hardware timer instead: alarm 0 of TIMER0 fires
//! every [`PERIOD_MS`], and its interrupt handler sends one `KEEPALIVE` on
//! the in-flight channel and services the USB device, then re-arms.
//!
//! ## Why this is safe alongside the polled USB stack
//!
//! `UsbDevice` and the FIDO class live in `main`'s frame and are not
//! designed for two contexts. Exclusion is by construction rather than by
//! lock:
//!
//! * the alarm is armed only for the duration of a CTAP2 dispatch
//!   ([`arm`] before `handle_cbor`, [`disarm`] after), so outside a
//!   command the main loop owns USB alone -- the U2F path (`u2f`
//!   feature) never arms it, its ECDSA-only work being far shorter than
//!   the host's watchdog;
//! * inside a dispatch the only main-context code that touches USB is
//!   the `host` closure (keepalive pumps, the presence wait), and it holds
//!   a [`UsbGuard`] while it does; the handler sees `USB_BUSY` and skips
//!   that tick rather than racing;
//! * everything else the dispatch does is computation, during which the
//!   handler has USB to itself.
//!
//! The two XIP-off windows in this firmware -- flash writes
//! (`ramfunc::flash_op_locked`) and the BOOTSEL chip-select sampler
//! (`board::bootsel`) -- already mask interrupts across the blackout,
//! because an interrupt vector fetched from a floated flash would fault.
//! That was true before this module existed and is what makes a timer
//! interrupt tolerable here at all.
//!
//! Counters ([`TICKS`], [`SENT`], [`SKIPPED`]) are kept for a debugger;
//! the silicon witness is the host, which counts the `KEEPALIVE` frames
//! it receives (`pqf_ctaphid::hid::Stats::keepalives`).

use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::hal;
use hal::fugit::MicrosDurationU32;
use hal::timer::Alarm as _;

pub type Bus = hal::usb::UsbBus;
type Alarm0 = hal::timer::Alarm0<hal::timer::CopyableTimer0>;

/// Keepalive period. Chrome's watchdog is quoted at a few hundred
/// milliseconds; the dual-core pump runs at ~50 ms.
pub const PERIOD_MS: u32 = 25;

static mut DEV: *mut usb_device::device::UsbDevice<'static, Bus> = null_mut();
static mut FIDO: *mut crate::fido_hid::FidoHidClass<'static, Bus> = null_mut();
static mut ALARM: Option<Alarm0> = None;

/// Channel of the command in flight; 0 = disarmed.
static CID: AtomicU32 = AtomicU32::new(0);
/// The main context is inside the USB stack: the handler must not be.
static USB_BUSY: AtomicBool = AtomicBool::new(false);

/// Alarm interrupts taken.
pub static TICKS: AtomicU32 = AtomicU32::new(0);
/// `KEEPALIVE` frames handed to the endpoint.
pub static SENT: AtomicU32 = AtomicU32::new(0);
/// Ticks skipped because the main context held USB.
pub static SKIPPED: AtomicU32 = AtomicU32::new(0);

/// Install the alarm and the USB objects the handler will drive, and
/// route the alarm interrupt to it.
///
/// # Safety
///
/// `dev` and `fido` must stay valid for the rest of the program (they are
/// `main`'s locals, and `main` never returns). Call once, before any
/// dispatch can [`arm`] the timer.
pub unsafe fn init(
    alarm: Alarm0,
    dev: *mut usb_device::device::UsbDevice<'static, Bus>,
    fido: *mut crate::fido_hid::FidoHidClass<'static, Bus>,
) {
    DEV = dev;
    FIDO = fido;
    ALARM = Some(alarm);
    #[cfg(target_arch = "arm")]
    {
        cortex_m::peripheral::NVIC::unmask(hal::pac::Interrupt::TIMER0_IRQ_0);
    }
    #[cfg(target_arch = "riscv32")]
    {
        hal::xh3irq::unmask(hal::pac::Interrupt::TIMER0_IRQ_0);
        riscv::register::mie::set_mext();
        riscv::interrupt::enable();
    }
}

/// Start the cadence for the command on `cid`.
pub fn arm(cid: u32) {
    CID.store(cid, Ordering::SeqCst);
    // SAFETY: `init` ran before any dispatch; the handler is the only other
    // user and it cannot run between these two statements on this core...
    // it can, actually, but it re-arms with the same period, so the order
    // is harmless.
    unsafe {
        if let Some(a) = (*core::ptr::addr_of_mut!(ALARM)).as_mut() {
            a.clear_interrupt();
            a.enable_interrupt();
            let _ = a.schedule(MicrosDurationU32::millis(PERIOD_MS));
        }
    }
}

/// Stop the cadence. A tick already pending sees `CID == 0` and does
/// nothing.
pub fn disarm() {
    CID.store(0, Ordering::SeqCst);
    unsafe {
        if let Some(a) = (*core::ptr::addr_of_mut!(ALARM)).as_mut() {
            a.disable_interrupt();
            let _ = a.cancel();
            a.clear_interrupt();
        }
    }
}

/// Held by the main context while it touches USB inside a dispatch.
pub struct UsbGuard(());

impl UsbGuard {
    pub fn enter() -> Self {
        USB_BUSY.store(true, Ordering::SeqCst);
        UsbGuard(())
    }
}

impl Drop for UsbGuard {
    fn drop(&mut self) {
        USB_BUSY.store(false, Ordering::SeqCst);
    }
}

/// The alarm handler proper. Re-arms first so a slow USB service cannot
/// stretch the cadence, then sends one frame and polls once.
fn on_alarm() {
    // SAFETY: interrupt context on the core that owns these objects; the
    // main context is either outside a dispatch (CID == 0, we return
    // before touching USB) or inside one and not touching USB (the guard
    // says so), or inside the guard (we skip).
    unsafe {
        if let Some(a) = (*core::ptr::addr_of_mut!(ALARM)).as_mut() {
            a.clear_interrupt();
            let _ = a.schedule(MicrosDurationU32::millis(PERIOD_MS));
        }
        TICKS.fetch_add(1, Ordering::Relaxed);
        let cid = CID.load(Ordering::SeqCst);
        if cid == 0 {
            return;
        }
        if USB_BUSY.load(Ordering::SeqCst) {
            SKIPPED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let dev = &mut *DEV;
        let fido = &mut *FIDO;
        let ka = crate::ctaphid::keepalive_frame(cid, crate::ctaphid::KEEPALIVE_PROCESSING);
        if fido.send_frame(&ka).is_ok() {
            SENT.fetch_add(1, Ordering::Relaxed);
        }
        let _ = dev.poll(&mut [fido as &mut dyn usb_device::class::UsbClass<Bus>]);
    }
}

#[cfg(target_arch = "arm")]
mod isr {
    use hal::pac::interrupt;
    use rp235x_hal as hal;

    #[interrupt]
    fn TIMER0_IRQ_0() {
        super::on_alarm();
    }
}

/// Hazard3: every external interrupt arrives as one machine-external
/// trap. rp235x-hal owns that trap (`MachineExternal` in its `arch.rs`),
/// asks the Xh3irq controller which line fired and calls the handler of
/// that name through the PAC's vector table, so this is the same symbol
/// the Arm side installs with `#[interrupt]`, minus the macro.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[allow(non_snake_case)]
pub fn TIMER0_IRQ_0() {
    on_alarm();
}
