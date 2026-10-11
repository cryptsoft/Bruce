//! Runtime sampling of the BOOTSEL button via the QSPI chip-select
//! line.
//!
//! Rust port of `picoboard/button/button.c` from Raspberry Pi
//! `pico-examples` -- Copyright (c) 2020 Raspberry Pi (Trading) Ltd.,
//! SPDX-License-Identifier: BSD-3-Clause -- see `THIRD_PARTY.md`
//! ("Raspberry Pi pico-examples" entry); the licence's conditions and
//! disclaimer are reproduced in `LICENSE-BSD-3-CLAUSE-PICO-EXAMPLES` at
//! the repository root. The copyleft-licensed
//! adaptations of the same routine that circulate in other FIDO
//! firmware were NOT consulted; this file derives from the BSD
//! upstream only.
//!
//! ## How it works
//!
//! On reference-design RP2350 boards the BOOTSEL button isn't on a
//! GPIO: it shorts the flash chip-select line (QSPI_SS) to ground
//! through a 1 kohm resistor, and the bootrom samples that line at reset
//! to decide whether to enter the USB bootloader. The same line is
//! observable at runtime:
//!
//!   1. Override the QSPI_SS pad's output-enable (`OEOVER = DISABLE`
//!      in `IO_QSPI.GPIO_QSPI_SS.CTRL`), tristating the chip-select
//!      driver. The pad's pull-up holds the line high; a pressed
//!      button wins through the 1 kohm and pulls it low.
//!   2. Busy-wait ~us for the line to settle.
//!   3. Read the line through `SIO.GPIO_HI_IN` (the HI register bank
//!      mirrors the QSPI pads; QSPI_CSN is bit 27 on RP2350). Pressed
//!      reads LOW.
//!   4. Restore `OEOVER = NORMAL` so the flash is reachable again.
//!
//! ## Why this is a RAM function with interrupts disabled
//!
//! While CS is floated the flash doesn't see its chip select, so the
//! XIP window (0x1000_0000..) is unreadable -- the same blackout
//! condition `ramfunc.rs` documents for erase/program sequences, just
//! a few microseconds long. So, per the same rules:
//!
//!   * the sampler lives in `.data.ramfunc` (copied to SRAM by
//!     cortex-m-rt at startup) and is `#[inline(never)]` so it is one
//!     RAM-resident symbol;
//!   * interrupts are masked across the window (an ISR fetched from
//!     XIP would fault) with the same raw `asm!` PRIMASK save/restore
//!     as `ramfunc::flash_op_locked` -- no out-of-line `.text` calls
//!     inside the window;
//!   * the settle delay is an inline-`nop` loop, mirroring upstream's
//!     volatile busy loop (`sleep_*` lives in flash);
//!   * the register pointers are materialised BEFORE the window, so
//!     only raw volatile loads/stores happen while CS is floated.
//!
//! ## Core 1
//!
//! Unlike the flash path, the sampler does NOT park core 1 -- the
//! blackout is a few microseconds, and it is only ever entered from
//! the `WaitForUp` gate in `main.rs`, which runs before a sign is
//! submitted, i.e. while core 1 sits in its idle worker spin loop.
//! That loop is a handful of instructions, resident in the XIP cache
//! after its first iteration, and nothing else runs on core 1 to
//! evict it -- so core 1 issues no flash fetch during the window.
//! (This matches upstream's caveat that the trick requires nobody
//! else to be touching flash concurrently.) Callers must preserve
//! that property: do not sample while a sign or a flash write is in
//! flight.
//!
//! ## Behavioural caveats (second-class button)
//!
//! Polling only -- QSPI_SS has no GPIO IRQ path, so edges can't be
//! caught in hardware; the board profile rate-limits sampling instead.
//! The button is still shared with the bootrom: held at power-on it
//! enters BOOTSEL mode as always (that's how this firmware gets
//! flashed); at runtime a press just reads as a level with no reset
//! side effects.

use crate::arch::{irq_restore, irq_save_disable, nop as ram_nop};

/// Sample the BOOTSEL button. Returns `true` while it is held down.
///
/// Costs a few microseconds of flash blackout per call (interrupts
/// masked, both cores must avoid XIP fetches -- see the module doc).
/// Callers should rate-limit; the Feitian board profile samples at
/// most every 2 ms.
#[inline(never)]
#[link_section = ".data.ramfunc"]
pub fn pressed() -> bool {
    use crate::hal::pac;

    // `OEOVER` field of IO_QSPI.GPIO_QSPI_SS.CTRL -- bits 15:14
    // (rp235x-pac `gpio_ctrl::OEOVER_W::new(self, 14)`, 2-bit field).
    // DISABLE (2) tristates the pad's output driver; NORMAL (0) hands
    // it back to the QMI peripheral.
    const OEOVER_LSB: u32 = 14;
    const OEOVER_BITS: u32 = 0b11 << OEOVER_LSB;
    const OEOVER_DISABLE: u32 = 2 << OEOVER_LSB;
    const OEOVER_NORMAL: u32 = 0 << OEOVER_LSB;
    // QSPI_CSN input mirror in SIO.GPIO_HI_IN -- bit 27 on RP2350
    // (rp235x-pac `gpio_hi_in::qspi_csn`, `bits >> 27`; the RP2040
    // equivalent was bit 1, one of the two ports' few differences).
    const QSPI_CSN_BIT: u32 = 1 << 27;

    // PADS_QSPI.GPIO_QSPI_SS field positions (rp235x-pac
    // `pads_qspi::gpio_qspi_ss`): PDE=2, PUE=3, IE=6, OD=7, ISO=8.
    //
    // Upstream's `get_bootsel_button()` samples the line without
    // touching the pad, trusting the pull-up, input buffer and
    // (RP2350-only) isolation latch to hold the reset defaults the
    // bootrom left. That trust does not survive a flash write: the
    // bootrom's `connect_internal_flash` / `flash_exit_xip` pair
    // reconfigures the QSPI pads for its own use and does not promise
    // to put every field back, so after the first credential or PIN
    // write the line can come back with the pull-up off -- floating,
    // where "not pressed" reads as whatever charge is left on the pad
    // and a real press can read either way. That is exactly the
    // intermittent user-presence failure this board showed: the gate
    // works on a fresh boot and stops once a CTAP op has written
    // flash. So drive the pad into a known sampling state here and
    // put it back afterwards, rather than inheriting one.
    const PDE_BIT: u32 = 1 << 2;
    const PUE_BIT: u32 = 1 << 3;
    const IE_BIT: u32 = 1 << 6;
    const OD_BIT: u32 = 1 << 7;
    const ISO_BIT: u32 = 1 << 8;

    // Materialise all three register pointers while flash is still
    // readable. Raw pointers into fixed peripheral address space;
    // nothing else in this firmware claims these registers (the HAL
    // never hands out IO_QSPI or PADS_QSPI, and SIO.GPIO_HI_IN is
    // read-only), so the volatile accesses below don't race any owned
    // register handle.
    let ss_ctrl: *mut u32 = unsafe { (*pac::IO_QSPI::ptr()).gpio_qspiss().gpio_ctrl().as_ptr() };
    let hi_in: *mut u32 = unsafe { (*pac::SIO::ptr()).gpio_hi_in().as_ptr() };
    let ss_pad: *mut u32 = unsafe { (*pac::PADS_QSPI::ptr()).gpio_qspi_ss().as_ptr() };

    // Mask interrupts for the blackout window, preserving the caller's
    // mask state (PRIMASK on Arm, mstatus.MIE on RISC-V) -- identical
    // pattern to `ramfunc::flash_op_locked`. The `crate::arch` shims
    // are inline(always) raw asm: no out-of-line `.text` call here.
    let saved = irq_save_disable();

    // SAFETY: volatile RMW of a device register we exclusively drive
    // (see pointer comment above); flash is unreachable from here
    // until OEOVER is restored, and everything in between is this RAM
    // function's own straight-line code.
    let pressed = unsafe {
        // Put the pad in a known state to sample in: pull-up on,
        // pull-down off, input buffer on, output-disable off,
        // isolation latch clear. Saved first and restored below, so
        // the QMI gets back exactly the pad it had.
        let pad = ss_pad.read_volatile();
        ss_pad.write_volatile((pad & !(PDE_BIT | OD_BIT | ISO_BIT)) | PUE_BIT | IE_BIT);

        // Float the chip select.
        let ctrl = ss_ctrl.read_volatile();
        ss_ctrl.write_volatile((ctrl & !OEOVER_BITS) | OEOVER_DISABLE);

        // Let the line settle through the pull-up / button. Upstream
        // uses a ~1000-iteration volatile loop; at 150 MHz this is on
        // the order of 10-20 us. Doubled here: the rise through the
        // pad's weak pull-up is the slow direction, and this runs
        // right after the pull-up was (re-)enabled above, so the line
        // may be starting from a fully discharged pad rather than
        // from a steady high.
        for _ in 0..2000 {
            ram_nop();
        }

        // Button shorts QSPI_SS to ground: pressed reads LOW. Three
        // reads, majority vote -- a single read of a line that has
        // just been floated is the one sample most exposed to a
        // coupled edge from the QMI's other QSPI lines.
        let mut low = 0u32;
        for _ in 0..3 {
            if hi_in.read_volatile() & QSPI_CSN_BIT == 0 {
                low += 1;
            }
            for _ in 0..50 {
                ram_nop();
            }
        }
        let state = low >= 2;

        // Hand the pad back to the QMI peripheral -- flash is
        // reachable again after this store -- and restore the pad
        // configuration the QMI was using.
        let ctrl = ss_ctrl.read_volatile();
        ss_ctrl.write_volatile((ctrl & !OEOVER_BITS) | OEOVER_NORMAL);
        ss_pad.write_volatile(pad);
        state
    };

    irq_restore(saved);
    pressed
}
