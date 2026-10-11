//! Runtime sampling of the BOOTSEL button via the QSPI chip-select
//! line.
//!
//! Carried over from the FIDO firmware (`crates/firmware/src/board/
//! bootsel.rs`) into the Secure world, with only the interrupt shims
//! swapped for `cortex-m` ones. It has to live here: user presence is
//! a Secure decision, and IO_QSPI is not in ACCESSCTRL's NS allow-list,
//! so NS could not sample the button even if it were trusted to.
//!
//! Rust port of `picoboard/button/button.c` from Raspberry Pi
//! `pico-examples` -- Copyright (c) 2020 Raspberry Pi (Trading) Ltd.,
//! SPDX-License-Identifier: BSD-3-Clause -- see `THIRD_PARTY.md`
//! ("Raspberry Pi pico-examples" entry); the licence's conditions and
//! disclaimer are reproduced in `LICENSE-BSD-3-CLAUSE-PICO-EXAMPLES` at
//! the repository root. The copyleft-licensed adaptations
//! of the same routine that circulate in other FIDO firmware were NOT
//! consulted; this file derives from the BSD upstream only.
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

/// A NOP that is genuinely emitted in place.
///
/// NOT `cortex_m::asm::nop`: in this build that compiles to `bl __nop`,
/// and `__nop` lives in flash. The settle loop below runs a thousand of
/// them *while the flash chip select is floated*, which is precisely
/// the out-of-line call into an unreadable XIP window that the module
/// documentation says must not happen. It survived because the callee
/// is tiny and hot enough to sit in the XIP cache, so it usually works
/// -- the worst kind of latent bug.
///
/// Same shape as `pqf-signer-core`'s `arch::nop`, which the FIDO
/// firmware relies on for the identical reason.
#[inline(always)]
fn ram_nop() {
    // SAFETY: `nop` has no operands and no memory/flag effects.
    #[cfg(any(target_arch = "arm", target_arch = "riscv32"))]
    unsafe {
        core::arch::asm!("nop", options(nomem, nostack, preserves_flags));
    }
    // Off-target the delay only has to be work the compiler will not
    // remove; the inline asm above is target-specific.
    #[cfg(not(any(target_arch = "arm", target_arch = "riscv32")))]
    core::hint::black_box(());
}

/// Mask interrupts, returning whether they had been enabled.
#[inline(always)]
fn irq_save_disable() -> bool {
    let was = cortex_m::register::primask::read().is_active();
    cortex_m::interrupt::disable();
    was
}

#[inline(always)]
fn irq_restore(was_enabled: bool) {
    if was_enabled {
        // SAFETY: only re-enabling because the caller had them enabled.
        unsafe { cortex_m::interrupt::enable() };
    }
}

/// Sample the BOOTSEL button. Returns `true` while it is held down.
///
/// Costs a few microseconds of flash blackout per call (interrupts
/// masked, both cores must avoid XIP fetches -- see the module doc).
/// Callers should rate-limit; the Feitian board profile samples at
/// most every 2 ms.
#[inline(never)]
// Gated to the board targets so the module builds on a host too;
// `.data.ramfunc` is not a section name a Mach-O linker accepts.
#[cfg_attr(
    any(target_arch = "arm", target_arch = "riscv32"),
    link_section = ".data.ramfunc"
)]
pub fn pressed() -> bool {
    use rp235x_hal::pac;

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

    // Materialise both register pointers while flash is still
    // readable. Raw pointers into fixed peripheral address space;
    // nothing else in this firmware claims either register (the HAL
    // never hands out IO_QSPI, and SIO.GPIO_HI_IN is read-only), so
    // the volatile accesses below don't race any owned register
    // handle.
    let ss_ctrl: *mut u32 = unsafe { (*pac::IO_QSPI::ptr()).gpio_qspiss().gpio_ctrl().as_ptr() };
    let hi_in: *mut u32 = unsafe { (*pac::SIO::ptr()).gpio_hi_in().as_ptr() };

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
        // Float the chip select.
        let ctrl = ss_ctrl.read_volatile();
        ss_ctrl.write_volatile((ctrl & !OEOVER_BITS) | OEOVER_DISABLE);

        // Let the line settle through the pull-up / button. Upstream
        // uses a ~1000-iteration volatile loop; at 150 MHz this is on
        // the order of 10-20 us.
        for _ in 0..1000 {
            ram_nop();
        }

        // Button shorts QSPI_SS to ground: pressed reads LOW.
        let state = hi_in.read_volatile() & QSPI_CSN_BIT == 0;

        // Hand the pad back to the QMI peripheral -- flash is
        // reachable again after this store.
        let ctrl = ss_ctrl.read_volatile();
        ss_ctrl.write_volatile((ctrl & !OEOVER_BITS) | OEOVER_NORMAL);
        state
    };

    irq_restore(saved);
    pressed
}

/// Diagnostic: return the raw pieces the sampler decides from.
///
/// Packs (ctrl_after_override & 0xffff) in the low 16 bits and the
/// QSPI_CSN input bit in bit 16. If the override never lands, the CTRL
/// readback shows it; if it lands and the line still reads high, the
/// problem is electrical rather than a wrong register.
#[cfg(feature = "dev-escape")]
#[inline(never)]
// Gated to the board targets so the module builds on a host too;
// `.data.ramfunc` is not a section name a Mach-O linker accepts.
#[cfg_attr(
    any(target_arch = "arm", target_arch = "riscv32"),
    link_section = ".data.ramfunc"
)]
pub fn probe() -> u32 {
    use rp235x_hal::pac;
    const OEOVER_LSB: u32 = 14;
    const OEOVER_BITS: u32 = 0b11 << OEOVER_LSB;
    const OEOVER_DISABLE: u32 = 2 << OEOVER_LSB;
    const OEOVER_NORMAL: u32 = 0 << OEOVER_LSB;
    const QSPI_CSN_BIT: u32 = 1 << 27;

    let ss_ctrl: *mut u32 = unsafe { (*pac::IO_QSPI::ptr()).gpio_qspiss().gpio_ctrl().as_ptr() };
    let hi_in: *mut u32 = unsafe { (*pac::SIO::ptr()).gpio_hi_in().as_ptr() };

    let saved = irq_save_disable();
    // SAFETY: same contract as `pressed`.
    let out = unsafe {
        let ctrl = ss_ctrl.read_volatile();
        ss_ctrl.write_volatile((ctrl & !OEOVER_BITS) | OEOVER_DISABLE);
        for _ in 0..1000 {
            ram_nop();
        }
        let back = ss_ctrl.read_volatile();
        let line = hi_in.read_volatile();
        let ctrl2 = ss_ctrl.read_volatile();
        ss_ctrl.write_volatile((ctrl2 & !OEOVER_BITS) | OEOVER_NORMAL);
        (back & 0xffff) | (u32::from(line & QSPI_CSN_BIT != 0) << 16)
    };
    irq_restore(saved);
    out
}
