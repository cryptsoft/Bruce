// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! RISC-V core-1 payload: scaffolding around the shared signing
//! worker for the mixed-architecture build (Arm core 0 + Hazard3
//! core 1 on the same RP2350).
//!
//! ## Life cycle
//!
//! 1. The Arm firmware (built with `-F core1_riscv`) holds core 1 in
//!    reset, flips its OTP ARCHSEL bit to RISC-V, and releases it --
//!    core 1 comes up as a Hazard3 in the boot ROM's wait-for-launch
//!    loop.
//! 2. The firmware runs the documented FIFO launch handshake with
//!    MTVEC = our trap loop (BFLASH+0), SP = top of the blob RAM
//!    window, PC = our entry (BFLASH+8). All three constants are
//!    defined in `pqf_signer_core::mixed` and pinned by `blob.x`
//!    ASSERTs.
//! 3. Our entry asm sets `gp` (the launch handshake doesn't), then
//!    [`blob_start`] copies `.data` (flash->RAM), zeroes `.bss`,
//!    initialises the private heap, reads the mailbox address that
//!    core 0 pushes through the SIO FIFO right after the handshake,
//!    and enters [`Core1Signer::worker_poll`] -- forever.
//!
//! ## Why `worker_poll` (and a private heap)
//!
//! * The event/unblock signal routing between an M33 and a Hazard3 is
//!   not hardware-verified, so the blob busy-polls instead of parking
//!   in `h3.block` -- it cannot miss a wake. See the signer-core
//!   module docs.
//! * The ML-DSA lowmem crate heap-allocates its working set; the blob
//!   brings its own allocator over a static buffer in blob RAM rather
//!   than sharing core 0's heap, so no allocator lock ever spans the
//!   two instruction sets.
//!
//! A panic here parks the core in the trap loop; core 0's signing
//! waits are already bounded (SPIN_CAP in ctap2.rs), so a wedged blob
//! degrades exactly like a wedged Arm core 1 would.

#![no_std]
#![no_main]

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

use embedded_alloc::LlffHeap as Heap;
use pqf_signer_core::signer::Core1Signer;

/// Mailbox address, stashed after the FIFO rendezvous so the panic
/// handler can poison it (report `STATE_ERROR` to core 0) if this
/// core dies -- e.g. a heap OOM mid-sign. Without that, core 0 would
/// spin against a dead worker (a multi-minute SPIN_CAP wait, then a
/// permanently wedged `submit()` -- user-visible as a frozen device).
static MAILBOX_ADDR: AtomicUsize = AtomicUsize::new(0);

/// 32 KiB private heap for the ML-DSA working set -- lives in `.bss`,
/// i.e. inside the blob RAM window. (The Arm firmware's 256 KiB main
/// heap comment explains the ML-DSA appetite; the lowmem crate's
/// core-1 slice of it is far smaller -- this matches the headroom the
/// 64 KiB stack + 128 KiB window design allows.)
const HEAP_SIZE: usize = 32 * 1024;

#[global_allocator]
static HEAP: Heap = Heap::empty();

static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

// Entry + trap asm. Layout contract (ASSERTed in blob.x, consumed by
// the firmware launcher via pqf_signer_core::mixed):
//   +0  pqf_blob_trap  -- wfi parking loop, handed to core 1 as MTVEC
//   +8  pqf_blob_entry -- set gp, jump to Rust
// `.option norvc` keeps every instruction 4 bytes so the offsets hold;
// `norelax` around the gp load stops the assembler from "relaxing" it
// into a gp-relative load of gp itself.
core::arch::global_asm!(
    ".section .blob_entry, \"ax\"",
    ".option push",
    ".option norvc",
    ".global pqf_blob_trap",
    "pqf_blob_trap:",
    "    wfi",
    "    j pqf_blob_trap",
    ".global pqf_blob_entry",
    "pqf_blob_entry:",
    ".option norelax",
    "    la gp, __global_pointer$",
    "    j {start}",
    ".option pop",
    start = sym blob_start,
);

/// Rust-side startup: runtime init, FIFO rendezvous, then the worker.
extern "C" fn blob_start() -> ! {
    // .data copy and .bss zero -- the blob has no riscv-rt, so we do
    // the two loops ourselves. Straight-line code only; no statics may
    // be touched before these finish.
    unsafe {
        extern "C" {
            static mut __sdata: u32;
            static mut __edata: u32;
            static __sidata: u32;
            static mut __sbss: u32;
            static mut __ebss: u32;
        }
        let mut src = core::ptr::addr_of!(__sidata);
        let mut dst = core::ptr::addr_of_mut!(__sdata);
        let dend = core::ptr::addr_of_mut!(__edata);
        while dst < dend {
            dst.write_volatile(src.read_volatile());
            dst = dst.add(1);
            src = src.add(1);
        }
        let mut bss = core::ptr::addr_of_mut!(__sbss);
        let bend = core::ptr::addr_of_mut!(__ebss);
        while bss < bend {
            bss.write_volatile(0);
            bss = bss.add(1);
        }
    }

    // Private heap over the static buffer (now-zeroed .bss).
    unsafe {
        #[allow(static_mut_refs)]
        HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE);
    }

    // Rendezvous: core 0 pushes `&CORE1_SIGNER as u32` into the
    // inter-core FIFO immediately after the launch handshake (whose
    // echoes have all been drained, so the first word we see IS the
    // mailbox). Raw SIO registers -- not worth a PAC dependency for
    // one status poll + one read.
    const SIO_FIFO_ST: *const u32 = 0xd000_0050 as *const u32;
    const SIO_FIFO_RD: *const u32 = 0xd000_0058 as *const u32;
    let mailbox = unsafe {
        // FIFO_ST.VLD (bit 0): RX FIFO non-empty.
        while SIO_FIFO_ST.read_volatile() & 1 == 0 {
            core::hint::spin_loop();
        }
        SIO_FIFO_RD.read_volatile() as *const Core1Signer
    };

    // SAFETY: core 0 guarantees the address is its 'static
    // CORE1_SIGNER mailbox, in always-mapped shared SRAM; the
    // protocol's state machine handles all further synchronisation.
    let signer: &'static Core1Signer = unsafe { &*mailbox };
    MAILBOX_ADDR.store(mailbox as usize, Ordering::Release);
    signer.worker_poll()
}

/// Minimal single-core critical-section for embedded-alloc: mask
/// M-mode interrupts (they are never enabled on this core, so this is
/// belt-and-braces) via the shared arch shims.
struct SingleCoreCs;
critical_section::set_impl!(SingleCoreCs);
// SAFETY: this core never shares the protected state (the private
// heap) with anyone -- core 0 has its own allocator -- so masking local
// interrupts is a complete critical section here.
unsafe impl critical_section::Impl for SingleCoreCs {
    unsafe fn acquire() -> critical_section::RawRestoreState {
        pqf_signer_core::arch::irq_save_disable()
    }
    unsafe fn release(saved: critical_section::RawRestoreState) {
        pqf_signer_core::arch::irq_restore(saved);
    }
}

/// Report the death to core 0, then park. Poisoning the mailbox with
/// `STATE_ERROR` routes core 0 into its existing errored-sign path
/// (drain + empty signature + RP-visible failure) instead of leaving
/// it spinning against a dead worker.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    let addr = MAILBOX_ADDR.load(Ordering::Acquire);
    if addr != 0 {
        // SAFETY: set once from the validated FIFO rendezvous value.
        let signer: &'static Core1Signer = unsafe { &*(addr as *const Core1Signer) };
        signer.poison();
    }
    loop {
        pqf_signer_core::arch::wfe();
    }
}
