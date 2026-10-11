// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The GDB stub's debug-unit registers and address whitelist.
//!
//! Correcting an earlier overstatement: before this file, **no line of
//! `crates/firmware/src/gdbstub.rs` ran in any host test.**
//! `tests/gdb_session.rs` models the TX queue with a hand-written
//! `Queue` rather than driving the real `Session`, and the whitelist
//! tests in `gdbstub-core` exercise `Mock`'s own toy window, not
//! `addr_ok`. The protocol was well covered; the file was not covered
//! at all.
//!
//! What made it unreachable was the MMIO: the FPB comparators and
//! DEMCR are raw volatile accesses to architected debug hardware, and
//! `cortex_m::asm::dsb` does not even link off-target. With those
//! behind `mmio`, the register programming becomes ordinary code.
//!
//! These are the bits that decide whether a breakpoint lands on the
//! instruction you asked for. A comparator written with the wrong
//! stride still "works" -- it sets a breakpoint, just not where you
//! said -- and on hardware that reads as a debugger that stops in the
//! wrong place occasionally, which is a miserable thing to chase.

use pqf_firmware_hosttest::gdbstub;

const SCB_DEMCR: u32 = 0xE000_EDFC;
const FP_CTRL: u32 = 0xE000_2000;
const FP_COMP0: u32 = 0xE000_2008;
const DEMCR_MON_EN: u32 = 1 << 16;
const DEMCR_MON_PEND: u32 = 1 << 17;
const DEMCR_MON_STEP: u32 = 1 << 18;
const FP_CTRL_KEY: u32 = 1 << 1;
const FP_CTRL_ENABLE: u32 = 1 << 0;
const FP_COMPS: u32 = 8;

/// The register file is a static shared by every test, so each takes
/// the crate's device lock and holds it for the duration. Relying on
/// `--test-threads=1` was not enough: the crate-wide `cargo test` sweep
/// in tools/host-tests.sh runs this binary without that flag, and the
/// tests then corrupt each other's registers. Same lock real_trng.rs
/// uses, for the same reason.
#[must_use]
fn fresh() -> pqf_firmware_hosttest::testlock::Guard {
    let g = pqf_firmware_hosttest::testlock::acquire();
    gdbstub::mmio::reset();
    g
}

fn read(addr: u32) -> u32 {
    gdbstub::mmio::read32(addr)
}

// ---------- init ----------

#[test]
fn init_enables_the_monitor_without_clobbering_the_rest_of_demcr() {
    // DEMCR carries unrelated debug configuration. Writing the bit
    // instead of OR-ing it in would silently turn other things off, and
    // nothing about the debugger would look wrong until whatever used
    // them stopped working.
    let _lock = fresh();
    let other = 0x0000_0FFF;
    gdbstub::mmio::write32(SCB_DEMCR, other);
    gdbstub::init();
    let d = read(SCB_DEMCR);
    assert_eq!(d & DEMCR_MON_EN, DEMCR_MON_EN, "MON_EN was not set");
    assert_eq!(d & other, other, "init clobbered unrelated DEMCR bits");
}

#[test]
fn init_arms_the_fpb_with_the_key_bit() {
    // FP_CTRL ignores any write without KEY set. Forgetting it is a
    // write that appears to succeed and does nothing at all.
    let _lock = fresh();
    gdbstub::init();
    let c = read(FP_CTRL);
    assert_eq!(
        c & FP_CTRL_KEY,
        FP_CTRL_KEY,
        "FP_CTRL written without KEY -- ignored by hardware"
    );
    assert_eq!(c & FP_CTRL_ENABLE, FP_CTRL_ENABLE, "FPB not enabled");
}

#[test]
fn init_clears_every_comparator_at_its_own_address() {
    // Eight comparators, four bytes apart. This is the stride: a loop
    // that forgot the x4 would write eight times into the first two
    // comparators and leave six holding whatever the ROM left there --
    // stale breakpoints that fire on unrelated code.
    let _lock = fresh();
    for i in 0..FP_COMPS {
        gdbstub::mmio::write32(FP_COMP0 + 4 * i, 0xDEAD_BEEF);
    }
    gdbstub::init();
    for i in 0..FP_COMPS {
        assert_eq!(
            read(FP_COMP0 + 4 * i),
            0,
            "comparator {i} (at {:#x}) was not cleared -- wrong stride?",
            FP_COMP0 + 4 * i
        );
    }
}

// ---------- breakpoints ----------

#[test]
fn a_breakpoint_lands_on_the_comparator_it_was_given() {
    // The engine picks the slot; this checks the write goes to THAT
    // comparator's address and carries the enable bit in bit 0.
    use pqf_gdbstub_core::Target;
    let _lock = fresh();
    gdbstub::init();
    let mut hw = gdbstub::Hw;
    let addr = 0x1000_4000u32;
    hw.set_breakpoint(3, addr);
    assert_eq!(
        read(FP_COMP0 + 4 * 3),
        addr | 1,
        "slot 3 does not hold the breakpoint; comparators are {:x?}",
        (0..FP_COMPS)
            .map(|i| read(FP_COMP0 + 4 * i))
            .collect::<Vec<_>>()
    );
    for i in 0..FP_COMPS {
        if i != 3 {
            assert_eq!(
                read(FP_COMP0 + 4 * i),
                0,
                "slot {i} was written too -- wrong stride?"
            );
        }
    }
}

#[test]
fn each_slot_maps_to_its_own_comparator_address() {
    // The stride, checked across every slot at once. A missing x4 puts
    // slot 1 on top of slot 0 and the earlier breakpoint quietly stops
    // working.
    use pqf_gdbstub_core::Target;
    let _lock = fresh();
    gdbstub::init();
    let mut hw = gdbstub::Hw;
    for i in 0..FP_COMPS {
        hw.set_breakpoint(i as usize, 0x1000_0000 + 0x1000 * i);
    }
    for i in 0..FP_COMPS {
        assert_eq!(
            read(FP_COMP0 + 4 * i),
            (0x1000_0000 + 0x1000 * i) | 1,
            "slot {i} holds the wrong value"
        );
    }
}

#[test]
fn clearing_a_breakpoint_frees_its_comparator_and_leaves_the_others() {
    use pqf_gdbstub_core::Target;
    let _lock = fresh();
    gdbstub::init();
    let mut hw = gdbstub::Hw;
    let a = 0x1000_4000u32;
    let b = 0x1000_8000u32;
    hw.set_breakpoint(0, a);
    hw.set_breakpoint(1, b);
    hw.clear_breakpoint(0);
    let live: Vec<u32> = (0..FP_COMPS).map(|i| read(FP_COMP0 + 4 * i)).collect();
    assert!(
        !live.contains(&(a | 1)),
        "the cleared breakpoint is still armed"
    );
    assert!(
        live.contains(&(b | 1)),
        "clearing one breakpoint removed another"
    );
}

// ---------- halt and single-step ----------

#[test]
fn raising_a_halt_sets_mon_pend_and_leaves_mon_en_alone() {
    // The monitor has to stay enabled while a halt is pending, or the
    // request is raised into a monitor that is not listening.
    let _lock = fresh();
    gdbstub::init();
    assert_eq!(
        read(SCB_DEMCR) & DEMCR_MON_PEND,
        0,
        "MON_PEND set before it was requested"
    );
    gdbstub::request_halt();
    let after = read(SCB_DEMCR);
    assert_eq!(
        after & DEMCR_MON_PEND,
        DEMCR_MON_PEND,
        "MON_PEND was not raised"
    );
    assert_eq!(
        after & DEMCR_MON_EN,
        DEMCR_MON_EN,
        "raising a halt cleared MON_EN"
    );
}

#[test]
fn the_engines_halt_request_is_deferred_rather_than_poking_demcr() {
    // Two things share the name. `Target::request_halt` is called from
    // inside packet handling and only records the intent; the free
    // `request_halt` is what actually pokes DEMCR, later, from a place
    // where that is safe. Pinning the split because collapsing it --
    // raising MON_PEND from inside the engine -- is a plausible
    // simplification that would re-enter the monitor while the monitor
    // is what is running.
    use pqf_gdbstub_core::Target;
    let _lock = fresh();
    gdbstub::init();
    gdbstub::Hw.request_halt();
    assert_eq!(
        read(SCB_DEMCR) & DEMCR_MON_PEND,
        0,
        "the engine's halt request wrote DEMCR directly instead of deferring"
    );
}

#[test]
fn fpb_enable_toggles_only_the_enable_bit_and_keeps_the_key() {
    let _lock = fresh();
    gdbstub::init();
    gdbstub::fpb_enable(false);
    let off = read(FP_CTRL);
    assert_eq!(off & FP_CTRL_ENABLE, 0, "FPB not disabled");
    assert_eq!(
        off & FP_CTRL_KEY,
        FP_CTRL_KEY,
        "KEY dropped -- the write is ignored by hardware"
    );

    gdbstub::fpb_enable(true);
    let on = read(FP_CTRL);
    assert_eq!(on & FP_CTRL_ENABLE, FP_CTRL_ENABLE, "FPB not re-enabled");
    assert_eq!(on & FP_CTRL_KEY, FP_CTRL_KEY, "KEY dropped on re-enable");
}

#[test]
fn mon_step_is_not_left_set_by_a_plain_halt() {
    // A MON_STEP left set turns the next resume into a single step, and
    // the target then stops one instruction later for no reason the
    // user asked for.
    let _lock = fresh();
    gdbstub::init();
    gdbstub::request_halt();
    assert_eq!(
        read(SCB_DEMCR) & DEMCR_MON_STEP,
        0,
        "MON_STEP set by a halt request that was not a step"
    );
}

// ---------- the address whitelist ----------

#[test]
fn the_whitelist_accepts_each_real_region() {
    // The accept half has never been checked anywhere: gdbstub-core's
    // tests use Mock's own toy window, not this function. A whitelist
    // that refused everything would pass every refusal test ever
    // written and make the debugger unable to read a single byte.
    for (name, addr) in [
        ("XIP flash", 0x1000_0000u32),
        ("SRAM", 0x2000_0000),
        ("peripherals", 0x4000_0000),
        ("PPB", 0xE000_0000),
    ] {
        assert!(gdbstub::addr_ok(addr, 4), "{name} start was refused");
    }
    assert!(
        gdbstub::addr_ok(0x2004_0000, 64),
        "the middle of SRAM was refused"
    );
}

#[test]
fn the_whitelist_refuses_the_gaps_between_regions() {
    for addr in [
        0x0000_0000u32,
        0x0FFF_FFFF,
        0x1020_0000,
        0x2008_2000,
        0xFFFF_FFF0,
    ] {
        assert!(!gdbstub::addr_ok(addr, 4), "{addr:#x} was allowed");
    }
}

#[test]
fn a_read_that_starts_inside_but_ends_outside_is_refused() {
    // The check is on the whole span, not the start. Allowing this
    // would let a debugger read off the end of a region -- exactly the
    // thing a whitelist exists to stop.
    assert!(
        gdbstub::addr_ok(0x2008_1FFC, 4),
        "the last word of SRAM should be readable"
    );
    assert!(
        !gdbstub::addr_ok(0x2008_1FFC, 8),
        "a span starting in SRAM and running past its end was allowed"
    );
    assert!(
        !gdbstub::addr_ok(0x101F_FFFC, 8),
        "a span running off the end of XIP flash was allowed"
    );
}

#[test]
fn an_address_plus_length_that_overflows_is_refused() {
    // addr + len wrapping would make a wild span look like a tiny one.
    assert!(
        !gdbstub::addr_ok(0xFFFF_FFFC, 8),
        "an overflowing span was allowed"
    );
    assert!(
        !gdbstub::addr_ok(0x2000_0000, u32::MAX),
        "a u32::MAX length was allowed"
    );
}

#[test]
fn a_zero_length_read_does_not_escape_the_whitelist() {
    // Degenerate, but a length of zero must not turn an out-of-range
    // address into an allowed one.
    assert!(
        !gdbstub::addr_ok(0x0000_0000, 0),
        "a zero-length read outside every region was allowed"
    );
}
