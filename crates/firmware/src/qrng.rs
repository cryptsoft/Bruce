// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! A quantum RNG over I2C -- the optional external
//! entropy source, and the one that goes FIRST when it is present.
//!
//! [`entropy::Entropy`](crate::entropy) is the picker: it asks a probed
//! [`Qrng`] for every byte and lets the on-die TRNG complete whatever the
//! chip leaves short. Nothing answering at boot means the firmware behaves
//! exactly as it did before this module existed.
//!
//! ## Register map
//!
//! The same numbers the qrngBridge
//! bring-up firmware validated on silicon:
//!
//! * 7-bit address `0x37`;
//! * `0x10` status, `0x00` = calibrated and ready;
//! * `0x12` packet, an 18-byte burst read: header (always `0xA2`), a health
//!   byte whose low nibble must be zero, then 16 bytes of entropy. Reading
//!   `0x12` latches a fresh packet; new entropy every ~500 us.
//!
//! ## Conditioning is not optional
//!
//! The part has no DRBG inside and its maker
//! claims >= 7.0 bits of min-entropy per byte, not 8; the raw stream is
//! measurably biased (ones ratio 0.4973 over 170 KB on this part). So no
//! raw byte ever leaves this module: every 32 bytes out are SHA-256 over
//! 64 raw bytes in -- 448 bits of claimed min-entropy for 256 out, past what
//! SP 800-90B asks of a vetted conditioner. Header and health bytes are
//! framing and never reach the hash; a packet with a bad header or a set
//! health bit is dropped whole.
//!
//! ## Failure policy
//!
//! One bad packet is dropped and the next read; a bus error is retried a
//! few times. A 64-byte draw that still cannot complete makes the request
//! come back short and the picker fills the rest from the TRNG -- a caller
//! never sees fewer bytes than it asked for, and none of them raw. After a
//! failed draw one status read decides what happened: a chip that no
//! longer answers has been unplugged and is written off on the spot (bus
//! released, TRNG serving from the next byte), while a chip that still
//! answers had a transient fault and is written off only after a run of
//! those. A chip absent at boot, or written off, is not looked for again
//! until the next boot.
//!
//! ## Nothing here blocks indefinitely
//!
//! An I2C slave interrupted mid-byte holds SDA low waiting for clocks that
//! never come; a driver that waits on it produces a firmware that is simply
//! dark. So [`hw`] checks the idle levels and clocks a stuck bus out before
//! the controller ever claims the pins, and every transfer carries a
//! deadline. The protocol logic is written against the small [`Bus`] trait
//! so the host suite can script every one of these paths
//! (`crates/firmware-hosttest/tests/real_qrng.rs`).

use crate::bc_crypto::sha256;

pub const I2C_ADDR: u8 = 0x37;
pub const REG_STATUS: u8 = 0x10;
pub const REG_PACKET: u8 = 0x12;
pub const PACKET_LEN: usize = 18;
pub const HEADER_BYTE: u8 = 0xA2;
pub const HEALTH_MASK: u8 = 0x0F;
pub const ENTROPY_PER_PKT: usize = 16;
/// 64 raw bytes -> 32 conditioned.
pub const RAW_PER_HASH: usize = 64;
pub const HASH_OUT: usize = 32;

/// Power-up initial (~260 us) + calibration + first frame; generous.
const READY_TRIES: u32 = 100; // x 1 ms
/// PD low >= 3 ms guarantees a clean power-down state.
const PD_HOLD_US: u32 = 5_000;
const PROBE_TRIES: u32 = 2;
/// Rejects tolerated inside one 64-byte draw before it is abandoned.
const BAD_PACKETS_PER_DRAW: u32 = 8;
const BUS_RETRIES_PER_PACKET: u32 = 3;
/// Consecutive short requests before the chip is written off.
const LOST_AFTER_FAILURES: u32 = 8;

/// A transaction that did not complete: NAK, timeout, arbitration, a bus
/// that is not there. The driver does not distinguish -- all of them mean
/// "this packet did not arrive".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusError;

/// What the protocol logic needs from the board. Implemented over the
/// RP2350 I2C block in [`hw`]; scripted by the host suite.
pub trait Bus {
    /// Register read: write `reg` (repeated start), then read `out.len()`
    /// bytes. Must be bounded.
    fn read_regs(&mut self, reg: u8, out: &mut [u8]) -> Result<(), BusError>;
    /// Drive PD (power-down, active low). No-op when PD is not wired.
    fn set_pd(&mut self, high: bool);
    /// Busy-wait. Only used during probe and error recovery.
    fn delay_us(&mut self, us: u32);
    /// Controller off, pins back to their reset state. Called once, when
    /// the chip is absent or has been written off.
    fn release(&mut self);
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Packets read off the chip.
    pub packets: u32,
    /// Packets dropped: header was not `0xA2`.
    pub header_err: u32,
    /// Packets dropped: health nibble set.
    pub health_err: u32,
    /// Transactions that failed or timed out.
    pub bus_err: u32,
    /// Conditioned bytes handed to callers.
    pub served: u32,
    /// Requests this source could not complete.
    pub short_requests: u32,
    /// Was present, then failed [`LOST_AFTER_FAILURES`] requests in a row.
    pub lost: bool,
}

pub struct Qrng<B: Bus> {
    bus: B,
    /// Conditioned output not yet handed out: the LAST `len` bytes of
    /// `out`. Draining advances from the front of that window so every
    /// byte is served exactly once; served bytes are wiped.
    out: [u8; HASH_OUT],
    len: usize,
    consecutive_failures: u32,
    present: bool,
    stats: Stats,
}

impl<B: Bus> Qrng<B> {
    /// Look for the chip. Decides absence by a NAK (microseconds -- an
    /// unpopulated bus never gets PD toggled), then power-cycles the part
    /// through PD for a clean calibration and waits for ready. `None`
    /// means nothing usable answered; the bus has been released.
    pub fn probe(mut bus: B) -> Option<Self> {
        let mut acked = false;
        for _ in 0..PROBE_TRIES {
            let mut st = [0xFFu8];
            if bus.read_regs(REG_STATUS, &mut st).is_ok() {
                acked = true;
                break;
            }
            bus.delay_us(500);
        }
        if !acked {
            bus.release();
            return None;
        }

        // SP 800-90B builds its restart tests on exactly this: a source
        // that resumes a fixed sequence after power-up is exposed by it,
        // and a fresh calibration per boot costs ~10 ms. No-op when PD is
        // not wired -- the breakout idles PD high through its own pull-up.
        bus.set_pd(false);
        bus.delay_us(PD_HOLD_US);
        bus.set_pd(true);
        bus.delay_us(PD_HOLD_US);

        if !Self::wait_ready(&mut bus, READY_TRIES) {
            // Answers on the bus but never calibrates. The TRNG is
            // known-good; a part that cannot report ready is not something
            // to draw keys from.
            bus.release();
            return None;
        }
        Some(Self {
            bus,
            out: [0u8; HASH_OUT],
            len: 0,
            consecutive_failures: 0,
            present: true,
            stats: Stats::default(),
        })
    }

    fn wait_ready(bus: &mut B, tries: u32) -> bool {
        for _ in 0..tries {
            let mut st = [0xFFu8];
            if bus.read_regs(REG_STATUS, &mut st).is_ok() && st[0] == 0x00 {
                return true;
            }
            bus.delay_us(1_000);
        }
        false
    }

    /// True while a chip that answered at boot is still believed healthy.
    pub fn present(&self) -> bool {
        self.present
    }

    /// Counters for a banner or a test; the firmware itself only reports
    /// presence (through the USB product string).
    #[allow(dead_code)]
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// One packet -> 16 entropy bytes. `Ok(true)` good, `Ok(false)` the
    /// packet was rejected (bad header or health) and dropped whole,
    /// `Err` a bus error (retryable).
    fn read_packet(&mut self, out: &mut [u8; ENTROPY_PER_PKT]) -> Result<bool, BusError> {
        let mut pkt = [0u8; PACKET_LEN];
        if self.bus.read_regs(REG_PACKET, &mut pkt).is_err() {
            self.stats.bus_err += 1;
            return Err(BusError);
        }
        self.stats.packets += 1;
        let ok = if pkt[0] != HEADER_BYTE {
            self.stats.header_err += 1;
            false
        } else if pkt[1] & HEALTH_MASK != 0 {
            self.stats.health_err += 1;
            false
        } else {
            out.copy_from_slice(&pkt[2..2 + ENTROPY_PER_PKT]);
            true
        };
        wipe(&mut pkt);
        Ok(ok)
    }

    /// Refill `out`: 64 raw -> SHA-256 -> 32. Only called with the window
    /// empty, so no unconsumed byte is ever overwritten. `false` = the
    /// draw could not complete and nothing is buffered.
    fn draw(&mut self) -> bool {
        let mut raw = [0u8; RAW_PER_HASH];
        let mut got = 0usize;
        let mut rejected = 0u32;
        let mut bus_failures = 0u32;
        let mut block = [0u8; ENTROPY_PER_PKT];

        while got < RAW_PER_HASH {
            match self.read_packet(&mut block) {
                Ok(true) => {
                    raw[got..got + ENTROPY_PER_PKT].copy_from_slice(&block);
                    got += ENTROPY_PER_PKT;
                    bus_failures = 0;
                }
                Ok(false) => {
                    rejected += 1;
                    if rejected > BAD_PACKETS_PER_DRAW {
                        wipe(&mut raw);
                        return false;
                    }
                }
                Err(BusError) => {
                    bus_failures += 1;
                    if bus_failures > BUS_RETRIES_PER_PACKET {
                        wipe(&mut raw);
                        return false;
                    }
                }
            }
        }
        wipe(&mut block);
        self.out = sha256(&raw);
        // The raw bytes are spent; do not leave them in RAM.
        wipe(&mut raw);
        self.len = HASH_OUT;
        true
    }

    /// Fill `out` with conditioned bytes. Returns how many were written:
    /// `out.len()` on success, less if the chip failed mid-request (the
    /// caller supplies the rest). Every byte is handed out exactly once.
    pub fn fill(&mut self, out: &mut [u8]) -> usize {
        if !self.present {
            return 0;
        }
        let mut done = 0usize;
        while done < out.len() {
            if self.len == 0 && !self.draw() {
                break;
            }
            let start = HASH_OUT - self.len;
            let take = core::cmp::min(out.len() - done, self.len);
            out[done..done + take].copy_from_slice(&self.out[start..start + take]);
            wipe(&mut self.out[start..start + take]);
            self.len -= take;
            done += take;
        }
        self.stats.served += done as u32;

        if done == out.len() {
            self.consecutive_failures = 0;
            return done;
        }

        // Short. One status read settles what happened: a part that has
        // been unplugged does not answer -- it NAKs, or an unpowered
        // breakout drags the lines down and the read times out -- and is
        // written off at once, so the very next request is the TRNG's
        // alone and nobody keeps paying for a dead bus. A part that still
        // answers had a transient fault (a reset mid-stream, a burst of
        // rejects); that is counted, and written off only after
        // `LOST_AFTER_FAILURES` of them in a row.
        self.stats.short_requests += 1;
        let mut st = [0xFFu8];
        let alive = self.bus.read_regs(REG_STATUS, &mut st).is_ok();
        self.consecutive_failures += 1;
        if !alive || self.consecutive_failures >= LOST_AFTER_FAILURES {
            self.present = false;
            self.stats.lost = true;
            self.len = 0;
            wipe(&mut self.out);
            self.bus.release();
        }
        done
    }
}

/// Zero through a volatile write so the compiler cannot elide it as a
/// dead store to a buffer about to go out of scope.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusively borrowed byte.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// The RP2350 side: pins, controller bring-up, bounded transfers.
///
/// Wiring is the Pimoroni Tiny 2350's QW/ST (Qwiic / STEMMA QT) connector:
/// SDA = GP12, SCL = GP13, which are **I2C0**. The 4-pin cable carries no
/// PD line, so PD is not driven -- the breakout idles it high itself -- and
/// [`Bus::set_pd`] is a no-op here. The Spotpear board uses GP12 for its
/// LCD reset, so `board::BoardPins::split` hands out no QRNG pins there
/// and the probe is skipped.
///
/// The controller is programmed directly through the PAC rather than via
/// `rp235x_hal::I2C`, whose blocking transfers have no deadline: a slave
/// holding SDA low would hang the calling core, and on this device that
/// core is the one servicing USB. The timing set-up mirrors the HAL's.
#[cfg(any(target_arch = "arm", target_arch = "riscv32"))]
pub mod hw {
    use super::{Bus, BusError, Qrng, I2C_ADDR};
    use crate::board::Timer;
    use crate::hal;
    use embedded_hal::digital::{InputPin, OutputPin, PinState};
    use hal::gpio::{
        bank0::{Gpio12, Gpio13},
        FunctionI2c, FunctionNull, FunctionSio, Pin, PullDown, PullNone, PullUp,
    };
    use hal::pac;

    /// I2C clock. The part allows 50-400 kHz; 100 kHz is what the source
    /// was qualified at (qrngBridge), and the bus is not the bottleneck:
    /// a 64-byte draw is four packets, ~7 ms, against a ~1 s hybrid sign.
    pub const BAUD_HZ: u32 = 100_000;
    /// Per transaction. A healthy 18-byte read takes ~1.7 ms at 100 kHz.
    const TIMEOUT_US: u64 = 20_000;

    /// The QW/ST pin pair, in its reset typestate, split out of
    /// `hal::gpio::Pins` by `board::BoardPins::split`.
    pub struct Pins {
        pub sda: Pin<Gpio12, FunctionNull, PullDown>,
        pub scl: Pin<Gpio13, FunctionNull, PullDown>,
    }

    type Sda = Pin<Gpio12, FunctionI2c, PullUp>;
    type Scl = Pin<Gpio13, FunctionI2c, PullUp>;

    pub struct I2cBus {
        i2c: pac::I2C0,
        // `Option` so `release(&mut self)` can convert them back.
        sda: Option<Sda>,
        scl: Option<Scl>,
        timer: Timer,
    }

    /// Bring the bus up and look for the chip. `None` = stuck bus, no
    /// chip, or a chip that never readies; the pins are back in their
    /// reset state either way.
    pub fn probe(
        i2c: pac::I2C0,
        pins: Pins,
        resets: &mut pac::RESETS,
        sys_hz: u32,
        timer: Timer,
    ) -> Option<Qrng<I2cBus>> {
        let Pins { sda, scl } = pins;

        // Idle levels first: a line held low is the one fault that looks
        // identical to "no chip" from inside a transaction, and the
        // controller would wait forever on it.
        let mut sda_in = sda.into_pull_up_input();
        let mut scl_in = scl.into_pull_up_input();
        wait_us(&timer, 100);
        let idle =
            |sda: &mut Pin<Gpio12, FunctionSio<hal::gpio::SioInput>, PullUp>,
             scl: &mut Pin<Gpio13, FunctionSio<hal::gpio::SioInput>, PullUp>| {
                sda.is_high().unwrap_or(false) && scl.is_high().unwrap_or(false)
            };
        if !idle(&mut sda_in, &mut scl_in) {
            // Standard stuck-bus recovery: up to nine SCL pulses so a
            // slave interrupted mid-byte can finish it, then a STOP.
            let mut scl_out = scl_in.into_push_pull_output_in_state(PinState::High);
            wait_us(&timer, 10);
            for _ in 0..9 {
                if sda_in.is_high().unwrap_or(true) {
                    break;
                }
                let _ = scl_out.set_low();
                wait_us(&timer, 10);
                let _ = scl_out.set_high();
                wait_us(&timer, 10);
            }
            // STOP: SDA rises while SCL is high.
            let sda_out = sda_in.into_push_pull_output_in_state(PinState::Low);
            wait_us(&timer, 10);
            let _ = scl_out.set_high();
            wait_us(&timer, 10);
            sda_in = sda_out.into_pull_up_input();
            scl_in = scl_out.into_pull_up_input();
            wait_us(&timer, 100);
            if !idle(&mut sda_in, &mut scl_in) {
                let _: Pin<Gpio12, FunctionNull, PullNone> = sda_in.into_floating_disabled();
                let _: Pin<Gpio13, FunctionNull, PullNone> = scl_in.into_floating_disabled();
                return None;
            }
        }

        // Controller set-up, as rp235x_hal::I2C::new_controller does it
        // (the HAL's reset trait is private, so the RESETS block is
        // driven directly; the un-reset wait is bounded like everything
        // else here).
        resets.reset().modify(|_, w| w.i2c0().set_bit());
        resets.reset().modify(|_, w| w.i2c0().clear_bit());
        let t0 = timer.get_counter().ticks();
        while !resets.reset_done().read().i2c0().bit_is_set() {
            if timer.get_counter().ticks().wrapping_sub(t0) > 1_000 {
                break;
            }
        }
        i2c.ic_enable().write(|w| w.enable().disabled());
        i2c.ic_con().modify(|_, w| {
            w.speed().fast();
            w.master_mode().enabled();
            w.ic_slave_disable().slave_disabled();
            w.ic_restart_en().enabled();
            w.tx_empty_ctrl().enabled()
        });
        let period = (sys_hz + BAUD_HZ / 2) / BAUD_HZ;
        let lcnt = period * 3 / 5;
        let hcnt = period - lcnt;
        let hold = (sys_hz * 3) / 10_000_000 + 1; // >= 300 ns SDA hold
                                                  // SAFETY: plain register writes with values in range for the
                                                  // clocks this firmware runs (150 MHz / 100 kHz -> 1500 cycles).
        unsafe {
            i2c.ic_tar().write(|w| w.ic_tar().bits(I2C_ADDR as u16));
            i2c.ic_fs_scl_hcnt()
                .write(|w| w.ic_fs_scl_hcnt().bits(hcnt as u16));
            i2c.ic_fs_scl_lcnt()
                .write(|w| w.ic_fs_scl_lcnt().bits(lcnt as u16));
            i2c.ic_fs_spklen().write(|w| {
                w.ic_fs_spklen()
                    .bits(if lcnt < 16 { 1 } else { (lcnt / 16) as u8 })
            });
            i2c.ic_sda_hold()
                .modify(|_, w| w.ic_sda_tx_hold().bits(hold as u16));
            i2c.ic_tx_tl().write(|w| w.tx_tl().bits(16));
            i2c.ic_rx_tl().write(|w| w.rx_tl().bits(0));
        }
        i2c.ic_con()
            .modify(|_, w| w.rx_fifo_full_hld_ctrl().enabled());
        i2c.ic_enable().write(|w| w.enable().enabled());

        let sda: Sda = sda_in.reconfigure();
        let scl: Scl = scl_in.reconfigure();

        Qrng::probe(I2cBus {
            i2c,
            sda: Some(sda),
            scl: Some(scl),
            timer,
        })
    }

    fn wait_us(timer: &Timer, us: u64) {
        let t0 = timer.get_counter().ticks();
        while timer.get_counter().ticks().wrapping_sub(t0) < us {}
    }

    impl I2cBus {
        fn now(&self) -> u64 {
            self.timer.get_counter().ticks()
        }

        /// Abort reason, if the last command aborted; clearing it also
        /// clears the flag (the hardware issued a STOP and flushed both
        /// FIFOs on its own).
        fn take_abort(&self) -> u32 {
            let r = self.i2c.ic_tx_abrt_source().read().bits();
            if r != 0 {
                let _ = self.i2c.ic_clr_tx_abrt().read();
            }
            r
        }

        /// Give up on a transfer that did not finish in time. Disable and
        /// re-enable the block: that discards both FIFOs and any command
        /// in flight. The block finishes the byte in flight before it
        /// reports disabled, which on a hung bus never happens, so the
        /// wait is capped at a millisecond and the re-enable proceeds
        /// regardless -- the driver writes the chip off after this anyway.
        fn recover(&self) {
            self.i2c.ic_enable().write(|w| w.enable().disabled());
            let t0 = self.now();
            while self.i2c.ic_enable_status().read().ic_en().bit_is_set() {
                if self.now().wrapping_sub(t0) > 1_000 {
                    break;
                }
            }
            let _ = self.take_abort();
            let _ = self.i2c.ic_clr_intr().read();
            self.i2c.ic_enable().write(|w| w.enable().enabled());
        }
    }

    impl Bus for I2cBus {
        fn read_regs(&mut self, reg: u8, out: &mut [u8]) -> Result<(), BusError> {
            if out.is_empty() || out.len() > 32 {
                return Err(BusError);
            }
            let deadline = self.now() + TIMEOUT_US;
            let _ = self.take_abort();

            // Register address, no STOP: the read that follows changes
            // direction and the controller inserts the repeated START.
            self.i2c.ic_data_cmd().write(|w| {
                w.stop().clear_bit();
                // SAFETY: an 8-bit data value.
                unsafe { w.dat().bits(reg) }
            });

            let last = out.len() - 1;
            let mut queued = 0usize;
            let mut i = 0usize;
            while i < out.len() {
                // Queue read commands as the TX FIFO has room; collect
                // bytes as the RX FIFO fills. Both bounded by the deadline.
                if queued < out.len() && self.i2c.ic_status().read().tfnf().bit_is_set() {
                    let is_last = queued == last;
                    self.i2c.ic_data_cmd().write(|w| {
                        w.stop().bit(is_last);
                        w.cmd().read()
                    });
                    queued += 1;
                }
                if self.i2c.ic_rxflr().read().bits() > 0 {
                    out[i] = self.i2c.ic_data_cmd().read().dat().bits();
                    i += 1;
                    continue;
                }
                if self.take_abort() != 0 {
                    // NAK on the address (no chip), on the register byte,
                    // or arbitration lost. The block has already STOPped.
                    return Err(BusError);
                }
                if self.now() > deadline {
                    self.recover();
                    return Err(BusError);
                }
            }
            // Leave STOP_DET clear so the next transfer starts clean.
            let _ = self.i2c.ic_clr_stop_det().read();
            Ok(())
        }

        fn set_pd(&mut self, _high: bool) {
            // No PD line on the QW/ST cable; the breakout keeps it high, so
            // the probe's power-cycle is a no-op on this wiring.
        }

        fn delay_us(&mut self, us: u32) {
            wait_us(&self.timer, us as u64);
        }

        fn release(&mut self) {
            self.i2c.ic_enable().write(|w| w.enable().disabled());
            if let Some(p) = self.sda.take() {
                let _: Pin<Gpio12, FunctionNull, PullNone> = p.into_floating_disabled();
            }
            if let Some(p) = self.scl.take() {
                let _: Pin<Gpio13, FunctionNull, PullNone> = p.into_floating_disabled();
            }
        }
    }
}
