// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! RP2350 TRNG driver (minimal).
//!
//! M4b: carried over verbatim from the Non-secure firmware
//! (`crates/firmware/src/trng.rs`) into the Secure world. The peripheral
//! is Secure-only -- ACCESSCTRL grants NS only USBCTRL, CLOCKS and
//! RESETS -- so entropy is now generated somewhere NS cannot read, which
//! is the precondition for every key M4 moves behind the boundary.
//!
//! Per RP2350 datasheet sec. 12.12: the TRNG produces 192 bits of entropy
//! per "EHR" cycle. Procedure:
//!   1. Reset TRNG (`trng_sw_reset = 1`).
//!   2. Configure sample count.
//!   3. Enable noise source (`rnd_source_enable = 1`).
//!   4. Poll `rng_isr.ehr_valid`.
//!   5. Read `ehr_data0..5` (24 bytes).
//!   6. Disable source. Repeat for more entropy.

use rp235x_hal as hal;

/// `RNG_ISR` status bits (RP2350 datasheet sec. 12.12). Bit 0 signals a
/// fresh 192-bit EHR; bits 1..3 are the on-die continuous health tests.
const ISR_EHR_VALID: u32 = 1 << 0;
const ISR_AUTOCORR_ERR: u32 = 1 << 1; // autocorrelation test; latches the source off until reset
const ISR_CRNGT_ERR: u32 = 1 << 2; // continuous (repetition) test
const ISR_VN_ERR: u32 = 1 << 3; // von-Neumann balancer error
const ISR_HEALTH_ERR: u32 = ISR_AUTOCORR_ERR | ISR_CRNGT_ERR | ISR_VN_ERR;

/// One EHR cycle yields 192 bits = 24 bytes of entropy.
const EHR_BYTES: usize = 24;

pub struct Trng {
    regs: hal::pac::TRNG,
    /// Residual entropy from the last EHR collection. A single EHR
    /// cycle costs ~100 us, yet a `next_u32` only needs 4 bytes; rather
    /// than collect a fresh 192-bit block per small request and discard
    /// the rest, leftover bytes are buffered here and drained first on
    /// the next `fill()`. `len` is how many bytes in `buf[..len]` remain
    /// unused. Every collected byte is handed out EXACTLY ONCE: bytes
    /// are copied out and the drained prefix is never re-read.
    buf: [u8; EHR_BYTES],
    /// Number of unconsumed bytes remaining at the *end* of `buf`
    /// (i.e. `buf[EHR_BYTES - len..]`). Draining advances from the front
    /// of that window so each byte is served once.
    len: usize,
}

impl Trng {
    /// Take ownership of the TRNG peripheral. Caller must already
    /// have un-reset it (rp235x_hal::resets if needed; on RP2350 the
    /// TRNG is in the standard peripheral reset set, which
    /// `init_clocks_and_plls` un-resets via watchdog tick setup).
    pub fn new(regs: hal::pac::TRNG) -> Self {
        Self {
            regs,
            buf: [0u8; EHR_BYTES],
            len: 0,
        }
    }

    /// Fill `out` with cryptographic-quality random bytes. Blocks
    /// until enough entropy is collected. Safe to call from any
    /// context.
    ///
    /// Buffered residual bytes from a previous collection are drained
    /// first; a fresh EHR is collected only when the buffer is empty.
    /// Each random byte produced by the hardware is handed to a caller
    /// exactly once -- never reused.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut filled = 0usize;
        while filled < out.len() {
            if self.len == 0 {
                self.refill();
            }
            // `refill()` guarantees `self.len == EHR_BYTES` here, so the
            // window is non-empty. Serve from the front of the unused
            // window and shrink it; consumed bytes are never read again.
            let start = EHR_BYTES - self.len;
            let want = out.len() - filled;
            let take = core::cmp::min(want, self.len);
            out[filled..filled + take].copy_from_slice(&self.buf[start..start + take]);
            // Zero the bytes we just handed out so the residual buffer
            // never retains entropy that has already been used.
            self.buf[start..start + take].fill(0);
            self.len -= take;
            filled += take;
        }
    }

    /// Collect one fresh 192-bit EHR block into `self.buf` and mark all
    /// 24 bytes as available. Only called when the residual buffer is
    /// empty, so no unconsumed entropy is ever overwritten.
    fn refill(&mut self) {
        self.collect_ehr();
        let words = [
            self.regs.ehr_data0().read().bits(),
            self.regs.ehr_data1().read().bits(),
            self.regs.ehr_data2().read().bits(),
            self.regs.ehr_data3().read().bits(),
            self.regs.ehr_data4().read().bits(),
            self.regs.ehr_data5().read().bits(),
        ];
        for (i, b) in self.buf.iter_mut().enumerate() {
            *b = (words[i / 4] >> ((i % 4) * 8)) as u8;
        }
        self.len = EHR_BYTES;
        // Reading the last EHR_DATA word clears EHR_VALID; we
        // still set rnd_source_enable = 0 to be explicit.
        self.regs
            .rnd_source_enable()
            .write(|w| unsafe { w.bits(0) });
    }

    fn collect_ehr(&mut self) {
        // The TRNG is the root of trust for every key, IV, and PIN
        // token. Two hardware failure modes must be handled, neither of
        // which the old "poll bit 0 forever" loop did:
        //   * A latched AUTOCORR_ERR stops the noise source until reset,
        //     so EHR_VALID would never assert and the poll would hang
        //     the calling core -- hence the bounded poll + SW-reset retry.
        //   * A transient CRNGT/VN failure still surfaces (low-entropy)
        //     data in EHR_DATA; we MUST discard a block whose health
        //     bits are set rather than hand it back as "random".
        // If no healthy block can be collected after a bounded number of
        // attempts we refuse to operate (panic) -- a dead device is far
        // safer than weak keys.
        const MAX_ATTEMPTS: u32 = 16;
        // The ring-oscillator source needs ~100 us at 125 MHz; cap the
        // poll well above that so a stuck source bails instead of hanging.
        const POLL_LIMIT: u32 = 4_000_000;

        for _ in 0..MAX_ATTEMPTS {
            // SW reset clears any stuck state / latched health error.
            self.regs.trng_sw_reset().write(|w| unsafe { w.bits(1) });
            for _ in 0..16 {
                core::hint::spin_loop();
            }
            self.regs.sample_cnt1().write(|w| unsafe { w.bits(0x1000) });
            // RND_SRC_SEL = 3: longest, most entropic ring (datasheet
            // recommendation for crypto use).
            self.regs.trng_config().write(|w| unsafe { w.bits(3) });
            self.regs.rng_imr().write(|w| unsafe { w.bits(0) });
            self.regs
                .rnd_source_enable()
                .write(|w| unsafe { w.bits(1) });

            let mut waited = 0u32;
            loop {
                let isr = self.regs.rng_isr().read().bits();
                // A health-test failure invalidates the whole block --
                // discard it, reset, and retry.
                if isr & ISR_HEALTH_ERR != 0 {
                    break;
                }
                if isr & ISR_EHR_VALID != 0 {
                    // Clear EHR_VALID; the EHR_DATA words retain their
                    // value for fill() to read out immediately after.
                    self.regs
                        .rng_icr()
                        .write(|w| unsafe { w.bits(ISR_EHR_VALID) });
                    return;
                }
                waited += 1;
                if waited >= POLL_LIMIT {
                    break; // source stuck (e.g. AUTOCORR latched off)
                }
                core::hint::spin_loop();
            }

            // Failed attempt: stop the source and clear all status bits
            // before the next reset.
            self.regs
                .rnd_source_enable()
                .write(|w| unsafe { w.bits(0) });
            self.regs
                .rng_icr()
                .write(|w| unsafe { w.bits(ISR_HEALTH_ERR | ISR_EHR_VALID) });
        }

        panic!("TRNG: no healthy entropy after retries");
    }
}

/// Implement `rand_core::CryptoRng + RngCore` so the p256 crate can
/// use this directly for keypair generation.
impl rand_core::RngCore for Trng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill(&mut buf);
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill(&mut buf);
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for Trng {}
