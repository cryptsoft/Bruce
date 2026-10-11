// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The entropy picker: the QRNG first, the on-die TRNG for everything else.
//!
//! Every random byte the firmware needs -- master keys on first boot,
//! ML-DSA seeds, P-256 scalars, IVs, `pinUvAuthToken`s, the vendor RNG
//! command, the per-boot USB serial -- comes through here. The order is
//! fixed: an [`Qrng`](crate::qrng::Qrng) that answered at boot serves the
//! request, and [`Trng`] completes whatever it leaves short -- the whole
//! request when no chip is present, the tail when a draw failed part way
//! (the chip's own bytes that did arrive are kept: they are conditioned
//! output, not a partial packet). A caller never sees fewer bytes than it
//! asked for and never sees a raw one.
//!
//! `Trng` itself is untouched by this: it stays the root of trust the
//! real-hardware suite and the drift test in `fw-secure` describe, and it
//! is what every build without a chip attached still runs on.

use crate::qrng::{Bus, Qrng, Stats};
use crate::trng::Trng;

/// Length of the `CMD_RNG_STATUS` payload: a source byte and seven
/// big-endian u32 counters.
pub const STATUS_LEN: usize = 29;
/// Source codes in that payload's first byte (wire-compatible with the C
/// port's `CTAPHID_RNG_SRC_*`). `3` = "built without QRNG support" exists
/// only in the C port; this firmware always probes.
pub const SRC_TRNG: u8 = 0;
pub const SRC_QRNG: u8 = 1;
pub const SRC_QRNG_LOST: u8 = 2;

pub struct Entropy<B: Bus> {
    qrng: Option<Qrng<B>>,
    trng: Trng,
    qrng_bytes: u32,
    fallback_bytes: u32,
}

impl<B: Bus> Entropy<B> {
    pub fn new(trng: Trng, qrng: Option<Qrng<B>>) -> Self {
        Self {
            qrng,
            trng,
            qrng_bytes: 0,
            fallback_bytes: 0,
        }
    }

    /// True while the external chip is live and first in the queue.
    pub fn qrng_present(&self) -> bool {
        self.qrng.as_ref().is_some_and(|q| q.present())
    }

    /// `"QRNG"` while the chip is live, `"TRNG"` otherwise.
    #[allow(dead_code)]
    pub fn source_name(&self) -> &'static str {
        if self.qrng_present() {
            "QRNG"
        } else {
            "TRNG"
        }
    }

    /// Bytes served by the QRNG and by the fallback, since boot.
    #[allow(dead_code)]
    pub fn split(&self) -> (u32, u32) {
        (self.qrng_bytes, self.fallback_bytes)
    }

    /// Which source a host would be told is serving: [`SRC_QRNG`] while
    /// the chip is live, [`SRC_QRNG_LOST`] if it answered at boot and has
    /// been written off since, [`SRC_TRNG`] if nothing answered at boot.
    pub fn source_code(&self) -> u8 {
        match &self.qrng {
            None => SRC_TRNG,
            Some(q) if q.present() => SRC_QRNG,
            Some(_) => SRC_QRNG_LOST,
        }
    }

    /// The `CMD_RNG_STATUS` payload: source byte, then qrng_bytes,
    /// fallback_bytes, packets, header_err, health_err, bus_err and
    /// short_requests as big-endian u32. Counters are zero when no chip
    /// was ever found.
    pub fn status_bytes(&self) -> [u8; STATUS_LEN] {
        let mut out = [0u8; STATUS_LEN];
        out[0] = self.source_code();
        let z = Stats::default();
        let s = self.qrng_stats().unwrap_or(&z);
        let words = [
            self.qrng_bytes,
            self.fallback_bytes,
            s.packets,
            s.header_err,
            s.health_err,
            s.bus_err,
            s.short_requests,
        ];
        for (i, w) in words.iter().enumerate() {
            out[1 + 4 * i..5 + 4 * i].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    #[allow(dead_code)]
    pub fn qrng_stats(&self) -> Option<&Stats> {
        self.qrng.as_ref().map(|q| q.stats())
    }

    /// Fill `out` completely. QRNG first; the TRNG completes the rest.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut done = 0usize;
        if let Some(q) = self.qrng.as_mut() {
            if q.present() {
                done = q.fill(out);
                self.qrng_bytes = self.qrng_bytes.wrapping_add(done as u32);
            }
        }
        if done < out.len() {
            self.trng.fill(&mut out[done..]);
            self.fallback_bytes = self.fallback_bytes.wrapping_add((out.len() - done) as u32);
        }
    }
}

impl<B: Bus> rand_core::RngCore for Entropy<B> {
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

impl<B: Bus> rand_core::CryptoRng for Entropy<B> {}
