// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! A simulated RP2350 flash, behind the same `rom_data` names the Secure
//! world calls.
//!
//! NOR semantics are modelled properly, because the storage design leans
//! on them: programming may only clear bits, never set them, which is
//! what lets a record be invalidated by writing its magic to zero
//! without erasing fifteen bystanders. A simulator that let a program
//! set bits would make that design look sound when it was not.

/// Sized to cover every offset either firmware addresses.
///
/// The Secure world's stores sit around 0x1F0000, inside 2 MiB. The
/// non-TrustZone Rust firmware puts its credential store at
/// `4 MiB - 4096` and works down from there, so the simulated die has to
/// be 4 MiB or those reads run off the end -- which they did, as a
/// segfault on the first test that touched the store.
///
/// Worth knowing rather than just accommodating: the Feitian's die is
/// 2 MiB (that was the root cause of the DFU work -- "a 2 MiB die
/// addressed as 4 MiB"), so on real hardware those 4 MiB offsets alias
/// down by wrapping. It works, and it is not obviously intended. The C
/// port derives its offset from `PICO_FLASH_SIZE_BYTES` instead of
/// hard-coding one.
pub const FLASH_LEN: usize = 4 * 1024 * 1024;

/// The simulated die. Erased state is all ones, as NOR flash is.
static mut FLASH: [u8; FLASH_LEN] = [0xff; FLASH_LEN];

/// Base of the simulated XIP window, for the storage modules' pointer
/// arithmetic. Takes the place of 0x10000000.
pub fn window() -> *const u8 {
    core::ptr::addr_of!(FLASH) as *const u8
}

/// Wipe to erased state. Every test starts from a known die.
pub fn reset_clock_and_button() {
    set_now_us(0);
    set_pressed(false);
}

pub fn reset() {
    // SAFETY: single-threaded tests.
    unsafe {
        let f = &mut *core::ptr::addr_of_mut!(FLASH);
        f.fill(0xff);
    }
    set_tear_after_bytes(None);
}

/// Power-loss injection. `Some(n)`: the next `n` programmed bytes land,
/// then power is "lost" -- the program in flight stops there and every
/// later erase and program is dropped, until `set_tear_after_bytes`
/// is called again (or `reset`). An erase issued before the budget runs
/// out still happens, as it would on a device that lost power after
/// it. `None` (the default) disables it.
pub fn set_tear_after_bytes(n: Option<usize>) {
    unsafe {
        TEAR_BUDGET = n;
        POWERED_OFF = false;
    }
}

/// Whether an injected power loss has happened since the last
/// `set_tear_after_bytes`.
pub fn torn() -> bool {
    unsafe { POWERED_OFF }
}

static mut TEAR_BUDGET: Option<usize> = None;
static mut POWERED_OFF: bool = false;

/// How many erases have happened, so a test can assert that a design
/// which claims to avoid them actually does.
pub static mut ERASE_COUNT: u32 = 0;
/// How many program operations have happened.
pub static mut PROGRAM_COUNT: u32 = 0;

pub fn erase_count() -> u32 {
    unsafe { ERASE_COUNT }
}
pub fn program_count() -> u32 {
    unsafe { PROGRAM_COUNT }
}
pub fn reset_counts() {
    unsafe {
        ERASE_COUNT = 0;
        PROGRAM_COUNT = 0;
    }
}

/// The microsecond clock the presence gate reads, driven by the test.
///
/// A free-running peripheral would leave the gate's debounce, sample
/// interval and window boundaries testable only by waiting. Settable,
/// they are testable exactly.
static mut NOW_US: u64 = 0;

pub fn now_us() -> u64 {
    unsafe { NOW_US }
}

pub fn advance_us(us: u64) {
    unsafe { NOW_US += us };
}

pub fn set_now_us(us: u64) {
    unsafe { NOW_US = us };
}

/// The BOOTSEL button, as the gate sees it.
static mut PRESSED: bool = false;

pub fn set_pressed(p: bool) {
    unsafe { PRESSED = p };
}

pub fn pressed() -> bool {
    unsafe { PRESSED }
}

/// The boot-ROM flash entry points the Secure world calls.
pub mod rom_data {
    use super::{FLASH, FLASH_LEN};

    /// No-ops here: they exist on silicon to hand the QSPI pads between
    /// XIP and direct command mode, which a simulated die does not have.
    pub fn connect_internal_flash() {}
    pub fn flash_exit_xip() {}
    pub fn flash_flush_cache() {}
    pub fn flash_enter_cmd_xip() {}

    /// Program `len` bytes at `addr`. AND-ed in, never assigned: NOR
    /// flash can clear a bit and never set one, and the whole
    /// invalidate-without-erasing scheme depends on that being true.
    ///
    /// # Safety
    /// `data` must be readable for `len` bytes.
    pub unsafe fn flash_range_program(addr: u32, data: *const u8, len: usize) {
        assert!(addr as usize + len <= FLASH_LEN, "program past the die end");
        super::PROGRAM_COUNT += 1;
        if super::POWERED_OFF {
            return;
        }
        let mut n = len;
        if let Some(budget) = super::TEAR_BUDGET {
            if budget <= len {
                n = budget;
                super::POWERED_OFF = true;
            }
            super::TEAR_BUDGET = Some(budget - n);
        }
        let f = &mut *core::ptr::addr_of_mut!(FLASH);
        for i in 0..n {
            f[addr as usize + i] &= *data.add(i);
        }
    }

    /// Erase `len` bytes at `addr` back to all ones.
    ///
    /// # Safety
    /// Mirrors the ROM signature; the range is checked.
    pub unsafe fn flash_range_erase(addr: u32, len: usize, _block: u32, _cmd: u8) {
        assert!(addr as usize + len <= FLASH_LEN, "erase past the die end");
        assert_eq!(addr as usize % 4096, 0, "erase must be sector-aligned");
        super::ERASE_COUNT += 1;
        if super::POWERED_OFF {
            return;
        }
        let f = &mut *core::ptr::addr_of_mut!(FLASH);
        for i in 0..len {
            f[addr as usize + i] = 0xff;
        }
    }
}

/// A simulated slice of the RP2350 peripheral set.
///
/// Only what the firmware modules under test actually touch. The point
/// is not to model the chip -- it is to let a test drive the *failure*
/// paths that hardware almost never takes and that therefore have never
/// run: a TRNG whose health tests fail, a noise source that never
/// asserts EHR_VALID, a device that has to decide between refusing to
/// operate and handing back weak keys.
pub mod pac {
    use core::cell::RefCell;
    use std::sync::Mutex;

    /// One 32-bit register. `read()`/`write()` mirror the svd2rust
    /// shape the firmware is written against.
    pub struct Reg {
        idx: usize,
    }

    pub struct R(u32);
    impl R {
        pub fn bits(&self) -> u32 {
            self.0
        }
    }
    pub struct W(u32);
    impl W {
        /// # Safety
        /// Mirrors svd2rust's unsafe `bits`; nothing here is unsafe.
        pub unsafe fn bits(&mut self, v: u32) -> &mut Self {
            self.0 = v;
            self
        }
    }

    /// Register indices, in the order `trng.rs` names them.
    pub const R_EHR0: usize = 0;
    pub const R_SW_RESET: usize = 6;
    pub const R_SAMPLE_CNT1: usize = 7;
    pub const R_CONFIG: usize = 8;
    pub const R_IMR: usize = 9;
    pub const R_SRC_ENABLE: usize = 10;
    pub const R_ISR: usize = 11;
    pub const R_ICR: usize = 12;
    const N_REGS: usize = 13;

    /// ISR bits, matching `trng.rs`.
    pub const ISR_EHR_VALID: u32 = 1 << 0;
    pub const ISR_HEALTH_ERR: u32 = (1 << 1) | (1 << 2);

    /// How the simulated noise source behaves on each attempt.
    #[derive(Clone, Copy, PartialEq, Debug)]
    pub enum Source {
        /// Asserts EHR_VALID after `polls` reads of ISR.
        Healthy { polls: u32 },
        /// Asserts a health-test error instead. The firmware must
        /// discard the block rather than hand it back.
        HealthError,
        /// Never asserts anything. The firmware must bail on its poll
        /// limit rather than hang the calling core.
        Stuck,
    }

    struct State {
        regs: [u32; N_REGS],
        /// Behaviour per attempt; the last entry repeats.
        script: Vec<Source>,
        attempt: usize,
        polls_this_attempt: u32,
        /// EHR words handed out, one set per successful collection.
        ehr_blocks: Vec<[u32; 6]>,
        block_idx: usize,
        pub sw_resets: u32,
        pub source_enables: u32,
    }

    impl State {
        fn new() -> Self {
            State {
                regs: [0; N_REGS],
                script: vec![Source::Healthy { polls: 1 }],
                attempt: 0,
                polls_this_attempt: 0,
                ehr_blocks: Vec::new(),
                block_idx: 0,
                sw_resets: 0,
                source_enables: 0,
            }
        }
        fn source(&self) -> Source {
            // `attempt` is incremented by the SW reset that *begins* an
            // attempt, so attempt 1 is scripted by entry 0.
            let i = self
                .attempt
                .saturating_sub(1)
                .min(self.script.len().saturating_sub(1));
            self.script.get(i).copied().unwrap_or(Source::Stuck)
        }
    }

    static STATE: Mutex<Option<State>> = Mutex::new(None);

    fn with<T>(f: impl FnOnce(&mut State) -> T) -> T {
        let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            *g = Some(State::new());
        }
        f(g.as_mut().unwrap())
    }

    /// Reset the simulated TRNG to a healthy source with no scripted
    /// entropy.
    pub fn trng_reset() {
        let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
        *g = Some(State::new());
    }

    /// Script how the source behaves, attempt by attempt. The last
    /// entry repeats for any further attempts.
    pub fn trng_script(script: &[Source]) {
        with(|s| {
            s.script = script.to_vec();
            s.attempt = 0;
            s.polls_this_attempt = 0;
        });
    }

    /// Queue the EHR words a successful collection hands back, in
    /// order. Exhausting the queue repeats the last block.
    pub fn trng_set_entropy(blocks: &[[u32; 6]]) {
        with(|s| {
            s.ehr_blocks = blocks.to_vec();
            s.block_idx = 0;
        });
    }

    pub fn trng_sw_resets() -> u32 {
        with(|s| s.sw_resets)
    }
    pub fn trng_source_enables() -> u32 {
        with(|s| s.source_enables)
    }
    /// How many attempts the firmware has started.
    pub fn trng_attempts() -> usize {
        with(|s| s.attempt)
    }

    impl Reg {
        pub fn read(&self) -> R {
            R(with(|s| {
                if self.idx == R_ISR {
                    // The ISR is where the source's behaviour shows.
                    s.polls_this_attempt += 1;
                    return match s.source() {
                        Source::Healthy { polls } => {
                            if s.polls_this_attempt >= polls {
                                ISR_EHR_VALID
                            } else {
                                0
                            }
                        }
                        Source::HealthError => ISR_HEALTH_ERR,
                        Source::Stuck => 0,
                    };
                }
                s.regs[self.idx]
            }))
        }

        pub fn write<F: FnOnce(&mut W) -> &mut W>(&self, f: F) {
            let mut w = W(0);
            f(&mut w);
            let v = w.0;
            with(|s| {
                match self.idx {
                    R_SW_RESET => {
                        s.sw_resets += 1;
                        // A software reset begins the next attempt.
                        s.attempt += 1;
                        s.polls_this_attempt = 0;
                    }
                    R_SRC_ENABLE if v == 1 => {
                        s.source_enables += 1;
                        // A successful collection latches the next
                        // scripted EHR block into the data registers.
                        if !s.ehr_blocks.is_empty() {
                            let b = s.ehr_blocks[s.block_idx.min(s.ehr_blocks.len() - 1)];
                            for (i, word) in b.iter().enumerate() {
                                s.regs[R_EHR0 + i] = *word;
                            }
                        }
                    }
                    R_ICR => {
                        // Clearing EHR_VALID advances to the next block.
                        if v & ISR_EHR_VALID != 0 && !s.ehr_blocks.is_empty() {
                            s.block_idx += 1;
                        }
                    }
                    _ => {}
                }
                s.regs[self.idx] = v;
            });
        }
    }

    /// The TRNG peripheral, as `trng.rs` addresses it.
    pub struct TRNG {
        _priv: RefCell<()>,
    }

    impl TRNG {
        /// Hand out the singleton. There is one TRNG on the chip and
        /// the firmware takes it by value.
        pub fn take() -> Self {
            TRNG {
                _priv: RefCell::new(()),
            }
        }
        pub fn ehr_data0(&self) -> Reg {
            Reg { idx: R_EHR0 }
        }
        pub fn ehr_data1(&self) -> Reg {
            Reg { idx: R_EHR0 + 1 }
        }
        pub fn ehr_data2(&self) -> Reg {
            Reg { idx: R_EHR0 + 2 }
        }
        pub fn ehr_data3(&self) -> Reg {
            Reg { idx: R_EHR0 + 3 }
        }
        pub fn ehr_data4(&self) -> Reg {
            Reg { idx: R_EHR0 + 4 }
        }
        pub fn ehr_data5(&self) -> Reg {
            Reg { idx: R_EHR0 + 5 }
        }
        pub fn trng_sw_reset(&self) -> Reg {
            Reg { idx: R_SW_RESET }
        }
        pub fn sample_cnt1(&self) -> Reg {
            Reg { idx: R_SAMPLE_CNT1 }
        }
        pub fn trng_config(&self) -> Reg {
            Reg { idx: R_CONFIG }
        }
        pub fn rng_imr(&self) -> Reg {
            Reg { idx: R_IMR }
        }
        pub fn rnd_source_enable(&self) -> Reg {
            Reg { idx: R_SRC_ENABLE }
        }
        pub fn rng_isr(&self) -> Reg {
            Reg { idx: R_ISR }
        }
        pub fn rng_icr(&self) -> Reg {
            Reg { idx: R_ICR }
        }
    }
    /// The QMI window-0 read configuration.
    ///
    /// Three registers, and the reason they matter is a measured bug:
    /// the boot ROM's `flash_enter_cmd_xip()` leaves XIP in slow
    /// single-bit 03h serial mode, discarding the fast quad setup boot
    /// stage 2 installed. Since a signature counter write precedes every
    /// signature, every post-write instruction fetch paid for it --
    /// 1327 cycles per cache line, turning a ~1.3 s ML-DSA-65 sign into
    /// ~13 s. `flash_op_locked` snapshots these around the flash op and
    /// puts them back. This shim exists so that restore can be tested.
    pub mod qmi {
        use std::sync::Mutex;

        #[derive(Clone, Copy, Default, PartialEq, Debug)]
        pub struct Window {
            pub timing: u32,
            pub rfmt: u32,
            pub rcmd: u32,
        }

        static W: Mutex<Window> = Mutex::new(Window {
            timing: 0,
            rfmt: 0,
            rcmd: 0,
        });
        static WRITES: Mutex<u32> = Mutex::new(0);

        pub fn set(w: Window) {
            *W.lock().unwrap_or_else(|e| e.into_inner()) = w;
        }
        pub fn get() -> Window {
            *W.lock().unwrap_or_else(|e| e.into_inner())
        }
        pub fn writes() -> u32 {
            *WRITES.lock().unwrap_or_else(|e| e.into_inner())
        }
        pub fn reset() {
            set(Window::default());
            *WRITES.lock().unwrap_or_else(|e| e.into_inner()) = 0;
        }
        /// What the boot ROM does to the window on the way out of a
        /// flash op: drops it back to slow serial reads.
        pub fn clobber_like_boot_rom() {
            set(Window {
                timing: 0x4000_0202,
                rfmt: 0x0000_1000,
                rcmd: 0x0000_a003,
            });
        }

        pub(crate) fn note_write() {
            *WRITES.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        }
    }

    pub struct QmiReg {
        which: u8,
    }
    pub struct QmiR(u32);
    impl QmiR {
        pub fn bits(&self) -> u32 {
            self.0
        }
    }
    pub struct QmiW(u32);
    impl QmiW {
        pub fn bits(&mut self, v: u32) -> &mut Self {
            self.0 = v;
            self
        }
    }
    impl QmiReg {
        pub fn read(&self) -> QmiR {
            let w = qmi::get();
            QmiR(match self.which {
                0 => w.timing,
                1 => w.rfmt,
                _ => w.rcmd,
            })
        }
        pub fn write<F: FnOnce(&mut QmiW) -> &mut QmiW>(&self, f: F) {
            let mut x = QmiW(0);
            f(&mut x);
            let mut w = qmi::get();
            match self.which {
                0 => w.timing = x.0,
                1 => w.rfmt = x.0,
                _ => w.rcmd = x.0,
            }
            qmi::set(w);
            qmi::note_write();
        }
    }

    pub struct QmiM;
    impl QmiM {
        pub fn m0_timing(&self) -> QmiReg {
            QmiReg { which: 0 }
        }
        pub fn m0_rfmt(&self) -> QmiReg {
            QmiReg { which: 1 }
        }
        pub fn m0_rcmd(&self) -> QmiReg {
            QmiReg { which: 2 }
        }
    }

    pub struct QMI;
    impl QMI {
        /// Mirrors svd2rust's `QMI::ptr()`. One global block.
        pub fn ptr() -> *const QmiM {
            static BLOCK: QmiM = QmiM;
            &BLOCK as *const QmiM
        }
    }
    /// Re-exported so the Secure world's `pac::IO_QSPI` / `pac::SIO`
    /// resolve. The types themselves live at the crate root because
    /// `bootsel.rs` reaches them through raw pointers into statics.
    pub use crate::{HiInReg, IoQspiBlock, IoQspiSs, QspiCtrlReg, SioBlock, IO_QSPI, SIO};
}

/// The two register blocks `bootsel.rs` reaches into.
///
/// It floats the QSPI chip select by writing OEOVER, waits, samples the
/// pad, and puts OEOVER back. The failure mode if it does not put it
/// back is quiet and total -- the flash CS stays floated, XIP is dead,
/// and the device wedges with no error anywhere -- so the point of
/// simulating these two registers is to check the restore.
///
/// The firmware writes through raw pointers, so these are plain cells
/// with no write hook. What a test can see is the state before and
/// after, and what the sample returns; it cannot see the moment of the
/// float. That is enough for the property that matters.
pub mod qspi {
    /// `IO_QSPI.gpio_qspiss.gpio_ctrl` and `SIO.gpio_hi_in`.
    pub static mut SS_CTRL: u32 = 0;
    pub static mut HI_IN: u32 = 0;

    pub fn reset() {
        unsafe {
            SS_CTRL = 0;
            HI_IN = 0;
        }
    }
    pub fn set_ss_ctrl(v: u32) {
        unsafe { SS_CTRL = v }
    }
    pub fn ss_ctrl() -> u32 {
        unsafe { SS_CTRL }
    }
    /// Bit 27 is QSPI_CSN. The sampler reads it as *low means pressed*.
    pub fn set_csn_low(low: bool) {
        unsafe {
            if low {
                HI_IN &= !(1u32 << 27);
            } else {
                HI_IN |= 1u32 << 27;
            }
        }
    }
}

/// `IO_QSPI`, as `bootsel.rs` addresses it.
pub struct IoQspiSs;
impl IoQspiSs {
    pub fn gpio_ctrl(&self) -> QspiCtrlReg {
        QspiCtrlReg
    }
}
pub struct QspiCtrlReg;
impl QspiCtrlReg {
    pub fn as_ptr(&self) -> *mut u32 {
        &raw mut qspi::SS_CTRL
    }
}
pub struct IoQspiBlock;
impl IoQspiBlock {
    pub fn gpio_qspiss(&self) -> IoQspiSs {
        IoQspiSs
    }
}
pub struct IO_QSPI;
impl IO_QSPI {
    pub fn ptr() -> *const IoQspiBlock {
        static B: IoQspiBlock = IoQspiBlock;
        &B as *const IoQspiBlock
    }
}

/// `SIO`, for `gpio_hi_in`.
pub struct SioBlock;
impl SioBlock {
    pub fn gpio_hi_in(&self) -> HiInReg {
        HiInReg
    }
}
pub struct HiInReg;
impl HiInReg {
    pub fn as_ptr(&self) -> *mut u32 {
        &raw mut qspi::HI_IN
    }
}
pub struct SIO;
impl SIO {
    pub fn ptr() -> *const SioBlock {
        static B: SioBlock = SioBlock;
        &B as *const SioBlock
    }
}
