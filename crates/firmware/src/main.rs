// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Day 2: USB HID + CTAP HID + CTAP2 dispatcher.
//!
//! Expected behaviour after flashing:
//!   - `fido2-token -I` shows proto 2, CBOR + NMSG capabilities,
//!     AAGUID, and ES256 in supported algorithms (no more U2F fallback)
//!   - `fido2-token -L` continues to list us
//!   - PING still round-trips bytes
//!
//! Internal architecture:
//!   USB -> FidoHidClass -> CtapHid (transport / framing)
//!                     -> ctap2::handle_cbor (CTAP2 dispatch)
//!                     <- serialized response back through CtapHid

#![no_std]
#![no_main]

extern crate alloc;

use core::mem::MaybeUninit;
use embedded_alloc::LlffHeap as Heap;
use panic_halt as _;

use rp235x_hal as hal;
use usb_device::{
    bus::UsbBusAllocator,
    device::{StringDescriptors, UsbDeviceBuilder, UsbDeviceState, UsbVidPid},
    LangID,
};

/// The USB classes this build polls.
///
/// Every `usb_dev.poll()` site must pass the same set, and the set
/// varies by feature. Written once here rather than at each of the
/// eight call sites: with two optional classes that is four
/// combinations per site, and a class omitted from one of them is an
/// interface that enumerates but never answers a request -- a failure
/// that looks like a host bug.
macro_rules! usb_classes {
    ($fido:ident, $gdb:ident, $dfu:ident) => {{
        #[cfg(all(feature = "gdb_stub", feature = "dfu_runtime"))]
        {
            &mut [
                &mut $fido as &mut dyn usb_device::class::UsbClass<_>,
                $gdb.class(),
                &mut $dfu,
            ]
        }
        #[cfg(all(feature = "gdb_stub", not(feature = "dfu_runtime")))]
        {
            &mut [
                &mut $fido as &mut dyn usb_device::class::UsbClass<_>,
                $gdb.class(),
            ]
        }
        #[cfg(all(not(feature = "gdb_stub"), feature = "dfu_runtime"))]
        {
            &mut [
                &mut $fido as &mut dyn usb_device::class::UsbClass<_>,
                &mut $dfu,
            ]
        }
        #[cfg(all(not(feature = "gdb_stub"), not(feature = "dfu_runtime")))]
        {
            &mut [&mut $fido]
        }
    }};
}

mod arch;
mod authenticator_config;
/// SHA-256 / HMAC / HKDF / ct-compare, on the Bouncy Castle port.
mod bc_crypto;
mod client_pin;
mod core1_signer;
// Custom core-1 launchers -- rp235x-hal's `multicore::spawn` is
// Arm-only in practice (PPB read + Arm-ABI stack-passed trampoline
// arguments); see the module docs. Two paths live there: the same-
// architecture launch for RISC-V firmware builds, and the ARCHSEL
// flip + embedded-payload launch for the mixed-architecture
// `core1_riscv` feature (Arm core 0 + Hazard3 core 1).
#[cfg(all(
    any(target_arch = "riscv32", feature = "core1_riscv"),
    not(feature = "single_core")
))]
mod core1_launch;

// `core1_riscv` IS the mixed mode -- on an all-RISC-V build core 1 is
// already a Hazard3; asking for the feature there is a config error.
#[cfg(all(target_arch = "riscv32", feature = "core1_riscv"))]
compile_error!(
    "Bruce: the `core1_riscv` feature selects the MIXED-architecture \
     mode (Arm core 0 + RISC-V core 1) and only applies to the Arm \
     target; a --target riscv32imac-unknown-none-elf build already runs \
     both cores as RISC-V."
);
mod credential_id;
mod credential_management;
mod ctap2;
#[cfg(feature = "gdb_stub")]
mod gdbstub;
mod large_blobs;

/// Pointers the GDB monitor needs from exception context.
///
/// `main` never returns, so these locals outlive every use; raw
/// pointers are the least machinery that lets the DebugMonitor handler
/// reach a `UsbDevice` that lives in `main`'s frame. The alternative --
/// making all three statics of their full generic types -- buys nothing
/// and costs a great deal of type noise.
#[cfg(feature = "gdb_stub")]
mod gdbctx {
    pub type Bus = rp235x_hal::usb::UsbBus;
    pub static mut DEV: *mut usb_device::device::UsbDevice<'static, Bus> = core::ptr::null_mut();
    pub static mut FIDO: *mut crate::fido_hid::FidoHidClass<'static, Bus> = core::ptr::null_mut();
    pub static mut GDB: *mut crate::gdbstub::Session<'static, Bus> = core::ptr::null_mut();

    /// Service USB and the GDB session. Runs with the rest of the
    /// firmware suspended, so it must not assume anything else is
    /// making progress.
    pub fn pump() -> bool {
        // SAFETY: set once in `main` before monitor mode is armed, and
        // `main`'s frame outlives every call.
        unsafe {
            let dev = &mut *DEV;
            let fido = &mut *FIDO;
            let gdb = &mut *GDB;
            dev.poll(&mut [
                fido as &mut dyn usb_device::class::UsbClass<Bus>,
                gdb.class(),
            ]);
            let resume = crate::gdbstub::service(gdb);
            gdb.flush();
            resume
        }
    }
}

/// False once `BOOT_FLAGS0` bits 17/18 are set: the BOOTSEL USB
/// interfaces are fused off, and entering BOOTSEL would take the device
/// off the bus until it is physically replugged. Read through the raw
/// 32-bit OTP window at row 0x48.
fn bootsel_available() -> bool {
    const OTP_DATA_RAW_BASE: usize = 0x4013_4000;
    const BOOT_FLAGS0_ROW: usize = 0x48;
    const DISABLE_MSD: u32 = 1 << 17;
    const DISABLE_PICOBOOT: u32 = 1 << 18;
    // SAFETY: a single 32-bit read of a memory-mapped OTP row. The
    // window is read-only and always mapped.
    let row = unsafe {
        core::ptr::read_volatile((OTP_DATA_RAW_BASE + BOOT_FLAGS0_ROW * 4) as *const u32)
    };
    row & (DISABLE_MSD | DISABLE_PICOBOOT) == 0
}

mod board;
mod ctaphid;
#[cfg(feature = "dfu_runtime")]
mod dfu_runtime;
mod fido_hid;
mod flash_store;
mod mldsa_alg;
mod ramfunc;
// Whether CTAPHID_CMD_REBOOT waits for a touch -- a pure const fn of
// two board facts and two features, host-tested by truth table in
// crates/firmware-hosttest. See `REBOOT_NEEDS_PRESENCE` below.
mod reboot_policy;
mod trng;
// The optional external quantum RNG and the picker that puts it ahead of
// the TRNG. `trng` stays the on-die driver; `entropy` is what main hands
// out.
mod entropy;
mod qrng;
// Single-core build: KEEPALIVE from a timer interrupt while core 0 signs.
#[cfg(feature = "single_core")]
mod keepalive_timer;

#[cfg(all(feature = "single_core", feature = "core1_riscv"))]
compile_error!("`single_core` and `core1_riscv` are exclusive: the mixed build IS a second core");
#[cfg(all(feature = "single_core", feature = "gdb_stub"))]
compile_error!("`single_core` and `gdb_stub` both drive USB from an exception context; pick one");
// Legacy CTAP1 / U2F transport. Off by default -- see the `u2f`
// feature in Cargo.toml: the module is dead code in a default build
// (CMD_MSG is refused with ERR_INVALID_CMD) and ships a hardcoded
// dev-only batch attestation key, so it must not be in production
// binaries.
#[cfg(feature = "u2f")]
mod u2f;

#[cfg(feature = "ed25519")]
mod ed25519_alg;

const XTAL_FREQ_HZ: u32 = 12_000_000;

/// 256 KiB heap. ML-DSA-65 keygen / signing has a large working set
/// (matrix A expansion = K*L = 6*5 = 30 polynomials x 1 KiB each =
/// 30 KiB, plus s1/s2/t0/t1 vectors, plus several CBOR-encoded
/// pubkey allocations). Without an alloc_error_handler, an OOM
/// silently aborts the chip, so over-provision is the safer side.
/// RP2350 has 520 KiB of SRAM total.
const HEAP_SIZE: usize = 256 * 1024;

#[global_allocator]
static HEAP: Heap = Heap::empty();

#[cfg(not(all(target_arch = "riscv32", target_os = "none")))]
#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

/// On RISC-V the IMAGE_DEF carries an explicit ENTRY_POINT item. Without
/// one the boot ROM's default entry is "start of the enclosing window" --
/// fine for a standalone image the ROM finds at its link base, wrong the
/// moment the DFU bootloader transplants this block into its block-loop
/// annex to launch the app after the architecture switch: the annex's
/// window starts at the bootloader, not at us. pc is the link base
/// (riscv-rt's `_start` sits exactly there; build.rs exports it to match
/// the linked layout); sp is scratch -- `_start` reloads it from the link
/// script before the first push. Mirrors what pico-sdk crt0 emits for
/// every C RISC-V image.
#[cfg(all(target_arch = "riscv32", target_os = "none"))]
#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::Block<4> = {
    const fn hex_u32(s: &str) -> u32 {
        let b = s.as_bytes();
        let mut i = 2; // skip "0x"
        let mut v: u32 = 0;
        while i < b.len() {
            let d = match b[i] {
                c @ b'0'..=b'9' => c - b'0',
                c @ b'a'..=b'f' => c - b'a' + 10,
                c @ b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("PQF_IMG_BASE is not hex"),
            };
            v = v * 16 + d as u32;
            i += 1;
        }
        v
    }
    const ENTRY: [u32; 3] =
        hal::block::item_entry_point(hex_u32(env!("PQF_IMG_BASE")), 0x2008_2000);
    hal::block::Block::new([
        hal::block::item_image_type_exe(
            hal::block::Security::Secure,
            hal::block::Architecture::Riscv,
        ),
        ENTRY[0],
        ENTRY[1],
        ENTRY[2],
    ])
};

/// Whether the user-presence gate auto-confirms instead of waiting for a
/// real gesture.
///
/// True on boards with no firmware-readable button (they cannot gate on a
/// gesture at all), and true on ANY board under the test-only
/// `test_no_user_button` feature, which exists so the on-silicon CTAP
/// matrix can run unattended. The C port's flag is
/// -DPQF_TEST_NO_USER_BUTTON=ON. Never ship a build with it on.
const UP_AUTOCONFIRM: bool = !board::HAS_USER_BUTTON || cfg!(feature = "test_no_user_button");

/// Whether `CTAPHID_CMD_REBOOT` (both modes, warm and BOOTSEL) waits for
/// a touch. Only on a board that has a presence input AND a BOOT button
/// to hold at power-on, and only with neither `reboot_no_up` nor
/// `test_no_user_button`; everywhere else the reboot confirms at once.
/// The second fact is the one that matters on the sealed Feitian USB-C
/// token: with no power-on BOOTSEL, the host-issued reboot is its only
/// way back into the bootloader, and gating that on a touch that fails
/// to register would leave it unflashable for good. The reasoning, and
/// the host test of every row, are in `reboot_policy.rs`. FIDO presence
/// is `UP_AUTOCONFIRM` above and is not affected.
const REBOOT_NEEDS_PRESENCE: bool = reboot_policy::reboot_needs_presence(
    board::HAS_USER_BUTTON,
    board::HAS_POWER_ON_BOOTSEL,
    cfg!(feature = "reboot_no_up"),
    cfg!(feature = "test_no_user_button"),
);

// The two policy markers, spelled exactly as tools/flash-usbc.sh,
// flash.sh and docs/BUILD.md expect them (the C port emits the same
// strings). Selected at compile time from the consts above, so the
// marker cannot disagree with the behaviour it describes.
const BI_REBOOT: &core::ffi::CStr = if REBOOT_NEEDS_PRESENCE {
    c"pqf-reboot=touch"
} else {
    c"pqf-reboot=no-touch"
};
const BI_FIDO_UP: &core::ffi::CStr = if UP_AUTOCONFIRM {
    c"pqf-fido-up=auto"
} else {
    c"pqf-fido-up=touch"
};

/// USB product string: the board profile's, unless the build names
/// another with `PQF_USB_PRODUCT` (build.sh: `USB_PRODUCT=...`). Unset or
/// empty keeps the board's. Checked here, at compile time, so a bad value
/// fails the build instead of the token's enumeration.
const USB_PRODUCT: &str = match option_env!("PQF_USB_PRODUCT") {
    Some(p) if !p.is_empty() => p,
    _ => board::USB_PRODUCT,
};
const _: () = {
    let b = USB_PRODUCT.as_bytes();
    assert!(
        b.len() <= 64,
        "PQF_USB_PRODUCT is longer than 64 characters"
    );
    let mut i = 0;
    while i < b.len() {
        assert!(
            b[i] >= 0x20 && b[i] < 0x7f,
            "PQF_USB_PRODUCT must be printable ASCII"
        );
        i += 1;
    }
};

/// `pqf-rk-slots=<n>`: how many discoverable credentials the image can
/// hold -- 6 by default, 7 more per `PQF_RESIDENT_EXTRA_SECTORS` sector.
/// The C port emits the same marker with its own count. Built from
/// `flash_store::TOTAL_SLOTS` itself, so it cannot disagree with it.
const BI_RK_SLOTS_BYTES: [u8; 24] = rk_slots_marker(flash_store::TOTAL_SLOTS);
const BI_RK_SLOTS: &core::ffi::CStr =
    match core::ffi::CStr::from_bytes_until_nul(&BI_RK_SLOTS_BYTES) {
        Ok(c) => c,
        Err(_) => panic!("pqf-rk-slots marker is not NUL-terminated"),
    };

/// `"pqf-rk-slots=" + decimal(n) + NUL`, zero-padded, at compile time.
const fn rk_slots_marker(n: usize) -> [u8; 24] {
    let prefix = b"pqf-rk-slots=";
    let mut out = [0u8; 24];
    let mut i = 0;
    while i < prefix.len() {
        out[i] = prefix[i];
        i += 1;
    }
    let mut digits = [0u8; 10];
    let mut nd = 0;
    let mut v = n;
    loop {
        digits[nd] = b'0' + (v % 10) as u8;
        nd += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while nd > 0 {
        nd -= 1;
        out[i] = digits[nd];
        i += 1;
    }
    out
}

/// A picotool "program feature" binary-info entry. rp-binary-info has a
/// `const fn` for this entry but no macro, so this is its `str!` macro
/// specialised to it: a static entry, and the address `.bi_entries`
/// lists.
macro_rules! bi_program_feature {
    ($value:expr) => {{
        static ENTRY: hal::binary_info::StringEntry = hal::binary_info::rp_program_feature($value);
        ENTRY.addr()
    }};
}

/// Binary info, readable by `picotool info -a` from the UF2 before it is
/// flashed as well as from a running token's flash. The description and
/// the `pqf-*` features say which board the image is for, what its
/// presence policies are and how many passkeys it can hold; for a USB-C token, which cannot be put
/// back into the bootloader by hand, checking them BEFORE flashing is
/// the only check that can still help.
#[link_section = ".bi_entries"]
#[used]
pub static PICOTOOL_ENTRIES: [hal::binary_info::EntryAddr; 8] = [
    hal::binary_info::rp_cargo_bin_name!(),
    hal::binary_info::rp_cargo_version!(),
    hal::binary_info::rp_program_description!(board::BI_DESCRIPTION),
    hal::binary_info::rp_program_build_attribute!(),
    bi_program_feature!(board::BI_BOARD),
    bi_program_feature!(BI_REBOOT),
    bi_program_feature!(BI_FIDO_UP),
    bi_program_feature!(BI_RK_SLOTS),
];

#[hal::entry]
fn main() -> ! {
    // --- Heap init ----------------------------------------------------
    {
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe {
            #[allow(static_mut_refs)]
            HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE)
        }
    }

    // --- HW bring-up --------------------------------------------------
    let mut pac = hal::pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);

    let clocks = hal::clocks::init_clocks_and_plls(
        XTAL_FREQ_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .unwrap();

    let timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);

    // `sio.fifo` is only borrowed mutably by the core-1 spawn.
    #[cfg_attr(feature = "single_core", allow(unused_mut))]
    let mut sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );
    // The QW/ST pins come out before the board profile takes the rest
    // (see `board::BoardPins`; `None` on a board that needs them). The
    // probe itself runs below, once the TRNG exists to fall back to.
    let (pins, qrng_pins) = board::BoardPins::split(pins);

    // --- Spawn core 1 (hybrid signing worker) ------------------------
    //
    // Core 1 sits in `core1_signer::CORE1_SIGNER.worker()` waiting for
    // a request to land in the shared SRAM region. Core 0 keeps doing
    // USB + CTAP HID work, and dispatches hybrid signs (which are too
    // slow on a single core for Chrome's CTAP HID watchdog) over via
    // `Core1Signer::submit` while pumping KEEPALIVE frames during the
    // wait. See `core1_signer.rs` for the synchronisation contract.
    #[cfg(all(
        target_arch = "arm",
        not(feature = "core1_riscv"),
        not(feature = "single_core")
    ))]
    {
        let mut mc = hal::multicore::Multicore::new(&mut pac.PSM, &mut pac.PPB, &mut sio.fifo);
        let cores = mc.cores();
        let core1 = &mut cores[1];
        // .take() returns None if we've already taken this stack --
        // can't happen here (single call site), but unwrap is documented.
        let stack_alloc = core1_signer::CORE1_STACK
            .take()
            .expect("core1 stack already taken");
        core1
            .spawn(stack_alloc, || core1_signer::CORE1_SIGNER.worker())
            .expect("core1 spawn");
    }
    // Mixed-architecture mode (`core1_riscv`): keep core 0 on this Arm
    // image, but flip core 1 to its Hazard3 incarnation (OTP ARCHSEL +
    // PSM reset) and launch the embedded riscv32 signing payload on it.
    // The worker and mailbox protocol are the same `pqf-signer-core`
    // code either way; the payload finds the mailbox via the FIFO word
    // pushed after the launch handshake. See `core1_launch` docs.
    #[cfg(all(target_arch = "arm", feature = "core1_riscv"))]
    core1_launch::spawn_core1_signer_riscv_blob(&mut pac.OTP, &mut pac.PSM, &mut sio.fifo)
        .expect("core1 riscv payload spawn");
    // RISC-V: same PSM-reset + boot-ROM FIFO handshake, done by our own
    // launcher (the HAL's spawn is Arm-only in practice -- it reads the
    // Arm-core-local PPB and passes trampoline arguments on the stack
    // per the Arm ABI; see `core1_launch` docs). The signer worker and
    // its mailbox protocol are identical on both instruction sets.
    #[cfg(all(target_arch = "riscv32", not(feature = "single_core")))]
    core1_launch::spawn_core1_signer(&mut pac.PSM, &mut sio.fifo).expect("core1 spawn");

    // Board-specific GPIO + state. The `crate::board` module
    // delegates to a board-specific submodule selected by cargo
    // feature (`board_tiny2350` / `board_xiao_rp2350`) -- each
    // submodule owns the LED pin(s), the GP23 quirk handling (if
    // any), and the user-presence button placeholder. See
    // `src/board/mod.rs` for the interface contract and the
    // "Adding a new board" recipe.
    //
    // Boards that declare `HAS_USER_BUTTON` (the Feitian RP2350 and the
    // Tiny 2350, both via their BOOT button sampled through the QSPI
    // chip-select -- see `board/bootsel.rs`; the Feitian USB-C token's
    // touch pad through the same sampler; the Tiny also reads a GP0
    // touch input) get a real
    // user-presence gate: the `WaitForUp` bodies below block on
    // `board.user_present()` for a fresh release->touch gesture. On
    // buttonless boards `WaitForUp` auto-confirms after the
    // KEEPALIVE-UPNEEDED + green-blink machinery, keeping the
    // protocol-level contract (timeout error code, host "touch your
    // key" UI) with a stubbed presence check.
    // `Timer<CopyableTimer0>` is `Copy`, so we hand the board its own
    // copy and keep ours for the main loop. `peripheral_clock.freq()`
    // is from the `hal::clocks::Clock` trait (imported below).
    let mut board = board::Board::setup(board::BoardSetup {
        pins,
        spi0: pac.SPI0,
        spi1: pac.SPI1,
        resets: &mut pac.RESETS,
        peripheral_clock_freq: {
            use hal::clocks::Clock as _;
            clocks.peripheral_clock.freq()
        },
        timer,
    });

    // Leaked deliberately: the GDB stub's monitor runs in exception
    // context and needs the USB device after `main`'s frame is no
    // longer the active one. The allocator lives for the life of the
    // firmware either way -- nothing ever tears USB down.
    let usb_bus: &'static UsbBusAllocator<_> = alloc::boxed::Box::leak(alloc::boxed::Box::new(
        UsbBusAllocator::new(hal::usb::UsbBus::new(
            pac.USB,
            pac.USB_DPRAM,
            clocks.usb_clock,
            true,
            &mut pac.RESETS,
        )),
    ));

    let mut fido = fido_hid::FidoHidClass::new(usb_bus);

    // Initialise the TRNG BEFORE we build the USB device, so we can
    // seed both the CredStore master keys (first boot) AND a fresh
    // per-boot random USB serial number. The latter is the workaround
    // for a real macOS HID-cache bug: with a hardcoded serial number
    // ("0001"), the macOS USB stack treats every re-enumeration of
    // this VID/PID/serial triple as the **same** device and serves
    // stale IOHIDDevice state to Chrome's WebAuthn USB transport.
    // Specifically: after `picotool load -x` (firmware update without
    // wiping flash), the device reboots in ~2 seconds -- too fast for
    // macOS to flush the previous session's CTAPHID capability cache,
    // so Chrome reads the OLD firmware's capability bits and tries
    // to use them with the NEW firmware's CTAP2 / U2F surface. The
    // mismatch surfaces as "Chrome can't detect the device" until the
    // user does a `picotool erase -a` (long enough disconnect window
    // for macOS to clean up) or unplugs/replugs.
    //
    // Generating a fresh 8-hex-char serial on each boot makes every
    // device-enumeration look like a different physical token, so
    // macOS / Chrome MUST re-query getInfo from scratch. The new
    // string is heap-leaked into a `'static &str` for the lifetime
    // of `main` -- the leak is one-shot at boot (~10 bytes
    // permanently) and dwarfed by the 256 KiB heap.
    //
    // Entropy comes from `entropy::Entropy`: a quantum RNG on
    // the QW/ST connector (I2C0, GP12/GP13) if one answers the probe here,
    // the on-die TRNG for anything it leaves short and for every board
    // with nothing attached. The probe is bounded (an empty bus is a NAK
    // in microseconds; every transfer has a deadline) and runs before
    // anything mints a key.
    let qrng = qrng_pins.and_then(|qrng_pins| {
        qrng::hw::probe(
            pac.I2C0,
            qrng_pins,
            &mut pac.RESETS,
            {
                use hal::clocks::Clock as _;
                clocks.system_clock.freq().to_Hz()
            },
            timer,
        )
    });
    let mut rng = entropy::Entropy::new(trng::Trng::new(pac.TRNG), qrng);
    let serial_static: &'static str = {
        let mut bytes = [0u8; 4];
        rng.fill(&mut bytes);
        let s = alloc::format!(
            "{:02X}{:02X}{:02X}{:02X}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3]
        );
        alloc::boxed::Box::leak(s.into_boxed_str())
    };

    // bcdDevice -- bumps with the Cargo package version so macOS
    // also sees firmware updates as "different device versions"
    // even across the same boot's serial number (belt-and-braces
    // alongside the randomized serial). Encoded as
    // (major << 8) | (minor << 4) | patch from CARGO_PKG_VERSION.
    // For `0.1.0` -> 0x0010. Bump the [package] version field in
    // Cargo.toml on each release and this updates automatically.
    const fn parse_bcd_device() -> u16 {
        let v = env!("CARGO_PKG_VERSION").as_bytes();
        // Crude: scan major/minor/patch from `X.Y.Z`. Single-digit
        // values map cleanly to 0x0XYZ; multi-digit values cap at
        // 0xF per nibble. `const fn` here can't call closures, so we
        // inline the digit conversion as a small helper.
        let mut maj = 0u16;
        let mut min = 0u16;
        let mut pat = 0u16;
        let mut i = 0;
        while i < v.len() && v[i] != b'.' {
            if v[i] >= b'0' && v[i] <= b'9' {
                maj = maj.wrapping_mul(10).wrapping_add((v[i] - b'0') as u16);
            }
            i += 1;
        }
        i += 1;
        while i < v.len() && v[i] != b'.' {
            if v[i] >= b'0' && v[i] <= b'9' {
                min = min.wrapping_mul(10).wrapping_add((v[i] - b'0') as u16);
            }
            i += 1;
        }
        i += 1;
        while i < v.len() && v[i] >= b'0' && v[i] <= b'9' {
            pat = pat.wrapping_mul(10).wrapping_add((v[i] - b'0') as u16);
            i += 1;
        }
        if maj > 0xF {
            maj = 0xF;
        }
        if min > 0xF {
            min = 0xF;
        }
        if pat > 0xF {
            pat = 0xF;
        }
        (maj << 8) | (min << 4) | pat
    }
    const BCD_DEVICE: u16 = parse_bcd_device();

    // The GDB stub's CDC interface must be allocated before the device
    // is built, so its endpoints are in the configuration descriptor.
    #[cfg(feature = "gdb_stub")]
    let mut gdb = gdbstub::Session::new(usb_bus);

    // Allocated AFTER the GDB session so the interface numbering matches
    // the C port's ordering (FIDO, [GDB CDC pair], DFU runtime last).
    // usb-device hands out interface numbers sequentially, so this is
    // the only thing that decides which number the host sees.
    #[cfg(feature = "dfu_runtime")]
    let mut dfu = dfu_runtime::DfuRuntimeClass::new(usb_bus);

    // The Rust port has no CDC banner, so the product string is where a
    // host can see which entropy source is live: " QRNG" is appended when
    // the external chip answered. Relying parties never see USB strings,
    // and macOS keys its HID cache on VID/PID/serial, so this is cosmetic
    // everywhere except to a human reading `ioreg`. One-shot leak, like
    // the serial above.
    let product_static: &'static str = {
        let mut name = alloc::string::String::from(USB_PRODUCT);
        if rng.qrng_present() {
            name.push_str(" QRNG");
        }
        // Same idea for the single-core build: the string is the only
        // place a host can see which signer this image runs.
        #[cfg(feature = "single_core")]
        name.push_str(" 1CORE");
        if name.len() == USB_PRODUCT.len() {
            USB_PRODUCT
        } else {
            alloc::boxed::Box::leak(name.into_boxed_str())
        }
    };
    // Vendor / product ids: TinyUSB's example vendor id plus a
    // project-local product id that mirrors the FIDO HID usage page --
    // the same pair the C port and the bootloader use. A placeholder:
    // no vendor id is registered for this project. Anyone shipping a
    // product replaces both with their own allocation (and the udev
    // rule in tools/udev/ with it).
    let mut usb_dev = UsbDeviceBuilder::new(usb_bus, UsbVidPid(0xcafe, 0xF1D0))
        .strings(&[StringDescriptors::new(LangID::EN_US)
            .manufacturer("Bruce")
            .product(product_static)
            .serial_number(serial_static)])
        .unwrap()
        .device_release(BCD_DEVICE)
        .max_packet_size_0(64)
        .unwrap()
        .build();

    // Monitor-mode debug, once the USB device exists: the monitor
    // services USB itself, so the context has to be registered before
    // any debug event can fire.
    #[cfg(feature = "gdb_stub")]
    {
        // SAFETY: `main` never returns, so these outlive every use.
        unsafe {
            gdbctx::DEV = &mut usb_dev;
            gdbctx::FIDO = &mut fido;
            gdbctx::GDB = &mut gdb;
            gdbstub::set_pump(gdbctx::pump);
        }
        gdbstub::init();
    }

    // Single-core: the KEEPALIVE timer needs the USB device and the FIDO
    // class from interrupt context, the same way the GDB monitor does.
    // Alarm 0 of TIMER0 is unused elsewhere in this firmware.
    #[cfg(feature = "single_core")]
    {
        let mut t = timer;
        let alarm = t.alarm_0().expect("TIMER0 alarm 0 is free");
        // SAFETY: `main` never returns, so `usb_dev` and `fido` outlive
        // every interrupt; nothing has armed the timer yet.
        unsafe {
            keepalive_timer::init(alarm, &mut usb_dev, &mut fido);
        }
    }

    let mut ctap = ctaphid::CtapHid::new();
    // Pass TRNG so first boot can seed `key_handle_{aes,hmac}_key`.
    let mut cred_store = ctap2::CredStore::load(&mut rng);
    let mut pin_session = client_pin::PinSession::new(&mut rng);

    let mut last_blink_ms: u64 = 0;
    let mut blink_state = false;
    let wink_until_us = core::cell::Cell::new(0u64);

    // Boot-time references for the LCD `Stats` snapshot built each
    // iteration. The strings here are compile-time constants whose
    // content reflects this firmware's actual algorithm + feature
    // set; the LCD just displays whatever string we hand it.
    const FIRMWARE_LABEL: &str = concat!(env!("CARGO_PKG_NAME"), " v", env!("CARGO_PKG_VERSION"));
    const ALGORITHM_LABEL: &str = {
        #[cfg(all(feature = "mldsa44", feature = "ed25519"))]
        {
            "ML-DSA-44 + ES256 + Ed25519"
        }
        #[cfg(all(feature = "mldsa65", feature = "ed25519"))]
        {
            "ML-DSA-65 + ES256 + Ed25519"
        }
        #[cfg(all(feature = "mldsa87", feature = "ed25519"))]
        {
            "ML-DSA-87 + ES256 + Ed25519"
        }
        #[cfg(all(feature = "mldsa44", not(feature = "ed25519")))]
        {
            "ML-DSA-44 + ES256"
        }
        #[cfg(all(feature = "mldsa65", not(feature = "ed25519")))]
        {
            "ML-DSA-65 + ES256"
        }
        #[cfg(all(feature = "mldsa87", not(feature = "ed25519")))]
        {
            "ML-DSA-87 + ES256"
        }
    };

    // Mutable Stats fields tracked across iterations. Built into a
    // `Stats` struct each loop pass for `board.tick`.
    let boot_us: u64 = timer.get_counter().ticks();
    let mut last_op: Option<&'static str> = None;
    let mut op_count: u32 = 0;

    // Bootloader launch guard, mirroring the C port's pqf_boot_checkin().
    //
    // If the DFU bootloader started this image it armed the hardware
    // watchdog immediately before branching here, and resets the chip
    // back into DFU mode unless we stand that guard down. Do it only
    // once the host has ENUMERATED us: checking in earlier disarms the
    // guard and then lets a broken image hang anyway, which is exactly
    // how a dark token survived a launch guard on the C side.
    //
    // Inert in a standalone build -- nothing armed the watchdog, so this
    // clears a bit that is already clear.
    let mut checked_in = false;
    // Timer ticks at which a pending DFU detach reboots; 0 = none armed.
    #[cfg(feature = "dfu_runtime")]
    let mut dfu_detach_due: u64 = 0;

    loop {
        if !checked_in && usb_dev.state() == UsbDeviceState::Configured {
            // SAFETY: a single RMW of WATCHDOG.CTRL.ENABLE. The HAL
            // Watchdog was constructed at boot but is not driving a
            // countdown here, and nothing on either core touches this
            // register at this point. Via the PAC rather than a literal
            // address: RP2350 puts WATCHDOG at 0x400d8000, not RP2040's
            // 0x40058000, and hardcoding the wrong one would land on an
            // entirely different peripheral.
            unsafe {
                let wd = &*hal::pac::WATCHDOG::ptr();
                wd.ctrl().modify(|_, w| w.enable().clear_bit());
                // Also stand down the bootloader's RISC-V bounce
                // sentinel (watchdog scratch 7): a RISC-V image reaches
                // this loop only because the bootloader's annex launch
                // worked, and clearing the sentinel is what tells the
                // next Arm-side boot it may launch RISC-V again. The
                // ROM never touches scratch 7 outside its magic
                // one-shot reboot types, and on Arm this clears a
                // register nothing set.
                wd.scratch7().reset();
                // Drop the bootloader's "come back into DFU" handshake,
                // as C's pqf_boot_checkin() does. The bootloader already
                // consumes scratch 2 when it reads it, so today this is
                // belt and braces -- but the DFU detach path below
                // reboots THROUGH the ROM with the magic in p0/p1, and
                // an image that inherited a live magic and then took an
                // ordinary reboot would bounce straight back into DFU.
                wd.scratch2().reset();
                wd.scratch3().reset();
            }
            checked_in = true;
        }

        // ---- DFU runtime detach ------------------------------------
        //
        // `dfu-util -D` sends DFU_DETACH to the runtime interface; the
        // class ACKs it and raises a flag. Reboot on a short delay
        // rather than immediately, so the control transfer's status
        // stage completes and the host sees the detach succeed -- the
        // same reason the C port arms a deadline instead of rebooting
        // inside the callback.
        //
        // The magic rides the ROM reboot's p0/p1 rather than being
        // written to watchdog scratch 2/3 by hand. The ROM stores those
        // parameters in exactly those registers, which is where the
        // bootloader looks (c/bootloader/src/main.c:95), and going
        // through the ROM is what makes the RISC-V case work at all: a
        // plain reset there leaves ARCHSEL alone and the ROM relaunches
        // this app through the block-loop annex, never reaching the
        // Arm-only bootloader. One path for both architectures, and it
        // is the path the C port already proved on silicon.
        //
        // Note `hal::reboot::reboot` cannot be used: it hardcodes
        // p0 = p1 = 0, which would not merely fail to carry the magic
        // but actively clear it.
        #[cfg(feature = "dfu_runtime")]
        if dfu.detach_requested() {
            if dfu_detach_due == 0 {
                dfu_detach_due = timer.get_counter().ticks() + 100_000; // 100 ms
            } else if timer.get_counter().ticks() >= dfu_detach_due {
                const PQF_DFU_SCRATCH_MAGIC: u32 = 0x5051_4446; // "PQDF"
                                                                // REBOOT2: NORMAL(0x0) | NO_RETURN_ON_SUCCESS(0x100),
                                                                // plus TO_ARM(0x10) where the bootloader's architecture
                                                                // differs from ours.
                #[cfg(target_arch = "riscv32")]
                const FLAGS: u32 = 0x0000 | 0x0010 | 0x0100;
                #[cfg(not(target_arch = "riscv32"))]
                const FLAGS: u32 = 0x0000 | 0x0100;
                hal::rom_data::reboot(FLAGS, 1, PQF_DFU_SCRATCH_MAGIC, !PQF_DFU_SCRATCH_MAGIC);
                // NO_RETURN_ON_SUCCESS means we only get here if the ROM
                // refused; there is nothing useful left to do.
                loop {
                    core::hint::spin_loop();
                }
            }
        }

        #[cfg(feature = "gdb_stub")]
        {
            gdbstub::poll(&mut gdb);
            gdb.flush();
        }

        if usb_dev.poll(usb_classes!(fido, gdb, dfu)) {
            if let Some(frame) = fido.recv_frame() {
                let outcome = ctap.handle_frame(&frame, timer.get_counter().ticks(), &mut || {
                    let now = timer.get_counter().ticks();
                    wink_until_us.set(now + 1_000_000);
                });
                let mut response = match outcome {
                    ctaphid::FrameOutcome::Idle => continue,
                    ctaphid::FrameOutcome::Reply(r) => r,
                    ctaphid::FrameOutcome::RngRequest { cid, count } => {
                        // Vendor CMD_RNG: hand back entropy straight from
                        // the picker -- QRNG-conditioned bytes when the chip
                        // is live, TRNG output otherwise.
                        // Count is already validated by the transport
                        // layer (1..=RNG_MAX). No UP gesture -- see the
                        // CMD_RNG doc comment in ctaphid.rs.
                        let mut bytes = alloc::vec![0u8; count];
                        rng.fill(&mut bytes);
                        ctap.build_response(cid, ctaphid::CMD_RNG, &bytes)
                    }
                    ctaphid::FrameOutcome::RngStatusRequest { cid } => {
                        // Vendor CMD_RNG_STATUS: which source is serving and
                        // the picker's counters; entropy.rs owns the layout.
                        ctap.build_response(cid, ctaphid::CMD_RNG_STATUS, &rng.status_bytes())
                    }
                    ctaphid::FrameOutcome::RebootRequest { cid, mode } => {
                        // Vendor CMD_REBOOT: test of user presence (same
                        // gesture as MakeCredential) where this board's
                        // policy asks for one, then reboot. On success the
                        // ROM reboot never returns and the device
                        // re-enumerates, so no response is sent; a
                        // declined / timed-out gate answers ERR_OTHER and
                        // the token stays running. Mirrors the WaitForUp
                        // loop used on the CBOR path.
                        //
                        // `REBOOT_NEEDS_PRESENCE` (see its doc and
                        // `reboot_policy.rs`) is false on buttonless
                        // boards, on the sealed USB-C token (no power-on
                        // BOOTSEL: this reboot is its only way back into
                        // the bootloader, so it must never hang on a
                        // touch), and under `reboot_no_up` (flash-station
                        // convenience) or `test_no_user_button`; then the
                        // gate confirms at once. FIDO user presence for
                        // MakeCredential / GetAssertion is unaffected.
                        let confirmed = if !REBOOT_NEEDS_PRESENCE {
                            true
                        } else {
                            let start = timer.get_counter().ticks();
                            let deadline = start.saturating_add(ctaphid::REBOOT_UP_TIMEOUT_US);
                            // The idle loop's heartbeat leaves blue on half
                            // the time. On boards whose r/g/b channels
                            // OR-merge onto one LED that keeps it solid and
                            // hides the blink below, so drop it for the gate;
                            // if the reboot is declined the heartbeat brings
                            // it back by itself.
                            board.b_off();
                            let mut last_pump = start;
                            let mut last_led_toggle = start;
                            let mut led_state = false;
                            let mut saw_release = !board.user_present();
                            let mut pressed_since: Option<u64> = None;
                            let mut released_since: Option<u64> = None;
                            loop {
                                let now = timer.get_counter().ticks();
                                let touched = board.user_present();
                                if touched {
                                    released_since = None;
                                }
                                if !touched {
                                    // Tolerate a dropped sample. Reading the button
                                    // means floating QSPI_SS for a few microseconds
                                    // (see board::bootsel), and a read can come back
                                    // wrong -- core 1 refetching its idle loop from XIP
                                    // lands in exactly that window, which is why this
                                    // only bites once something has written flash and
                                    // flushed the XIP cache. Resetting the whole
                                    // accumulation on one bad read meant a genuinely
                                    // held button could never reach the 20 ms
                                    // threshold, and the gate timed out and declined the reboot
                                    // with the button down. Only a release that
                                    // persists counts as one.
                                    match released_since {
                                        None => released_since = Some(now),
                                        Some(r0) if now.saturating_sub(r0) >= 6_000 => {
                                            saw_release = true;
                                            pressed_since = None;
                                        }
                                        _ => {}
                                    }
                                } else if saw_release {
                                    match pressed_since {
                                        None => pressed_since = Some(now),
                                        Some(t0) if now.saturating_sub(t0) >= 20_000 => {
                                            board.g_off();
                                            break true;
                                        }
                                        _ => {}
                                    }
                                }
                                if now >= deadline {
                                    board.g_off();
                                    break false;
                                }
                                if now.saturating_sub(last_led_toggle) >= 100_000 {
                                    last_led_toggle = now;
                                    led_state = !led_state;
                                    if led_state {
                                        board.g_on();
                                    } else {
                                        board.g_off();
                                    }
                                }
                                if now.saturating_sub(last_pump) >= 50_000 {
                                    last_pump = now;
                                    let ka =
                                        ctaphid::keepalive_frame(cid, ctaphid::KEEPALIVE_UPNEEDED);
                                    let _ = fido.send_frame(&ka);
                                }
                                let _ = usb_dev.poll(usb_classes!(fido, gdb, dfu));
                                crate::arch::nop();
                            }
                        };
                        // Refuse BOOTSEL on a part whose BOOTSEL USB
                        // interfaces are fused off. The ROM still enters
                        // the mode; it just exposes nothing, so the
                        // device drops off the bus and stays there until
                        // someone physically power-cycles it. The host
                        // cannot know this and any host can ask, so the
                        // check belongs here. DFU is unaffected -- that
                        // is the bootloader's own USB device, not the
                        // ROM's.
                        let bootsel_ok = mode != ctaphid::REBOOT_BOOTSEL || bootsel_available();
                        if confirmed && bootsel_ok {
                            let kind = if mode == ctaphid::REBOOT_BOOTSEL {
                                hal::reboot::RebootKind::BootSel {
                                    picoboot_disabled: false,
                                    msd_disabled: false,
                                }
                            } else {
                                hal::reboot::RebootKind::Normal
                            };
                            // -> ! (device re-enumerates; never returns)
                            hal::reboot::reboot(kind, hal::reboot::RebootArch::Normal);
                        }
                        // Declined, timed out, or refused because BOOTSEL is
                        // fused off -- stay running and tell the host.
                        ctap.build_response(cid, ctaphid::CMD_ERROR, &[ctaphid::ERR_OTHER])
                    }
                    ctaphid::FrameOutcome::CborMessage { cid, payload } => {
                        // Send one KEEPALIVE before we start the
                        // potentially-long ML-DSA-65 work. The host
                        // resets its command-timeout when it sees
                        // this; without it macOS gives up after a
                        // few seconds and aborts the request.
                        let ka = ctaphid::keepalive_frame(cid, ctaphid::KEEPALIVE_PROCESSING);
                        loop {
                            match fido.send_frame(&ka) {
                                Ok(_) => break,
                                Err(usb_device::UsbError::WouldBlock) => {
                                    let _ = usb_dev.poll(usb_classes!(fido, gdb, dfu));
                                }
                                Err(_) => break,
                            }
                        }
                        // Light red LED so the user (and developer)
                        // can see crypto work is in flight.
                        board.r_on();
                        let resp_bytes = {
                            // `host` covers the two ops `ctap2`
                            // needs from us during a CTAP2 command:
                            //
                            //   HostOp::Pump          -- push CTAP HID
                            //     KEEPALIVE frames + drive USB so
                            //     Chrome's watchdog doesn't time out
                            //     during slow crypto. Called between
                            //     ML-DSA keygen / mu / sign phases.
                            //
                            //   HostOp::WaitForUp     -- block up to
                            //     `timeout_us` waiting for a fresh
                            //     GP23 press. While waiting we keep
                            //     pumping KEEPALIVEs (host watchdog
                            //     stays calm) AND flash the green
                            //     LED at ~250 ms cadence so the user
                            //     sees that we want a touch.
                            //
                            // Both ops are folded into one closure so
                            // they can share `&mut fido` / `&mut
                            // usb_dev` / `&mut board` without
                            // tripping Rust's aliasing rules.
                            let mut host = |op: ctap2::HostOp| -> bool {
                                // Single-core: this closure is the only
                                // main-context code that touches USB inside
                                // a dispatch; tell the KEEPALIVE timer to
                                // stay off it meanwhile.
                                #[cfg(feature = "single_core")]
                                let _usb = keepalive_timer::UsbGuard::enter();
                                let pump = |fido: &mut fido_hid::FidoHidClass<'_, _>,
                                            usb_dev: &mut usb_device::device::UsbDevice<'_, _>| {
                                    for _ in 0..3 {
                                        let ka = ctaphid::keepalive_frame(
                                            cid,
                                            ctaphid::KEEPALIVE_PROCESSING,
                                        );
                                        let mut tries = 0;
                                        loop {
                                            match fido.send_frame(&ka) {
                                                Ok(_) => break,
                                                Err(usb_device::UsbError::WouldBlock) => {
                                                    let _ = usb_dev.poll(&mut [&mut *fido]);
                                                    tries += 1;
                                                    if tries > 8 { break; }
                                                }
                                                Err(_) => break,
                                            }
                                        }
                                    }
                                    let _ = usb_dev.poll(&mut [&mut *fido]);
                                };
                                match op {
                                    ctap2::HostOp::Pump => {
                                        pump(&mut fido, &mut usb_dev);
                                        // L15: `pump` just polled USB, so the rx ring may
                                        // now hold a CTAPHID_CANCEL for this channel.
                                        // Consume it and report it (returning `false`) so
                                        // ctap2 aborts the in-flight sign with
                                        // KEEPALIVE_CANCEL. `true` = keep pumping.
                                        !fido.take_cancel(cid, ctaphid::CMD_CANCEL)
                                    }
                                    ctap2::HostOp::WaitForUp { timeout_us } => {
                                        // Boards with no firmware-readable button
                                        // (every board except the Tiny 2350's GP0
                                        // touch pad) can't gate on a real gesture, so
                                        // they auto-confirm UP as before rather than
                                        // time out. This is a compile-time const, so
                                        // the real gate below is dropped entirely on
                                        // those boards.
                                        if UP_AUTOCONFIRM {
                                            return true;
                                        }
                                        // Real CTAP user-presence gate on the GP0
                                        // capacitive touch button. Wait up to
                                        // `timeout_us` for a FRESH touch: if the pad
                                        // is already held on entry (carried over from
                                        // a previous op) we require a release first,
                                        // so one continuous touch can't satisfy
                                        // back-to-back operations. A confirmed touch
                                        // must be held ~20 ms (debounce + deliberate
                                        // tap). While waiting we blink the green LED
                                        // and ship KEEPALIVE-UPNEEDED every 50 ms so
                                        // the host UI shows "touch your key". Returns
                                        // true on a fresh touch, false on timeout
                                        // (-> CTAP2_ERR_OPERATION_DENIED).
                                        let start = timer.get_counter().ticks();
                                        let deadline = start.saturating_add(timeout_us);
                                        // The CBOR dispatch lit the red "busy" channel
                                        // before calling us, and the idle loop's
                                        // heartbeat leaves blue on half the time. On
                                        // boards whose r/g/b channels OR-merge onto
                                        // one physical LED (Feitian, XIAO, Waveshare,
                                        // Spotpear) either one keeps the LED solid, so
                                        // the blink below is invisible and the user is
                                        // never told to touch -- the gate then times
                                        // out into CTAP2_ERR_OPERATION_DENIED with no
                                        // cue that anything was wanted. Blue is the
                                        // sly one: the heartbeat toggles as soon as
                                        // the idle loop resumes after anything longer
                                        // than its 500 ms period, so a login sent
                                        // straight after a registration always gets
                                        // the opposite blue to it, and one of the two
                                        // gates was always dark. Drop both for the
                                        // gate; red is restored on every exit path
                                        // below, and the heartbeat brings blue back
                                        // by itself.
                                        board.r_off();
                                        board.b_off();
                                        let mut last_pump = start;
                                        let mut last_led_toggle = start;
                                        let mut led_state = false;
                                        // Only accept a press once the pad has been
                                        // seen released -- true immediately if it's
                                        // already released on entry.
                                        let mut saw_release = !board.user_present();
                                        let mut pressed_since: Option<u64> = None;
                                        let mut released_since: Option<u64> = None;
                                        loop {
                                            let now = timer.get_counter().ticks();
                                            let touched = board.user_present();
                                            if touched {
                                                released_since = None;
                                            }
                                            if !touched {
                                                // Tolerate a dropped sample. Reading the button
                                                // means floating QSPI_SS for a few microseconds
                                                // (see board::bootsel), and a read can come back
                                                // wrong -- core 1 refetching its idle loop from XIP
                                                // lands in exactly that window, which is why this
                                                // only bites once something has written flash and
                                                // flushed the XIP cache. Resetting the whole
                                                // accumulation on one bad read meant a genuinely
                                                // held button could never reach the 20 ms
                                                // threshold, and the gate timed out into CTAP2_ERR_OPERATION_DENIED
                                                // with the button down. Only a release that
                                                // persists counts as one.
                                                match released_since {
                                                    None => released_since = Some(now),
                                                    Some(r0) if now.saturating_sub(r0) >= 6_000 => {
                                                        saw_release = true;
                                                        pressed_since = None;
                                                    }
                                                    _ => {}
                                                }
                                            } else if saw_release {
                                                match pressed_since {
                                                    None => pressed_since = Some(now),
                                                    Some(t0)
                                                        if now.saturating_sub(t0) >= 20_000 =>
                                                    {
                                                        board.g_off();
                                                        board.r_on();
                                                        return true;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            if now >= deadline {
                                                board.g_off();
                                                board.r_on();
                                                return false;
                                            }
                                            if now.saturating_sub(last_led_toggle) >= 100_000 {
                                                last_led_toggle = now;
                                                led_state = !led_state;
                                                if led_state {
                                                    board.g_on();
                                                } else {
                                                    board.g_off();
                                                }
                                            }
                                            if now.saturating_sub(last_pump) >= 50_000 {
                                                last_pump = now;
                                                let ka = ctaphid::keepalive_frame(
                                                    cid,
                                                    ctaphid::KEEPALIVE_UPNEEDED,
                                                );
                                                let _ = fido.send_frame(&ka);
                                            }
                                            let _ = usb_dev.poll(usb_classes!(fido, gdb, dfu));
                                            crate::arch::nop();
                                        }
                                    }
                                }
                            };
                            #[cfg(feature = "single_core")]
                            keepalive_timer::arm(cid);
                            let reply = ctap2::handle_cbor(
                                &payload,
                                &mut rng,
                                &mut pin_session,
                                &mut cred_store,
                                &mut host,
                                timer.get_counter().ticks(),
                                cid.to_be_bytes(),
                            );
                            #[cfg(feature = "single_core")]
                            keepalive_timer::disarm();
                            reply
                        };
                        board.r_off();
                        // Label the just-completed op for the LCD's
                        // "Last op" field. We classify by the CTAP2
                        // command byte (first byte of the payload).
                        // Only successful commands count toward
                        // `op_count` -- failures (response[0] != 0x00)
                        // are recorded as `last_op` but not counted.
                        if !payload.is_empty() {
                            let op = match payload[0] {
                                0x01 => Some("MakeCredential"),
                                0x02 => Some("GetAssertion"),
                                0x04 => Some("GetInfo"),
                                0x06 => Some("ClientPIN"),
                                0x07 => Some("Reset"),
                                0x08 => Some("GetNextAssertion"),
                                0x0A => Some("CredentialMgmt"),
                                0x0B => Some("Selection"),
                                0x0C => Some("LargeBlobs"),
                                0x0D => Some("AuthnrConfig"),
                                _ => None,
                            };
                            if op.is_some() {
                                last_op = op;
                                if !resp_bytes.is_empty() && resp_bytes[0] == 0x00 {
                                    op_count = op_count.saturating_add(1);
                                }
                            }
                        }
                        ctap.build_response(cid, ctaphid::CMD_CBOR, &resp_bytes)
                    }
                    // Legacy U2F dispatch is only compiled when the
                    // `u2f` feature is on. In a default build the
                    // `U2fMessage` variant doesn't exist (and CMD_MSG
                    // is refused upstream), so this arm is absent.
                    #[cfg(feature = "u2f")]
                    ctaphid::FrameOutcome::U2fMessage { cid, payload } => {
                        // CTAP1 / U2F APDU (Phase 11b). U2F crypto is
                        // pure ECDSA-P256 -- no ML-DSA -- so it runs to
                        // completion in <100 ms on core 0 and doesn't
                        // need the keepalive pump machinery the CTAP2
                        // hybrid path uses. We still need a `host`
                        // closure to satisfy the `u2f::handle`
                        // signature; only `HostOp::WaitForUp` is
                        // actually exercised (UP gate before
                        // REGISTER and AUTHENTICATE).
                        board.r_on();
                        let resp_bytes = {
                            let mut host = |op: ctap2::HostOp| -> bool {
                                match op {
                                    ctap2::HostOp::Pump => {
                                        let _ = usb_dev.poll(usb_classes!(fido, gdb, dfu));
                                        true
                                    }
                                    ctap2::HostOp::WaitForUp { timeout_us } => {
                                        if UP_AUTOCONFIRM {
                                            return true; // no readable button -> auto-confirm
                                        }
                                        // Same real GP0 capacitive-touch user-presence
                                        // gate as the CTAP2 path above (fresh
                                        // release-then-touch, 20 ms debounce, blink +
                                        // KEEPALIVE-UPNEEDED, false on timeout). U2F
                                        // REGISTER / AUTHENTICATE require UP too.
                                        let start = timer.get_counter().ticks();
                                        let deadline = start.saturating_add(timeout_us);
                                        // The CBOR dispatch lit the red "busy" channel
                                        // before calling us, and the idle loop's
                                        // heartbeat leaves blue on half the time. On
                                        // boards whose r/g/b channels OR-merge onto
                                        // one physical LED (Feitian, XIAO, Waveshare,
                                        // Spotpear) either one keeps the LED solid, so
                                        // the blink below is invisible and the user is
                                        // never told to touch -- the gate then times
                                        // out into CTAP2_ERR_OPERATION_DENIED with no
                                        // cue that anything was wanted. Blue is the
                                        // sly one: the heartbeat toggles as soon as
                                        // the idle loop resumes after anything longer
                                        // than its 500 ms period, so a login sent
                                        // straight after a registration always gets
                                        // the opposite blue to it, and one of the two
                                        // gates was always dark. Drop both for the
                                        // gate; red is restored on every exit path
                                        // below, and the heartbeat brings blue back
                                        // by itself.
                                        board.r_off();
                                        board.b_off();
                                        let mut last_pump = start;
                                        let mut last_led_toggle = start;
                                        let mut led_state = false;
                                        let mut saw_release = !board.user_present();
                                        let mut pressed_since: Option<u64> = None;
                                        let mut released_since: Option<u64> = None;
                                        loop {
                                            let now = timer.get_counter().ticks();
                                            let touched = board.user_present();
                                            if touched {
                                                released_since = None;
                                            }
                                            if !touched {
                                                // Tolerate a dropped sample. Reading the button
                                                // means floating QSPI_SS for a few microseconds
                                                // (see board::bootsel), and a read can come back
                                                // wrong -- core 1 refetching its idle loop from XIP
                                                // lands in exactly that window, which is why this
                                                // only bites once something has written flash and
                                                // flushed the XIP cache. Resetting the whole
                                                // accumulation on one bad read meant a genuinely
                                                // held button could never reach the 20 ms
                                                // threshold, and the gate timed out into CTAP2_ERR_OPERATION_DENIED
                                                // with the button down. Only a release that
                                                // persists counts as one.
                                                match released_since {
                                                    None => released_since = Some(now),
                                                    Some(r0) if now.saturating_sub(r0) >= 6_000 => {
                                                        saw_release = true;
                                                        pressed_since = None;
                                                    }
                                                    _ => {}
                                                }
                                            } else if saw_release {
                                                match pressed_since {
                                                    None => pressed_since = Some(now),
                                                    Some(t0)
                                                        if now.saturating_sub(t0) >= 20_000 =>
                                                    {
                                                        board.g_off();
                                                        board.r_on();
                                                        return true;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            if now >= deadline {
                                                board.g_off();
                                                board.r_on();
                                                return false;
                                            }
                                            if now.saturating_sub(last_led_toggle) >= 100_000 {
                                                last_led_toggle = now;
                                                led_state = !led_state;
                                                if led_state {
                                                    board.g_on();
                                                } else {
                                                    board.g_off();
                                                }
                                            }
                                            if now.saturating_sub(last_pump) >= 50_000 {
                                                last_pump = now;
                                                let ka = ctaphid::keepalive_frame(
                                                    cid,
                                                    ctaphid::KEEPALIVE_UPNEEDED,
                                                );
                                                let _ = fido.send_frame(&ka);
                                            }
                                            let _ = usb_dev.poll(usb_classes!(fido, gdb, dfu));
                                            crate::arch::nop();
                                        }
                                    }
                                }
                            };
                            u2f::handle(&payload, &mut rng, &cred_store, &mut host)
                        };
                        board.r_off();
                        // Classify the U2F op by its INS byte for the
                        // LCD's "Last op" line. APDU layout:
                        // CLA | INS | P1 | P2 | Lc1 Lc2 Lc3 | data | Le.
                        // `payload[1]` is INS. U2F responses end with
                        // a 2-byte SW; SW = 0x9000 = success.
                        if payload.len() >= 4 {
                            let op = match payload[1] {
                                0x01 => Some("U2F Register"),
                                0x02 => Some("U2F Auth"),
                                0x03 => Some("U2F Version"),
                                _ => None,
                            };
                            if op.is_some() {
                                last_op = op;
                                if resp_bytes.len() >= 2
                                    && resp_bytes[resp_bytes.len() - 2] == 0x90
                                    && resp_bytes[resp_bytes.len() - 1] == 0x00
                                {
                                    op_count = op_count.saturating_add(1);
                                }
                            }
                        }
                        ctap.build_response(cid, ctaphid::CMD_MSG, &resp_bytes)
                    }
                };
                while let Some(out) = response.next_frame() {
                    loop {
                        match fido.send_frame(&out) {
                            Ok(_) => break,
                            Err(usb_device::UsbError::WouldBlock) => {
                                let _ = usb_dev.poll(usb_classes!(fido, gdb, dfu));
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        }

        let now_us = timer.get_counter().ticks();

        // Transport maintenance sweep, run once per loop iteration:
        //
        //   1. If the RX ring dropped an inbound frame (back-pressure
        //      while we were busy in synchronous crypto), the frame
        //      stream has a gap -- abort any in-flight reassembly with
        //      ERR_CHANNEL_BUSY so the host retries cleanly rather
        //      than desynchronising sequence numbers (L19).
        //   2. If a multi-frame transaction has stalled with no
        //      progress past MSG_TIMEOUT_US, drop it and emit
        //      ERR_MSG_TIMEOUT, freeing the single reassembly slot a
        //      stalled host would otherwise wedge forever (L16).
        //
        // Overflow is checked first: a dropped frame is the more
        // specific cause and its reply supersedes a timeout we'd
        // otherwise raise on the same partial message.
        let sweep_reply = if fido.take_overflow() {
            ctap.poll_overflow()
        } else {
            ctap.poll_timeout(now_us)
        };
        if let Some(mut response) = sweep_reply {
            while let Some(out) = response.next_frame() {
                loop {
                    match fido.send_frame(&out) {
                        Ok(_) => break,
                        Err(usb_device::UsbError::WouldBlock) => {
                            let _ = usb_dev.poll(usb_classes!(fido, gdb, dfu));
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        if now_us.saturating_sub(last_blink_ms) >= 500_000 {
            last_blink_ms = now_us;
            blink_state = !blink_state;
            if blink_state {
                board.b_on();
            } else {
                board.b_off();
            }
        }
        if now_us < wink_until_us.get() {
            board.g_on();
        } else {
            board.g_off();
        }

        // Hand the current device state to the active board profile.
        // The board decides whether to do anything with it -- Tiny
        // 2350 and XIAO RP2350 ignore it; the Waveshare profile
        // redraws the on-board LCD at ~5 Hz. `Stats` is rebuilt
        // every iteration; the fields are all `Copy` or `&str` so
        // the allocation cost is zero.
        let stats = board::Stats {
            firmware: FIRMWARE_LABEL,
            algorithm: ALGORITHM_LABEL,
            serial: serial_static,
            pin_set: cred_store.pin.pin_set != 0,
            pin_retries: cred_store.pin.retries_left as u8,
            resident_cred_count: cred_store.active_count() as u32,
            last_op,
            op_count,
            uptime_secs: (now_us.saturating_sub(boot_us) / 1_000_000) as u32,
            last_make_cred_algs: &cred_store.last_make_cred_algs
                [..cred_store.last_make_cred_alg_count as usize],
        };
        board.tick(&stats);
    }
}
