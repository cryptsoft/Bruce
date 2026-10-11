// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Feitian RP2350 USB-C token -- the sealed, capacitive-touch variant
//! of the Feitian RP2350 dev board.
//!
//! Hardware-wise this is the [`super::feitian_rp2350`] profile: GP25
//! LED, active-high; user presence sampled on QSPI_SS through
//! [`super::bootsel`] at one sample per 2 ms; no display; the same
//! flash layout (`build.rs` treats both Feitian features alike). `Board`
//! is therefore re-exported from that module rather than copied -- one
//! sampler, one LED driver, one place to fix either. What differs is the
//! identity below and one fact about the case:
//!
//!   * **No way into BOOTSEL at power-on.** The token is sealed, its
//!     input is a capacitive pad rather than a button, and on the sample
//!     we had the bootrom's power-on BOOTSEL sensing did not work: only
//!     RUNTIME touch registered. So `HAS_POWER_ON_BOOTSEL = false`, and
//!     by the policy in `reboot_policy.rs` `CTAPHID_CMD_REBOOT` needs no
//!     touch on this board -- the host-issued reboot is the ONLY route
//!     back to the bootloader, and an image that gated it on a touch the
//!     pad might never deliver would leave the token unflashable for
//!     good. FIDO presence (MakeCredential / GetAssertion) still
//!     requires the touch.
//!
//!   * **Touch pad read through the QSPI_SS sampler.** `HAS_USER_BUTTON
//!     = true` began as the working assumption from the one USB-C
//!     sample: its pad registered at runtime through the same
//!     chip-select trick the dev board's button uses. The first
//!     production token confirmed it on 2026-10-02 (register and login
//!     through the pad; docs/TESTING.md). If a later batch wires the
//!     pad differently, `user_present()` will need its own reader here
//!     (and until then the FIDO gate would time out -- the reboot path
//!     is unaffected either way, by design).
//!
//! Identify an image built for this board before flashing it:
//! `picotool info -a <file.uf2>` lists `pqf-board=feitian_rp2350_usbc`
//! and `pqf-reboot=no-touch` under "features".

use core::ffi::CStr;

/// The dev board's LED driver and QSPI_SS presence sampler, unchanged.
/// See [`super::feitian_rp2350`] for the pin-level "why".
pub use super::feitian_rp2350::Board;

/// Human-readable board name. Part of the per-board interface
/// contract documented in `board/mod.rs`. Currently unused -- kept
/// for future log / panic surfaces that want to print which board
/// the firmware was built for. Suppresses the `dead_code` warning
/// at the module level rather than at every call site.
#[allow(dead_code)]
pub const NAME: &str = "Feitian RP2350 USB-C";

/// USB product string for this board's build. Distinct from the dev
/// board's so a host with both attached can tell them apart (the
/// reboot CLIs select a token by product substring).
pub const USB_PRODUCT: &str = "Feitian USB-C PQC";

/// The capacitive pad is read through the QSPI chip-select sampler in
/// [`super::bootsel`], like the dev board's button, so `main.rs`
/// enforces a real touch in the CTAP `WaitForUp` gate. Began as the
/// working assumption from the one USB-C sample (see the module doc);
/// confirmed on the first production token, 2026-10-02.
pub const HAS_USER_BUTTON: bool = true;

/// Sealed case, capacitive pad, and the bootrom's power-on BOOTSEL
/// sensing does not work on this token: there is NO physical route into
/// the ROM bootloader. This is the one board fact that turns the
/// `CTAPHID_CMD_REBOOT` presence gate off by default (see
/// `reboot_policy.rs`) -- the host-issued reboot must never depend on a
/// touch that might not register, or the token can never be reflashed.
pub const HAS_POWER_ON_BOOTSEL: bool = false;

/// picotool program-feature entry naming this board, so an image can be
/// identified before it is flashed (`picotool info -a <file.uf2>`).
pub const BI_BOARD: &CStr = c"pqf-board=feitian_rp2350_usbc";

/// picotool program description for this board's build.
pub const BI_DESCRIPTION: &CStr =
    c"Hybrid PQC FIDO2 authenticator on RP2350 (Feitian RP2350 USB-C)";
