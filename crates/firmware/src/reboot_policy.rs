// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Whether `CTAPHID_CMD_REBOOT` waits for a user-presence gesture.
//!
//! The vendor reboot command (`ctaphid::CMD_REBOOT`) takes a running
//! token into the RP2350 ROM bootloader for reflashing, or warm-reboots
//! it. By default it is gated behind the same presence gesture as
//! MakeCredential, so a host -- or malware on it -- cannot knock an
//! authenticator off the bus into mass-storage mode without the owner's
//! touch. That gate is only a safety feature while the owner has some
//! OTHER way back into the bootloader should the gesture ever fail to
//! register: a BOOT button to hold while plugging in.
//!
//! The sealed Feitian USB-C token has no such button. Its user input is
//! a capacitive pad, and the bootrom's power-on BOOTSEL sensing does not
//! work on it; `CMD_REBOOT` is the ONLY way back into the bootloader. An
//! image on that token that gates the reboot on a touch is one flaky pad
//! -- or one firmware bug in the sampler -- away from a token that can
//! never be reflashed. So the gate is a per-board policy, decided here
//! from two board facts and two build features:
//!
//! ```text
//! needs presence = HAS_USER_BUTTON && HAS_POWER_ON_BOOTSEL
//!                  && !reboot_no_up && !test_no_user_button
//! ```
//!
//! * no button: nothing could satisfy the gate, so it auto-confirms
//!   (this was already the rule);
//! * no power-on BOOTSEL: the gate would make reflashing depend on the
//!   touch input, so it is off for such a board whatever the build
//!   flags -- the board profile decides it, not a feature the person
//!   flashing has to remember;
//! * `reboot_no_up`: a flash station's explicit opt-out on a button
//!   board (see `Cargo.toml`);
//! * `test_no_user_button`: the never-ship test gate that already
//!   auto-confirms every presence check.
//!
//! FIDO user presence for MakeCredential / GetAssertion is NOT decided
//! here (that is `UP_AUTOCONFIRM` in `main.rs`) and is unchanged by any
//! of this: the USB-C token still requires a touch to register or sign.
//!
//! The decision is a `const fn` with no dependencies, so that an image's
//! reboot behaviour is fixed at compile time (`main.rs` folds it into
//! the picotool `pqf-reboot=` feature string, readable BEFORE flashing)
//! and so that `crates/firmware-hosttest` can pull this file in by
//! `#[path]` and check the truth table on the host.

/// See the module doc for what each input means and why. The two board
/// facts come from the active `board` profile's consts, the two flags
/// from `cfg!(feature = ...)`.
pub const fn reboot_needs_presence(
    has_user_button: bool,
    has_power_on_bootsel: bool,
    reboot_no_up: bool,
    test_no_user_button: bool,
) -> bool {
    has_user_button && has_power_on_bootsel && !reboot_no_up && !test_no_user_button
}
