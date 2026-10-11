// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// Does the PIN retry budget survive a reset, and does the
// per-boot soft block clear on one?
//
// The host test suite cannot answer either question. Its flash is a
// simulated die living in process memory, so "persisted" there means
// "still in the same array a moment later" -- which is equally true of a
// counter that never reached flash at all. And its notion of a power
// cycle is a function call, so a volatile flag that in reality sits in
// a register the boot path never clears would look like it cleared.
//
// Both directions are security-relevant, in opposite ways:
//
//   * If the **persistent** counter resets on reboot, eight guesses
//     becomes eight *per power cycle*. Someone holding the token can
//     cycle it as often as they like, so the budget is unlimited --
//     while every host-side measurement of it still reads 8.
//
//   * If the **volatile** soft block does *not* clear on reboot, a user
//     who fat-fingers their PIN three times has bricked the token until
//     they burn the remaining real attempts. That is the failure that
//     gets a device returned.
//
// So this drives the pair against real silicon and a real reset:
//
//   1. read the budget                          (persistent, in flash)
//   2. three wrong PINs -> soft block            (volatile, per boot)
//   3. reset the token
//   4. budget is still down 3                    <- reached flash
//      soft block is gone                        <- cleared on boot
//   5. the correct PIN is still accepted         <- the hash survived
//      and restores the full budget              <- and so does reset-on-success
//
// Nothing here needs a finger. ClientPIN is not user-presence gated,
// which is what makes this runnable against the shipping image with
// presence enforced, and unattended.
//
// Needs a build where the vendor reboot (0x51) is reachable without a
// touch -- `-Dreboot_no_up=ON`, or a test image. Without it, step 3
// falls back to asking for a replug.
//
//   cargo run -p pqf-ctaphid --example pin_persistence \
//       --target $(rustc -vV | awk '/host/{print $2}') -- <pin>

use std::process::Command;
use std::{thread, time::Duration};

use pqf_ctaphid::ctap2::client_pin::{self, permission, PinRetries};
use pqf_ctaphid::ctap2::pin_protocol::Protocol;
use pqf_ctaphid::ctap2::{Error, Status};
use pqf_ctaphid::{ctap2, hid};

/// Wrong on purpose, and long enough to pass the 4-byte minimum so the
/// device actually checks it rather than rejecting it as malformed.
const WRONG_PIN: &[u8] = b"00000000";

fn fail(msg: &str) -> ! {
    eprintln!("\nFAIL: {msg}");
    std::process::exit(1);
}

/// Open the first FIDO device, waiting for it to appear. Called after a
/// reset, when re-enumeration takes a moment.
fn open_waiting() -> hid::Device {
    for attempt in 0..60 {
        if let Ok(list) = hid::enumerate() {
            if let Some(info) = list.first() {
                if let Ok(dev) = hid::Device::open(info) {
                    return dev;
                }
            }
        }
        if attempt == 6 {
            println!("  (still waiting for the token to enumerate...)");
        }
        thread::sleep(Duration::from_millis(500));
    }
    fail("no FIDO device appeared");
}

fn retries(dev: &hid::Device) -> PinRetries {
    match client_pin::get_pin_retries(dev) {
        Ok(r) => r,
        Err(e) => fail(&format!("getPinRetries failed: {e}")),
    }
}

fn describe(r: &PinRetries) -> String {
    match r.power_cycle_state {
        Some(true) => format!("{} left, power-cycle required", r.retries),
        Some(false) => format!("{} left, no power cycle required", r.retries),
        None => format!("{} left, powerCycleState not reported", r.retries),
    }
}

/// One PIN attempt. Returns Ok(()) if accepted, or the CTAP status.
fn try_pin(dev: &hid::Device, pin: &[u8]) -> Result<(), Status> {
    let session = match client_pin::establish_session(dev, Protocol::V2) {
        Ok(s) => s,
        Err(e) => fail(&format!("could not establish a PIN session: {e}")),
    };
    match client_pin::get_pin_uv_auth_token_using_pin(
        dev,
        session,
        pin,
        permission::GET_ASSERTION,
        Some("persistence.test"),
    ) {
        Ok(_) => Ok(()),
        Err(Error::Ctap(s)) => Err(s),
        Err(e) => fail(&format!("PIN attempt failed for a non-CTAP reason: {e}")),
    }
}

/// Reset the token. Prefers the vendor reboot; falls back to asking.
fn reset_token(dev: hid::Device) {
    drop(dev); // release the HID handle before the device drops off the bus

    let reboot = ["./c/hid/reboot", "c/hid/reboot"]
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .copied();

    match reboot {
        Some(path) => {
            println!("  {path} warm");
            match Command::new(path).arg("warm").output() {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    fail(&format!(
                        "the vendor reboot was refused ({}). If this image gates \
                         CMD_REBOOT behind user presence, rebuild with \
                         -Dreboot_no_up=ON, or unplug and replug and rerun with \
                         PQF_MANUAL_CYCLE=1.\n{err}",
                        o.status
                    ));
                }
                Err(e) => fail(&format!("could not run {path}: {e}")),
            }
        }
        None => fail(
            "c/hid/reboot is not built (make -C c/hid), and no manual cycle was \
             requested. Rerun with PQF_MANUAL_CYCLE=1 to be prompted instead.",
        ),
    }
    thread::sleep(Duration::from_secs(2));
}

fn manual_cycle() {
    println!("\n  Unplug the token, plug it back in, then press Return.");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

fn main() {
    let pin = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: pin_persistence <current-pin>");
            eprintln!("  set PQF_MANUAL_CYCLE=1 to be prompted to replug instead of");
            eprintln!("  using the vendor reboot command.");
            std::process::exit(2);
        }
    };
    let pin = pin.into_bytes();
    if pin == WRONG_PIN {
        fail("the PIN under test must differ from the deliberately-wrong one");
    }
    let manual = std::env::var_os("PQF_MANUAL_CYCLE").is_some();

    println!("== PIN state across a reset ==\n");

    let dev = open_waiting();
    let info = match ctap2::get_info::get_info(&dev) {
        Ok(i) => i,
        Err(e) => fail(&format!("getInfo failed: {e}")),
    };
    if !info.pin_set() {
        fail(
            "this device has no PIN set -- nothing to measure. Set one first \
             (examples/pin_set.rs), then rerun with that PIN.",
        );
    }

    // ---- 1. establish a known baseline -------------------------------
    // Read the budget first only to report where the device was found;
    // the correct PIN below resets it to the maximum, so the number that
    // the rest of the test measures against has to be read *after* that.
    // Reading it before is a live trap: the arithmetic then compares a
    // pre-reset figure against a post-reset one and silently reports
    // three spent retries as zero.
    let found = retries(&dev);
    println!("  found:                      {}", describe(&found));

    // A success costs nothing and clears both counters, so this doubles
    // as a check that the supplied PIN is right -- without it, a mistyped
    // argument would spend three retries and only report the mistake at
    // the very end, with the budget already gone.
    match try_pin(&dev, &pin) {
        Ok(()) => println!("  the supplied PIN is correct"),
        Err(Status::PinInvalid) => fail(
            "the supplied PIN is wrong. Nothing has been spent -- check it and \
             rerun. (The conformance suite leaves 123456 set.)",
        ),
        Err(Status::PinAuthBlocked) => fail(
            "the device is still soft-blocked from an earlier run, so it will \
             not answer any PIN until it is reset. Run `./c/hid/reboot warm` \
             and try again. (This test leaves the device blocked when it \
             fails partway through -- that is the state under test, not a \
             defect.)",
        ),
        Err(s) => fail(&format!(
            "the supplied PIN answered {s:?} (0x{:02x})",
            s as u8
        )),
    }

    let start = retries(&dev);
    println!("  baseline after a success:   {}", describe(&start));
    if start.retries < 4 {
        fail(&format!(
            "a correct PIN left only {} retries. The firmware is supposed to \
             restore the full budget on success.",
            start.retries
        ));
    }
    if start.power_cycle_state == Some(true) {
        fail("the device reports a power cycle is required even after a correct PIN");
    }

    // ---- 2. burn the per-boot allowance ------------------------------
    // Both ports keep a volatile consecutive-failure counter and refuse
    // once it reaches 3. The guard is evaluated on entry, before a retry
    // is spent, so the refusal surfaces on the *fourth* call rather than
    // as the answer to the third. Whether the third wrong PIN should
    // itself answer 0x34 is a reading of CTAP 2.1 sec. 6.5.5.6 that the two
    // obvious readings disagree on, and it is not the property worth
    // pinning a test to. The invariant that matters is the budget:
    //
    //   at most 3 persistent retries are spendable per power cycle,
    //   and the attempt that trips the block costs nothing.
    //
    // That is what an attacker holding the token runs into, and it holds
    // under either reading. So: attempt up to 4 times, and measure.
    const SOFT_BLOCK_AT: u32 = 3;
    println!("\n  wrong PIN attempts, until the device refuses:");
    let mut blocked_at = None;
    for n in 1..=SOFT_BLOCK_AT + 1 {
        match try_pin(&dev, WRONG_PIN) {
            Ok(()) => fail("a deliberately wrong PIN was ACCEPTED"),
            Err(Status::PinInvalid) => println!("    {n}: pinInvalid (0x31)"),
            Err(Status::PinAuthBlocked) => {
                println!("    {n}: pinAuthBlocked (0x34) -- per-boot block engaged");
                blocked_at = Some(n);
                break;
            }
            Err(Status::PinBlocked) => {
                fail("the device hard-blocked -- its retry budget is exhausted")
            }
            Err(s) => fail(&format!("wrong PIN answered {s:?} (0x{:02x})", s as u8)),
        }
    }

    let burned = retries(&dev);
    println!("  after the block:            {}", describe(&burned));

    let blocked_at = match blocked_at {
        Some(n) => n,
        None => fail(&format!(
            "the device never refused: {} consecutive wrong PINs all answered \
             pinInvalid. Without a per-power-cycle block the whole retry budget \
             can be spent in one uninterrupted session.",
            SOFT_BLOCK_AT + 1
        )),
    };

    // The blocked attempt must not have cost a retry -- otherwise the
    // block is a speed bump that still drains the budget.
    let spent = start.retries - burned.retries;
    if spent != SOFT_BLOCK_AT as u64 {
        fail(&format!(
            "{blocked_at} wrong PINs spent {spent} persistent retries, expected \
             {SOFT_BLOCK_AT} (was {}, now {}). Either a blocked attempt is still \
             charging the budget, or the charge is not landing at all.",
            start.retries, burned.retries
        ));
    }
    println!("    {spent} retries spent over {blocked_at} attempts -- the blocked one was free");

    // Once blocked, it must stay blocked for the rest of the boot: a
    // fresh ECDH handshake must not talk the device back into answering.
    // Each attempt above already established a new session, but say it
    // explicitly, because "re-key to clear the block" is exactly the
    // bypass a per-session counter would have.
    match try_pin(&dev, WRONG_PIN) {
        Err(Status::PinAuthBlocked) => {
            println!("    still blocked after a fresh key agreement")
        }
        Err(Status::PinInvalid) => fail(
            "a fresh key agreement cleared the per-boot block. The counter is \
             per-session, not per-power-cycle, so the block is bypassable by \
             re-running getKeyAgreement between guesses.",
        ),
        Ok(()) => fail("a deliberately wrong PIN was ACCEPTED while blocked"),
        Err(s) => fail(&format!(
            "blocked device answered {s:?} (0x{:02x})",
            s as u8
        )),
    }
    // And a *correct* PIN must not clear it either, while blocked.
    match try_pin(&dev, &pin) {
        Err(Status::PinAuthBlocked) => {
            println!("    the correct PIN is refused too, while blocked")
        }
        Ok(()) => fail(
            "the correct PIN was accepted while the device was supposed to be \
             blocked. The block only stops wrong guesses, which is not what it \
             is for: it exists to force a power cycle.",
        ),
        Err(s) => fail(&format!(
            "blocked device answered {s:?} (0x{:02x}) to the correct PIN",
            s as u8
        )),
    }
    let still = retries(&dev);
    if still.retries != burned.retries {
        fail(&format!(
            "attempts made while blocked still charged the budget: {} -> {}",
            burned.retries, still.retries
        ));
    }
    // The block is now the device's whole answer to every PIN operation,
    // so it has to be visible on the wire. CTAP 2.1 sec. 6.5.5 gives
    // getPinRetries key 0x04 for exactly this; without it a client sees
    // a healthy-looking retry count next to a blanket 0x34 and has
    // nothing to tell the user except to keep guessing.
    if still.power_cycle_state != Some(true) {
        fail(
            "the device is refusing every PIN but getPinRetries does not report \
             powerCycleState=true (key 0x04). A conformant client has no way to \
             learn that the fix is a replug rather than another attempt.",
        );
    }
    println!("    getPinRetries reports powerCycleState=true");

    // ---- 3. the reset ------------------------------------------------
    println!("\n  resetting the token...");
    if manual {
        drop(dev);
        manual_cycle();
    } else {
        reset_token(dev);
    }
    let dev = open_waiting();

    // ---- 4. what survived, and what did not --------------------------
    let after = retries(&dev);
    println!("  after the reset:            {}", describe(&after));

    if after.retries != burned.retries {
        fail(&format!(
            "THE RETRY COUNTER DID NOT SURVIVE THE RESET: {} before, {} after. \
             The counter is not reaching flash, so the {}-attempt budget is \
             really {}-per-power-cycle -- unlimited to anyone holding the token.",
            burned.retries, after.retries, start.retries, start.retries
        ));
    }
    println!(
        "    persistent counter survived (still {} left)",
        after.retries
    );

    if after.power_cycle_state.unwrap_or(false) {
        fail(
            "THE SOFT BLOCK SURVIVED THE RESET. It is supposed to be per-power-\
             cycle state. A user who mistypes three times would have to spend \
             real retries to recover, and a reset would not help them.",
        );
    }
    println!("    per-boot soft block cleared");

    // ---- 5. the PIN itself still works -------------------------------
    // Proves the stored hash persisted too, not just the counter, and
    // that a success resets the budget on the far side of a reboot.
    match try_pin(&dev, &pin) {
        Ok(()) => println!("\n  correct PIN accepted after the reset"),
        Err(Status::PinInvalid) => fail(
            "the correct PIN was refused after a reset -- the stored PIN hash did \
             not survive, or was rewritten by the failed attempts",
        ),
        Err(Status::PinAuthBlocked) => fail(
            "the device was still soft-blocked when a correct PIN was offered, \
             even though getPinRetries said otherwise",
        ),
        Err(s) => fail(&format!(
            "the correct PIN answered {s:?} (0x{:02x})",
            s as u8
        )),
    }

    let restored = retries(&dev);
    println!("  after the correct PIN:      {}", describe(&restored));
    if restored.retries != start.retries {
        fail(&format!(
            "a correct PIN did not restore the full budget across a reset: {} of \
             {} -- the reset-on-success write is not landing in flash",
            restored.retries, start.retries
        ));
    }

    println!(
        "\nPASS -- the counter and the PIN hash reached flash, the per-boot block \
         cleared on reset, and a success restored the budget."
    );
}
