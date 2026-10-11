// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// Reboot an attached Bruce token via the vendor command
// CTAPHID_CMD_REBOOT -- the Rust counterpart of c/hid/reboot.c, built on
// hid::Device::reboot().
//
// Run:
//   cargo run -p pqf-ctaphid --example reboot \
//       --target $(rustc -vV | awk '/host/{print $2}') -- [bootsel|warm] [product-substring]
//
//   (no args)      -> BOOTSEL (USB mass storage / DFU), the only token
//   bootsel        -> same
//   warm           -> warm reboot back into the firmware
//   bootsel Tiny   -> pick a token by product-string substring (needed
//   warm Bruce    when several tokens are attached)
//
// User presence: on a build whose board enforces it (Feitian BOOTSEL
// button, Tiny 2350 GP0 capacitive pad) you must press/touch the token
// within ~10 s or the reboot is declined; buttonless /
// PQF_TEST_NO_USER_BUTTON builds reboot immediately. The token drops
// off the bus on success, so this is fire-and-forget (see
// hid::Device::reboot) -- confirm by polling for it to re-appear
// (e.g. `picotool info` for the BOOTSEL device).

use pqf_ctaphid::hid::{self, RebootMode};

// A Bruce token: FIDO product id 0xF1D0 and either the Bruce
// manufacturer string or the placeholder vendor id 0xcafe both firmware
// ports use.
fn is_pqf(d: &hid::DeviceInfo) -> bool {
    d.product_id == 0xF1D0
        && (d
            .manufacturer
            .as_deref()
            .map_or(false, |m| m.contains("Bruce"))
            || d.vendor_id == 0xcafe)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mode_arg = args.next();
    let filter = args.next();

    let (mode, label) = match mode_arg.as_deref() {
        None | Some("bootsel") => (RebootMode::Bootsel, "BOOTSEL (USB mass storage / DFU)"),
        Some("warm") => (RebootMode::Warm, "warm (back into firmware)"),
        Some(other) => {
            eprintln!("usage: reboot [bootsel|warm] [product-substring] (got {other:?})");
            std::process::exit(2);
        }
    };

    // Select the target token. With several attached (a flash station),
    // pass a product-substring to disambiguate; refuse to guess.
    let infos = hid::enumerate()?;
    let mut matches: Vec<&hid::DeviceInfo> = infos
        .iter()
        .filter(|d| is_pqf(d))
        .filter(|d| match &filter {
            Some(sub) => d
                .product
                .as_deref()
                .map_or(false, |p| p.contains(sub.as_str())),
            None => true,
        })
        .collect();

    for d in &matches {
        println!(
            "candidate: {} (vid={:04x} pid={:04x})",
            d.product.as_deref().unwrap_or("?"),
            d.vendor_id,
            d.product_id
        );
    }
    if matches.is_empty() {
        eprintln!("no matching Bruce token found (plugged in and in application mode?)");
        std::process::exit(2);
    }
    if matches.len() > 1 {
        eprintln!(
            "{} tokens match -- pass a product-substring to pick one",
            matches.len()
        );
        std::process::exit(2);
    }

    let info = matches.remove(0);
    let dev = hid::Device::open(info)?;
    println!("sending CMD_REBOOT: {label}");
    dev.reboot(mode)?;
    println!(
        "sent. If this build enforces user presence, PRESS/TOUCH the token \
         NOW (within ~10s); otherwise it reboots immediately."
    );
    Ok(())
}
