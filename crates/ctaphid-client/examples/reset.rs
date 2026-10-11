// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// Wipe an attached authenticator with authenticatorReset (CTAP 2.1
// sec. 6.5): every credential, the PIN and its retry counter, the
// per-device master keys, the alwaysUv flag. There is no undo.
//
//   cargo run -p pqf-ctaphid --example reset \
//       --target $(rustc -vV | awk '/host/{print $2}') -- [product-substring]
//
// Opens the first FIDO HID device, or the first whose product string
// contains the substring. On a board with a button the firmware wants
// a touch before it wipes, and the spec lets it insist on a recent
// power-up as well: if it answers OperationDenied or UserActionTimeout,
// replug and rerun within ~10 s. Exit 0 on success, 1 on error.

use pqf_ctaphid::{ctap2, hid};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = std::env::args().nth(1);
    let infos = hid::enumerate()?;
    let info = infos
        .iter()
        .find(|d| match &filter {
            Some(sub) => d
                .product
                .as_deref()
                .map_or(false, |p| p.contains(sub.as_str())),
            None => true,
        })
        .ok_or(match &filter {
            Some(sub) => format!("no FIDO HID device whose product contains {sub:?}"),
            None => "no FIDO HID device plugged in".to_string(),
        })?;
    let dev = hid::Device::open(info)?;

    println!(
        "about to wipe {} ({:04x}:{:04x}) at {}",
        info.product.as_deref().unwrap_or("?"),
        info.vendor_id,
        info.product_id,
        info.path
    );
    println!("  every resident credential and every credential id ever issued,");
    println!("  the PIN and its retry counter, the per-device master keys.");
    println!("touch the button now if this board has one...");

    ctap2::reset::reset(&dev)?;
    println!("reset: ok -- the device is factory-fresh");
    Ok(())
}
