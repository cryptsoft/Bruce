// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// PIN-protocol smoke test against a wiped device.
//
//   1. Enumerate + open the first FIDO HID device.
//   2. getInfo -- confirm clientPin is supported and currently
//      false (= PIN not set).
//   3. Run getPinRetries -- should report the device's initial
//      retry budget (8 for Bruce firmware).
//   4. Establish a PIN-protocol-v2 session.
//   5. setPin with a fixed test PIN.
//   6. getPinRetries again -- should still be 8 (PIN setting
//      doesn't burn a retry).
//   7. Use getPinUvAuthTokenUsingPinWithPermissions to mint a
//      pinUvAuthToken -- proves the encrypt / decrypt / HMAC path
//      works end-to-end. Caller can then use the token for
//      MakeCredential / GetAssertion.
//
// Run with the device wiped, otherwise step 5 will fail (setPin
// requires PIN-currently-unset).
//
// Build + run:
//   cargo run -p pqf-ctaphid --example pin_set \
//       --target $(rustc -vV | awk '/host/{print $2}')

use pqf_ctaphid::ctap2::client_pin::permission;
use pqf_ctaphid::ctap2::pin_protocol::Protocol;
use pqf_ctaphid::{ctap2, hid};

const TEST_PIN: &[u8] = b"1234";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let info = hid::enumerate()?
        .into_iter()
        .next()
        .ok_or("no FIDO HID device plugged in")?;
    println!(
        "Opening {} ({:04x}:{:04x})",
        info.path, info.vendor_id, info.product_id
    );
    let dev = hid::Device::open(&info)?;
    println!("INIT ok: cid=0x{:08x}", dev.cid());

    let info = ctap2::get_info::get_info(&dev)?;
    let pin_set = info.pin_set();
    println!(
        "Device PIN state: pin_set={pin_set} (clientPin option = {:?})",
        info.option("clientPin")
    );

    let r = ctap2::client_pin::get_pin_retries(&dev)?;
    println!(
        "getPinRetries: retries={} power_cycle_state={:?}",
        r.retries, r.power_cycle_state
    );

    if pin_set {
        println!(
            "\nDevice already has a PIN set. This example only exercises setPin on a wiped \
             device; rerun after `picotool erase -a` + reflash if you want to test the setPin \
             path."
        );
        return Ok(());
    }

    println!("\nEstablishing PIN protocol v2 session...");
    let session = ctap2::client_pin::establish_session(&dev, Protocol::V2)?;
    println!("  ECDH complete, shared secret derived");

    println!("setPin (new PIN = {:?})...", std::str::from_utf8(TEST_PIN)?);
    ctap2::client_pin::set_pin(&dev, &session, TEST_PIN)?;
    println!("  ok");

    let r = ctap2::client_pin::get_pin_retries(&dev)?;
    println!(
        "getPinRetries (after setPin): retries={} power_cycle_state={:?}",
        r.retries, r.power_cycle_state
    );

    println!("\nMinting pinUvAuthToken (MakeCred + GetAssert permissions, rpId=test.local)...");
    let session = ctap2::client_pin::establish_session(&dev, Protocol::V2)?;
    let auth = ctap2::client_pin::get_pin_uv_auth_token_using_pin(
        &dev,
        session,
        TEST_PIN,
        permission::MAKE_CREDENTIAL | permission::GET_ASSERTION,
        Some("test.local"),
    )?;
    println!(
        "  pinUvAuthToken received: {} bytes, protocol={:?}",
        auth.token().len(),
        auth.protocol,
    );

    // Demonstrate sign() -- exactly the call MakeCredential would
    // make over the clientDataHash to populate `pinUvAuthParam`.
    let dummy_client_data_hash = [0x42u8; 32];
    let sig = auth.sign(&dummy_client_data_hash)?;
    println!(
        "  HMAC over dummy client_data_hash: {} bytes ({})",
        sig.len(),
        sig.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    );

    Ok(())
}
