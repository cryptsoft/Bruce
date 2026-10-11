// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// End-to-end smoke test against an attached FIDO HID device.
//
//   1. Enumerate FIDO devices.
//   2. Open the first one.
//   3. Confirm the CTAPHID INIT handshake succeeded.
//   4. Round-trip a CTAPHID PING.
//   5. Call `authenticatorGetInfo` and print the result.
//
// Build + run:
//   cargo run -p pqf-ctaphid --example probe \
//       --target $(rustc -vV | awk '/host/{print $2}')

use pqf_ctaphid::{ctap2, hid};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let infos = hid::enumerate()?;
    println!("Found {} FIDO HID device(s):", infos.len());
    for d in &infos {
        println!(
            "  {} {:04x}:{:04x} {:?}",
            d.path, d.vendor_id, d.product_id, d.product
        );
    }
    let info = match infos.first() {
        Some(d) => d,
        None => {
            println!("\nNo FIDO HID device plugged in -- nothing else to do.");
            return Ok(());
        }
    };

    let dev = hid::Device::open(info)?;
    println!(
        "\nINIT ok: cid=0x{:08x} caps=0x{:02x} ver={}.{}.{}",
        dev.cid(),
        dev.capabilities().0,
        dev.firmware_version().0,
        dev.firmware_version().1,
        dev.firmware_version().2,
    );
    let caps = dev.capabilities();
    println!(
        "  caps:  cbor={} wink={} nmsg={}",
        caps.cbor(),
        caps.wink(),
        caps.nmsg()
    );

    // PING -- verifies the framing layer round-trips arbitrary
    // payloads, not just the 8-byte INIT nonce.
    let payload = b"pqf-ctaphid hello, world :)";
    dev.ping(payload)?;
    println!("\nPING echo verified ({} bytes)", payload.len());

    // getInfo -- first real CTAP2 call.
    println!("\nauthenticatorGetInfo:");
    let info = ctap2::get_info::get_info(&dev)?;
    println!("  versions:                  {:?}", info.versions);
    println!("  extensions:                {:?}", info.extensions);
    println!(
        "  aaguid:                    {}",
        info.aaguid
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!("  options:");
    for (k, v) in &info.options {
        println!("    {:30} {}", format!("{k}:"), v);
    }
    if let Some(s) = info.max_msg_size {
        println!("  maxMsgSize:                {s}");
    }
    if let Some(ref p) = info.pin_uv_auth_protocols {
        println!("  pinUvAuthProtocols:        {:?}", p);
    }
    if let Some(s) = info.max_credential_count_in_list {
        println!("  maxCredentialCountInList:  {s}");
    }
    if let Some(s) = info.max_credential_id_length {
        println!("  maxCredentialIdLength:     {s}");
    }
    if let Some(ref t) = info.transports {
        println!("  transports:                {:?}", t);
    }
    if let Some(ref a) = info.algorithms {
        println!("  algorithms:");
        for alg in a {
            println!("    alg={:4}  type={}", alg.alg, alg.credential_type);
        }
    }
    if let Some(s) = info.max_serialized_large_blob_array {
        println!("  maxSerializedLargeBlobArray: {s}");
    }
    if let Some(b) = info.force_pin_change {
        println!("  forcePINChange:            {b}");
    }
    if let Some(s) = info.min_pin_length {
        println!("  minPINLength:              {s}");
    }
    if let Some(s) = info.firmware_version {
        println!("  firmwareVersion:           {s:#010x}");
    }
    if let Some(s) = info.max_cred_blob_length {
        println!("  maxCredBlobLength:         {s}");
    }

    Ok(())
}
