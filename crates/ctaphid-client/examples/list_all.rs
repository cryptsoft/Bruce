// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Every HID device on the bus, FIDO or not -- for working out why a
//! token is not being seen.
//!
//! Goes through `hid::list_all` rather than building its own
//! `hidapi::HidApi`: all hidapi use in this crate is confined to one
//! worker thread, and a second context created here would defeat that.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for d in pqf_ctaphid::hid::list_all()? {
        println!(
            "{:04x}:{:04x} usage_page=0x{:04x} usage=0x{:04x} path={:?} product={}",
            d.vendor_id,
            d.product_id,
            d.usage_page,
            d.usage,
            d.path,
            d.product.unwrap_or_default()
        );
    }
    Ok(())
}
