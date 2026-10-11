// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// PQF_APP_OFFSET selects the blob's flash window (see src/mixed.rs
// BLOB_FLASH_ORIGIN). Without this, changing the variable would not
// rebuild the crate and the constant would silently disagree with the
// linker scripts.
fn main() {
    println!("cargo:rerun-if-env-changed=PQF_APP_OFFSET");
}
