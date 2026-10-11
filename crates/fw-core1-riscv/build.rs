// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// build.rs -- make `blob.x` discoverable to the linker (the firmware's
// build.rs passes `-C link-arg=-Tblob.x` when it cross-compiles this
// crate). Same OUT_DIR copy trick as the firmware's own scripts.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let blob_x = include_bytes!("blob.x");
    File::create(out.join("blob.x"))
        .unwrap()
        .write_all(blob_x)
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=blob.x");
    println!("cargo:rerun-if-changed=build.rs");
}
