// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Build script for the Non-secure image (Milestone 1).
//!
//! Puts `memory-nonsecure.x` on the linker search path, and points the
//! linker at `libnsclib.a` -- the Secure-gateway veneer import library
//! that `fw-secure`'s build emitted at `target/nsc/`. Linking it lets
//! the NS code call `sg_led_set` (and, later, the real gateways); the
//! calls resolve to SG veneers in the Secure image's NSC region.
//!
//! `fw-secure` must be built first so the archive exists. If it is
//! missing we still emit the search path -- the link will then fail with
//! a clear "cannot find -lnsclib", which is the correct signal to build
//! the Secure image.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out.join("memory.x"), include_bytes!("memory-nonsecure.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());

    // The veneer import library from the Secure build.
    let nsc = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("..")
        .join("..")
        .join("target")
        .join("nsc");
    println!("cargo:rustc-link-search=native={}", nsc.display());
    // Link the veneer import library so `sg_led_set` resolves to the
    // Secure image's SG stub address.
    println!("cargo:rustc-link-lib=static=nsclib");
    println!(
        "cargo:rerun-if-changed={}",
        nsc.join("libnsclib.a").display()
    );

    println!("cargo:rerun-if-changed=memory-nonsecure.x");
    println!("cargo:rerun-if-changed=build.rs");
}
