// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Build script for the Secure image (Milestone 1).
//!
//! Two jobs:
//!   1. Put `memory-secure.x` (our S/NSC/NS memory map) on the linker
//!      search path, the standard cortex-m-rt `INCLUDE memory.x` way.
//!   2. Emit the CMSE import library -- `libnsclib.a`, a table of the
//!      Secure-gateway veneer addresses -- so the Non-secure crate can
//!      link against `sg_led_set` et al. without knowing our internal
//!      symbol layout. This is the `--out-implib` half of the CMSE
//!      build flow (see docs/TRUSTZONE.md); the NS crate's build.rs
//!      copies the archive out of here via a fixed path.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    // 1. memory-secure.x -> OUT_DIR, and OUT_DIR onto the link search path.
    fs::write(out.join("memory.x"), include_bytes!("memory-secure.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory-secure.x");
    println!("cargo:rerun-if-changed=build.rs");

    // 2. CMSE import library. `--cmse-implib` tells the linker the
    //    output is (also) a secure import lib; `--out-implib` names it.
    //    We drop it at a stable path a sibling crate can find rather
    //    than deep inside this crate's OUT_DIR hash.
    let implib = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("..")
        .join("..")
        .join("target")
        .join("nsc")
        .join("libnsclib.a");
    fs::create_dir_all(implib.parent().unwrap()).unwrap();
    println!("cargo:rustc-link-arg=--cmse-implib");
    println!("cargo:rustc-link-arg=--out-implib={}", implib.display());
    // Pin the veneer section at the NSC window base (top of the Secure
    // FLASH region). lld synthesizes `.gnu.sgstubs` too late for the
    // linker script to place it, so give it a fixed address here.
    println!("cargo:rustc-link-arg=--section-start=.gnu.sgstubs=0x100F0000");
}
