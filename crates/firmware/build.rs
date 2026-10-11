// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// build.rs -- linker-script plumbing, plus (for the mixed-architecture
// `core1_riscv` feature) cross-compiling the RISC-V core-1 payload.
//
// ## Linker scripts
//
// Arm build: cortex-m-rt's `link.x` does `INCLUDE memory.x` to pull in
// the chip-specific memory map. For ld / rust-lld to resolve that, the
// directory containing `memory.x` must be on the linker's search path,
// so we copy it into OUT_DIR and emit `cargo:rustc-link-search`. Which
// file becomes OUT_DIR/memory.x depends on the build: the plain
// `memory.x`, or `memory_core1riscv.x` when the `core1_riscv` feature
// carves out the core-1 blob windows.
//
// RISC-V build: there is no `link.x`+`memory.x` split -- the whole
// layout lives in our self-contained `rp235x_riscv.x` (passed via
// `-Trp235x_riscv.x` in `.cargo/config.toml`). Same OUT_DIR trick.
//
// ## The core-1 payload (feature `core1_riscv`)
//
// The mixed-architecture build embeds a standalone riscv32imac binary
// for core 1. We build it here so `cargo build -F core1_riscv` stays a
// one-step build:
//
//   1. `cargo build` the `pqf-core1-riscv` workspace member for
//      riscv32imac-unknown-none-elf, with its own RUSTFLAGS (blob.x
//      linker script -- CARGO_ENCODED_RUSTFLAGS overrides the
//      workspace .cargo/config.toml riscv flags) and its own
//      --target-dir under OUT_DIR (a nested cargo may not touch the
//      parent's target dir -- the lock is held).
//   2. llvm-objcopy (from the pinned toolchain's llvm-tools) the ELF
//      to a flat binary in OUT_DIR.
//   3. core1_launch.rs `include_bytes!`s it into the `.core1_blob`
//      section, which memory_core1riscv.x pins at the launch address.
//
// The ML-DSA level feature is forwarded so the blob's mailbox layout
// (sized by MLDSA_SIG_LEN) always matches the firmware's.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // Both Feitian features are the same die in a different case (the
    // USB-C token re-exports the dev board's profile), so the flash
    // bound below applies to either.
    let feitian = env::var_os("CARGO_FEATURE_BOARD_FEITIAN_RP2350").is_some()
        || env::var_os("CARGO_FEATURE_BOARD_FEITIAN_RP2350_USBC").is_some();
    let core1_riscv = env::var_os("CARGO_FEATURE_CORE1_RISCV").is_some();

    // --- memory map selection -----------------------------------------
    let memory_x: &[u8] = if core1_riscv {
        include_bytes!("memory_core1riscv.x")
    } else {
        include_bytes!("memory.x")
    };
    // --- DFU app slot relocation --------------------------------------
    // PQF_APP_OFFSET=1 relocates the linked FLASH region into the DFU
    // bootloader's app slot, mirroring the C port's option of the same
    // name. The origin/length track PQF_APP_IMAGE_OFF / PQF_IMAGE_MAX_LEN
    // in c/common/pqf_image.h -- keep them in lockstep.
    //
    // The default 0x10000000 origin is for a standalone image the bootrom
    // starts directly; an image the DFU bootloader installs runs from the
    // app slot instead and must be linked for it, or it branches into the
    // wrong addresses the moment it is chain-loaded.
    // The Feitian RP2350 carries a 2 MiB die; memory.x declares 4096K for
    // the Tiny 2350. Overstating flash does not overflow, it ALIASES --
    // the mechanism that had the DFU staging slot erasing the
    // bootloader's own vector table (see c/common/pqf_image.h). Nothing
    // currently links past ~1 MiB so this is latent rather than live, but
    // it costs nothing to bound the region to the real device. Scoped to
    // the one board whose size has actually been measured; every other
    // board keeps its declared length.
    let memory_x_owned;
    let memory_x: &[u8] = if env::var_os("PQF_APP_OFFSET").is_some() {
        let text = String::from_utf8_lossy(memory_x);
        let mut out_text = String::with_capacity(text.len());
        for line in text.lines() {
            if line.trim_start().starts_with("FLASH : ORIGIN") {
                // A mixed image also carries the blob, so core 0 stops
                // where the relocated blob window begins.
                out_text.push_str(if core1_riscv {
                    "    FLASH : ORIGIN = 0x10021000, LENGTH = 508K /* up to the blob window */"
                } else {
                    "    FLASH : ORIGIN = 0x10021000, LENGTH = 944K /* pqf app slot (pqf_image.h) */"
                });
            } else if line.trim_start().starts_with("BLOB  : ORIGIN") {
                // 0x10180000 is 1.5 MiB up, outside the DFU app slot, so
                // a mixed image could not be installed over DFU at all.
                // 128K is ample for the ~78 KiB blob. Must agree with
                // signer-core BLOB_FLASH_ORIGIN and fw-core1-riscv/blob.x.
                out_text
                    .push_str("    BLOB  : ORIGIN = 0x100A0000, LENGTH = 128K /* pqf app slot */");
            } else {
                out_text.push_str(line);
            }
            out_text.push('\n');
        }
        memory_x_owned = out_text.into_bytes();
        println!("cargo:warning=PQF_APP_OFFSET -- linking into the DFU app slot at 0x10021000");
        &memory_x_owned
    } else if feitian && !core1_riscv {
        let text = String::from_utf8_lossy(memory_x);
        let mut out_text = String::with_capacity(text.len());
        for line in text.lines() {
            if line.trim_start().starts_with("FLASH : ORIGIN") {
                out_text.push_str(
                    "    FLASH : ORIGIN = 0x10000000, LENGTH = 2048K \
/* Feitian: measured 2 MiB die, not the pico2 default */",
                );
            } else {
                out_text.push_str(line);
            }
            out_text.push('\n');
        }
        memory_x_owned = out_text.into_bytes();
        &memory_x_owned
    } else {
        memory_x
    };

    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(memory_x)
        .unwrap();

    // --- discoverable-credential overflow sectors -----------------------
    // PQF_RESIDENT_EXTRA_SECTORS=N adds N sectors of 7 discoverable
    // credentials each below the master-key sector (flash_store.rs reads
    // the same variable with option_env! and sizes the store from it).
    // Here: validate it before anything compiles, and hand every linker
    // script the sector count to reserve, so the image-overlap ASSERT
    // grows with the store. 8 is flash_store::MAX_RESIDENT_EXTRA_SECTORS
    // -- the RAM bound, since every slot is held in RAM.
    let extra_sectors: u32 = match env::var("PQF_RESIDENT_EXTRA_SECTORS") {
        Err(_) => 0,
        Ok(v) if v.is_empty() => 0,
        Ok(v) => match v.parse::<u32>() {
            Ok(n) if n <= 8 => n,
            _ => panic!("PQF_RESIDENT_EXTRA_SECTORS must be a number from 0 to 8 (got {v:?})"),
        },
    };
    // The DFU flash map (c/common/pqf_image.h) puts its install journal
    // and staging slot directly below the persisted sectors, which is
    // where the overflow sectors would go. Refuse the combination rather
    // than let a DFU update erase passkeys, or a passkey write erase the
    // journal.
    assert!(
        extra_sectors == 0 || env::var_os("PQF_APP_OFFSET").is_none(),
        "PQF_RESIDENT_EXTRA_SECTORS cannot be combined with PQF_APP_OFFSET: \
         the DFU map's boot-state and staging sectors sit where the overflow \
         sectors would go"
    );
    File::create(out.join("pqf_reserve.x"))
        .unwrap()
        .write_all(
            format!(
                "/* Generated by build.rs from PQF_RESIDENT_EXTRA_SECTORS={extra_sectors}: \
the store, large-blob and key sectors plus the overflow sectors. */\n\
_pqf_reserved_sectors = {};\n",
                3 + extra_sectors
            )
            .as_bytes(),
        )
        .unwrap();
    if extra_sectors != 0 {
        println!(
            "cargo:warning=PQF_RESIDENT_EXTRA_SECTORS={extra_sectors} -- {} discoverable credential slots",
            6 + 7 * extra_sectors
        );
    }
    println!("cargo:rerun-if-env-changed=PQF_RESIDENT_EXTRA_SECTORS");
    // The RISC-V target does not use memory.x at all -- its layout lives
    // in rp235x_riscv.x -- so PQF_APP_OFFSET has to relocate this script
    // too, or a riscv image silently keeps linking at 0x10000000 and
    // never chain-loads when the DFU bootloader installs it.
    let riscv_x_owned;
    let riscv_x: &[u8] = {
        let base = include_bytes!("rp235x_riscv.x");
        if env::var_os("PQF_APP_OFFSET").is_some() {
            let text = String::from_utf8_lossy(base);
            let mut o = String::with_capacity(text.len());
            for line in text.lines() {
                if line.trim_start().starts_with("FLASH : ORIGIN") {
                    o.push_str(
                        "    FLASH : ORIGIN = 0x10021000, LENGTH = 944K \
/* pqf app slot (pqf_image.h) */",
                    );
                } else {
                    o.push_str(line);
                }
                o.push('\n');
            }
            riscv_x_owned = o.into_bytes();
            &riscv_x_owned
        } else if feitian {
            let text = String::from_utf8_lossy(base);
            let mut o = String::with_capacity(text.len());
            for line in text.lines() {
                if line.trim_start().starts_with("FLASH : ORIGIN") {
                    o.push_str(
                        "    FLASH : ORIGIN = 0x10000000, LENGTH = 2048K \
/* Feitian: measured 2 MiB die */",
                    );
                } else {
                    o.push_str(line);
                }
                o.push('\n');
            }
            riscv_x_owned = o.into_bytes();
            &riscv_x_owned
        } else {
            base
        }
    };
    File::create(out.join("rp235x_riscv.x"))
        .unwrap()
        .write_all(riscv_x)
        .unwrap();
    // The RISC-V IMAGE_DEF needs an explicit ENTRY_POINT item (main.rs):
    // without one the ROM's default is "start of the enclosing window",
    // which is only right for an image the ROM finds at its own link
    // base. Hand main.rs the link base so the item tracks the layout
    // chosen above.
    println!(
        "cargo:rustc-env=PQF_IMG_BASE={}",
        if env::var_os("PQF_APP_OFFSET").is_some() {
            "0x10021000"
        } else {
            "0x10000000"
        }
    );
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-env-changed=PQF_APP_OFFSET");
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=memory_core1riscv.x");
    println!("cargo:rerun-if-changed=rp235x_riscv.x");
    println!("cargo:rerun-if-changed=build.rs");

    // --- mixed-architecture core-1 payload ------------------------------
    if core1_riscv {
        let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        assert_eq!(
            target_arch, "arm",
            "the `core1_riscv` feature is the MIXED-architecture mode (Arm \
             core 0 + RISC-V core 1) and only makes sense on the Arm target; \
             for an all-RISC-V device just build --target \
             riscv32imac-unknown-none-elf without it"
        );
        build_core1_blob(&out);
    }
}

/// Cross-compile crates/fw-core1-riscv and objcopy it to
/// OUT_DIR/core1_blob.bin.
fn build_core1_blob(out: &PathBuf) {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let blob_dir = manifest_dir.parent().unwrap().join("fw-core1-riscv");
    let signer_dir = manifest_dir.parent().unwrap().join("signer-core");
    // Directory-level rerun-if-changed walks recursively, so edits to
    // the payload or the shared worker retrigger this script.
    println!("cargo:rerun-if-changed={}", blob_dir.display());
    println!("cargo:rerun-if-changed={}", signer_dir.display());

    // Forward the ML-DSA level (exactly one is set -- signer-core's
    // compile_error! guards enforce it globally).
    let mldsa = if env::var_os("CARGO_FEATURE_MLDSA44").is_some() {
        "mldsa44"
    } else if env::var_os("CARGO_FEATURE_MLDSA87").is_some() {
        "mldsa87"
    } else {
        "mldsa65"
    };

    let blob_target_dir = out.join("core1-blob-target");
    let cargo = env::var_os("CARGO").unwrap();
    // The blob's own link flags. \x1f is CARGO_ENCODED_RUSTFLAGS's
    // separator; this env var outranks every config-file rustflags
    // source, so the workspace's riscv `-Trp235x_riscv.x` never leaks
    // into the payload link. Keep the target features in sync with
    // .cargo/config.toml's riscv section.
    // The payload links at an absolute address, so relocating the blob
    // window means regenerating its own script too -- otherwise the
    // firmware places the bytes at 0x100A0000 while the blob still
    // expects to execute from 0x10180000.
    let blob_ld_arg = if env::var_os("PQF_APP_OFFSET").is_some() {
        let src = std::fs::read_to_string(blob_dir.join("blob.x")).expect("blob.x");
        let mut o = String::with_capacity(src.len());
        for l in src.lines() {
            if l.trim_start().starts_with("BFLASH : ORIGIN") {
                o.push_str("    BFLASH : ORIGIN = 0x100A0000, LENGTH = 128K");
            } else {
                o.push_str(l);
            }
            o.push('\n');
        }
        std::fs::write(out.join("blob_app.x"), o).unwrap();
        format!("link-arg=-T{}", out.join("blob_app.x").display())
    } else {
        "link-arg=-Tblob.x".to_string()
    };

    let encoded_rustflags = [
        "-C",
        "link-arg=--nmagic",
        "-C",
        &blob_ld_arg,
        "-C",
        "target-feature=+zba,+zbb,+zbs,+zbkb",
    ]
    .join("\x1f");

    let status = Command::new(&cargo)
        .current_dir(&blob_dir)
        .args([
            "build",
            "--release",
            "--target",
            "riscv32imac-unknown-none-elf",
            "--no-default-features",
            "--features",
            mldsa,
        ])
        .arg("--target-dir")
        .arg(&blob_target_dir)
        // Scrub the parent build's flag/target environment so the
        // payload gets exactly the flags above and nothing else.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env_remove("CARGO_BUILD_TARGET")
        .env_remove("CARGO_TARGET_DIR")
        .env("CARGO_ENCODED_RUSTFLAGS", encoded_rustflags)
        .status()
        .expect("spawning nested cargo for the core-1 payload failed");
    assert!(
        status.success(),
        "building the RISC-V core-1 payload (crates/fw-core1-riscv) failed"
    );

    let blob_elf = blob_target_dir.join("riscv32imac-unknown-none-elf/release/pqf-core1-riscv");
    let blob_bin = out.join("core1_blob.bin");

    // llvm-objcopy ships in the toolchain's llvm-tools component
    // (pinned in rust-toolchain.toml).
    let rustc = env::var_os("RUSTC").unwrap();
    let sysroot = Command::new(&rustc)
        .arg("--print")
        .arg("sysroot")
        .output()
        .expect("rustc --print sysroot failed");
    let sysroot = String::from_utf8(sysroot.stdout).unwrap();
    let host = env::var("HOST").unwrap();
    let objcopy = PathBuf::from(sysroot.trim())
        .join("lib/rustlib")
        .join(&host)
        .join("bin/llvm-objcopy");

    let status = Command::new(&objcopy)
        .arg("-O")
        .arg("binary")
        .arg(&blob_elf)
        .arg(&blob_bin)
        .status()
        .expect("spawning llvm-objcopy failed (is the llvm-tools component installed?)");
    assert!(
        status.success(),
        "llvm-objcopy of the core-1 payload failed"
    );
}
