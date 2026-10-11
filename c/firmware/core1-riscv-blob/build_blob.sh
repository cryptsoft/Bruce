#!/usr/bin/env bash
# build_blob.sh -- cross-compile the RISC-V core-1 signing blob to a flat
# binary for embedding in the Arm image (C port mixed mode).
#
# Usage: build_blob.sh <riscv-gcc> <riscv-objcopy> <firmware-dir> <out.bin>
#
# Standalone of the pico-sdk build: the blob links against its own tiny
# runtime (blob_start.S + blob_main.c) + newlib/libgcc via nosys.specs,
# NOT pico-sdk. The crypto is the C port's own openssl-mini, the exact
# same sources core 0 compiles for Arm -- so a signature is byte-identical
# whichever core produced it. Invoked by CMake at build time; can also be
# run by hand to sanity-check the blob in isolation.
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

CC="${1:?riscv gcc path}"
OBJCOPY="${2:?riscv objcopy path}"
FW="${3:?firmware dir}"
OUT="${4:?output .bin path}"
# Hybrid ML-DSA level (44/65/87). MUST match the Arm image's
# PQF_HYBRID_VARIANT -- the mailbox/signature-buffer sizes in
# core1_mailbox.h depend on it, and the two link units share that ABI.
VARIANT="${5:-65}"
# ML-DSA streaming-A policy (0 off / 1 on / 2 auto). MUST match the Arm
# image's PQF_MLDSA_LOWMEM: it only changes how much heap the signing
# loop asks for, but the blob's arena is sized against that figure.
LOWMEM="${6:-2}"

BLOB="$FW/core1-riscv-blob"
OM="$FW/openssl-mini"
ELF="${OUT%.bin}.elf"

# Hazard3 ISA: rv32imac + Zicsr/Zifencei + the Zb* bitmanip/crypto
# subsets the RP2350 Hazard3 implements. Must match a toolchain multilib
# (newlib + libgcc); verified against the riscv32-unknown-elf GCC 15.
ARCH="-march=rv32imac_zicsr_zifencei_zba_zbb_zbkb_zbs -mabi=ilp32"

# -w: the vendored openssl-mini emits the same warnings the Arm build
#     silences per-file; the blob compiles the whole set at once.
# -ffreestanding -fno-pic -fno-builtin -fno-common: bare-metal, position-
#     dependent (it runs at a fixed XIP address), no implicit libcalls.
# -mstrict-align: Hazard3 traps on ANY misaligned scalar access
#     (mcause 4/6), but this GCC's default model is
#     __riscv_misaligned_slow ("supported, just slow") -- under which
#     GCC itself may emit unchecked word accesses. The prebuilt newlib
#     has the same flaw baked in; pqf_align_str.c (in SRCS below)
#     replaces the two functions disassembly-confirmed unsafe
#     (memcmp/strcmp) -- the silicon-confirmed cause of the "random"
#     RISC-V freezes, and the leading explanation for this blob's
#     previously-observed random signing failures.
CF="-O2 -w -ffreestanding -fno-pic -fno-builtin -fno-common \
    -mstrict-align \
    -DPQF_HYBRID_VARIANT=$VARIANT \
    -DPQF_MLDSA_LOWMEM=$LOWMEM \
    -ffunction-sections -fdata-sections -std=gnu11"

INC="-I $FW/src -I $OM/include -I $OM/src -I $OM/src/bn -I $OM/src/ec -I $OM/src/ml_dsa"

# Crypto sources: hybrid_sign() + BN/EC/ML-DSA + the SHA/SHAKE/AES/EVP
# primitives it pulls in. NOT pqf_rand (the blob has its own TRNG
# RAND_bytes) nor the PIN/HKDF/HMAC/AES adapters (signing doesn't use
# them) -- the standalone link confirms the set is closed.
SRCS=(
    "$BLOB/blob_start.S"
    "$BLOB/blob_main.c"
    "$BLOB/blob_alloc.c"
    "$FW/src/hybrid.c"
    "$FW/src/pqf_align_str.c"
    "$OM"/src/bn/*.c
    "$OM"/src/ec/*.c
    "$OM"/src/ml_dsa/*.c
    "$OM/src/sha256.c"
    "$OM/src/sha512.c"
    "$OM/src/sha3.c"
    "$OM/src/keccak1600.c"
    "$OM/src/aes_core.c"
    "$OM/src/pqf_sha256.c"
    "$OM/src/pqf_evp.c"
    "$OM/src/packet.c"
    "$OM/src/buffer.c"
)

echo "[blob] $CC $ARCH"
# shellcheck disable=SC2086
"$CC" $ARCH $CF $INC \
    -nostartfiles -T "${PQF_BLOB_LD:-$BLOB/blob.ld}" -Wl,--gc-sections \
    -o "$ELF" "${SRCS[@]}" \
    --specs=nosys.specs -lc -lgcc -lm

"$OBJCOPY" -O binary "$ELF" "$OUT"
echo "[blob] wrote $OUT ($(wc -c < "$OUT") bytes)"
