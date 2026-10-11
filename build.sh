#!/usr/bin/env bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# build.sh -- build the Rust firmware and emit `bruce.uf2` at the
# repo root, ready for `./flash.sh`.
#
# Usage:
#   ./build.sh                            # default: tiny2350 + mldsa65
#   ./build.sh tiny2350
#   ./build.sh xiao_rp2350
#   ./build.sh feitian_rp2350
#   ./build.sh feitian_rp2350_usbc        # sealed USB-C token: no power-on
#                                         # BOOTSEL, so CMD_REBOOT needs no touch
#                                         # on this board by default (FIDO UP
#                                         # intact); flash only per
#                                         # docs/FLASHING.md (USB-C token)
#   ./build.sh waveshare_rp2350_lcd_1_47
#   ./build.sh spotpear_rp2350_lcd_1_28
#
#   MLDSA=44 ./build.sh                   # ML-DSA-44 instead of 65
#   MLDSA=87 ./build.sh
#   ED25519=1 ./build.sh                  # extra Ed25519 algorithm
#   REBOOT_NO_UP=1 ./build.sh             # CMD_REBOOT needs no touch
#                                         # (flash station; FIDO UP intact).
#                                         # Only changes tiny2350 and
#                                         # feitian_rp2350; no other board
#                                         # asks for one anyway
#   SINGLE_CORE=1 ./build.sh              # core 1 asleep; KEEPALIVE from a
#                                         # timer interrupt while core 0 signs
#   RK_SECTORS=3 ./build.sh               # 3 extra flash sectors of
#                                         # discoverable credentials: 6 + 7
#                                         # per sector = 27 (0..8, default 0
#                                         # = today's 6). Enlarging keeps the
#                                         # PIN and every passkey; see
#                                         # docs/BUILD.md before shrinking
#   USB_PRODUCT="Example USB-C PQC" ./build.sh feitian_rp2350_usbc
#                                         # USB product string instead of the
#                                         # board's (printable ASCII, up to 64
#                                         # characters); unset = the board's
#
# The Rust firmware lives under `crates/firmware/`; this script wraps
# `cargo build --release -p bruce` with the right feature flags and
# then runs `picotool uf2 convert` on the resulting ELF.

set -euo pipefail

# ---- Defaults ----
# Default board matches Cargo.toml's default feature set and the README:
# the Pimoroni Tiny 2350 is the reference board the firmware ships against.
BOARD="${1:-tiny2350}"
MLDSA="${MLDSA:-65}"
ED25519="${ED25519:-0}"
REBOOT_NO_UP="${REBOOT_NO_UP:-0}"
SINGLE_CORE="${SINGLE_CORE:-0}"
RK_SECTORS="${RK_SECTORS:-0}"
USB_PRODUCT="${USB_PRODUCT:-}"

case "$BOARD" in
    tiny2350|xiao_rp2350|feitian_rp2350|feitian_rp2350_usbc|waveshare_rp2350_lcd_1_47|spotpear_rp2350_lcd_1_28)
        ;;
    -h|--help|help)
        sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "build.sh: unknown board: $BOARD" >&2
        echo "valid: tiny2350, xiao_rp2350, feitian_rp2350, feitian_rp2350_usbc, waveshare_rp2350_lcd_1_47, spotpear_rp2350_lcd_1_28" >&2
        exit 1
        ;;
esac

case "$MLDSA" in
    44|65|87) ;;
    *)
        echo "build.sh: MLDSA must be 44, 65, or 87 (got: $MLDSA)" >&2
        exit 1
        ;;
esac

case "$RK_SECTORS" in
    0|1|2|3|4|5|6|7|8) ;;
    *)
        echo "build.sh: RK_SECTORS must be 0..8 (got: $RK_SECTORS)" >&2
        exit 1
        ;;
esac
# Always exported, 0 included: build.rs reruns when the value changes,
# so a default build after an RK_SECTORS=3 one really is a default build.
export PQF_RESIDENT_EXTRA_SECTORS="$RK_SECTORS"
# Likewise always exported, empty included: empty means the board's own
# name, so a default build after a USB_PRODUCT one gets that name back.
# The firmware checks the value at compile time (main.rs, USB_PRODUCT).
export PQF_USB_PRODUCT="$USB_PRODUCT"

FEATURES="mldsa${MLDSA},board_${BOARD}"
if [ "$ED25519" = "1" ]; then
    FEATURES="${FEATURES},ed25519"
fi
if [ "$REBOOT_NO_UP" = "1" ]; then
    FEATURES="${FEATURES},reboot_no_up"
fi
if [ "$SINGLE_CORE" = "1" ]; then
    FEATURES="${FEATURES},single_core"
fi

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

echo ">> PQF_RESIDENT_EXTRA_SECTORS=$RK_SECTORS${USB_PRODUCT:+ PQF_USB_PRODUCT=\"$USB_PRODUCT\"} cargo build --release -p bruce --no-default-features --features $FEATURES"
cargo build --release -p bruce --no-default-features --features "$FEATURES"

ELF="target/thumbv8m.main-none-eabihf/release/bruce"
UF2="bruce.uf2"

if [ ! -f "$ELF" ]; then
    echo "build.sh: expected $ELF after cargo build, not found" >&2
    exit 1
fi

echo ">> picotool uf2 convert $ELF $UF2 --family rp2350-arm-s"
picotool uf2 convert -t elf "$ELF" "$UF2" --family rp2350-arm-s

ls -la "$UF2"
echo "done. board=$BOARD mldsa=$MLDSA ed25519=$ED25519 single_core=$SINGLE_CORE rk_sectors=$RK_SECTORS${USB_PRODUCT:+ usb_product=\"$USB_PRODUCT\"}"
