#!/usr/bin/env bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# build-c.sh -- build the C firmware and emit `bruce-c.uf2` at the repo
# root, ready for `./flash.sh bruce-c.uf2`. The C counterpart of
# ./build.sh: same board names, same environment knobs.
#
# Usage:
#   ./build-c.sh                          # default: tiny2350 + mldsa65
#   ./build-c.sh tiny2350
#   ./build-c.sh xiao_rp2350
#   ./build-c.sh feitian_rp2350
#   ./build-c.sh feitian_rp2350_usbc      # sealed USB-C token: CMD_REBOOT
#                                         # needs no touch by default --
#                                         # its power-on BOOTSEL does not
#                                         # work, so that command is its
#                                         # only way back into the
#                                         # bootloader (docs/REBOOT.md)
#   ./build-c.sh waveshare_rp2350_lcd_1_47
#   ./build-c.sh spotpear_rp2350_lcd_1_28
#
#   MLDSA=44 ./build-c.sh                 # ML-DSA-44 instead of 65
#   MLDSA=87 ./build-c.sh
#   REBOOT_NO_UP=1 ./build-c.sh           # CMD_REBOOT needs no touch
#                                         # (flash station; FIDO UP intact;
#                                         # only tiny2350 / feitian_rp2350
#                                         # gate it in the first place)
#   SINGLE_CORE=1 ./build-c.sh            # core 1 asleep; KEEPALIVE from the
#                                         # crypto's own yield hook
#   RISCV=1 ./build-c.sh                  # both cores Hazard3 (needs a
#                                         # riscv32 GCC on PATH or
#                                         # PQF_RISCV_TOOLCHAIN_BIN)
#   RK_SECTORS=3 ./build-c.sh             # 3 extra flash sectors of
#                                         # discoverable credentials: 7 + 7
#                                         # per sector = 28 (0..8, default 0
#                                         # = today's 7); see docs/BUILD.md
#   CMAKE_EXTRA="-DPQF_QRNG=OFF" ./build-c.sh   # anything else, verbatim
#
# Needs (see docs/GETTING-STARTED.md for install commands):
#   - PICO_SDK_PATH pointing at a pico-sdk checkout WITH its tinyusb
#     submodule (default: ~/pico-sdk if it exists)
#   - arm-none-eabi-gcc, cmake >= 3.13, and picotool with the same
#     major.minor as the SDK (the SDK refuses an older one). If yours is
#     older, PICOTOOL_FORCE_FETCH_FROM_GIT=1 lets the SDK build its own
#     copy inside the build directory instead.
#
# Note the raw CMake default board is the Waveshare LCD module; this
# wrapper defaults to the Tiny 2350 so it matches ./build.sh.

set -euo pipefail

BOARD="${1:-tiny2350}"
MLDSA="${MLDSA:-65}"
REBOOT_NO_UP="${REBOOT_NO_UP:-0}"
SINGLE_CORE="${SINGLE_CORE:-0}"
RISCV="${RISCV:-0}"
RK_SECTORS="${RK_SECTORS:-0}"
CMAKE_EXTRA="${CMAKE_EXTRA:-}"

case "$BOARD" in
    tiny2350|xiao_rp2350|feitian_rp2350|feitian_rp2350_usbc|waveshare_rp2350_lcd_1_47|spotpear_rp2350_lcd_1_28)
        ;;
    -h|--help|help)
        sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "build-c.sh: unknown board: $BOARD" >&2
        echo "valid: tiny2350, xiao_rp2350, feitian_rp2350, feitian_rp2350_usbc, waveshare_rp2350_lcd_1_47, spotpear_rp2350_lcd_1_28" >&2
        exit 1
        ;;
esac
case "$MLDSA" in
    44|65|87) ;;
    *) echo "build-c.sh: MLDSA must be 44, 65, or 87 (got: $MLDSA)" >&2; exit 1 ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

# ---- Prerequisites, checked up front so the failure names the cause ----
: "${PICO_SDK_PATH:=$HOME/pico-sdk}"
export PICO_SDK_PATH
if [ ! -f "$PICO_SDK_PATH/pico_sdk_init.cmake" ]; then
    echo "build-c.sh: PICO_SDK_PATH=$PICO_SDK_PATH is not a pico-sdk checkout." >&2
    echo "  git clone -b 2.3.1 https://github.com/raspberrypi/pico-sdk.git ~/pico-sdk" >&2
    echo "  git -C ~/pico-sdk submodule update --init lib/tinyusb" >&2
    exit 1
fi
if [ ! -f "$PICO_SDK_PATH/lib/tinyusb/src/tusb.h" ]; then
    echo "build-c.sh: the pico-sdk at $PICO_SDK_PATH has no TinyUSB (submodule not initialised)." >&2
    echo "  git -C $PICO_SDK_PATH submodule update --init lib/tinyusb" >&2
    exit 1
fi
for tool in cmake picotool; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "build-c.sh: $tool not found on PATH (docs/GETTING-STARTED.md, 'Install the tools')." >&2
        exit 1
    }
done
if [ "$RISCV" = "1" ]; then
    if ! command -v riscv32-unknown-elf-gcc >/dev/null 2>&1 && [ -z "${PQF_RISCV_TOOLCHAIN_BIN:-}" ]; then
        echo "build-c.sh: RISCV=1 needs riscv32-unknown-elf-gcc on PATH, or PQF_RISCV_TOOLCHAIN_BIN=<its bin dir>." >&2
        exit 1
    fi
else
    command -v arm-none-eabi-gcc >/dev/null 2>&1 || {
        echo "build-c.sh: arm-none-eabi-gcc not found on PATH (docs/GETTING-STARTED.md, 'Install the tools')." >&2
        exit 1
    }
fi
# The SDK insists on a picotool of its own major.minor. Say so before
# CMake does, and name the way out.
need=$(sed -n 's/.*picotool_VERSION_REQUIRED \([0-9.]*\).*/\1/p' "$PICO_SDK_PATH/tools/CMakeLists.txt" | head -1)
have=$(picotool version 2>/dev/null | sed -n 's/^picotool v\([0-9.]*\).*/\1/p')
if [ -n "$need" ] && [ -n "$have" ] && [ "${PICOTOOL_FORCE_FETCH_FROM_GIT:-0}" != "1" ]; then
    if [ "${have%.*}" != "${need%.*}" ]; then
        echo "build-c.sh: picotool $have does not match the SDK's required $need (major.minor must agree)." >&2
        echo "  Either upgrade picotool, or let the SDK build its own copy:" >&2
        echo "    PICOTOOL_FORCE_FETCH_FROM_GIT=1 ./build-c.sh $BOARD" >&2
        exit 1
    fi
fi

case "$RK_SECTORS" in
    0|1|2|3|4|5|6|7|8) ;;
    *) echo "build-c.sh: RK_SECTORS must be 0..8 (got: $RK_SECTORS)" >&2; exit 1 ;;
esac

# ---- Configure + build ----
BUILD_DIR="c/firmware/build-${BOARD}"
[ "$RISCV" = "1" ] && BUILD_DIR="${BUILD_DIR}-riscv"
ARGS=(-DPQF_BOARD="$BOARD" -DPQF_HYBRID_VARIANT="$MLDSA")
# ON or OFF, never left out: CMake caches a -D in the build directory,
# so a knob passed only when set would stay ON for every later build of
# the same board -- a REBOOT_NO_UP=1 run would quietly make the next
# plain one ungated too.
if [ "$REBOOT_NO_UP" = "1" ]; then ARGS+=(-DPQF_REBOOT_NO_UP=ON); else ARGS+=(-DPQF_REBOOT_NO_UP=OFF); fi
if [ "$SINGLE_CORE" = "1" ];  then ARGS+=(-DPQF_SINGLE_CORE=ON);  else ARGS+=(-DPQF_SINGLE_CORE=OFF);  fi
# Always passed, 0 included, for the same caching reason.
ARGS+=(-DPQF_RESIDENT_EXTRA_SECTORS="$RK_SECTORS")
[ "$RISCV" = "1" ]        && ARGS+=(-DPQF_PLATFORM=rp2350-riscv)
if [ "${PICOTOOL_FORCE_FETCH_FROM_GIT:-0}" = "1" ]; then
    ARGS+=(-DPICOTOOL_FORCE_FETCH_FROM_GIT=1)
fi
# shellcheck disable=SC2206
[ -n "$CMAKE_EXTRA" ] && ARGS+=($CMAKE_EXTRA)

echo ">> cmake -S c/firmware -B $BUILD_DIR ${ARGS[*]}"
cmake -S c/firmware -B "$BUILD_DIR" "${ARGS[@]}"
echo ">> cmake --build $BUILD_DIR -j"
cmake --build "$BUILD_DIR" -j

UF2_SRC="$BUILD_DIR/bruce_c.uf2"
UF2="bruce-c.uf2"
[ -f "$UF2_SRC" ] || { echo "build-c.sh: expected $UF2_SRC after the build, not found" >&2; exit 1; }
cp "$UF2_SRC" "$UF2"
ls -la "$UF2"
echo "done. board=$BOARD mldsa=$MLDSA single_core=$SINGLE_CORE riscv=$RISCV reboot_no_up=$REBOOT_NO_UP rk_sectors=$RK_SECTORS"
echo "flash with: ./flash.sh $UF2   (board in BOOTSEL)"
