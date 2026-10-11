#!/usr/bin/env bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# wipe.sh -- erase the whole flash of an RP2350 development board in
# BOOTSEL: the firmware, every resident credential, the master keys and
# the PIN. The factory reset. After it you must flash again.
#
#   ./wipe.sh tiny2350                  # also xiao_rp2350, spotpear_rp2350_lcd_1_28
#   ./wipe.sh waveshare_rp2350_lcd_1_47 # 16 MiB part: an explicit range
#   ./wipe.sh feitian_rp2350                # flash size not in OTP: an explicit range
#   ./wipe.sh -y <board>                # no confirmation prompt (WIPE_YES=1 does the same)
#
# The board name picks the erase that works on that part: `picotool
# erase -a` on the boards whose flash size picotool can read, a ranged
# erase on the two where it cannot (docs/FLASHING.md, "Wiping the
# device"). The Feitian RP2350 USB-C token is refused: tools/flash-usbc.sh
# erases it as part of every flash, and nothing else should.
#
# Before it erases, the script shows the device picotool sees, reads the
# board marker of the image already in flash (`picotool info -a` with no
# file reads it) and refuses when that marker says USB-C token or names
# a different board than you did (WIPE_TRUST_NAME=1 overrides the
# latter, for a stale marker), then asks for confirmation, because it
# erases whatever is in BOOTSEL. It does NOT try to reboot the device
# into BOOTSEL itself -- hold BOOT and tap
# RESET yourself, confirm the `RP2350` mass-storage volume mounts, then
# run this. The `picotool reboot -u -f` path is never used here; it has
# hung a device before.

set -euo pipefail

YES="${WIPE_YES:-0}"
BOARD=""
for arg in "$@"; do
    case "$arg" in
        -h|--help)
            sed -n '/^#   \.\/wipe\.sh /,/^# device"/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        -y|--yes) YES=1 ;;
        -*) echo "wipe.sh: unknown option $arg" >&2; exit 1 ;;
        *) BOARD="$arg" ;;
    esac
done

case "$BOARD" in
    tiny2350|xiao_rp2350|spotpear_rp2350_lcd_1_28)
        ERASE=(picotool erase -a)
        WORDS="the whole flash (4 MiB, size read from the part)" ;;
    waveshare_rp2350_lcd_1_47)
        ERASE=(picotool erase -r 0x10000000 0x11000000)
        WORDS="0x10000000-0x11000000 (16 MiB; picotool cannot read this part's size)" ;;
    feitian_rp2350)
        ERASE=(picotool erase -r 0x10000000 0x10400000)
        WORDS="0x10000000-0x10400000 (4 MiB window; the flash size is not programmed in OTP)" ;;
    feitian_rp2350_usbc)
        echo "wipe.sh: REFUSING. The Feitian RP2350 USB-C token is erased only by tools/flash-usbc.sh," >&2
        echo "  as part of a flash that proves the way back (docs/FLASHING.md, 'The Feitian RP2350 USB-C token')." >&2
        exit 2 ;;
    "")
        echo "wipe.sh: say which board is in BOOTSEL, so the right erase is used:" >&2
        echo "  ./wipe.sh tiny2350 | xiao_rp2350 | spotpear_rp2350_lcd_1_28 | waveshare_rp2350_lcd_1_47 | feitian_rp2350" >&2
        exit 1 ;;
    *)
        echo "wipe.sh: unknown board: $BOARD" >&2
        echo "  valid: tiny2350, xiao_rp2350, spotpear_rp2350_lcd_1_28, waveshare_rp2350_lcd_1_47, feitian_rp2350" >&2
        exit 1 ;;
esac

command -v picotool >/dev/null 2>&1 || {
    echo "wipe.sh: picotool not found on PATH (docs/GETTING-STARTED.md, 'Install the tools')." >&2
    exit 1
}

# ---- Which device? ----
INFO="$(picotool info -a 2>/dev/null)" || INFO=""
# `|| true`: with no device grep matches nothing, and under `set -e` a
# failing command substitution would end the script before it could say so.
DEVICE="$(printf '%s\n' "$INFO" | grep -iE 'chipid|flash size|type:' | sed 's/^ */  /' || true)"
if [ -z "$DEVICE" ]; then
    echo "wipe.sh: no RP2350 in BOOTSEL found. Replug holding BOOT and try again" >&2
    echo "  (docs/GETTING-STARTED.md section 6 has the recipe per board)." >&2
    exit 1
fi
# The image already in flash says which board it was built for; that
# marker outranks the name on the command line, because the name is the
# easy thing to get wrong and the token is the costly thing to erase.
DEV_BOARD_ID="$(printf '%s' "$INFO" | tr -s ' \n' ' ' | sed -n 's/.*pqf-board=\([A-Za-z0-9_-]*\).*/\1/p')"
echo "device in BOOTSEL:"
echo "$DEVICE"
case "$DEV_BOARD_ID" in
    *usbc*)
        echo "  current image: built for the RP2350 USB-C token"
        echo "wipe.sh: REFUSING. The board in BOOTSEL carries a USB-C token image. If it is a" >&2
        echo "  real token, only tools/flash-usbc.sh may erase it; if it is a development board" >&2
        echo "  that rehearsed a USB-C image, put a development image on it with flash.sh first." >&2
        exit 2 ;;
    "")
        echo "  current image: no readable marker (blank, or an image not from this tree)" ;;
    "$BOARD")
        echo "  current image: built for $BOARD, as named" ;;
    *)
        echo "  current image: built for $DEV_BOARD_ID"
        if [ "${WIPE_TRUST_NAME:-0}" != "1" ]; then
            echo "wipe.sh: REFUSING. You named $BOARD but the board carries an image built for" >&2
            echo "  $DEV_BOARD_ID. Run ./wipe.sh $DEV_BOARD_ID, or, if that marker is stale," >&2
            echo "  WIPE_TRUST_NAME=1 ./wipe.sh $BOARD." >&2
            exit 2
        fi ;;
esac
echo "board named:   $BOARD"
echo "erase:         $WORDS"
echo "this removes the firmware, every credential, the master keys and the PIN."

if [ "$YES" != "1" ]; then
    if [ -t 0 ]; then
        printf '\nErase it? [y/N] '
        read -r answer
        case "$answer" in
            y|Y|yes|YES) ;;
            *) echo "wipe.sh: nothing erased."; exit 3 ;;
        esac
    else
        echo "wipe.sh: no terminal to confirm on; pass -y to erase without a prompt." >&2
        exit 3
    fi
fi

echo ">> ${ERASE[*]}"
if ! "${ERASE[@]}"; then
    echo "wipe.sh: picotool erase failed. If the device dropped off the bus, replug it" >&2
    echo "  holding BOOT and run this again; the flash is in an unknown state until an erase completes." >&2
    exit 1
fi
echo "done. flash is blank -- run ./flash.sh next to put firmware back."
