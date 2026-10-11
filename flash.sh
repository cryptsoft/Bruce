#!/usr/bin/env bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# flash.sh -- load a built UF2 onto an RP2350 development board in
# BOOTSEL, after saying which board the image is for and checking what
# the board in BOOTSEL currently carries.
#
#   ./flash.sh                          # ./bruce.uf2, the last ./build.sh output
#   ./flash.sh bruce-c.uf2           # the C image, or any other UF2 (paths are
#                                       # relative to where you run this)
#   ./flash.sh -y file.uf2              # no confirmation prompt (FLASH_YES=1 does the same);
#                                       # required when there is no terminal to ask on
#   ./flash.sh --board feitian_rp2350   # say which board is in BOOTSEL (FLASH_BOARD=...
#                                       # does the same); required when the board is blank
#
# Before it writes, the script reads the image's picotool markers and
# prints, in plain words, which board the image was built for, whether
# its host reboot into boot mode needs a button press, and how many
# passkey slots it has. Every board's build lands in the same file, so
# the board line is the check that the file is the one you meant. It
# then reads the markers of the image already on the board in BOOTSEL
# (`picotool info -a` with no file reads them from flash) and compares.
# At a terminal it asks for confirmation; with no terminal it refuses
# unless given -y.
#
# Refusals, because each is how a token is lost:
#   - an image built for the RP2350 USB-C token is refused: that token
#     is flashed only with tools/flash-usbc.sh (docs/FLASHING.md, "The
#     Feitian USB-C token"). FLASH_ALLOW_USBC_IMAGE=1 overrides, for
#     rehearsing such an image on a development board with a BOOT button;
#   - a board in BOOTSEL with no readable image marker (blank, or an
#     image not from this tree) is refused unless --board says which
#     board it is: a blank USB-C token looks exactly like a blank
#     development board. A USB-C id there is refused (tools/flash-usbc.sh),
#     and the named board must be the one the image was built for;
#   - when the board in BOOTSEL carries a USB-C token image, any image
#     whose markers do not say its host reboot needs no touch is refused
#     -- one that needs a press, and one that records no policy or one
#     this script does not know -- because a token whose reboot waits
#     for a press it cannot give has no way back into boot mode.
#     FLASH_BOARD_IS_DEV=1 overrides, for a development board that was
#     used to rehearse a USB-C image and has a BOOT button of its own.
#
# As with wipe.sh, this expects the device already in BOOTSEL mode --
# hold BOOT, tap RESET, confirm the `RP2350` USB mass-storage volume
# mounts, then run this script. It deliberately does NOT call
# `picotool reboot -u -f`; that path has hung a device before.

set -euo pipefail

YES="${FLASH_YES:-0}"
SAID_BOARD="${FLASH_BOARD:-}"
UF2=""
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            sed -n '/^#   \.\/flash\.sh /,/^# unless given -y\./p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        -y|--yes) YES=1 ;;
        --board)
            [ $# -ge 2 ] || { echo "flash.sh: --board needs a board id" >&2; exit 1; }
            SAID_BOARD="$2"; shift ;;
        --board=*) SAID_BOARD="${1#--board=}" ;;
        -*) echo "flash.sh: unknown option $1" >&2; exit 1 ;;
        *) UF2="$1" ;;
    esac
    shift
done

# The board ids build.sh takes, without the USB-C token's: flash.sh
# never flashes that one, so naming it is refused below.
DEV_BOARDS="tiny2350 xiao_rp2350 feitian_rp2350 waveshare_rp2350_lcd_1_47 spotpear_rp2350_lcd_1_28"

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
# No cd: a relative path means relative to where the user is. Only the
# default is anchored at the repository root.
[ -n "$UF2" ] || UF2="$REPO_ROOT/bruce.uf2"

if [ ! -f "$UF2" ]; then
    echo "flash.sh: $UF2 not found." >&2
    echo "  Did you run ./build.sh (or ./build-c.sh) first?" >&2
    exit 1
fi

command -v picotool >/dev/null 2>&1 || {
    echo "flash.sh: picotool not found on PATH (docs/GETTING-STARTED.md, 'Install the tools')." >&2
    exit 1
}

# picotool wraps long lines, so whitespace is normalised before matching.
marker() {  # marker <info text> <name> -> value or ""
    printf '%s' "$1" | sed -n "s/.*pqf-$2=\([A-Za-z0-9_-]*\).*/\1/p"
}
board_words() {  # board_words <pqf-board id> -> plain words
    case "$1" in
        tiny2350)                  echo "Pimoroni Tiny 2350" ;;
        xiao_rp2350)               echo "Seeed Studio XIAO RP2350" ;;
        feitian_rp2350)            echo "Feitian RP2350 (BOOTSEL button is the presence button)" ;;
        *usbc*)                    echo "RP2350 USB-C token (sealed, touch pad, no power-on BOOTSEL)" ;;
        waveshare_rp2350_lcd_1_47) echo "Waveshare RP2350-LCD-1.47" ;;
        spotpear_rp2350_lcd_1_28)  echo "Spotpear RP2350-LCD-1.28" ;;
        "")                        echo "unknown -- no pqf-board marker (an image from before the markers, or not built from this tree)" ;;
        *)                         echo "unknown board id '$1'" ;;
    esac
}

# ---- What is this image? ----
INFO="$(picotool info -a "$UF2" 2>/dev/null | tr -s ' \n' ' ')" || INFO=""
BOARD_ID="$(marker "$INFO" board)"
REBOOT="$(marker "$INFO" reboot)"
UP="$(marker "$INFO" fido-up)"
SLOTS="$(marker "$INFO" rk-slots)"
case "$REBOOT" in
    touch)    REBOOT_WORDS="needs a button press (the board must have a BOOTSEL button)" ;;
    no-touch) REBOOT_WORDS="no touch needed" ;;
    *)        REBOOT_WORDS="not recorded in the image" ;;
esac
case "$UP" in
    touch) UP_WORDS="a real press or touch" ;;
    auto)  UP_WORDS="auto-confirmed (a test build, or a board with no readable button)" ;;
    *)     UP_WORDS="not recorded in the image" ;;
esac

echo "image:            $UF2"
echo "built for:        $(board_words "$BOARD_ID")"
echo "host reboot into boot mode: $REBOOT_WORDS"
echo "FIDO presence:    $UP_WORDS"
[ -n "$SLOTS" ] && echo "passkey slots:    $SLOTS"

# ---- What is on the board in BOOTSEL? ----
DEV="$(picotool info -a 2>/dev/null | tr -s ' \n' ' ')" || DEV=""
if [ -z "$DEV" ]; then
    echo "flash.sh: no RP2350 in BOOTSEL found. Replug holding BOOT and try again" >&2
    echo "  (docs/GETTING-STARTED.md section 6 has the recipe per board)." >&2
    exit 1
fi
DEV_BOARD_ID="$(marker "$DEV" board)"
if [ -n "$DEV_BOARD_ID" ]; then
    echo "board in BOOTSEL: carries an image built for $(board_words "$DEV_BOARD_ID")"
else
    echo "board in BOOTSEL: carries no readable image marker (blank, or an image not from this tree)"
fi

# ---- Refusals ----
refuse() {  # refuse <line>...
    echo >&2
    for line in "$@"; do echo "$line" >&2; done
    exit 2
}
case "$BOARD_ID" in
    *usbc*)
        if [ "${FLASH_ALLOW_USBC_IMAGE:-0}" != "1" ]; then
            refuse \
                "flash.sh: REFUSING. This image is built for the RP2350 USB-C token." \
                "  A USB-C token is flashed only with tools/flash-usbc.sh, which checks the" \
                "  file, erases first and proves the way back into boot mode" \
                "  (docs/FLASHING.md, 'The Feitian USB-C token')." \
                "  To rehearse this image on a development board that HAS a BOOT button:" \
                "    FLASH_ALLOW_USBC_IMAGE=1 ./flash.sh $UF2"
        fi
        ;;
esac
# The board the user named, if any: one of ours, never the USB-C token,
# and the board the image was built for.
if [ -n "$SAID_BOARD" ]; then
    case " $DEV_BOARDS " in
        *" $SAID_BOARD "*) ;;
        *)
            case "$SAID_BOARD" in
                *usbc*)
                    refuse \
                        "flash.sh: REFUSING. You said the board in BOOTSEL is the RP2350 USB-C token." \
                        "  A USB-C token is flashed only with tools/flash-usbc.sh, which checks the" \
                        "  file, erases first and proves the way back into boot mode" \
                        "  (docs/FLASHING.md, 'The Feitian USB-C token')." ;;
            esac
            echo "flash.sh: unknown board id '$SAID_BOARD' (one of: $DEV_BOARDS)" >&2
            exit 1 ;;
    esac
    if [ "$SAID_BOARD" != "$BOARD_ID" ]; then
        case "$BOARD_ID" in
            *usbc*)
                # A USB-C image on a named development board: the
                # rehearsal FLASH_ALLOW_USBC_IMAGE=1 exists for (without
                # it the image was refused above).
                ;;
            "")
                refuse \
                    "flash.sh: REFUSING. This image carries no pqf-board marker, so nothing says it" \
                    "  was built for the $(board_words "$SAID_BOARD"). Rebuild it with ./build.sh $SAID_BOARD." ;;
            *)
                refuse \
                    "flash.sh: REFUSING. You said the board in BOOTSEL is the $(board_words "$SAID_BOARD")," \
                    "  but this image was built for the $(board_words "$BOARD_ID")." \
                    "  Rebuild for the board you have (./build.sh $SAID_BOARD) or name the right one." ;;
        esac
    fi
fi
# A board with no marker could be anything, a blank USB-C token included.
if [ -z "$DEV_BOARD_ID" ] && [ -z "$SAID_BOARD" ]; then
    refuse \
        "flash.sh: REFUSING. The board in BOOTSEL carries no readable image marker -- it is" \
        "  blank, or carries an image not from this tree -- so flash.sh cannot tell which" \
        "  board it is. A blank RP2350 USB-C token looks exactly like this, and the wrong" \
        "  image would leave it unflashable. Say which board it is:" \
        "    ./flash.sh --board <id> $UF2" \
        "  (<id> is one of: $DEV_BOARDS). A USB-C token is flashed only with" \
        "  tools/flash-usbc.sh (docs/FLASHING.md, 'The Feitian USB-C token')."
fi
case "$DEV_BOARD_ID" in
    *usbc*)
        if [ "$REBOOT" != "no-touch" ] && [ "${FLASH_BOARD_IS_DEV:-0}" != "1" ]; then
            echo >&2
            if [ "$REBOOT" = "touch" ]; then
                echo "flash.sh: REFUSING. The board in BOOTSEL carries a USB-C token image, and this" >&2
                echo "  file's host reboot into boot mode waits for a button press. On a USB-C token" >&2
                echo "  that press can never come, and the token could never be reflashed again." >&2
            else
                echo "flash.sh: REFUSING. The board in BOOTSEL carries a USB-C token image, and this" >&2
                echo "  file does not say its host reboot into boot mode needs no touch (pqf-reboot" >&2
                echo "  is ${REBOOT:-missing}). Without that, nothing says a USB-C token could ever get" >&2
                echo "  back into boot mode to be reflashed." >&2
            fi
            echo "  If this is really a USB-C token, use tools/flash-usbc.sh. If it is a" >&2
            echo "  development board with a BOOT button that rehearsed a USB-C image:" >&2
            echo "    FLASH_BOARD_IS_DEV=1 ./flash.sh $UF2" >&2
            exit 2
        fi
        echo "NOTE: the board in BOOTSEL carries a USB-C token image. If it is a real token,"
        echo "  stop and use tools/flash-usbc.sh; flash.sh does none of that tool's checks."
        ;;
    "")
        ;;
    *)
        if [ -n "$BOARD_ID" ] && [ "$DEV_BOARD_ID" != "$BOARD_ID" ]; then
            echo "NOTE: the board's current image was built for $(board_words "$DEV_BOARD_ID"),"
            echo "  this file for $(board_words "$BOARD_ID"). Make sure that is what you mean."
        fi
        ;;
esac

# ---- Confirm ----
if [ "$YES" != "1" ]; then
    if [ -t 0 ]; then
        printf '\nFlash this image onto the board in BOOTSEL? [y/N] '
        read -r answer
        case "$answer" in
            y|Y|yes|YES) ;;
            *) echo "flash.sh: nothing written."; exit 3 ;;
        esac
    else
        echo "flash.sh: no terminal to confirm on; pass -y to flash without a prompt." >&2
        exit 3
    fi
fi

echo ">> picotool load -x $UF2"
if ! picotool load -x "$UF2"; then
    echo "flash.sh: picotool load failed. Is the board still in BOOTSEL (the RP2350 drive mounted)?" >&2
    echo "  Replug holding BOOT and try again; docs/GETTING-STARTED.md section 6 has the recipe per board." >&2
    exit 1
fi
echo "done. device rebooted into the new firmware."
