#!/bin/bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Flash the Rust firmware, verifying the image is the one you meant.
#
# Exists because `cargo build` writes every profile to the SAME path.
# Build feature set A, then build feature set B to check it compiles,
# and the artifact on disk is B -- so copying "the" ELF afterwards
# silently flashes the wrong firmware. That has now stranded this board
# twice: both times with a board_tiny2350 image, whose user-presence
# input is an unwired GPIO, so its CMD_REBOOT can never be confirmed and
# the only way back is the physical BOOTSEL button.
#
#   flash-fw.sh <elf> [required-symbol ...]
#
# Every required symbol must be present in the ELF, so an image built
# without the feature you wanted is refused rather than flashed.
set -e
ELF="$1"; shift
[ -f "$ELF" ] || { echo "  missing: $ELF"; exit 1; }

NM=$(command -v arm-none-eabi-nm || command -v nm)
for sym in "$@"; do
  if ! "$NM" "$ELF" 2>/dev/null | grep -q "$sym"; then
    echo "  REFUSING: '$sym' not in $(basename "$ELF")."
    echo "  That image was not built with the features you asked for."
    exit 1
  fi
  echo "  verified present: $sym"
done

# An image without a software escape can only be recovered with the
# physical button. That is fine at a desk and a dead end otherwise, and
# it has stranded this board three times. Refuse by default.
#
# The board string is the reliable tell: board_feitian_rp2350 puts
# "Feitian RP2350 PQC" in the binary, and that is the only profile whose
# presence input is actually wired on this hardware -- so it is the only
# one whose CMD_REBOOT can ever be confirmed.
if ! strings "$ELF" 2>/dev/null | grep -q "Feitian RP2350 PQC"; then
  echo "  REFUSING: this image is not a board_feitian_rp2350 build."
  echo "  Its user-presence input is not wired on this board, so"
  echo "  CMD_REBOOT can never be confirmed and there is NO software"
  echo "  way back -- only the physical BOOTSEL button."
  echo "  Build with --no-default-features --features"
  echo "    mldsa65,board_feitian_rp2350,test_no_user_button,reboot_no_up"
  echo "  or set ALLOW_NO_ESCAPE=1 if someone is holding the board."
  [ "$ALLOW_NO_ESCAPE" = "1" ] || exit 1
fi

picotool info >/dev/null 2>&1 || { echo "  board is not in BOOTSEL"; exit 1; }
# picotool dispatches on the extension, and cargo's artifact has none.
STAGED="${TMPDIR:-/tmp}/$(basename "$ELF").elf"
cp "$ELF" "$STAGED"
picotool load "$STAGED" >/dev/null 2>&1 || { echo "  load FAILED"; exit 1; }
picotool reboot -a -c arm >/dev/null 2>&1
sleep 10
echo "  flashed: $(basename "$ELF")"
