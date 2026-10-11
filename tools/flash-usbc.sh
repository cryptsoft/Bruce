#!/usr/bin/env bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# flash-usbc.sh -- the only supported way to put an image on an RP2350
# USB-C token.
#
# The sealed Feitian RP2350 USB-C token has a capacitive touch pad and no
# working power-on BOOTSEL. Once it runs firmware, the only way back
# into the RP2350 boot ROM (boot mode: the RP2350 drive, picotool) is
# that firmware's CTAPHID_CMD_REBOOT, sent by `c/hid/reboot bootsel`.
# An image whose reboot waits for a touch, an image built for another
# board, or an image that hangs before USB leaves the token unflashable
# for good. So this script checks the file, erases before it writes,
# verifies what it wrote, and proves the way back before it says PASS.
#
#   tools/flash-usbc.sh --check <file.uf2>   # inspect only; exit 0 if safe for a USB-C token
#   tools/flash-usbc.sh <file.uf2>           # inspect, erase, flash, prove the way back
#
# The steps, each printed as it runs:
#   0. Tools: picotool >= 2.0 on PATH, perl; c/hid/reboot (built with
#      `make -C c/hid reboot` if missing; not needed for --check).
#   1. Inspect a private copy of the file with `picotool info -a`. It
#      must carry pqf-board=feitian_rp2350_usbc and pqf-reboot=no-touch,
#      be family rp2350-arm-s, image type ARM Secure, binary start
#      0x10000000, and every UF2 block must be rp2350-arm-s inside the
#      first 2 MiB of flash. pqf-fido-up=auto (a test build) is a
#      warning, not a refusal. --check stops here.
#   2. Find the token: exactly one RP2350 in boot mode (a blank token is
#      in boot mode by itself), or exactly one Bruce token running
#      firmware, which is asked to reboot into boot mode.
#   3. Erase 0x10000000-0x10200000: the image AND the credential store
#      and PIN. Mandatory; see FLASHING.md below for why.
#   4. `picotool load -v`; the token is rebooted only if the write and
#      the verify both succeed.
#   5. Wait for the new firmware to come up as a FIDO device.
#   6. Prove the way back, never skipped: `c/hid/reboot bootsel` must
#      reach boot mode with no touch, and `picotool reboot` must bring
#      the firmware back.
#   7. Summary.
#
# Exit codes:
#   0  PASS (with --check: the file may go on a USB-C token)
#   1  usage, or a missing tool
#   2  REFUSED: the file is not safe for a USB-C token; nothing was written
#   3  no token found, more than one candidate attached, or the token
#      could not be put into boot mode; nothing was written
#   4  the erase or the write failed; the token is still in boot mode
#   5  the new image did not come up as a FIDO device
#   6  the way back failed: the token did not go into boot mode on
#      request with no touch, or did not come back from it
#
# There is deliberately no override: no flag, no environment variable.
# A file this script refuses does not go on a USB-C token -- rebuild it
# with ./build.sh feitian_rp2350_usbc or ./build-c.sh feitian_rp2350_usbc.
# The file is copied before it is inspected and the copy is what gets
# written, so a rebuild in another terminal cannot swap it in between.
#
# The procedure is docs/FLASHING.md, "The Feitian RP2350 USB-C token". The
# erase-first rule is the same page's "Intermittent dark device after
# flashing (erase first)"; the host-driven reboot is its "Software
# BOOTSEL entry (no button)", and docs/REBOOT.md.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REBOOT="$REPO_ROOT/c/hid/reboot"
BOARD_ID="feitian_rp2350_usbc"
ERASE_FROM="0x10000000"
ERASE_TO="0x10200000"
REBUILD="Build it with ./build.sh $BOARD_ID or ./build-c.sh $BOARD_ID."

# ---- output ----

say()  { printf '%s\n' "$*"; }
step() { printf '\n== Step %s: %s\n' "$1" "$2"; }
fail() { local code="$1"; shift; local l; for l in "$@"; do say "$l"; done; exit "$code"; }
# Another program's output, indented; progress bars reduced to 100%.
show() {
  printf '%s\n' "$1" | tr '\r' '\n' \
    | awk 'NF && (!/%[ \t]*$/ || /100%[ \t]*$/)' | sed 's/^/    | /'
}
loud() { local l; for l in "$@"; do say "!!! $l"; done; }

# ---- private copy, and what an interruption means ----

WORK=""
PHASE="inspect"
cleanup() { if [ -n "$WORK" ]; then rm -rf "$WORK"; fi; }
on_signal() {
  say ""
  case "$PHASE" in
    erase|write)
      say "INTERRUPTED while the token was being erased or written."
      say "It is still in boot mode, with a blank or partly written flash."
      say "Leave it plugged in and run this tool again: it erases first." ;;
    boot|proof)
      say "INTERRUPTED after the image was written and verified."
      say "Run c/hid/reboot --list and picotool info -a to see where the"
      say "token is, then run this tool again before trusting it." ;;
    *)
      say "INTERRUPTED. Nothing was written to any device." ;;
  esac
  exit 130
}
trap cleanup EXIT
trap on_signal INT TERM

# ---- polling ----

nap() { perl -e 'select(undef, undef, undef, 0.5)'; }

# RP2350s in boot mode: picotool prints one "Device Information" block
# per device. Its not-found message contains the word BOOTSEL, so that
# word is never what is matched. Sets BOOTSEL_N and PT_OUT.
count_bootsel() {
  PT_OUT="$(picotool info -a 2>&1)" || true
  BOOTSEL_N="$(printf '%s\n' "$PT_OUT" \
    | grep -cE '^[[:space:]]*Device Information[[:space:]]*$' || true)"
  if [ "$BOOTSEL_N" -lt 2 ] && [[ $PT_OUT == *[Mm]ultiple* ]]; then
    BOOTSEL_N=2
  fi
}

# Bruce tokens running firmware. `c/hid/reboot --list` only
# enumerates; it never opens a device. Sets FIDO_N and FIDO_LINES.
count_fido() {
  local out
  out="$("$REBOOT" --list 2>&1)" || true
  FIDO_LINES="$(printf '%s\n' "$out" | { grep '^found: ' || true; })"
  FIDO_N="$(printf '%s\n' "$out" | grep -c '^found: ' || true)"
}

fido_product() {
  printf '%s\n' "$FIDO_LINES" | sed -n '1s/^found: \(.*\) (vid=.*$/\1/p'
}

# The chip type picotool reports for the device in boot mode.
bootsel_type() {
  printf '%s\n' "$PT_OUT" | awk '
    /^[[:space:]]*Device Information[[:space:]]*$/ { d = 1; next }
    d && /^[[:space:]]*type:/ { sub(/^[[:space:]]*type:[[:space:]]*/, ""); print; exit }'
}

# wait_for bootsel|fido <seconds>: poll every 0.5 s until exactly one is
# there (return 0) or the time is up (return 1). Sets WAITED.
wait_for() {
  local start="$SECONDS" deadline=$((SECONDS + $2))
  while :; do
    if [ "$1" = bootsel ]; then
      count_bootsel
      if [ "$BOOTSEL_N" -eq 1 ]; then WAITED=$((SECONDS - start)); return 0; fi
    else
      count_fido
      if [ "$FIDO_N" -eq 1 ]; then WAITED=$((SECONDS - start)); return 0; fi
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then WAITED=$((SECONDS - start)); return 1; fi
    nap
  done
}

# c/hid/reboot bootsel, output kept (it would tell the user to press
# something). Sets R_RC and R_OUT.
send_bootsel() {
  R_RC=0
  R_OUT="$("$REBOOT" bootsel 2>&1)" || R_RC=$?
}

# A line saying where the token is now.
state_line() {
  count_fido
  count_bootsel
  if [ "$FIDO_N" -eq 1 ]; then
    say "Current state: the token is running firmware as a FIDO device ($(fido_product))."
  elif [ "$BOOTSEL_N" -eq 1 ]; then
    say "Current state: the token is in boot mode (reflashable). Leave it plugged in."
  elif [ "$FIDO_N" -gt 1 ] || [ "$BOOTSEL_N" -gt 1 ]; then
    say "Current state: more than one device is attached now; unplug all but the token."
  else
    say "Current state: the token shows up neither as a FIDO device nor in boot mode."
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    say "(no sha256sum or shasum here)"
  fi
}

# ---- arguments ----

usage() {
  say "usage: tools/flash-usbc.sh --check <file.uf2>   inspect only; exit 0 if safe for a USB-C token"
  say "       tools/flash-usbc.sh <file.uf2>           inspect, erase, flash, prove the way back"
  say "There is no override option. The procedure is docs/FLASHING.md, 'The Feitian RP2350 USB-C token'."
}

MODE="flash"
case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  --check) MODE="check"; shift ;;
  -*) say "flash-usbc.sh: unknown option '$1'."; usage; exit 1 ;;
esac
if [ "$#" -ne 1 ]; then usage; exit 1; fi
UF2="$1"

# ---- step 0: tools ----

step 0 "check the tools"
if ! command -v picotool >/dev/null 2>&1; then
  fail 1 "picotool is not installed, or not on PATH." \
    "Install picotool 2.0 or newer as described in docs/GETTING-STARTED.md (section 2), then run this again."
fi
PT_VERSION="$(picotool version 2>&1)" || PT_VERSION=""
PT_VERSION="$(printf '%s\n' "$PT_VERSION" | sed -n '1p')"
PT_MAJOR="$(printf '%s\n' "$PT_VERSION" | { grep -oE 'v[0-9]+\.[0-9]+' || true; } \
  | sed -n '1s/^v\([0-9]*\)\..*/\1/p')"
if [ -z "$PT_MAJOR" ]; then
  fail 1 "Could not tell which picotool this is ('picotool version' printed: $PT_VERSION)." \
    "Install picotool 2.0 or newer as described in docs/GETTING-STARTED.md (section 2)."
fi
if [ "$PT_MAJOR" -lt 2 ]; then
  fail 1 "picotool is too old: $PT_VERSION. The RP2350 needs picotool 2.0 or newer;" \
    "install it as described in docs/GETTING-STARTED.md (section 2)."
fi
say "  picotool: $PT_VERSION"
if ! command -v perl >/dev/null 2>&1; then
  fail 1 "perl is not installed. This script uses it to read the UF2 file and to wait" \
    "in half seconds; install perl (macOS and almost every Linux ship it)."
fi

if [ "$MODE" = "flash" ]; then
  if [ ! -x "$REBOOT" ] || [ "$REPO_ROOT/c/hid/reboot.c" -nt "$REBOOT" ]; then
    say "  c/hid/reboot is missing or older than its source; building it: make -C c/hid reboot"
    MK_RC=0
    MK_OUT="$(make -C "$REPO_ROOT/c/hid" reboot 2>&1)" || MK_RC=$?
    if [ "$MK_RC" -ne 0 ]; then
      show "$MK_OUT"
      fail 1 "Could not build c/hid/reboot. Install a C compiler and make (macOS:" \
        "xcode-select --install; Debian/Ubuntu: sudo apt install build-essential), then" \
        "run: make -C c/hid reboot"
    fi
  fi
  RB_RC=0
  RB_OUT="$("$REBOOT" --list 2>&1)" || RB_RC=$?
  if [ "$RB_RC" -gt 1 ]; then
    show "$RB_OUT"
    fail 1 "c/hid/reboot --list does not work here (exit $RB_RC; its output is above)." \
      "Rebuild it with: make -C c/hid reboot"
  fi
  say "  c/hid/reboot: $REBOOT"
fi

# ---- step 1: inspect ----

step 1 "inspect the file"
if [ ! -f "$UF2" ]; then fail 1 "No such file: $UF2"; fi
case "$UF2" in
  *.uf2|*.UF2) ;;
  *) fail 2 "REFUSED: $UF2 is not a .uf2 file. Only the UF2 that ./build.sh or" \
       "./build-c.sh writes can go on a USB-C token. Nothing was written to any device." ;;
esac

TMPBASE="${TMPDIR:-/tmp}"
WORK="$(mktemp -d "${TMPBASE%/}/flash-usbc.XXXXXX")"
IMG="$WORK/image.uf2"
cp "$UF2" "$IMG"
SHA="$(sha256_of "$IMG")"
say "  file:   $UF2"
say "  sha256: $SHA"

INFO_RC=0
INFO="$(cd "$WORK" && picotool info -a image.uf2 2>&1)" || INFO_RC=$?
if [ "$INFO_RC" -ne 0 ]; then
  show "$INFO"
  fail 2 "REFUSED: picotool could not read this file (exit $INFO_RC), so it cannot be" \
    "identified. $REBUILD Nothing was written to any device."
fi
# picotool wraps long lines, the features line included.
NORM="$(printf '%s\n' "$INFO" | tr -s ' \t\r\n' ' ')"

marker_values() {
  printf '%s\n' "$NORM" | { grep -oE "$1=[A-Za-z0-9_-]+" || true; } \
    | sed "s/^$1=//" | sort -u
}
count_values() { printf '%s' "$1" | grep -c . || true; }
one_line() { printf '%s' "$1" | tr '\n' ' ' | sed 's/ *$//'; }
field() {
  printf '%s\n' "$INFO" | sed -n "s/^[[:space:]]*$1:[[:space:]]*//p" \
    | sed 's/[[:space:]]*$//' | sort -u
}

BOARD_V="$(marker_values pqf-board)"
REBOOT_V="$(marker_values pqf-reboot)"
UP_V="$(marker_values pqf-fido-up)"
FAMILY_V="$(printf '%s\n' "$NORM" | { grep -oE "family ID '[^']*'" || true; } \
  | sed "s/^family ID '//; s/'\$//" | sort -u)"
ITYPE_V="$(field 'image type')"
BSTART_V="$(field 'binary start')"

# Every UF2 block, not just what picotool summarises: a mixed file
# (Arm plus RISC-V, say) or one that writes outside the image region is
# refused. The one block the Pico SDK adds as its RP2350-E10 workaround
# (family "absolute", 256 bytes at 0x10ffff00) is expected and skipped.
SCAN_RC=0
SCAN="$(perl -e '
  use strict; use warnings;
  my %name = (0xe48bff56 => "rp2040", 0xe48bff57 => "absolute",
              0xe48bff58 => "data", 0xe48bff59 => "rp2350-arm-s",
              0xe48bff5a => "rp2350-riscv", 0xe48bff5b => "rp2350-arm-ns");
  open(my $fh, "<:raw", $ARGV[0]) or die "cannot open the copy: $!\n";
  my ($n, $bad, $e10, $lo, $hi) = (0, 0, 0);
  my %fam;
  while (1) {
    my $got = read($fh, my $blk, 512);
    die "read error: $!\n" unless defined $got;
    last if $got == 0;
    if ($got != 512) { $bad++; last }
    my ($m0, $m1, $flags, $addr, $size, undef, undef, $fid) = unpack("V8", $blk);
    my $mend = unpack("V", substr($blk, 508, 4));
    if ($m0 != 0x0A324655 || $m1 != 0x9E5D5157 || $mend != 0x0AB16F30) { $bad++; next }
    next if $flags & 0x1;
    my $f = ($flags & 0x2000) ? ($name{$fid} // sprintf("0x%08x", $fid)) : "no-family";
    if ($f eq "absolute" && $addr == 0x10ffff00 && $size == 256) { $e10++; next }
    $fam{$f}++;
    $n++;
    $lo = $addr if !defined $lo || $addr < $lo;
    $hi = $addr + $size if !defined $hi || $addr + $size > $hi;
  }
  printf "blocks=%d\nbad=%d\ne10=%d\nfamilies=%s\nlo=0x%08x\nhi=0x%08x\n",
    $n, $bad, $e10, join(",", sort keys %fam), $lo // 0, $hi // 0;
' "$IMG" 2>&1)" || SCAN_RC=$?
if [ "$SCAN_RC" -ne 0 ]; then
  fail 2 "REFUSED: could not read the UF2 blocks: $SCAN. Nothing was written to any device."
fi
scan() { printf '%s\n' "$SCAN" | sed -n "s/^$1=//p"; }
BLK_N="$(scan blocks)"; BLK_BAD="$(scan bad)"; BLK_FAM="$(scan families)"
BLK_LO="$(scan lo)"; BLK_HI="$(scan hi)"

show_value() { if [ -n "$1" ]; then one_line "$1"; else printf '(none)'; fi; }
say "  pqf-board:    $(show_value "$BOARD_V")"
say "  pqf-reboot:   $(show_value "$REBOOT_V")"
say "  pqf-fido-up:  $(show_value "$UP_V")"
say "  family:       $(show_value "$FAMILY_V")"
say "  image type:   $(show_value "$ITYPE_V")"
say "  binary start: $(show_value "$BSTART_V")"
say "  UF2 blocks:   $BLK_N ($(show_value "$BLK_FAM"), $BLK_LO..$BLK_HI)"

board_desc() {
  case "$1" in
    feitian_rp2350) printf 'the USB-A board with a button' ;;
    tiny2350) printf 'the Pimoroni Tiny 2350 development board' ;;
    xiao_rp2350) printf 'the Seeed XIAO RP2350 development board' ;;
    waveshare_rp2350_lcd_1_47) printf 'the Waveshare RP2350-LCD-1.47 development board' ;;
    spotpear_rp2350_lcd_1_28) printf 'the Spotpear RP2350-LCD-1.28 development board' ;;
    *) printf 'a board this tool does not know' ;;
  esac
}

REASONS=""
NREASONS=0
# why <first line> [more lines...]: one reason to refuse.
why() {
  NREASONS=$((NREASONS + 1))
  REASONS="$REASONS
REFUSED: $1"
  shift
  local l
  for l in "$@"; do REASONS="$REASONS
         $l"; done
}

NB="$(count_values "$BOARD_V")"
NR="$(count_values "$REBOOT_V")"
if [ "$NB" -eq 0 ] && [ "$NR" -eq 0 ]; then
  why "this image carries no pqf-board / pqf-reboot marker, so it cannot be identified." \
    "Only images built from this tree after the USB-C profile was added are allowed." \
    "$REBUILD"
else
  if [ "$NB" -eq 0 ]; then
    why "this image carries no pqf-board marker, so the board it was built for cannot" \
      "be identified. $REBUILD"
  elif [ "$NB" -gt 1 ]; then
    why "this image names more than one board ($(one_line "$BOARD_V")), so it cannot be" \
      "identified. $REBUILD"
  elif [ "$BOARD_V" != "$BOARD_ID" ]; then
    why "this image was built for $BOARD_V ($(board_desc "$BOARD_V")), not for the USB-C token." \
      "$REBUILD"
  fi
  if [ "$NR" -eq 0 ]; then
    why "this image carries no pqf-reboot marker, so nothing shows that its reboot into" \
      "boot mode needs no touch. $REBUILD"
  elif [ "$NR" -gt 1 ]; then
    why "this image carries conflicting pqf-reboot markers ($(one_line "$REBOOT_V"))." \
      "$REBUILD"
  elif [ "$REBOOT_V" = "touch" ]; then
    why "this image needs a button press to get back into boot mode (pqf-reboot=touch)." \
      "The USB-C token has no button you can hold at power-on, so it could never be reflashed."
  elif [ "$REBOOT_V" != "no-touch" ]; then
    why "this image says pqf-reboot=$REBOOT_V; only pqf-reboot=no-touch may go on a USB-C token."
  fi
fi

if [ -z "$FAMILY_V" ]; then
  why "picotool reports no family ID for this file, so it cannot be identified."
elif [ "$FAMILY_V" != "rp2350-arm-s" ]; then
  case "$FAMILY_V" in
    *riscv*)
      why "this is a RISC-V image (family $(one_line "$FAMILY_V")). A RISC-V image leaves core 1" \
        "switched to RISC-V and the next Arm image hangs before USB -- never on a USB-C token." \
        "Build a plain Arm image: no RISCV=1, no riscv32 target." ;;
    *arm-ns*)
      why "this is a TrustZone Non-secure image (family $(one_line "$FAMILY_V")): half of a" \
        "pair, not a whole firmware. Only a plain Arm build goes on a USB-C token." ;;
    *)
      why "this image is for family $(one_line "$FAMILY_V"), not rp2350-arm-s (a plain Arm" \
        "RP2350 firmware). $REBUILD" ;;
  esac
elif [ "$BLK_FAM" != "rp2350-arm-s" ]; then
  why "the UF2 file holds blocks for $(show_value "$BLK_FAM"), not only rp2350-arm-s." \
    "A mixed-architecture file can leave core 1 switched to RISC-V, and the next Arm" \
    "image then hangs before USB -- never on a USB-C token. $REBUILD"
fi
if [ "$BLK_BAD" -gt 0 ]; then
  why "this is not a well-formed UF2 file ($BLK_BAD damaged or truncated blocks)."
fi
if [ "$BLK_N" -eq 0 ]; then
  why "this UF2 file holds nothing to write."
elif [ $((BLK_LO)) -lt $((ERASE_FROM)) ] || [ $((BLK_HI)) -gt $((ERASE_TO)) ]; then
  why "this UF2 writes $BLK_LO..$BLK_HI, outside the first 2 MiB of flash" \
    "($ERASE_FROM..$ERASE_TO) where a plain firmware image lives and which this tool erases."
fi

if [ -z "$ITYPE_V" ]; then
  why "picotool reports no image type for this file, so the boot ROM would not know" \
    "how to start it. $REBUILD"
elif [ "$ITYPE_V" != "ARM Secure" ]; then
  why "picotool reports image type '$(one_line "$ITYPE_V")', not 'ARM Secure'. Only a plain" \
    "Arm Secure firmware may go on a USB-C token (no RISC-V, no TrustZone Non-secure half)."
fi

if [ -z "$BSTART_V" ]; then
  why "picotool reports no binary start for this image, so where it is linked cannot" \
    "be checked. $REBUILD"
elif [ "$BSTART_V" != "0x10000000" ]; then
  why "this image starts at $(one_line "$BSTART_V"), not 0x10000000: it is linked for a DFU" \
    "app slot / bootloader layout, not for a bare token."
fi

if [ "$NREASONS" -gt 0 ]; then
  say "$REASONS"
  say ""
  say "This file must not go on a Feitian RP2350 USB-C token, and there is no override."
  say "Nothing was written to any device."
  exit 2
fi

if [ "$UP_V" = "auto" ]; then
  say ""
  say "WARNING: this is a test build: FIDO presence auto-confirms (pqf-fido-up=auto)."
  say "WARNING: do not hand it to a user -- it logs anyone in without a touch."
elif [ "$UP_V" != "touch" ]; then
  say "  NOTE: pqf-fido-up is $(show_value "$UP_V"); cannot tell whether FIDO presence is a real touch."
fi
say "  OK: built for the Feitian RP2350 USB-C token, and its reboot into boot mode needs no touch."

if [ "$MODE" = "check" ]; then
  say ""
  say "--check: the file may go on a USB-C token. Nothing was written to any device."
  say "Next: rehearse it on a Feitian RP2350 with tools/flash-usbc.sh $UF2"
  say "(docs/FLASHING.md, 'Step 2: rehearse on a USB-A board')."
  exit 0
fi

# ---- step 2: find the token ----

PHASE="find"
step 2 "find the token"
# Give a token that was plugged in a moment ago time to enumerate.
DEADLINE=$((SECONDS + 5))
while :; do
  count_bootsel
  count_fido
  if [ "$BOOTSEL_N" -gt 0 ] || [ "$FIDO_N" -gt 0 ]; then break; fi
  if [ "$SECONDS" -ge "$DEADLINE" ]; then break; fi
  nap
done

if [ "$BOOTSEL_N" -gt 1 ]; then
  fail 3 "More than one RP2350 is in boot mode. Unplug all of them except the token" \
    "you mean to flash, then run this again. Nothing was written."
fi
if [ "$FIDO_N" -gt 1 ]; then
  show "$FIDO_LINES"
  fail 3 "More than one Bruce token is attached (listed above). Unplug all of them" \
    "except the token you mean to flash, then run this again. Nothing was written."
fi
if [ "$BOOTSEL_N" -eq 1 ] && [ "$FIDO_N" -eq 1 ]; then
  show "$FIDO_LINES"
  fail 3 "One RP2350 is in boot mode AND a Bruce token is running (listed above):" \
    "two candidates. Unplug the one you do not mean to flash, then run this again." \
    "Nothing was written."
fi

WAS_IN_BOOTSEL="$BOOTSEL_N"   # 1: already in boot mode (a blank token)
if [ "$BOOTSEL_N" -eq 0 ] && [ "$FIDO_N" -eq 1 ]; then
  say "  found one Bruce token running firmware: $(fido_product)"
  say "  asking it to reboot into boot mode: c/hid/reboot bootsel"
  send_bootsel
  if [ "$R_RC" -ne 0 ]; then show "$R_OUT"; fi
  say "  waiting for it in boot mode (picotool info -a every 0.5 s)"
  START=$SECONDS
  DEADLINE=$((SECONDS + 60))
  NEXT_SEND=$((SECONDS + 12))
  ASKED=0
  while :; do
    count_bootsel
    if [ "$BOOTSEL_N" -eq 1 ]; then break; fi
    if [ "$BOOTSEL_N" -gt 1 ]; then
      fail 3 "More than one RP2350 is in boot mode now. Unplug all but the token and" \
        "run this again. Nothing was written."
    fi
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
      say ""
      say "The token did not go into boot mode within 60 s. Nothing was written."
      state_line
      fail 3 "If it is still running firmware, that image gates the reboot on a press" \
        "that did not come. On a USB-C token, touch the pad within 10 s of" \
        "c/hid/reboot bootsel; if that never works, the token cannot be updated." \
        "See docs/FLASHING.md, 'When something goes wrong' (the USB-C token section)."
    fi
    if [ "$SECONDS" -ge "$NEXT_SEND" ]; then
      if [ "$ASKED" -eq 0 ]; then
        say "  not in boot mode after 12 s."
        say "  The running image may need a button press: press the token's button now"
        say "  (on the USB-C token: touch the pad). Asking again every 11 s, up to 60 s."
        ASKED=1
      else
        say "  asking again ($((DEADLINE - SECONDS)) s left): press the button / touch the pad now."
      fi
      count_fido
      if [ "$FIDO_N" -eq 1 ]; then send_bootsel; fi
      NEXT_SEND=$((SECONDS + 11))
    fi
    nap
  done
  say "  in boot mode after about $((SECONDS - START)) s."
elif [ "$BOOTSEL_N" -eq 0 ]; then
  if [ -n "$PT_OUT" ] && [[ $PT_OUT != *"No accessible RP-series devices in BOOTSEL mode were found"* ]]; then
    show "$PT_OUT"
  fi
  fail 3 "No token found: plug the token in (a blank token shows up in boot mode by itself)." \
    "Use a data-capable cable into a direct port, no hub; on Linux install the udev rules" \
    "from tools/udev/. Nothing was written."
fi

CHIP="$(bootsel_type)"
case "$CHIP" in
  ""|RP2350*) ;;
  *) fail 3 "The device in boot mode is an $CHIP, not an RP2350. Unplug it and plug in the" \
       "token. Nothing was written." ;;
esac
if [ "$WAS_IN_BOOTSEL" -eq 1 ]; then
  say "  found one RP2350 in boot mode."
fi

# ---- step 3: erase ----

step 3 "erase the flash"
say "  Do not unplug the token from here until you see PASS."
say "  This wipes $ERASE_FROM..$ERASE_TO: the firmware image AND the credential store"
say "  and PIN (on these 2 MiB parts the first 2 MiB is the whole flash). Every site"
say "  the token was registered with has to be registered again."
say "  That is deliberate. Loaded without an erase, about 1 flash in 9 came up dark"
say "  (no USB, not in boot mode); a blank RP2350 comes up in boot mode by itself, a"
say "  half-written one does not. See docs/FLASHING.md, \"Intermittent dark device"
say "  after flashing (erase first)\"."
say "  running: picotool erase -r $ERASE_FROM $ERASE_TO"
PHASE="erase"
ER_RC=0
ER_OUT="$(picotool erase -r "$ERASE_FROM" "$ERASE_TO" 2>&1)" || ER_RC=$?
show "$ER_OUT"
if [ "$ER_RC" -ne 0 ]; then
  fail 4 "FAILED: picotool could not erase the token (exit $ER_RC; its output is above)." \
    "The token is still in boot mode and nothing new was written. Leave it plugged in," \
    "fix the cause (cable, hub: use a direct port) and run this tool again."
fi

# ---- step 4: write and verify ----

step 4 "write and verify the image"
say "  running: picotool load -v $UF2   (the checked copy, sha256 ${SHA:0:16}...)"
PHASE="write"
LD_RC=0
LD_OUT="$(cd "$WORK" && picotool load -v image.uf2 2>&1)" || LD_RC=$?
show "$LD_OUT"
# picotool exits non-zero when the verify fails; its words are a second check.
VERIFY_BAD='[Vv]erif[a-z]* *[Ff][Aa][Ii][Ll]|[Mm]ismatch|did not match'
if [ "$LD_RC" -eq 0 ] && [[ $LD_OUT =~ $VERIFY_BAD ]]; then
  LD_RC=99
fi
if [ "$LD_RC" -ne 0 ]; then
  say ""
  say "FAILED: the write or the verify did not succeed (exit $LD_RC; picotool's output is"
  say "above). The token was NOT rebooted."
  say "  erasing again so the flash is blank: picotool erase -r $ERASE_FROM $ERASE_TO"
  RE_RC=0
  RE_OUT="$(picotool erase -r "$ERASE_FROM" "$ERASE_TO" 2>&1)" || RE_RC=$?
  show "$RE_OUT"
  if [ "$RE_RC" -eq 0 ]; then
    fail 4 "The flash is blank again (the safe state) and the token is still in boot mode." \
      "Leave it plugged in, fix the cause (cable, hub, file) and run this tool again."
  fi
  fail 4 "Could not erase it again either, so the flash may be partly written. The token" \
    "stays in boot mode only while it stays plugged in: do NOT unplug it. Fix the cause" \
    "(cable, hub, file) and run this tool again straight away; it erases before it writes."
fi

say "  written and verified. Starting the new firmware: picotool reboot -a -c arm"
PHASE="boot"
PR_RC=0
PR_OUT="$(picotool reboot -a -c arm 2>&1)" || PR_RC=$?
show "$PR_OUT"
if [ "$PR_RC" -ne 0 ]; then
  count_bootsel
  if [ "$BOOTSEL_N" -eq 1 ]; then
    fail 4 "FAILED: picotool could not reboot the token (exit $PR_RC). It is still in boot" \
      "mode, with the new image written and verified. Leave it plugged in and run this" \
      "tool again."
  fi
  say "  (picotool reported an error, but the token has left boot mode; carrying on)"
fi

# ---- step 5: wait for the firmware ----

step 5 "wait for the new firmware"
say "  polling c/hid/reboot --list every 0.5 s, up to 20 s"
if ! wait_for fido 20; then
  say ""
  if [ "$FIDO_N" -gt 1 ]; then
    show "$FIDO_LINES"
    fail 5 "More than one Bruce token is attached now (listed above). Unplug all but" \
      "the token and run c/hid/reboot --list to see it."
  fi
  loud "FAILED: the image did not come up as a FIDO device within 20 s."
  loud "$(state_line)"
  loud "Unplug the token, plug it back in ONCE, and run: c/hid/reboot --list"
  loud "If it shows up there, run this tool again. If it never appears (and"
  loud "picotool info -a does not show it in boot mode either), the image hangs"
  loud "before USB, and a USB-C token cannot be reflashed by software. That is"
  loud "exactly why docs/FLASHING.md says to rehearse the same file on a"
  loud "USB-A board first."
  exit 5
fi
PRODUCT="$(fido_product)"
say "  up after about $WAITED s: $PRODUCT"

# ---- step 6: prove the way back ----

way_back_fail() {
  say ""
  say "FAIL: $1"
  state_line
  say "Do NOT flash anything else onto this token until c/hid/reboot bootsel works."
  shift
  local l
  for l in "$@"; do say "$l"; done
  say "See docs/FLASHING.md, 'When something goes wrong' (the USB-C token section)."
  exit 6
}

step 6 "prove the way back: into boot mode and out again, with no touch"
PHASE="proof"
nap; nap    # let the firmware settle after it enumerates
say "  asking the firmware to reboot into boot mode: c/hid/reboot bootsel"
say "  polling picotool info -a every 0.5 s, up to 12 s"
START=$SECONDS
DEADLINE=$((SECONDS + 12))
send_bootsel
SENDS=1
while :; do
  count_bootsel
  if [ "$BOOTSEL_N" -eq 1 ]; then break; fi
  if [ "$SECONDS" -ge "$DEADLINE" ]; then
    way_back_fail "the token did not go into boot mode within 12 s of c/hid/reboot bootsel." \
      "Try c/hid/reboot bootsel by hand and watch picotool info -a."
  fi
  if [ "$R_RC" -ne 0 ] && [ "$SENDS" -lt 3 ]; then
    # The request never went out (the device was not ready to be
    # opened); that is not a question of touch, so send it again.
    say "  the request did not go out ($(printf '%s\n' "$R_OUT" | sed -n '$p')); sending it again"
    nap
    count_fido
    if [ "$FIDO_N" -eq 1 ]; then send_bootsel; fi
    SENDS=$((SENDS + 1))
  fi
  nap
done
say "  in boot mode after about $((SECONDS - START)) s, with no touch."

say "  starting the firmware again: picotool reboot -a -c arm"
PR_RC=0
PR_OUT="$(picotool reboot -a -c arm 2>&1)" || PR_RC=$?
show "$PR_OUT"
if [ "$PR_RC" -ne 0 ]; then
  count_bootsel
  if [ "$BOOTSEL_N" -eq 1 ]; then
    way_back_fail "picotool could not reboot the token out of boot mode (exit $PR_RC)."
  fi
fi
say "  polling c/hid/reboot --list every 0.5 s, up to 20 s"
if ! wait_for fido 20; then
  way_back_fail "the token went into boot mode, but did not come back as a FIDO device within 20 s of picotool reboot." \
    "Unplug it, plug it back in ONCE, and run c/hid/reboot --list."
fi
say "  running again after about $WAITED s: $(fido_product)"
say ""
say "PASS: the token went back into boot mode with no touch and is running again."

# ---- step 7: summary ----

step 7 "summary"
say "  file:    $UF2"
say "  sha256:  $SHA"
say "  markers: pqf-board=$BOARD_V pqf-reboot=$REBOOT_V pqf-fido-up=$(show_value "$UP_V")"
say "  token:   $PRODUCT"
say "  result:  PASS"
if [ "$UP_V" = "auto" ]; then
  say "  WARNING: test build (pqf-fido-up=auto): do not hand this token to a user."
fi
say "Rehearsing on a USB-A board? The USB-C token can take this exact file."
