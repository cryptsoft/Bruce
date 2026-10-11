#!/bin/bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Flash a TrustZone image pair.
#
# Exists because a silently-skipped flash reads as a firmware result.
# Twice now a step failed quietly -- once a stale bootloader, once a
# missing helper swallowed by `&&` -- and the previous image answered
# the test, which was then written up as a property of the new one. So
# every step here is checked and every failure is loud.
#
#   flash-tz.sh <fw-secure.elf> <fw-nonsecure.elf>
set -e
SEC="$1"; NS="$2"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
REBOOT="$REPO/c/hid/reboot"

[ -n "$SEC" ] && [ -n "$NS" ] || { echo "usage: $0 <secure.elf> <nonsecure.elf>"; exit 1; }
[ -f "$SEC" ] || { echo "  MISSING secure elf: $SEC"; exit 1; }
[ -f "$NS"  ] || { echo "  MISSING nonsecure elf: $NS"; exit 1; }
[ -x "$REBOOT" ] || { echo "  $REBOOT not built -- run make in c/hid"; exit 1; }

# Say which build this is. The dev and production images differ in what
# they even expose -- production has no injection veneer and no raw M4c
# gateways -- so flashing the wrong one makes the test suite fail in
# ways that look like firmware bugs. It has already cost one debugging
# round: the presence gate "broke" when it was simply doing its job in
# an image with no way to inject a touch.
# The Secure ELF and the veneer import library must describe the same
# gateway set. They can disagree: libnsclib.a is a build.rs side effect
# and cargo skips build.rs for a crate it considers fresh, so the file
# on disk can belong to a different feature set than the ELF beside it.
# When they disagree, the Non-secure image was linked against the wrong
# table and nothing good follows.
IMPLIB="$REPO/target/nsc/libnsclib.a"
if [ -f "$IMPLIB" ]; then
  elf_n=$(nm "$SEC" 2>/dev/null | grep -c " T sg_")
  lib_n=$(nm "$IMPLIB" 2>/dev/null | grep -c " A sg_")
  if [ "$elf_n" != "$lib_n" ]; then
    echo "  MISMATCH: Secure ELF exports $elf_n veneers, libnsclib.a lists $lib_n."
    echo "  The Non-secure image is linked against the wrong table."
    echo "  Fix: touch crates/fw-secure/src/main.rs and rebuild BOTH crates."
    exit 1
  fi
fi

if nm "$SEC" 2>/dev/null | grep -q " T sg_reboot_bootsel"; then
  echo "  image: DEV (dev-escape on -- BOOTSEL escape, touch injection, raw M4c veneers)"
elif [ "$ALLOW_PROD" = "1" ]; then
  echo "  image: PRODUCTION -- ALLOW_PROD=1 given; you will need the button to get back"
else
  cat <<'WARN'
  REFUSING to flash: this is a PRODUCTION image (no dev-escape).

  It has no CTAPHID reboot command and no Secure dead-man's switch, by
  design. Once it is running, the ONLY way back is holding the physical
  BOOTSEL button at power-on -- there is no software path, which is the
  entire point of the feature being off.

  That is fine at a desk and a dead end for an unattended session; it
  has already stranded this board once. Build with
  --features dev-escape, or set ALLOW_PROD=1 if you are holding it.
WARN
  exit 1
fi

"$REBOOT" bootsel TZ >/dev/null 2>&1 || true
# Poll rather than sleeping a fixed 6 s. The reboot takes about that
# long, so the fixed wait was a race -- it aborted on a board that
# reached BOOTSEL a moment later, and that reads as a hardware fault.
for _ in $(seq 1 25); do
    picotool info >/dev/null 2>&1 && break
    sleep 1
done
picotool info >/dev/null 2>&1 || { echo "  board did NOT reach BOOTSEL -- aborting"; exit 1; }
# picotool dispatches on the FILE EXTENSION, and a cargo artefact has
# none -- it answers "does not have a recognized file type" and this
# script reported "secure load FAILED", which reads like a flash error.
# tools/flash-fw.sh already stages through a .elf path for exactly this
# reason; do the same here.
STAGE_SEC="${TMPDIR:-/tmp}/pqf-tz-secure.elf"
STAGE_NS="${TMPDIR:-/tmp}/pqf-tz-nonsecure.elf"
cp "$SEC" "$STAGE_SEC" || { echo "  could not stage the secure elf"; exit 1; }
cp "$NS"  "$STAGE_NS"  || { echo "  could not stage the nonsecure elf"; exit 1; }

picotool load "$STAGE_SEC" >/dev/null 2>&1 || { echo "  secure load FAILED"; exit 1; }
picotool load "$STAGE_NS"  >/dev/null 2>&1 || { echo "  nonsecure load FAILED"; exit 1; }
picotool reboot -a -c arm >/dev/null 2>&1
sleep 10
n=$(ioreg -p IOUSB -l -w 0 2>/dev/null | grep -c 'Bruce TZ-NS' || true)
[ "$n" -gt 0 ] || { echo "  did NOT enumerate after flash"; exit 1; }
echo "  flashed and enumerated: $(basename "$SEC")"
