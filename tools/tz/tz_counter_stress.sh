#!/bin/bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Reboot the board repeatedly and check the signature counter never
# rewinds.
#
# Each boot appends one reservation record, so ~16 cycles walk a sector
# to full and force the ping-pong erase -- the one path where a
# mis-ordered write could lose the high-water. Twenty cycles crosses it.
#
# The counter is read with the tz_test example's --count mode (one
# MakeCredential, prints `signCount=N`), from the in-tree client.
#
#   tz_counter_stress.sh [cycles]
set -e
CYCLES="${1:-20}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
REBOOT="$REPO/c/hid/reboot"
HOST=$(rustc -vV | awk '/^host:/{print $2}')
[ -x "$REBOOT" ] || { echo "  $REBOOT not built -- run make in c/hid"; exit 1; }

# One signature; prints the counter it came back with, nothing else.
count() {
  ( cd "$REPO" && cargo run -q --release -p pqf-ctaphid --example tz_test \
      --target "$HOST" -- --count ) 2>&1 | sed -n 's/^signCount=//p'
}

prev=$(count)
[ -n "$prev" ] || { echo "  could not read the counter -- is the TZ-NS image up?"; exit 1; }
echo "start: $prev"
for i in $(seq 1 "$CYCLES"); do
  "$REBOOT" bootsel TZ >/dev/null 2>&1 || true
  sleep 5
  picotool reboot -a -c arm >/dev/null 2>&1
  sleep 9
  now=$(count)
  [ -n "$now" ] || { echo "cycle $i: no counter came back"; echo "STRESS FAILED"; exit 1; }
  [ "$now" -gt "$prev" ] || { echo "cycle $i: $prev -> $now (REWOUND)"; echo "STRESS FAILED"; exit 1; }
  echo "cycle $i: $prev -> $now"
  prev=$now
done
echo "STRESS PASSED: $CYCLES reboots, counter never rewound"
