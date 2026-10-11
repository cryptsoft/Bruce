#!/usr/bin/env bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# silicon-sweep.sh -- the full port x ML-DSA-level matrix on one board.
#
# Six configurations: both ports at ML-DSA 44, 65 and 87. Each is rebuilt
# from source, flashed, and then driven with the in-tree client:
# alg_roundtrip for the level's composite, pqc_roundtrip for whichever
# hybrid the build picks. Roughly half an hour. The broad CTAP 2.1
# conformance surface is the external conformance suite's job; set
# PQF_CONFORMANCE_CMD to a command that takes a COSE alg id as its last
# argument and it is run for each configuration as well.
#
# Built with PQF_TEST_NO_USER_BUTTON, because a conformance suite cannot
# press a button. That means these runs say nothing about the presence
# gate -- that is covered separately, on host (fido_hid, and the Rust
# gate's own suite) and by tools/tz/tz_test on silicon.
#
# TWO THINGS THIS SCRIPT LEARNED THE HARD WAY:
#
#   The readiness probe is liveness ONLY. An earlier version ran a full
#   conformance run to decide whether the board had come back, which conflated
#   "the device is present" with "every conformance check passes" -- and
#   each call takes ten-plus seconds, so the loop timed out while a
#   perfectly healthy token sat there working. It reported DID NOT
#   RE-ENUMERATE for a board that was answering. A readiness check must
#   not be the test.
#
#   Do not pipe this through `tail`. Results are written to
#   /tmp/silicon-results.txt as each configuration finishes precisely so
#   progress is visible; a pipe buffers everything until exit, and a run
#   that shows nothing for half an hour is indistinguishable from a hung
#   one.
set -u
cd "$(dirname "$0")/.."
: "${PICO_SDK_PATH:=$HOME/pico-sdk}"; export PICO_SDK_PATH
HOST=$(rustc -vV | awk '/^host:/{print $2}')
RESULTS=/tmp/silicon-results.txt
: > "$RESULTS"

bootsel() {
  # The TrustZone image needs the TZ form; the plain images take the
  # bare one. Try both -- a reboot that silently did nothing shows up
  # later as a mystery flash failure.
  ./c/hid/reboot bootsel >/dev/null 2>&1 || ./c/hid/reboot bootsel TZ >/dev/null 2>&1
  for _ in $(seq 1 20); do picotool info >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
# Liveness only. The first version of this ran a full conformance run as its
# readiness probe, which conflated "the device is back" with "every
# conformance check passes" -- and each call takes ten-plus seconds, so
# the loop timed out while the token was sitting there working. It
# reported DID NOT RE-ENUMERATE for a healthy device. A readiness check
# must not be the test.
wait_up() {
  for _ in $(seq 1 40); do
    sleep 1
    if ioreg -p IOUSB -l -w 0 2>/dev/null | grep -qi '"USB Product Name" = .*pqc'; then
      sleep 2   # let the HID interface settle before the first transaction
      return 0
    fi
  done
  return 1
}

# The composite COSE ids each level mints: the draft-ietf-jose-pq-
# composite-sigs-04 requests, still provisional. One place per level;
# must match crates/signer-core/src/mldsa_alg.rs and c/firmware/src/hybrid.h.
ALG_MLDSA44=-54
ALG_MLDSA65=-55
ALG_MLDSA87=-56

run_one() {  # port level alg
  local port lvl alg name
  port="$1"; lvl="$2"; alg="$3"; name="$port/ML-DSA-$lvl"
  echo "=== $name ==="
  bootsel || { echo "  $name: NEVER REACHED BOOTSEL" | tee -a "$RESULTS"; return 1; }

  if [ "$port" = C ]; then
    cmake -S c/firmware -B "c/firmware/build-sw$lvl" -DPQF_BOARD=feitian_rp2350 \
      -DPQF_HYBRID_VARIANT="$lvl" -DPQF_TEST_NO_USER_BUTTON=ON >/dev/null 2>&1 \
      && cmake --build "c/firmware/build-sw$lvl" -j8 >/dev/null 2>&1 \
      || { echo "  $name: BUILD FAILED" | tee -a "$RESULTS"; return 1; }
    picotool load "c/firmware/build-sw$lvl/bruce_c.uf2" >/dev/null 2>&1
  else
    case "$lvl" in 44) f=mldsa44;; 65) f=mldsa65;; 87) f=mldsa87;; esac
    cargo build -q --release --no-default-features \
      --features "$f,board_feitian_rp2350,test_no_user_button,reboot_no_up" \
      --target thumbv8m.main-none-eabihf -p bruce >/dev/null 2>&1 \
      || { echo "  $name: BUILD FAILED" | tee -a "$RESULTS"; return 1; }
    cp target/thumbv8m.main-none-eabihf/release/bruce "/tmp/rs$lvl.elf"
    picotool load "/tmp/rs$lvl.elf" >/dev/null 2>&1
  fi
  picotool reboot -a -c arm >/dev/null 2>&1
  wait_up || { echo "  $name: DID NOT RE-ENUMERATE" | tee -a "$RESULTS"; return 1; }

  local a b r
  a=$(BRUCE_PIN=123456 cargo run -q --release -p pqf-ctaphid --example alg_roundtrip \
        --target "$HOST" -- "$alg" 2>&1 | grep -E "round trip OK|signature|FAIL|error" | tr '\n' ' ')
  if [ -n "${PQF_CONFORMANCE_CMD:-}" ]; then
    b=$($PQF_CONFORMANCE_CMD "$alg" 2>&1 | grep -E "^passed |RESULT" | tr '\n' ' ')
  else
    b="(PQF_CONFORMANCE_CMD unset -- conformance run skipped)"
  fi
  r=$(BRUCE_PIN=123456 cargo run -q --release -p pqf-ctaphid --example pqc_roundtrip \
        --target "$HOST" 2>&1 | grep -E "round trip OK|signature" | tr '\n' ' ')
  printf '  %-16s alg_roundtrip: %s\n                   conformance:   %s\n                   pqc_roundtrip: %s\n' \
    "$name" "$a" "$b" "$r" | tee -a "$RESULTS"
}

run_one C    44 "$ALG_MLDSA44"
run_one C    65 "$ALG_MLDSA65"
run_one C    87 "$ALG_MLDSA87"
run_one Rust 44 "$ALG_MLDSA44"
run_one Rust 65 "$ALG_MLDSA65"
run_one Rust 87 "$ALG_MLDSA87"
echo; echo "=== summary ==="; cat "$RESULTS"
