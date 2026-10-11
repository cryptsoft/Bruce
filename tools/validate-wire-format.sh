#!/usr/bin/env bash
# validate-wire-format.sh -- silicon validation for the CTAP 2.1 wire-format
# corrections: the largeBlobs / credentialManagement / authenticatorConfig
# parameter renumbering, and the GetAssertion allowList fix.
#
# Those changes are host-tested and cannot be finished on the host: they
# alter what goes over the USB cable, so the only thing that settles them
# is a token answering a real client. This runs that, for one port at a
# time, and refuses to flash anything it cannot get back out of.
#
#   tools/validate-wire-format.sh c        # the C port
#   tools/validate-wire-format.sh rust     # the Rust port
#
# The images are built with PQF_REBOOT_NO_UP / reboot_no_up: FIDO user
# presence for MakeCredential and GetAssertion stays fully enforced, so
# the token is still a real authenticator and the ceremonies below are
# real ceremonies. Only CMD_REBOOT skips the touch, which is what gives
# an unattended run a way back to BOOTSEL. Do NOT substitute
# PQF_TEST_NO_USER_BUTTON: it auto-confirms every gesture, and a run
# against it proves nothing about presence.
#
# What it does not cover: a real browser. Chrome driving passkey
# management is the one thing that turns "no conformant client could use
# these commands" from a strong inference into an observation, and it
# needs a human. See docs/TESTING.md.
#
# SPDX-License-Identifier: Apache-2.0
set -u

PORT="${1:-}"
case "$PORT" in
  c|rust) ;;
  *) echo "usage: $0 c|rust" >&2; exit 2 ;;
esac

REPO="$(cd "$(dirname "$0")/.." && pwd)"
: "${PICO_SDK_PATH:=$HOME/pico-sdk}"
export PICO_SDK_PATH
HOST=$(rustc -vV | awk '/^host:/{print $2}')
# The credentialManagement / largeBlobs / authenticatorConfig wire
# checks need a full CTAP 2.1 conformance client, which is not part of
# this repository. Point PQF_CONFORMANCE_CMD at one (it is run with the
# COSE alg id as its last argument); without it those steps are named
# as skipped rather than passed over in silence.
example() { # <name> [args...]
    local name="$1"; shift
    BRUCE_PIN="${BRUCE_PIN:-123456}" cargo run -q --release -p pqf-ctaphid \
        --example "$name" --target "$HOST" -- "$@"
}

# The composite COSE id of the ML-DSA-65 image this script builds: the
# draft-ietf-jose-pq-composite-sigs-04 request, still provisional. Must
# match crates/signer-core/src/mldsa_alg.rs and c/firmware/src/hybrid.h.
ALG_MLDSA65=-55

fail=0
step() { printf '\n=== %s ===\n' "$1"; }
ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }

# The running token is found over HID, never by a serial port: the Rust
# port exposes no CDC serial interface at all, and a serial device on
# the host could be anything. c/hid/reboot --list matches only this
# project's FIDO device (its product id, and the 0xcafe vendor id or
# the Bruce manufacturer string), opens nothing and sends nothing --
# the same poll tools/flash-usbc.sh uses.
REBOOT_TOOL="$REPO/c/hid/reboot"
make -s -C "$REPO/c/hid" reboot >/tmp/pqf-hid.log 2>&1 \
  || { bad "could not build c/hid/reboot (see /tmp/pqf-hid.log)"; exit 1; }
token_running() { "$REBOOT_TOOL" --list >/dev/null 2>&1; }

# ---- 1. the token has to be here -------------------------------------

# A board being in BOOTSEL is not evidence it is the one you meant: a
# board from an unrelated project on the same host looks identical, and
# flashing it would erase its firmware. picotool reports the program
# name, so check it. Learned by nearly doing it.
check_board() {
    local name
    name=$(picotool info 2>/dev/null | awk '/^ name:/ {print $2}')
    case "$name" in
        Bruce|bruce_c|bruce) ok "board is ${name}" ;;
        "") if [ "${ALLOW_UNKNOWN_BOARD:-0}" = 1 ]; then
                ok "board reports no name; ALLOW_UNKNOWN_BOARD is set"
            else
                bad "the board reports no program name -- blank chip, or not ours"
                echo "  set ALLOW_UNKNOWN_BOARD=1 if you are certain" >&2
                exit 1
            fi ;;
        *)  if [ "${OVERWRITE_BOARD:-}" = "$name" ]; then
                ok "OVERWRITE_BOARD=$name -- erasing '$name' as instructed"
            else
                bad "that is '$name', not this project's firmware"
                echo "  Flashing it would erase whatever it is." >&2
                echo "  If that is intended: OVERWRITE_BOARD=$name $0 $PORT" >&2
                exit 1
            fi ;;
    esac
}

step "locating the token"
if picotool info >/dev/null 2>&1; then
    ok "in BOOTSEL"
    check_board
elif token_running; then
    ok "running; asking it to reboot into BOOTSEL"
    # CMD_REBOOT mode 0x01. Ungated on these builds, so no touch needed;
    # on an image with the gate, press the button when the LED asks.
    "$REBOOT_TOOL" bootsel >/dev/null 2>&1 \
      || echo "  (the reboot was not accepted; hold BOOT and tap RESET)"
    for _ in $(seq 1 20); do
        picotool info >/dev/null 2>&1 && break
        sleep 1
    done
    picotool info >/dev/null 2>&1 || { bad "never reached BOOTSEL"; exit 1; }
    ok "reached BOOTSEL"
    check_board
else
    echo "  no token found. Plug it in and run this again." >&2
    exit 1
fi

# ---- 2. build, with the escape verified -------------------------------

step "building the $PORT image (ML-DSA-65, reboot escape on)"
if [ "$PORT" = c ]; then
    BUILD="$REPO/c/firmware/build-ship65"
    cmake -S "$REPO/c/firmware" -B "$BUILD" \
          -DPQF_BOARD=feitian_rp2350 -DPQF_HYBRID_VARIANT=65 \
          -DPQF_REBOOT_NO_UP=ON >/tmp/pqf-cm.log 2>&1 \
      || { bad "cmake configure (see /tmp/pqf-cm.log)"; exit 1; }
    grep -q "PQF_REBOOT_NO_UP" /tmp/pqf-cm.log \
      || { bad "the configure output does not mention the reboot escape"; exit 1; }
    cmake --build "$BUILD" -j8 >/tmp/pqf-build.log 2>&1 \
      || { bad "build (see /tmp/pqf-build.log)"; exit 1; }
    IMAGE="$BUILD/bruce_c.uf2"
    ok "built $(basename "$IMAGE")"
    picotool load "$IMAGE" >/dev/null 2>&1 || { bad "picotool load"; exit 1; }
else
    ( cd "$REPO" && cargo build --release --no-default-features \
        --features mldsa65,board_feitian_rp2350,reboot_no_up \
        --target thumbv8m.main-none-eabihf -p bruce ) >/tmp/pqf-build.log 2>&1 \
      || { bad "cargo build (see /tmp/pqf-build.log)"; exit 1; }
    IMAGE="$REPO/target/thumbv8m.main-none-eabihf/release/bruce"
    # flash-fw.sh refuses an image with no software escape, which is the
    # whole point of routing through it rather than calling picotool.
    "$REPO/tools/flash-fw.sh" "$IMAGE" || { bad "flash refused or failed"; exit 1; }
fi
picotool reboot -a -c arm >/dev/null 2>&1
for _ in $(seq 1 20); do
    token_running && break
    sleep 1
done
token_running || { bad "the token did not re-enumerate as this project's FIDO device"; exit 1; }
ok "re-enumerated (c/hid/reboot --list sees it)"

# ---- 3. the commands the renumbering was about ------------------------

step "alg_roundtrip $ALG_MLDSA65 (the composite this build mints)"
out=$(example alg_roundtrip "$ALG_MLDSA65" 2>&1); rc=$?
printf '%s\n' "$out" | tail -20
[ "$rc" = 0 ] && ok "alg_roundtrip $ALG_MLDSA65" || bad "alg_roundtrip $ALG_MLDSA65"

step "largeBlobs, credentialManagement, authenticatorConfig"
# These three are what the renumbering changed. The conformance suite
# exercises credential management and largeBlobs; anything it cannot
# reach is named here rather than passed over in silence.
if [ -n "${PQF_CONFORMANCE_CMD:-}" ]; then
    # Once: the status reported is the status of the output shown.
    out=$($PQF_CONFORMANCE_CMD "$ALG_MLDSA65" 2>&1); rc=$?
    printf '%s\n' "$out" | tail -30
    [ "$rc" = 0 ] && ok "conformance suite" || bad "conformance suite"
else
    bad "PQF_CONFORMANCE_CMD unset -- the wire checks for these three commands did not run"
fi

step "pqc_roundtrip"
out=$(example pqc_roundtrip 2>&1); rc=$?
printf '%s\n' "$out" | tail -10
[ "$rc" = 0 ] && ok "roundtrip" || bad "roundtrip"

printf '\n'
[ "$fail" = 0 ] && echo "all silicon checks passed ($PORT port)" \
                || echo "SOMETHING FAILED ($PORT port) -- read the output above"
exit "$fail"
