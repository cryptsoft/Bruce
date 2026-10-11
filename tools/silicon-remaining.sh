#!/usr/bin/env bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# silicon-remaining.sh -- run the hardware tests that were still owed after
# the 2026-08-17 validation run (see docs/TESTING.md, "Silicon validation
# status"). Everything here needs a real token; nothing here can be faked
# on the host, which is why it is a script rather than a CI job.
#
#   1. GDB stub      -- enumerate, confirm the 2nd CDC appears, attach gdb
#   2. TrustZone     -- M1/M2b/M3: LED, CTAPHID PING, getInfo via gateway
#   3. USB gadget    -- separate firmware; confirm it enumerates as a NIC
#
# ORDER MATTERS AND THE GADGET IS LAST ON PURPOSE. Its firmware is not a
# FIDO device and carries no BOOTSEL path of its own, so once it is
# flashed there is NO software route back -- CTAPHID reboot cannot reach
# it and picotool cannot see it. It strands the token until someone holds
# BOOT and taps RESET. Learned the hard way on 2026-08-17: running it
# second cost the TrustZone stage its turn.
#
# NOT run here, deliberately:
#   - DFU. No longer because it is unproven -- it works end to end, see
#     docs/DFU.md "Silicon status" -- but because provisioning replaces
#     the bootloader, so a stage that flashed it would leave every later
#     stage running against a different image. Drive it by hand.
#   - The arena shrink. Fails in a way that costs you the working token
#     (an undersized arena gives you signatures that never complete). Use
#     a spare board and docs/ by hand.
#   - Secure boot. tools/secureboot-provision.sh stages it deliberately;
#     the final fuse must never be automated. See docs/SECUREBOOT.md.
#   - Real-browser WebAuthn. Confirmed working by the author against a
#     live site (registration, login and passkey management); nothing
#     here re-runs it.
#
# Usage: hold BOOT, tap RESET, then
#     ./tools/silicon-remaining.sh [gdb|gadget|trustzone|all]
#
# Each stage leaves the token in BOOTSEL for the next. If a stage finds the
# device dark, it STOPS rather than cascading -- that failure is intermittent
# (about one flash in nine, see docs/FLASHING.md) and is not evidence
# against whatever was being flashed. Press BOOT+RESET and re-run.

set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
: "${PICO_SDK_PATH:=$HOME/pico-sdk}"
export PICO_SDK_PATH
OUT=${OUT:-/tmp/silicon-remaining}; mkdir -p "$OUT"
STAGE=${1:-all}

say() { printf '\n=== %s ===\n' "$1"; }
need_bootsel() {
    for _ in $(seq 1 20); do picotool info >/dev/null 2>&1 && return 0; sleep 1; done
    echo "!! not in BOOTSEL -- hold BOOT, tap RESET, re-run" >&2; exit 1
}
flash() { # <uf2>
    need_bootsel
    picotool erase -a >/dev/null 2>&1
    picotool load -x "$1" >/dev/null 2>&1 || { echo "!! flash failed" >&2; exit 1; }
    sleep 9
}
HOST=$(rustc -vV | awk '/^host:/{print $2}')
# INIT + PING + the full getInfo map, from the in-tree client.
probe() { cargo run -q --release -p pqf-ctaphid --example probe --target "$HOST" 2>&1; }
enumerated() { probe | grep -q authenticatorGetInfo; }
dark_stop() {
    echo "!! device is dark. This is the intermittent failure (~1 flash in 9)," >&2
    echo "   NOT evidence against $1. BOOT+RESET and re-run." >&2
    exit 2
}

# ---------------------------------------------------------------- GDB stub
if [ "$STAGE" = gdb ] || [ "$STAGE" = all ]; then
    say "1/3 GDB stub on silicon"
    d=$OUT/build-gdb
    cmake -S c/firmware -B "$d" -DCMAKE_BUILD_TYPE=Release -DPQF_BOARD=feitian_rp2350 \
        -DPQF_HYBRID_VARIANT=65 -DPQF_GDB_STUB=ON -DPQF_TEST_NO_USER_BUTTON=ON >/dev/null 2>&1
    cmake --build "$d" -j8 >/dev/null 2>&1 || { echo "!! build failed"; exit 1; }
    flash "$d/bruce_c.uf2"
    enumerated || dark_stop "the GDB stub"
    echo "FIDO still works with the stub linked:"
    probe | grep -E 'f1d0|caps:|alg=' | sed 's/^/    /'
    echo "CDC interfaces (the stub adds a 2nd; docs/GDB_DEBUG.md says it is the HIGHER-numbered tty):"
    ls /dev/cu.usbmodem* 2>/dev/null | sed 's/^/    /'
    GDBTTY=$(ls /dev/cu.usbmodem* 2>/dev/null | sort | tail -1)
    echo "Attaching arm-none-eabi-gdb to $GDBTTY ..."
    arm-none-eabi-gdb -q -batch -ex "set confirm off" -ex "set pagination off" \
        -ex "target remote $GDBTTY" -ex "info registers pc sp" \
        -ex "break pqf_mldsa_sign" -ex "detach" \
        "$d/bruce_c.elf" 2>&1 | sed 's/^/    /'
    echo "^ PC/SP read and a breakpoint set over USB = the DebugMonitor + FPB path the"
    echo "  host harness could only stub. That is the part that was still owed."
    ( cd c/hid && ./reboot bootsel ) >/dev/null 2>&1; sleep 3
fi

# ------------------------------------------------------------- TrustZone
if [ "$STAGE" = trustzone ] || [ "$STAGE" = all ]; then
    say "2/3 TrustZone-M split (crates/fw-secure + crates/fw-nonsecure, in tree)"
    ./build-tz.sh 2>&1 | tail -3 | sed 's/^/    /'
    [ -f fw-secure.uf2 ] && [ -f fw-nonsecure.uf2 ] || { echo "!! build-tz.sh produced no images"; exit 1; }
    need_bootsel
    picotool erase -a >/dev/null 2>&1
    # Order matters: -x executes after load, so Secure must be written LAST
    # or it branches into NS flash that is not there yet.
    picotool load    fw-nonsecure.uf2 >/dev/null 2>&1
    picotool load -x fw-secure.uf2    >/dev/null 2>&1
    sleep 8
    echo "M1  -- LED blinking? (S->NS handoff + SG veneer call) -- LOOK AT THE TOKEN"
    echo "M2b -- CTAPHID present, caps 0x0d, PING round-trips:"
    probe | grep -E 'f1d0|caps:|PING' | sed 's/^/    /'
    echo "M3  -- getInfo via the Secure sg_get_info gateway:"
    probe | grep -E 'versions:|aaguid:' | sed 's/^/    /'
    echo "!! This OVERWRITES the FIDO firmware -- reflash with ./flash.sh after."
fi

# ------------------------------------------------------------ USB gadget
if [ "$STAGE" = gadget ] || [ "$STAGE" = all ]; then
    say "3/3 USB CDC-NCM network gadget"
    d=$OUT/build-gadget
    cmake -S c/gadget -B "$d" -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1
    cmake --build "$d" -j8 >/dev/null 2>&1 || { echo "!! build failed"; exit 1; }
    uf2=$(ls "$d"/*.uf2 2>/dev/null | head -1)
    flash "$uf2"
    echo "This firmware is NOT a FIDO token -- it should appear as a network interface:"
    ifconfig 2>/dev/null | grep -iE "^en[0-9]+|NCM|RNDIS" | sed 's/^/    /'
    networksetup -listallhardwareports 2>/dev/null | grep -iB1 -A2 "usb" | sed 's/^/    /'
    echo "Documented success (c/gadget/README.md) is more than enumeration:"
    echo "  the device should serve DHCP on 192.168.7.1/24 and answer a ping."
    ping -c 3 -t 5 192.168.7.1 2>&1 | tail -3 | sed 's/^/    /'
    echo
    echo "!! THE TOKEN IS NOW STRANDED. This firmware is not a FIDO device and has"
    echo "   no BOOTSEL path, so nothing in software can reach it. Hold BOOT and tap"
    echo "   RESET to get it back, then reflash a normal build."
fi

say "done"
echo "Reflash a normal build before carrying the token:"
echo "    cmake -S c/firmware -B build -DPQF_BOARD=feitian_rp2350 -DPQF_HYBRID_VARIANT=65"
echo "    cmake --build build -j8 && picotool erase -a && picotool load -x build/bruce_c.uf2"
