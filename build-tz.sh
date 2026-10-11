#!/usr/bin/env bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# build-tz.sh -- build the TrustZone-M split images (Milestone 1).
#
# Builds the Secure image first (it emits the veneer import library
# target/nsc/libnsclib.a), then the Non-secure image (which links
# against it), then converts both ELFs to UF2. See docs/TRUSTZONE.md.
#
# Flashing (with the board in BOOTSEL): load BOTH. ORDER AND FLAGS
# MATTER -- this header used to say "-x" on both, Secure first, which
# does not work and the M1 bring-up corrected it (docs/TRUSTZONE.md):
#
#   picotool load    fw-nonsecure.uf2     # write only, do NOT execute
#   picotool load -x fw-secure.uf2        # write, then run
#
# -x means execute-after-load. The boot ROM runs the Secure image, which
# hands off to the NS image, so the NS flash must already be written
# when Secure starts. Loading Secure with -x first makes it branch into
# unwritten NS flash.
#
# Current state (M4c): the device enumerates as a CTAPHID token whose USB
# stack, CTAPHID framing and CBOR demux all run Non-secure, calling into
# Secure for service. Exit checks, cheapest first:
#   - LED blinks              -> S->NS handoff + SG veneer call work (M1)
#   - the probe example sees caps 0x0d and PING round-trips  (M2b-2)
#   - probe's getInfo succeeds via the sg_get_info gateway     (M3)
#   - tools/tz/tz_transport.c  -> multi-frame reassembly           (M4a)
#   - the tz_test example      -> Secure-only credential keys      (M4c)
#
# It ENUMERATING at all is itself an assertion: the NS image runs a
# fail-closed self-test over every veneer first (M5), and refuses to
# bring USB up if any of them accepts a Secure pointer.
#
# TZ_DEV_ESCAPE=1 ./build-tz.sh adds the dev-escape feature to BOTH
# images: a CTAPHID reboot command (c/hid/reboot bootsel TZ) and a Secure
# dead-man'"'"'s switch that reclaims the board if NS stops checking in.
# Dev only -- it lets NS reach BOOTSEL. The default build leaves it out,
# so a default image has no such path; get back into the bootloader with
# the board's BOOT button.
#
# This is a standalone experiment; it OVERWRITES the FIDO firmware, so
# reflash ./flash.sh (or the real UF2) afterward to restore normal
# operation.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

# Off by default; see the header. Both crates get the same answer, which
# the libnsclib.a note below is about.
TZ_FEATURES=""
if [ "${TZ_DEV_ESCAPE:-0}" = "1" ]; then
    TZ_FEATURES="--features dev-escape"
    echo ">> TZ_DEV_ESCAPE=1: building both images WITH the dev escape (NS can reach BOOTSEL)"
else
    echo ">> building without the dev escape (TZ_DEV_ESCAPE=1 adds it)"
fi

# ORDER AND FEATURES BOTH MATTER. target/nsc/libnsclib.a is shared state
# between the two crates: it lists the veneers the Secure image actually
# exported. Build Secure in one configuration and Non-secure in another
# and you get an undefined-symbol link error at best -- or, if the
# mismatch happens to resolve, an image calling a veneer that is not
# there. Always build both from the same feature set.
echo ">> building Secure image (emits target/nsc/libnsclib.a)"
# The touch is NOT superstition. libnsclib.a is a side effect of
# fw-secure's build.rs, and cargo only runs build.rs when it decides the
# crate is stale. Build fw-secure for feature set A, then for feature
# set B that it has already cached, and cargo reports "Fresh" -- so
# build.rs does not re-run and the implib left on disk still belongs to
# A. The Non-secure image then links against the wrong veneer table:
# either an undefined-symbol error, or worse, a silent link against a
# table that happens to resolve.
#
# This has bitten twice. Once it looked like a dead board (the dev NS
# build failed to link, cargo left the previous PRODUCTION binary in
# place, and that got flashed and would not enumerate).
touch crates/fw-secure/src/main.rs
# shellcheck disable=SC2086
( cd crates/fw-secure && cargo build --release $TZ_FEATURES )

echo ">> building Non-secure image (links the veneer import library)"
# shellcheck disable=SC2086
( cd crates/fw-nonsecure && cargo build --release $TZ_FEATURES )

echo ">> converting to UF2"
picotool uf2 convert -t elf \
    crates/fw-secure/target/thumbv8m.main-none-eabihf/release/fw-secure \
    fw-secure.uf2 --family rp2350-arm-s
picotool uf2 convert -t elf \
    crates/fw-nonsecure/target/thumbv8m.main-none-eabihf/release/fw-nonsecure \
    fw-nonsecure.uf2 --family rp2350-arm-s

ls -la fw-secure.uf2 fw-nonsecure.uf2
echo "done. Flash in THIS order:"
echo "    picotool load    fw-nonsecure.uf2"
echo "    picotool load -x fw-secure.uf2"
echo "LED blink = boundary proven; then the probe example's getInfo (M3)."
