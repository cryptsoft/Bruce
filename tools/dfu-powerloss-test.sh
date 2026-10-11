#!/usr/bin/env bash
# dfu-powerloss-test.sh -- exercise the DFU bootloader's install journal.
#
# The journal exists so that losing power during the staging->app copy
# does not leave a half-written application. Until 2026-09-01 it had
# never run: the obvious test is to pull the cable during the manifest,
# which needs a hand on the board and a window measured in milliseconds.
#
# It does not need that. What a power loss actually produces is a
# particular state in flash -- a staged image plus a pending journal --
# and the interesting code is what the NEXT boot does with it. That
# state can be written directly over BOOTSEL, which is what this does.
# The replay path is exercised for real; only the interruption is
# synthesised.
#
# Four cases, and the three refusals matter more than the success:
#
#   1. corrupt journal (bad check word)     -> must NOT install
#   2. valid journal + good staging         -> must install (the replay)
#   3. valid journal + corrupt staging      -> must refuse, clear journal
#   4. journal/staging total_len disagree   -> must refuse
#
# Case 4 is the one a power loss between the two writes really produces.
# Case 3 is the one that would install a broken application if the
# bootloader trusted the journal instead of re-verifying.
#
# Usage:
#   tools/dfu-powerloss-test.sh <good.dfu> <other.dfu>
#
# Both must be signed for THIS board (tools/pqf_sign.py --board ...) and
# `other` must differ visibly from what is installed -- the C and Rust
# ports share a VID:PID but not a product string ("Bruce (C port)"
# against "<board> PQC"), which makes "did it install?" a one-line check
# rather than a hash comparison.
#
# Requires a provisioned board: bootloader + an app already installed.
# Leaves the app slot holding whichever image case 2 installed.
#
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

GOOD="${1:-}"
OTHER="${2:-}"
[ -f "$GOOD" ] && [ -f "$OTHER" ] || {
    sed -n '2,40p' "$0"; exit 1
}

OUT="${PQF_PL_OUT:-$REPO/build-powerloss}"
mkdir -p "$OUT"

# Flash map, mirroring c/common/pqf_image.h. If those constants move,
# these must move with them -- a stale offset here writes the journal
# into the middle of the staging slot and the test silently means
# nothing.
STAGE_XIP=0x1010D000
STATE_XIP=0x101FA000
APP_XIP=0x10020000

PASS=0; FAIL=0
ok()   { printf '  \033[32mok\033[0m    %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
say()  { printf '\n== %s ==\n' "$1"; }

bootsel() {
    picotool info >/dev/null 2>&1 && return 0
    ./c/hid/reboot bootsel >/dev/null 2>&1
    for _ in $(seq 1 15); do sleep 1; picotool info >/dev/null 2>&1 && return 0; done
    echo "!! could not reach BOOTSEL" >&2; exit 1
}

# Build a journal record: magic "PQBS", state PENDING, total_len, and
# the xor check the bootloader recomputes (c/bootloader/src/main.c:327).
journal() { # <total_len> <outfile> [corrupt]
    python3 - "$1" "$2" "${3:-}" <<'PY'
import struct, sys
total = int(sys.argv[1]); out = sys.argv[2]; corrupt = sys.argv[3]
MAGIC, PENDING, CHECK = 0x53425150, 1, 0xA5A5A5A5
chk = (MAGIC ^ PENDING ^ total ^ CHECK) & 0xFFFFFFFF
if corrupt == "corrupt":
    chk ^= 0xFF
open(out, "wb").write(struct.pack("<IIII", MAGIC, PENDING, total, chk))
PY
}

running_vid() {
    for _ in $(seq 1 20); do
        sleep 1
        v=$(cargo run -q -p pqf-ctaphid --example probe \
              --target "$(rustc -vV | awk '/^host:/{print $2}')" 2>/dev/null \
            | awk '/DevSrvsID/{print $2}')
        [ -n "$v" ] && { echo "$v"; return 0; }
    done
    echo "none"
}

slot_version() {
    bootsel
    picotool save -r "$APP_XIP" 0x10021000 "$OUT/slot.bin" -t bin >/dev/null 2>&1 || return 1
    python3 tools/pqf_sign.py info --in "$OUT/slot.bin" 2>/dev/null \
        | awk '/fw_version/{print $2}'
}

journal_erased() {
    bootsel
    picotool save -r "$STATE_XIP" 0x101FA010 "$OUT/j.bin" -t bin >/dev/null 2>&1 || return 1
    python3 -c "import sys;d=open('$OUT/j.bin','rb').read();sys.exit(0 if set(d)=={0xff} else 1)"
}

stage_and_boot() { # <image> <journal>
    bootsel
    picotool load -t bin "$1" -o "$STAGE_XIP" >/dev/null 2>&1 || return 1
    picotool load -t bin "$2" -o "$STATE_XIP" >/dev/null 2>&1 || return 1
    picotool reboot >/dev/null 2>&1
    sleep 12
}

OTHER_LEN=$(wc -c < "$OTHER" | tr -d ' ')
GOOD_LEN=$(wc -c < "$GOOD" | tr -d ' ')
journal "$OTHER_LEN" "$OUT/j_valid.bin"
journal "$OTHER_LEN" "$OUT/j_bad.bin" corrupt
journal "$((OTHER_LEN - 4096))" "$OUT/j_mismatch.bin"
python3 -c "
import shutil; shutil.copy('$OTHER','$OUT/other_corrupt.dfu')
d=bytearray(open('$OUT/other_corrupt.dfu','rb').read()); d[len(d)//2]^=0xFF
open('$OUT/other_corrupt.dfu','wb').write(d)"

BEFORE=$(running_vid)
printf 'installed app enumerates as %s\n' "$BEFORE"

say "1. corrupt journal -- must not install"
stage_and_boot "$OTHER" "$OUT/j_bad.bin"
[ "$(running_vid)" = "$BEFORE" ] \
    && ok "a journal with a bad check word installed nothing" \
    || bad "a corrupt journal was acted on"

say "2. valid journal + good staging -- the replay"
stage_and_boot "$OTHER" "$OUT/j_valid.bin"
AFTER=$(running_vid)
[ "$AFTER" != "$BEFORE" ] && [ "$AFTER" != "none" ] \
    && ok "replay installed the staged image ($BEFORE -> $AFTER)" \
    || bad "replay did not install (still $AFTER)"
journal_erased && ok "journal cleared after a successful replay" \
                || bad "journal left pending -- it would replay every boot"
V=$(slot_version); printf '        app slot now fw_version %s\n' "${V:-?}"

say "3. valid journal + corrupt staging -- must refuse"
picotool reboot >/dev/null 2>&1; sleep 10
NOW=$(running_vid)
stage_and_boot "$OUT/other_corrupt.dfu" "$OUT/j_valid.bin"
[ "$(running_vid)" = "$NOW" ] \
    && ok "a corrupt staged image was refused, app untouched" \
    || bad "a corrupt staged image was installed"
journal_erased && ok "journal cleared even though the copy was refused" \
                || bad "journal left pending after a refusal"

say "4. journal and staging disagree on length -- must refuse"
picotool reboot >/dev/null 2>&1; sleep 10
NOW=$(running_vid)
stage_and_boot "$GOOD" "$OUT/j_mismatch.bin"
[ "$(running_vid)" = "$NOW" ] \
    && ok "a length mismatch was refused" \
    || bad "installed despite journal/staging disagreeing on length"

picotool reboot >/dev/null 2>&1
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
