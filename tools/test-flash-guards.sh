#!/usr/bin/env bash
# test-flash-guards.sh -- flash.sh's refusals, against a mock picotool.
#
# flash.sh decides from two `picotool info -a` readings (the image's
# markers and the board's) whether `picotool load` may run. A refusal
# that stops being reached is invisible: the script just flashes. So
# each case here gives the script a canned image and a canned board
# and checks both the exit status and whether `load` was called --
# the refusals, and the ordinary flashes that must still go through,
# because a guard that refuses everything passes every refusal test.
#
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
: > "$T/image.uf2"

# The mock: `info -a <file>` prints $MOCK_IMAGE, `info -a` prints
# $MOCK_BOARD (or fails when $MOCK_NO_BOARD is set, nothing in BOOTSEL),
# `load` records that it ran.
cat > "$T/bin/picotool" <<'MOCK'
#!/usr/bin/env bash
case "$1" in
    info)
        if [ $# -ge 3 ]; then printf '%b\n' "$MOCK_IMAGE"; exit 0; fi
        [ -n "${MOCK_NO_BOARD:-}" ] && exit 1
        printf '%b\n' "$MOCK_BOARD"; exit 0 ;;
    load) : > "$MOCK_LOADED"; exit 0 ;;
esac
exit 1
MOCK
chmod +x "$T/bin/picotool"

markers() {  # markers <board> <reboot> -> picotool-style program info
    local m="Program Information\n name: bruce\n"
    [ -n "$1" ] && m="$m pqf-board=$1\n"
    [ -n "$2" ] && m="$m pqf-reboot=$2\n"
    printf '%s pqf-fido-up=touch\n pqf-rk-slots=41' "$m"
}
BLANK="Program Information\n none"

# case <label> <want rc> <want load yes|no> <image> <board> [env/args...]
case_() {
    local label="$1" want_rc="$2" want_load="$3" image="$4" board="$5"; shift 5
    local envs=() args=()
    for a in "$@"; do
        case "$a" in *=*) envs+=("$a") ;; *) args+=("$a") ;; esac
    done
    rm -f "$T/loaded"
    local rc
    env PATH="$T/bin:$PATH" MOCK_IMAGE="$image" MOCK_BOARD="$board" \
        MOCK_LOADED="$T/loaded" ${envs[@]+"${envs[@]}"} \
        ./flash.sh -y ${args[@]+"${args[@]}"} "$T/image.uf2" >"$T/out" 2>&1
    rc=$?
    local loaded=no; [ -f "$T/loaded" ] && loaded=yes
    if [ "$rc" = "$want_rc" ] && [ "$loaded" = "$want_load" ]; then
        ok "$label"
    else
        bad "$label" "rc $rc (want $want_rc), load $loaded (want $want_load): $(tr '\n' ' ' < "$T/out" | cut -c1-200)"
    fi
}

FEITIAN_TOUCH=$(markers feitian_rp2350 touch)
TINY_TOUCH=$(markers tiny2350 touch)
USBC_NOTOUCH=$(markers feitian_rp2350_usbc no-touch)
FEITIAN_NOREBOOT=$(markers feitian_rp2350 "")
FEITIAN_ODD=$(markers feitian_rp2350 sometimes)
NO_MARKERS="Program Information\n name: something"

echo "-- a board in BOOTSEL with no marker (blank, or not ours) --"
case_ "blank board, no --board: refused, nothing written" 2 no "$FEITIAN_TOUCH" "$BLANK"
case_ "blank board named as the image's board: flashed" 0 yes "$FEITIAN_TOUCH" "$BLANK" --board feitian_rp2350
case_ "FLASH_BOARD= does the same as --board" 0 yes "$FEITIAN_TOUCH" "$BLANK" FLASH_BOARD=feitian_rp2350
case_ "blank board named as the USB-C token: refused" 2 no "$FEITIAN_TOUCH" "$BLANK" --board feitian_rp2350_usbc
case_ "blank board named as another board than the image's: refused" 2 no "$FEITIAN_TOUCH" "$BLANK" --board tiny2350
case_ "an image with no markers onto a named blank board: refused" 2 no "$NO_MARKERS" "$BLANK" --board feitian_rp2350
case_ "an unknown board id: refused" 1 no "$FEITIAN_TOUCH" "$BLANK" --board pico9
case_ "-y does not stand in for --board" 2 no "$TINY_TOUCH" "$BLANK"

echo "-- a board that carries a USB-C token image --"
case_ "a touch image: refused" 2 no "$FEITIAN_TOUCH" "$USBC_NOTOUCH"
case_ "an image with no reboot marker: refused" 2 no "$FEITIAN_NOREBOOT" "$USBC_NOTOUCH"
case_ "an image with an unknown reboot policy: refused" 2 no "$FEITIAN_ODD" "$USBC_NOTOUCH"
case_ "an image with no markers at all: refused" 2 no "$NO_MARKERS" "$USBC_NOTOUCH"
case_ "a touch image with FLASH_BOARD_IS_DEV=1 (a rehearsal board): flashed" 0 yes "$FEITIAN_TOUCH" "$USBC_NOTOUCH" FLASH_BOARD_IS_DEV=1
case_ "a no-touch USB-C image, rehearsal allowed: flashed" 0 yes "$USBC_NOTOUCH" "$USBC_NOTOUCH" FLASH_ALLOW_USBC_IMAGE=1

echo "-- images built for the USB-C token --"
case_ "a USB-C image onto a development board: refused" 2 no "$USBC_NOTOUCH" "$FEITIAN_TOUCH"
case_ "a USB-C image onto a blank board: refused" 2 no "$USBC_NOTOUCH" "$BLANK"
case_ "a USB-C image rehearsed on a named blank dev board: flashed" 0 yes "$USBC_NOTOUCH" "$BLANK" --board tiny2350 FLASH_ALLOW_USBC_IMAGE=1

echo "-- the ordinary reflash still goes through --"
case_ "same board, same image kind: flashed" 0 yes "$FEITIAN_TOUCH" "$FEITIAN_TOUCH"
case_ "another dev board's image: flashed (with a note)" 0 yes "$TINY_TOUCH" "$FEITIAN_TOUCH"
case_ "a matching --board on a marked board: flashed" 0 yes "$FEITIAN_TOUCH" "$FEITIAN_TOUCH" --board feitian_rp2350
case_ "nothing in BOOTSEL: refused" 1 no "$FEITIAN_TOUCH" "$BLANK" MOCK_NO_BOARD=1

printf '\n%d checks, %d failure(s)\n' "$((PASS+FAIL))" "$FAIL"
[ "$FAIL" = 0 ]
