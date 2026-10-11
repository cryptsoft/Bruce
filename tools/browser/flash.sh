#!/usr/bin/env bash
# flash.sh -- put the before-fix or after-fix firmware on the token, for
# the browser check next door.
#
#   tools/browser/flash.sh before   # the parameter numbering as it was
#   tools/browser/flash.sh after    # as CTAP 2.1 specifies
#
# largeblob-check.html is only evidence if it is run against both. A
# pass on `before` would mean the whole finding is wrong, which is worth
# more than a pass on `after`.
#
# `before` is built from the commit prior to the fix rather than from a
# hand-reverted tree, so it is the real previous firmware and not an
# approximation of it. That commit is in the development history only:
# the published repository is a single commit, so there `before` stops
# with a message and only `after` runs (tools/browser/README.md).
#
# REFUSES TO FLASH THE WRONG BOARD. A device being in BOOTSEL is not
# evidence it is the one you meant: a board from an unrelated project on
# the same host looks identical, and flashing it would erase that
# firmware. `picotool info` reports the program name, so the name is
# checked.
#
# SPDX-License-Identifier: Apache-2.0
set -u

WHICH="${1:-}"
case "$WHICH" in before|after) ;; *) echo "usage: $0 before|after" >&2; exit 2 ;; esac

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
: "${PICO_SDK_PATH:=$HOME/pico-sdk}"
export PICO_SDK_PATH

# The commit before the wire-format corrections landed (the parent of
# 64ce6a3, "make the three unreachable commands reachable"). Hashes are
# those of the current history; `before` needs that history present --
# a checkout that was squashed or shallow-cloned cannot build it, and
# says so below rather than building something else.
BEFORE_REF="${BEFORE_REF:-0782c7a}"

# ---- 1. the board has to be the right board --------------------------

picotool info >/dev/null 2>&1 || {
    echo "  no board in BOOTSEL. Hold BOOT, tap RESET, try again." >&2
    exit 1
}
NAME=$(picotool info 2>/dev/null | awk '/^ name:/ {print $2}')
echo "  board in BOOTSEL reports: ${NAME:-<none>}"
case "$NAME" in
    Bruce|bruce_c|bruce) ;;
    "")
        echo "  REFUSING: the board reports no program name. That is either a" >&2
        echo "  blank chip or something this script cannot identify. Set" >&2
        echo "  ALLOW_UNKNOWN_BOARD=1 if you are certain." >&2
        [ "${ALLOW_UNKNOWN_BOARD:-0}" = 1 ] || exit 1 ;;
    *)
        # Named override: OVERWRITE_BOARD must equal the program name
        # being erased, so the decision names its own casualty and a
        # stale env var cannot silently wipe a different board later.
        if [ "${OVERWRITE_BOARD:-}" = "$NAME" ]; then
            echo "  OVERWRITE_BOARD=$NAME -- erasing '$NAME' as instructed."
        else
            echo "  REFUSING: that is '$NAME', not this project's firmware." >&2
            echo "  Flashing it would erase whatever it is." >&2
            echo "  If that is intended: OVERWRITE_BOARD=$NAME $0 $WHICH" >&2
            exit 1
        fi ;;
esac

# ---- 2. build ---------------------------------------------------------

if [ "$WHICH" = before ]; then
    WT=/tmp/pqf-before
    BUILD=/tmp/pqf-before-build
    git -C "$REPO" cat-file -e "$BEFORE_REF^{commit}" 2>/dev/null \
        || { echo "  $BEFORE_REF is not in this history (squashed or shallow clone?) -- \`before\` needs the full history" >&2; exit 1; }
    [ -d "$WT" ] || git -C "$REPO" worktree add "$WT" "$BEFORE_REF" >/dev/null 2>&1 \
        || { echo "  could not create the before-fix worktree" >&2; exit 1; }
    SRC="$WT/c/firmware"
    echo "  building the BEFORE image from $(git -C "$WT" rev-parse --short HEAD)"
else
    BUILD="$REPO/c/firmware/build-ship65"
    SRC="$REPO/c/firmware"
    echo "  building the AFTER image from $(git -C "$REPO" rev-parse --short HEAD)"
fi

cmake -S "$SRC" -B "$BUILD" -DPQF_BOARD=feitian_rp2350 \
      -DPQF_HYBRID_VARIANT=65 -DPQF_REBOOT_NO_UP=ON >/tmp/pqf-fl-cm.log 2>&1 \
  || { echo "  cmake configure failed (/tmp/pqf-fl-cm.log)" >&2; exit 1; }
grep -q "PQF_REBOOT_NO_UP" /tmp/pqf-fl-cm.log \
  || { echo "  REFUSING: the configure output does not mention the reboot" >&2
       echo "  escape, so this image would have no software way back." >&2; exit 1; }
cmake --build "$BUILD" -j8 >/tmp/pqf-fl-build.log 2>&1 \
  || { echo "  build failed (/tmp/pqf-fl-build.log)" >&2; exit 1; }

IMAGE="$BUILD/bruce_c.uf2"
[ -f "$IMAGE" ] || { echo "  no image at $IMAGE" >&2; exit 1; }
echo "  built $(basename "$IMAGE"), $(wc -c <"$IMAGE" | tr -d ' ') bytes"

# ---- 3. flash ---------------------------------------------------------

picotool load "$IMAGE" >/dev/null 2>&1 || { echo "  load failed" >&2; exit 1; }
picotool reboot -a -c arm >/dev/null 2>&1
echo "  flashed the $WHICH image; waiting for it to come back..."
for _ in $(seq 1 20); do
    ls /dev/cu.usbmodem* >/dev/null 2>&1 && break
    sleep 1
done
ls /dev/cu.usbmodem* >/dev/null 2>&1 \
  && echo "  re-enumerated. Now run the browser check." \
  || echo "  it did not re-enumerate -- check the board before running anything."

cat <<'TXT'

  Next:
    python3 -m http.server -d tools/browser 8765
    open http://localhost:8765/largeblob-check.html

  On the BEFORE image the write step should fail.
  On the AFTER image the blob should round-trip.
TXT
