#!/usr/bin/env bash
# ascii-check.sh -- refuse non-ASCII bytes in text files.
#
# This repository is ASCII only: source, docs, scripts, build files and
# commit messages. Not as a style preference but so that every byte of it
# reads the same in a serial console, a hex dump, a diff on a machine with
# no fonts, and a grep with any locale. The conversion that established
# it is recorded in docs/BUILD.md ("ASCII only").
#
# Modes:
#   ascii-check.sh --staged        the index, as a pre-commit hook sees it
#   ascii-check.sh --all           every tracked file (tools/host-tests.sh)
#   ascii-check.sh FILE...         the named files on disk
#
# Binary files are skipped by git's own heuristic (`git grep -I`) or, for
# files on disk, by a NUL byte in the first 8 KiB. Every hit is printed as
# file:line:column with the code point, so it can be fixed rather than
# hunted for. Exit 1 on any hit.
#
# Bypass, if you genuinely mean it:  git commit --no-verify
#
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail
export LC_ALL=C

report() {   # stdin: "path:line:text" lines from grep; print path:line:col U+XXXX
    if command -v python3 >/dev/null 2>&1; then
        python3 -c '
import sys
for raw in sys.stdin.buffer.read().split(b"\n"):
    if not raw: continue
    path, line, text = raw.split(b":", 2)
    col = 0
    for i, byte in enumerate(text):
        if byte > 127:
            col = i + 1; break
    try:
        ch = text[col-1:].decode("utf-8", "replace")[0]
        cp = "U+%04X" % ord(ch)
    except Exception:
        cp = "byte 0x%02X" % text[col-1]
    print("  %s:%s:%d  %s" % (path.decode(), line.decode(), col, cp))'
    else
        sed 's/^/  /'
    fi
}

hits=""
case "${1:-}" in
    --staged)
        # Paths staged for add/copy/modify/rename; `git grep --cached -I`
        # reads the index and skips what git considers binary.
        paths=$(git diff --cached --name-only --diff-filter=ACMR -z | tr '\0' '\n')
        [ -n "$paths" ] || exit 0
        hits=$(printf '%s\n' "$paths" | tr '\n' '\0' | \
               xargs -0 git grep -I -n -e '[^[:print:][:space:]]' --cached -- 2>/dev/null)
        ;;
    --all)
        hits=$(git grep -I -n -e '[^[:print:][:space:]]' -- . 2>/dev/null)
        ;;
    "")
        echo "usage: $0 --staged | --all | FILE..." >&2; exit 2 ;;
    *)
        for f in "$@"; do
            [ -f "$f" ] || continue
            if head -c 8192 -- "$f" | tr -d '\000' | cmp -s - <(head -c 8192 -- "$f"); then
                h=$(grep -n -e '[^[:print:][:space:]]' -- "$f" | sed "s|^|$f:|")
                [ -n "$h" ] && hits="${hits}${hits:+$'\n'}$h"
            fi
        done
        ;;
esac

if [ -n "$hits" ]; then
    printf '\nREFUSING: non-ASCII characters in text files.\n\n' >&2
    printf '%s\n' "$hits" | report >&2
    cat >&2 <<'MSG'

This repository is ASCII only. Replace the character: -- for a dash,
-> for an arrow, x for a multiplication sign, sec. for a section sign,
<= and >= for the comparison signs, straight quotes, "yes"/"no" for check
marks, and +, - and | for box drawing. Escape a byte you really need
inside a string literal (\xNN, \u{NNNN}). See docs/BUILD.md, "ASCII only".
To override this once: git commit --no-verify
MSG
    exit 1
fi
exit 0
