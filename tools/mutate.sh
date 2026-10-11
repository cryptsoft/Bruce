#!/usr/bin/env bash
# mutate.sh -- measure whether a suite actually constrains its module.
#
# A green suite says the code passes its tests. It does not say the tests
# would notice if the code were wrong, and the difference has already
# mattered twice in this repository: a signature-counter assertion that
# passed because of a RAM stub and would have passed with the firmware
# logic deleted, and a whitelist believed covered whose tests exercised a
# different mock entirely. Both were found by hand, one at a time.
#
# This does it mechanically. For each mutable site in a source file it
# makes one small change, rebuilds, and runs the suite:
#
#   killed      the suite failed -- it constrains that line
#   SURVIVED    the suite passed with the code broken -- it does not
#   (skipped)   the mutant does not compile, so no test could catch it
#               and it is not counted either way
#
# One class of survivor is not a gap: a line inside a #[cfg] the host
# build does not compile -- a `target_arch` block, say. The mutant is
# applied to the file, the host binary never contains the line, and the
# suite passes because nothing changed. upgate.rs's TIMER0 read is the
# standing example. Check the cfg before chasing a survivor; those need
# silicon, not another host test.
#
# Survivors are the output. Each one is a line the suite does not
# constrain, which is either a gap worth closing or a line that does not
# matter -- and telling those two apart is the review.
#
# Usage:
#   tools/mutate.sh rust <src-file> <suite-name> [pattern]
#   tools/mutate.sh c    <src-file> <make-target> [pattern]
#
#   tools/mutate.sh rust crates/fw-nonsecure/src/cborr.rs cborr
#   tools/mutate.sh c    c/firmware/src/ctaphid.c test_ctaphid
#
# Env: PQF_MUT_OUT (work dir, default a mktemp), PQF_MUT_MAX (cap).
#
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail
cd "$(dirname "$0")/.."

MODE="${1:?rust|c}"; SRC="${2:?source file}"; SUITE="${3:?suite}"
PATTERN="${4:-}"
MAX="${PQF_MUT_MAX:-400}"
OUT="${PQF_MUT_OUT:-$(mktemp -d)}"
HOST=$(rustc -vV | awk '/^host:/{print $2}')
: "${PICO_SDK_PATH:=$HOME/pico-sdk}"; export PICO_SDK_PATH

[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 1; }
mkdir -p "$OUT"
cp "$SRC" "$OUT/orig"
restore() { cp "$OUT/orig" "$SRC"; }
trap restore EXIT INT TERM

run_suite() {
    case "$MODE" in
        rust) cargo test -q -p pqf-fw-secure-hosttest --target "$HOST" \
                  --test "$SUITE" >/dev/null 2>&1 ;;
        rust-fw) cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
                  --test "$SUITE" >/dev/null 2>&1 ;;
        c)    rm -f "c/firmware/test/build/$SUITE"
              make -C c/firmware/test "build/$SUITE" >/dev/null 2>&1 \
                  && "c/firmware/test/build/$SUITE" >/dev/null 2>&1 ;;
    esac
}

# The baseline has to be green, or every mutant "dies" for the wrong
# reason and the run reports perfect coverage of nothing.
printf 'baseline: '
if run_suite; then echo "green"; else echo "RED -- fix the suite first"; exit 1; fi

# Generate one mutant per site. Deliberately small edits: an operator
# flipped, a constant nudged, a negation dropped. A mutant that changes
# too much stops resembling the mistakes people actually make.
python3 - "$SRC" "$OUT/plan.txt" "$PATTERN" "$MAX" <<'PY'
import re, sys
src, plan, pattern, cap = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
lines = open(src).read().split("\n")

# (regex, replacement) applied to one occurrence at a time.
# Comparison operators are matched only when SPACED. In Rust an
# unspaced `<` is nearly always a generic -- Option<u64>, Reader<'a>,
# fn f<T> -- and mutating those produces a syntax error rather than a
# behaviour, which costs a full rebuild to discover. The first run of
# this script wasted 27 of 30 mutants exactly that way.
OPS = [
    (r' == ', ' != '), (r' != ', ' == '),
    (r' <= ', ' < '),  (r' >= ', ' > '),
    (r' < ', ' <= '),  (r' > ', ' >= '),
    (r' < ', ' > '),   (r' > ', ' < '),
    (r' && ', ' || '), (r' \|\| ', ' && '),
    (r'\breturn true\b', 'return false'), (r'\breturn false\b', 'return true'),
    (r'\bSome\(true\)', 'Some(false)'), (r'\bSome\(false\)', 'Some(true)'),
    (r'\bis_some\(\)', 'is_none()'), (r'\bis_none\(\)', 'is_some()'),
    (r'\bis_empty\(\)', 'len() == 99999'),
    (r'\.min\(', '.max('), (r'\.max\(', '.min('),
    (r'\bchecked_add\b', 'wrapping_add'), (r'\bchecked_mul\b', 'wrapping_mul'),
    (r'\bchecked_sub\b', 'wrapping_sub'), (r'\bsaturating_sub\b', 'wrapping_sub'),
    (r'\btry_from\b', 'try_from_TRUNC'),
]

# Off-by-one on any bound. This is the mutation that matters most for
# parsers: a length check that admits one byte too many is the classic
# way an attacker-facing reader goes wrong, and it is the kind of edit
# that compiles every time.
BOUNDS = re.compile(r'(?<![\w.])(\d{1,6})(?![\w.])')

out, n = [], 0
for i, line in enumerate(lines):
    st = line.strip()
    # Comments and attributes are not behaviour.
    if not st or st.startswith(("//", "/*", "*", "#[", "#!")):
        continue
    if pattern and not re.search(pattern, line):
        continue
    for rx, rep in OPS:
        for m in re.finditer(rx, line):
            if n >= cap:
                break
            mutated = line[:m.start()] + rep + line[m.end():]
            if mutated == line:
                continue
            out.append(f"{i}\t{rx} -> {rep}\t{mutated}")
            n += 1
    # Nudge integer literals, but only on lines that look like a bound
    # or a size -- a literal in an index table or an error code is not a
    # limit and mutating it tests nothing.
    if re.search(r'(len|size|max|min|count|depth|>|<|\[|LEN|MAX|_N\b)', line):
        for m in BOUNDS.finditer(line):
            if n >= cap:
                break
            v = int(m.group(1))
            for delta in (1, -1):
                if v + delta < 0:
                    continue
                mutated = line[:m.start()] + str(v + delta) + line[m.end():]
                out.append(f"{i}\t{v} -> {v + delta}\t{mutated}")
                n += 1
open(plan, "w").write("\n".join(out))
print(f"  {n} mutants over {len(lines)} lines")
PY

TOTAL=0; KILLED=0; SURVIVED=0; SKIPPED=0
: > "$OUT/survivors.txt"

while IFS=$'\t' read -r idx desc mutated; do
    [ -n "${idx:-}" ] || continue
    TOTAL=$((TOTAL+1))
    python3 - "$OUT/orig" "$SRC" "$idx" "$mutated" <<'PY'
import sys
orig, dst, idx, mutated = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
lines = open(orig).read().split("\n")
lines[idx] = mutated
open(dst, "w").write("\n".join(lines))
PY
    # A mutant that does not build is not a behaviour any test could
    # catch, so it is excluded rather than counted as a kill -- counting
    # it would inflate the score with compiler errors.
    case "$MODE" in
        rust)    build=$(cargo test -q -p pqf-fw-secure-hosttest --target "$HOST" --test "$SUITE" --no-run 2>&1) ;;
        rust-fw) build=$(cargo test -q -p pqf-firmware-hosttest --target "$HOST" --test "$SUITE" --no-run 2>&1) ;;
        # rm first: Apple ships GNU make 3.81, which compares mtimes in
        # whole seconds, so a mutate-build-restore cycle inside one second
        # leaves the PREVIOUS mutant's binary in place and every result
        # after it is a lie. Found the hard way.
        c)       rm -f "c/firmware/test/build/$SUITE"
                 build=$(make -C c/firmware/test "build/$SUITE" 2>&1) ;;
    esac
    if [ $? -ne 0 ]; then
        SKIPPED=$((SKIPPED+1)); printf '.'; continue
    fi
    if run_suite; then
        SURVIVED=$((SURVIVED+1))
        printf 'S'
        printf '%s:%d  %s\n      %s\n' "$SRC" "$((idx+1))" "$desc" "$(echo "$mutated" | sed 's/^[[:space:]]*//')" \
            >> "$OUT/survivors.txt"
    else
        KILLED=$((KILLED+1)); printf 'x'
    fi
done < "$OUT/plan.txt"

restore
printf '\n\n%s vs %s\n' "$SRC" "$SUITE"
printf '  %d viable mutants: %d killed, %d SURVIVED  (%d did not compile)\n' \
    "$((KILLED+SURVIVED))" "$KILLED" "$SURVIVED" "$SKIPPED"
if [ "$SURVIVED" -gt 0 ]; then
    printf '\nsurvivors -- lines this suite does not constrain:\n\n'
    cat "$OUT/survivors.txt"
fi
printf '\nwork dir: %s\n' "$OUT"
