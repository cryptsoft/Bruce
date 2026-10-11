#!/usr/bin/env bash
# vendor-bc-rust.sh -- refresh crates/bc-rust-mini from a bc-rust checkout.
#
# The Rust firmware's ML-DSA, SHA-2, SHA-3, HMAC and HKDF come from the
# Bouncy Castle Rust port (https://github.com/bcgit/bc-rust), on a
# branch that carries no_std support for those crates. The subset the
# firmware needs is vendored under crates/bc-rust-mini/ so the tree
# builds on its own; this script is the only way that directory is
# meant to change.
#
#   tools/vendor-bc-rust.sh [path-to-bc-rust-checkout]   (default ../bc-rust)
#
# What it does, in order:
#   1. records the checkout's branch, commit and date in
#      crates/bc-rust-mini/UPSTREAM;
#   2. replaces crates/bc-rust-mini/crypto/<crate> for every crate in
#      CRATES below with a copy from the checkout (build outputs
#      excluded), and LICENSE.md with the checkout's;
#   3. transliterates the non-ASCII characters in the copied text to
#      ASCII -- this repository is ASCII only (docs/BUILD.md, "ASCII
#      only") -- with the fixed map at the bottom of this file. Upstream
#      writes FIPS 204 notation into its comments (mathematical italic
#      letters, Greek, the arrow and membership signs); the map turns
#      those into plain letters and names; the alarm emoji and the
#      decorations are dropped. A non-ASCII character inside a string
#      literal (upstream has a few in test assertion messages) becomes
#      its \u{XXXX} escape, which leaves the string's value unchanged.
#      The script REFUSES to finish if a non-ASCII character sits
#      anywhere else (an identifier, a char literal, a test vector), or
#      is in a comment and not in the map, so nothing is ever silently
#      changed.
#
# It does not touch crates/bc-rust-mini/Cargo.toml (the nested
# workspace root, kept by hand -- compare it with the checkout's root
# Cargo.toml after a refresh) or README.md. Afterwards:
#
#   cargo build --release && tools/host-tests.sh rust
#   (cd crates/bc-rust-mini && cargo test --target "$(rustc -vV | awk '/host/{print $2}')")
#   -- the vendored suites; the host triple is needed because the root
#   .cargo/config.toml defaults every build under it to the embedded target
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-$REPO/../bc-rust}"
DST="$REPO/crates/bc-rust-mini"
UPSTREAM_URL="https://github.com/bcgit/bc-rust"

# The crates the firmware links (default-features = false), the
# crates those pull in, and the two dev-only crates (hex,
# core-test-framework) the vendored test suites need.
CRATES="core core-test-framework hex hkdf hmac mldsa-lowmemory rng sha2 sha3 utils"

[ -f "$SRC/Cargo.toml" ] && [ -d "$SRC/crypto" ] \
    || { echo "not a bc-rust checkout: $SRC" >&2; exit 1; }
for c in $CRATES; do
    [ -f "$SRC/crypto/$c/Cargo.toml" ] || { echo "missing crate in checkout: crypto/$c" >&2; exit 1; }
done
if [ -n "$(git -C "$SRC" status --porcelain 2>/dev/null)" ]; then
    echo "REFUSING: the checkout at $SRC has local modifications; commit or stash them first" >&2
    exit 1
fi

branch=$(git -C "$SRC" rev-parse --abbrev-ref HEAD)
commit=$(git -C "$SRC" rev-parse HEAD)
date=$(git -C "$SRC" log -1 --format=%cs)
mkdir -p "$DST/crypto"
cat > "$DST/UPSTREAM" <<EOF
upstream: $UPSTREAM_URL
branch:   $branch
commit:   $commit
date:     $date
crates:   $CRATES
EOF

for c in $CRATES; do
    rm -rf "$DST/crypto/$c"
    mkdir -p "$DST/crypto/$c"
    ( cd "$SRC/crypto/$c" && tar --exclude=./target --exclude='./.DS_Store' -cf - . ) \
        | ( cd "$DST/crypto/$c" && tar -xf - )
done
cp "$SRC/LICENSE.md" "$DST/LICENSE.md"

# 3. ASCII transliteration, comments only.
python3 - "$DST" <<'PY'
import os, re, sys, unicodedata
dst = sys.argv[1]

# Fixed map, keyed by code point, for everything NFKC does not already
# reduce to ASCII. Mathematical alphanumerics (U+1D400-1D7FF) and the
# letterlike symbols fold to plain letters under NFKC first; Greek
# letters and operators are named here. (Keyed by number so this file
# is itself ASCII.)
MAP = {
    # Greek (after NFKC folds the mathematical variants to these)
    0x03b1: 'alpha', 0x03b2: 'beta', 0x03b3: 'gamma', 0x03b4: 'delta',
    0x03b5: 'epsilon', 0x03b6: 'zeta', 0x03b7: 'eta', 0x03b8: 'theta',
    0x03b9: 'iota', 0x03ba: 'kappa', 0x03bb: 'lambda', 0x03bc: 'mu',
    0x03bd: 'nu', 0x03be: 'xi', 0x03c0: 'pi', 0x03c1: 'rho',
    0x03c3: 'sigma', 0x03c4: 'tau', 0x03c5: 'upsilon', 0x03c6: 'phi',
    0x03c7: 'chi', 0x03c8: 'psi', 0x03c9: 'omega',
    0x0391: 'Alpha', 0x0392: 'Beta', 0x0393: 'Gamma', 0x0394: 'Delta',
    0x0398: 'Theta', 0x039b: 'Lambda', 0x03a0: 'Pi', 0x03a3: 'Sigma',
    0x03a6: 'Phi', 0x03a8: 'Psi', 0x03a9: 'Omega',
    # operators and relations
    0x2212: '-', 0x2190: '<-', 0x2192: '->', 0x2194: '<->',
    0x2208: 'in', 0x2209: 'not in', 0x22c5: '*', 0x2217: '*',
    0x00d7: 'x', 0x2225: '||', 0x2016: '||', 0x2218: 'o',
    0x22a5: 'bot', 0x2295: 'xor', 0x2264: '<=', 0x2265: '>=',
    0x2261: '==', 0x2260: '!=', 0x2248: '~', 0x221e: 'inf',
    0x222a: 'U', 0x2229: 'intersect', 0x00b1: '+-', 0x2211: 'sum',
    0x221a: 'sqrt', 0x25b7: '//', 0x2026: '...',
    # primes, hats, tildes (combining marks follow their base letter)
    0x2032: "'", 0x2033: "''", 0x0302: '^', 0x0303: '~',
    # punctuation
    0x2014: '--', 0x2013: '--', 0x201c: '"', 0x201d: '"',
    0x2018: "'", 0x2019: "'", 0x00a0: ' ',
    # accented Latin letters in prose ("Merkle-Damgard", "naive")
    0x00e5: 'a', 0x00e4: 'a', 0x00e9: 'e', 0x00ef: 'i', 0x00f6: 'o',
    0x00fc: 'u',
    # emoji (the alarm, the decorations): dropped, together with one
    # neighbouring space (the sentinel is removed below)
    0x1f6a8: '\x00', 0x1f409: '\x00', 0x1f40d: '\x00', 0x1f41c: '\x00',
}

def fold(ch):
    if ord(ch) < 128:
        return ch
    n = unicodedata.normalize('NFKC', ch)
    if all(ord(c) < 128 for c in n):
        return n
    out = ''
    for c in n:
        if ord(c) < 128:
            out += c
        elif ord(c) in MAP:
            out += MAP[ord(c)]
        else:
            raise KeyError(ch)
    return out

def transliterate_line(line, in_block, p, ln):
    """Fold every non-ASCII character on the line: a comment character
    through the map, a string-literal character to its \\u{XXXX} escape.
    Returns the new line, the block-comment state at its end, and the
    problems found (unmapped characters, characters outside both)."""
    out, i, n = '', 0, len(line)
    in_str = False
    unmapped, outside = set(), []
    while i < n:
        c = line[i]
        if in_block:
            if line.startswith('*/', i):
                out += '*/'; i += 2; in_block = False; continue
            out += fold_or_keep(c, unmapped); i += 1; continue
        if in_str:
            if c == '\\' and i + 1 < n:
                out += line[i:i+2]; i += 2; continue
            if c == '"':
                in_str = False
            out += c if ord(c) < 128 else '\\u{%X}' % ord(c)
            i += 1; continue
        if line.startswith('//', i):
            out += fold_comment(line[i:], unmapped); break
        if line.startswith('/*', i):
            out += '/*'; i += 2; in_block = True; continue
        if c == '"':
            in_str = True; out += c; i += 1; continue
        if ord(c) > 127:
            outside.append(f'{p}:{ln}')
        out += c; i += 1
    return out, in_block, unmapped, outside

def fold_or_keep(c, unmapped):
    try:
        return fold(c)
    except KeyError:
        unmapped.add(c)
        return c

def fold_comment(text, unmapped):
    return ''.join(fold_or_keep(c, unmapped) for c in text)

unmapped, outside, changed = set(), [], 0
for root, dirs, files in os.walk(dst):
    dirs[:] = [d for d in dirs if d != 'target']
    for f in files:
        p = os.path.join(root, f)
        raw = open(p, 'rb').read()
        if b'\0' in raw[:8192] or all(b < 128 for b in raw):
            continue
        text = raw.decode('utf-8')
        lines = text.split('\n')
        in_block = False
        new = []
        for ln, line in enumerate(lines, 1):
            if any(ord(c) > 127 for c in line) or in_block or '/*' in line:
                line, in_block, um, outs = transliterate_line(line, in_block, p, ln)
                unmapped |= um
                outside += outs
                line = re.sub(r' ?\x00', '', line).rstrip()
            new.append(line)
        out = '\n'.join(new)
        if out != text:
            open(p, 'w', encoding='utf-8').write(out)
            changed += 1

if outside:
    print('REFUSING: non-ASCII outside a comment (extend the script deliberately):', file=sys.stderr)
    for x in outside:
        print('  ' + x, file=sys.stderr)
if unmapped:
    print('REFUSING: characters with no ASCII mapping:', file=sys.stderr)
    for c in sorted(unmapped):
        print(f'  U+{ord(c):04X} {c!r}', file=sys.stderr)
if outside or unmapped:
    sys.exit(1)
print(f'transliterated comments in {changed} file(s)')
PY

"$REPO/tools/ascii-check.sh" $(find "$DST" -type f -not -path '*/target/*') \
    || { echo "the vendored tree is still not ASCII clean" >&2; exit 1; }

echo "vendored $CRATES"
echo "from $branch @ ${commit:0:12} ($date) into crates/bc-rust-mini"
echo "now: compare crates/bc-rust-mini/Cargo.toml with $SRC/Cargo.toml, then build and test"
