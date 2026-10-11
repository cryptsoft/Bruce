#!/usr/bin/env bash
# test-ascii-check.sh -- the ASCII guards, exercised in a scratch repository.
#
# Builds a throwaway git repo, installs the two hooks the way BUILD.md says
# to, and checks: an ASCII commit passes; a staged em dash is refused and
# named by file, line, column and code point; a binary file with high
# bytes is skipped; a non-ASCII commit message is refused; the tree-wide
# mode finds a planted character. Prints "N checks, M failure(s)" and
# exits non-zero on any failure, like tools/test-key-guards.sh.
#
# SPDX-License-Identifier: Apache-2.0
set -u
TOOLS=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
checks=0; fails=0
check() {   # label expected actual
    checks=$((checks+1))
    if [ "$2" = "$3" ]; then printf '  ok    %s\n' "$1"
    else printf '  FAIL  %s: expected [%s] got [%s]\n' "$1" "$2" "$3"; fails=$((fails+1)); fi
}
cd "$T" && git init -q . && git config user.email t@example.invalid && git config user.name t
mkdir -p tools .git/hooks
cp "$TOOLS/ascii-check.sh" "$TOOLS/pre-commit.sh" "$TOOLS/commit-msg.sh" "$TOOLS/pre-commit-key-guard.sh" tools/
ln -sf ../../tools/pre-commit.sh .git/hooks/pre-commit
ln -sf ../../tools/commit-msg.sh .git/hooks/commit-msg
printf '*.bin binary\n' > .gitattributes

printf 'plain ascii\n' > a.txt; git add .gitattributes a.txt
git commit -q -m "ascii commit" 2>/dev/null; check "an ASCII commit passes" 0 $?

printf 'an em dash \xe2\x80\x94 here\n' > b.txt; git add b.txt
out=$(git commit -q -m "dash" 2>&1); rc=$?
check "a staged em dash is refused" 1 $rc
check "the hit is named file:line:column with its code point" 1 "$(printf '%s\n' "$out" | grep -c 'b.txt:1:12  U+2014')"
git reset -q b.txt; rm b.txt

printf '\xff\xfe\x00\x01binary' > blob.bin; git add blob.bin
git commit -q -m "binary fixture" 2>/dev/null; check "a binary file with high bytes is skipped" 0 $?

printf 'ok\n' > c.txt; git add c.txt
git commit -q -m "$(printf 'message with a dash \xe2\x80\x94 in it')" 2>/dev/null; check "a non-ASCII commit message is refused" 1 $?
git commit -q -m "plain message" 2>/dev/null; check "the same commit passes with an ASCII message" 0 $?

printf 'planted \xc2\xb5s\n' > d.txt; git add d.txt; git commit -q --no-verify -m "planted" 2>/dev/null
tools/ascii-check.sh --all >/dev/null 2>&1; check "--all finds a character that got past the hook" 1 $?
tools/ascii-check.sh a.txt c.txt >/dev/null 2>&1; check "FILE... mode passes clean files" 0 $?
tools/ascii-check.sh d.txt >/dev/null 2>&1; check "FILE... mode flags a dirty file" 1 $?

printf '%d checks, %d failure(s)\n' "$checks" "$fails"
[ "$fails" -eq 0 ]
