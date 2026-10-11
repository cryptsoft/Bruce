#!/usr/bin/env bash
# pre-commit-key-guard.sh -- refuse to commit a private key.
#
# .gitignore already keeps a stray *.pem out of `git add -A`, but that is
# only one of the ways this goes wrong. It does not cover `git add -f`, a
# key saved under a name the ignore rules do not match, a key pasted into
# a script or a test fixture, or a key that arrives inside a file that is
# tracked for other reasons. Those are the realistic accidents, because
# none of them look like adding a key.
#
# So this checks CONTENT, not filenames: anything staged that carries a
# PEM private-key header is refused, with the two keys published in this
# repository allow-listed by their exact blob hash. Changing either one --
# even re-encoding it -- changes the hash, and the commit stops.
#
# A key that reaches a commit has to be treated as disclosed even if the
# commit is amended away, because it was on disk in a working tree and may
# already be in a reflog, a stash, or an editor's undo history. The point
# of a pre-commit check is that revoking is the alternative.
#
# Install (through the dispatcher that also runs the ASCII check):
#   ln -sf ../../tools/pre-commit.sh .git/hooks/pre-commit
#
# Bypass, if you genuinely mean it:  git commit --no-verify
#
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail

# Blob hashes of keys/pqf-dev-fw.pem and keys/pqf-dev-bootkey.pem: the
# dev keys are committed on purpose and must keep working.
ALLOWED_BLOBS="
1dffceb55ffcec1e476bb5b3595cf2c2242f48da
5b33e36e2b8ab7c68d1502a0c75d6066a3359ba2
"

# Any of these headers means a private key, whatever the file is called.
PATTERN='BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY'

fail=0
while IFS= read -r path; do
    [ -n "$path" ] || continue
    blob=$(git ls-files -s -- "$path" 2>/dev/null | awk '{print $2}')
    [ -n "$blob" ] || continue
    case "$ALLOWED_BLOBS" in *"$blob"*) continue ;; esac
    if git cat-file blob "$blob" 2>/dev/null | grep -Eq "$PATTERN"; then
        if [ $fail -eq 0 ]; then
            printf '\nREFUSING THE COMMIT: a private key is staged.\n\n' >&2
        fi
        printf '  %s\n' "$path" >&2
        fail=1
    fi
done < <(git diff --cached --name-only --diff-filter=ACM)

if [ $fail -ne 0 ]; then
    cat >&2 <<'EOF'

A private key must never be committed here. The two dev keys already in
keys/ are allow-listed by content hash; anything else is either a mistake
or a key that now has to be treated as disclosed and rotated.

  - a production signing key belongs offline, on a machine that does not
    have this repository checked out -- docs/SECUREBOOT.md, 'Production
    key ceremony'
  - if this really is a new throwaway dev key, add its blob hash to
    ALLOWED_BLOBS in tools/pre-commit-key-guard.sh, deliberately
  - to override this once: git commit --no-verify

EOF
    exit 1
fi
exit 0
