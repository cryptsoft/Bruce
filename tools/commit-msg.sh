#!/usr/bin/env bash
# commit-msg.sh -- the commit message is ASCII only, like the tree.
#
# Comment lines (the ones git strips) are ignored. Install:
#   ln -sf ../../tools/commit-msg.sh .git/hooks/commit-msg
#
# SPDX-License-Identifier: Apache-2.0
set -u
export LC_ALL=C
msg="$1"
if hits=$(grep -v '^#' -- "$msg" | grep -n -e '[^[:print:][:space:]]'); then
    printf '\nREFUSING: non-ASCII characters in the commit message.\n\n' >&2
    printf '%s\n' "$hits" | sed 's/^/  line /' >&2
    printf '\nThis repository is ASCII only, commit messages included: -- for a dash,\n-> for an arrow, straight quotes. To override this once: git commit --no-verify\n' >&2
    exit 1
fi
exit 0
