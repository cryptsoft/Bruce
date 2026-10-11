#!/usr/bin/env bash
# pre-commit.sh -- the repository's pre-commit hook: every guard in turn.
#
#   tools/pre-commit-key-guard.sh   no private key in a commit
#   tools/ascii-check.sh --staged   no non-ASCII byte in a text file
#
# Install (once per clone):
#   ln -sf ../../tools/pre-commit.sh .git/hooks/pre-commit
#   ln -sf ../../tools/commit-msg.sh .git/hooks/commit-msg
#
# Bypass, if you genuinely mean it:  git commit --no-verify
#
# SPDX-License-Identifier: Apache-2.0
set -u
here=$(cd "$(dirname "$(readlink "$0" || echo "$0")")" 2>/dev/null && pwd)
[ -n "$here" ] && [ -x "$here/ascii-check.sh" ] || here=$(git rev-parse --show-toplevel)/tools
rc=0
"$here/pre-commit-key-guard.sh" || rc=1
"$here/ascii-check.sh" --staged || rc=1
exit $rc
