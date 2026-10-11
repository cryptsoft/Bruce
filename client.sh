#!/usr/bin/env bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# client.sh -- run one of the host-side client examples against a token.
#
# The examples live in crates/ctaphid-client/examples and are built for
# the host, not the firmware target the workspace defaults to, so the
# long form needs the host triple on every call:
#
#   cargo run -p pqf-ctaphid --example probe --target "$(rustc -vV | awk '/host/{print $2}')"
#
# This wrapper supplies it:
#
#   ./client.sh probe                  # enumerate the token, print getInfo
#   ./client.sh register               # one registration (touch the button)
#   ./client.sh pqc_roundtrip          # register + sign with the hybrid, check the signature
#   ./client.sh reboot bootsel         # arguments after the name go to the example
#   ./client.sh list                   # every example, one per line
#
# Environment the examples read is passed through unchanged, for example
# BRUCE_PIN=1234 ./client.sh register.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
EXAMPLES="$REPO_ROOT/crates/ctaphid-client/examples"

usage() {
    sed -n '/^# This wrapper supplies it:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}

case "${1:-}" in
    "")
        usage >&2
        exit 1
        ;;
    -h|--help|help)
        usage
        exit 0
        ;;
    list)
        for f in "$EXAMPLES"/*.rs; do
            n="$(basename "$f" .rs)"
            case "$n" in
                tz_*) echo "$n    (needs the TrustZone image from ./build-tz.sh, docs/TRUSTZONE.md)" ;;
                *)    echo "$n" ;;
            esac
        done
        exit 0
        ;;
esac

EXAMPLE="$1"
shift
# A leading "--" is allowed, so the long form's habit carries over.
[ "${1:-}" = "--" ] && shift

if [ ! -f "$EXAMPLES/$EXAMPLE.rs" ]; then
    echo "client.sh: no example named '$EXAMPLE'. The examples are:" >&2
    ls "$EXAMPLES"/*.rs | xargs -n1 basename | sed 's/\.rs$//' | sed 's/^/  /' >&2
    exit 1
fi

HOST="$(rustc -vV | awk '/^host:/{print $2}')"
cd "$REPO_ROOT"
exec cargo run -p pqf-ctaphid --example "$EXAMPLE" --target "$HOST" -- "$@"
