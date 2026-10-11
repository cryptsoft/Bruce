#!/usr/bin/env bash
# test-key-guards.sh -- the dev-key guards, checked against the real keys.
#
# These guards recognise the two published dev keys by a pinned
# fingerprint and a pinned blob hash. That is the right design and it has
# one specific way of rotting: if a dev key is ever regenerated, or the
# committed key stops being the one the constants describe, every guard
# keeps passing while guarding nothing. Nothing about the failure is
# visible -- `sign` stops printing a warning, `secureboot-provision.sh`
# stops refusing, and both look like a clean run.
#
# So the first two checks here are the load-bearing ones: they assert the
# pins still match the keys actually in the tree. The rest exercise each
# guard from both sides, because a guard that refuses everything passes
# every refusal test ever written.
#
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$3], got [$2]"; fi; }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

fp() {  # sha256 over the uncompressed public point, same as pqf_sign.py
    openssl ec -in "$1" -pubout -outform DER 2>/dev/null \
        | tail -c 65 | shasum -a 256 | awk '{print $1}'
}

# ---- the pins still describe the keys that are actually committed ----

check "the pinned fw fingerprint matches keys/pqf-dev-fw.pem" \
    "$(grep -c "$(fp keys/pqf-dev-fw.pem)" tools/pqf_sign.py)" "1"
check "the pinned bootkey fingerprint matches keys/pqf-dev-bootkey.pem" \
    "$(grep -c "$(fp keys/pqf-dev-bootkey.pem)" tools/secureboot-provision.sh)" "1"
check "the pre-commit allow-list holds the fw key's current blob" \
    "$(grep -c "$(git ls-files -s keys/pqf-dev-fw.pem | awk '{print $2}')" tools/pre-commit-key-guard.sh)" "1"
check "the pre-commit allow-list holds the bootkey's current blob" \
    "$(grep -c "$(git ls-files -s keys/pqf-dev-bootkey.pem | awk '{print $2}')" tools/pre-commit-key-guard.sh)" "1"

# ---- pqf_sign.py: refuses a dev key under --production, accepts a real one ----

openssl ecparam -name prime256v1 -genkey -noout -out "$T/real.pem" 2>/dev/null
head -c 4096 /dev/urandom > "$T/app.bin"

python3 tools/pqf_sign.py sign --production --key keys/pqf-dev-fw.pem \
    --in "$T/app.bin" --out "$T/a.dfu" --fw-version 1 >/dev/null 2>&1
check "sign --production refuses the dev key" "$?" "1"

python3 tools/pqf_sign.py sign --production --key "$T/real.pem" \
    --in "$T/app.bin" --out "$T/b.dfu" --fw-version 1 >/dev/null 2>&1
check "sign --production accepts a non-dev key" "$?" "0"

# Without --production it must still WORK -- dev builds depend on it, and
# a guard that broke them would simply be turned off.
python3 tools/pqf_sign.py sign --key keys/pqf-dev-fw.pem \
    --in "$T/app.bin" --out "$T/c.dfu" --fw-version 1 >/dev/null 2>&1
check "sign without --production still signs with the dev key" "$?" "0"

warn=$(python3 tools/pqf_sign.py sign --key keys/pqf-dev-fw.pem --in "$T/app.bin" \
        --out "$T/d.dfu" --fw-version 1 2>&1 >/dev/null | grep -c "DEVELOPMENT KEY")
check "...and says so on stderr" "$warn" "1"

python3 tools/pqf_sign.py fingerprint --key keys/pqf-dev-bootkey.pem --strict >/dev/null 2>&1
check "fingerprint --strict exits 3 for a dev key" "$?" "3"
python3 tools/pqf_sign.py fingerprint --key "$T/real.pem" --strict >/dev/null 2>&1
check "fingerprint --strict exits 0 for a real key" "$?" "0"

# export-pubkey must mark the generated header, both ways round.
python3 tools/pqf_sign.py export-pubkey --key keys/pqf-dev-fw.pem \
    --out "$T/dev.h" --name t >/dev/null 2>&1
check "export-pubkey marks a dev key IS_DEV 1" \
    "$(grep -c 'PQF_BOOT_PUBKEY_IS_DEV 1' "$T/dev.h")" "1"
python3 tools/pqf_sign.py export-pubkey --production --key "$T/real.pem" \
    --out "$T/prod.h" --name t >/dev/null 2>&1
check "export-pubkey marks a real key IS_DEV 0" \
    "$(grep -c 'PQF_BOOT_PUBKEY_IS_DEV 0' "$T/prod.h")" "1"
python3 tools/pqf_sign.py export-pubkey --production --key keys/pqf-dev-fw.pem \
    --out "$T/no.h" --name t >/dev/null 2>&1
check "export-pubkey --production refuses a dev key" "$?" "1"

# ---- the C guard: fires under PQF_PRODUCTION, silent otherwise ----

cat > "$T/guard.c" <<'EOF'
#include "pqf_boot_pubkey.h"
#if defined(PQF_PRODUCTION) && PQF_BOOT_PUBKEY_IS_DEV
#error "dev key in a production build"
#endif
int main(void) { return 0; }
EOF
cp "$T/dev.h" "$T/pqf_boot_pubkey.h"
cc -I "$T" -fsyntax-only "$T/guard.c" >/dev/null 2>&1
check "a dev-keyed header compiles without PQF_PRODUCTION" "$?" "0"
cc -I "$T" -DPQF_PRODUCTION=1 -fsyntax-only "$T/guard.c" >/dev/null 2>&1
check "a dev-keyed header fails to compile under PQF_PRODUCTION" "$?" "1"
cp "$T/prod.h" "$T/pqf_boot_pubkey.h"
cc -I "$T" -DPQF_PRODUCTION=1 -fsyntax-only "$T/guard.c" >/dev/null 2>&1
check "a real-keyed header compiles under PQF_PRODUCTION" "$?" "0"

# The shipping header must carry the macro at all: without it the #error
# in main.c is dead and the guard is decorative.
check "the committed bootloader header defines IS_DEV" \
    "$(grep -c 'define PQF_BOOT_PUBKEY_IS_DEV' c/bootloader/src/pqf_boot_pubkey.h)" "1"
check "main.c actually consumes it" \
    "$(grep -c 'PQF_BOOT_PUBKEY_IS_DEV' c/bootloader/src/main.c)" "1"

# ---- secureboot-provision.sh: the one-way burn ----
# Both terminal stages must consult the guard. Checking the call sites is
# the point: the function existing proves nothing.
check "stage_key calls check_not_dev_key" \
    "$(awk '/^stage_key\(\)/,/^}/' tools/secureboot-provision.sh | grep -c check_not_dev_key)" "1"
check "stage_enable calls check_not_dev_key" \
    "$(awk '/^stage_enable\(\)/,/^}/' tools/secureboot-provision.sh | grep -c check_not_dev_key)" "1"

mkdir -p build-secureboot && echo '{}' > "$T/otp_key.json"
out=$(PQF_SB_OUT="$T" ./tools/secureboot-provision.sh key 2>&1)
check "the dev boot key is refused before any device is touched" \
    "$(printf '%s' "$out" | grep -c 'refusing to burn the published dev boot key')" "1"
check "...and it refuses BEFORE looking for a board" \
    "$(printf '%s' "$out" | grep -c 'no RP-series device')" "0"

openssl ecparam -name secp256k1 -genkey -noout -out "$T/realboot.pem" 2>/dev/null
out=$(PQF_SB_OUT="$T" PQF_SB_KEY="$T/realboot.pem" ./tools/secureboot-provision.sh key 2>&1)
check "a real boot key gets past the guard" \
    "$(printf '%s' "$out" | grep -c 'refusing to burn')" "0"
out=$(PQF_SB_OUT="$T" PQF_SB_ALLOW_DEV_KEY=1 ./tools/secureboot-provision.sh key 2>&1)
check "PQF_SB_ALLOW_DEV_KEY=1 overrides, loudly" \
    "$(printf '%s' "$out" | grep -c 'This board is being spent')" "1"

# ---- .gitignore ----
touch "$T/x.pem"
git check-ignore -q keys/some-new-key.pem
check ".gitignore covers a new key in keys/" "$?" "0"
git check-ignore -q tools/stray.pem
check ".gitignore covers a stray .pem anywhere" "$?" "0"
git check-ignore -q keys/pqf-dev-fw.pem
check "...but not the committed dev keys" "$?" "1"

printf '\n  %d checks, %d failure(s)\n' "$((PASS+FAIL))" "$FAIL"
[ "$FAIL" -eq 0 ]
