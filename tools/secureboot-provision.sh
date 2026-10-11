#!/usr/bin/env bash
# secureboot-provision.sh -- RP2350 secure boot for the Bruce
# DFU bootloader, in stages that can each be undone until the last one.
#
# The whole point of the staging is that ONE step is terminal and the
# rest are not. Run them in order, verify between, and the only way to
# lose a board is to skip ahead.
#
#   seal    build a signed bootloader + the OTP rows it needs   (no device)
#   key     program the boot key hash into OTP                  (one-way, harmless)
#   flash   install the sealed bootloader and prove it boots    (reversible)
#   enable  turn secure boot on                                 (TERMINAL)
#   verify  read back what the silicon thinks
#
# WHY THE ORDER MATTERS, AND WHY BOOTSEL MUST OUTLIVE IT
#
# The bootrom verifies the bootloader against the key hash in OTP. Get
# any of that wrong -- wrong hash, unsealed image, wrong key slot --
# and once secure boot is on the bootrom refuses to boot the
# bootloader. No bootloader means no DFU, because DFU *is* the
# bootloader. The only way back is BOOTSEL, to write a correctly
# sealed image.
#
# So: do NOT blow the BOOT_FLAGS0 DISABLE_BOOTSEL_* fuses until
# `verify` says secure boot is on and the board still boots. Those two
# fuses together -- secure boot misconfigured, BOOTSEL gone -- are the
# one combination with no recovery of any kind. See docs/SECUREBOOT.md.
#
# Usage:
#   tools/secureboot-provision.sh seal   [--key <pem>] [--bootloader <uf2>]
#   tools/secureboot-provision.sh key
#   tools/secureboot-provision.sh flash
#   tools/secureboot-provision.sh enable      # refuses without I_MEAN_IT=1
#   tools/secureboot-provision.sh verify
#
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

# Work area. Override with PQF_SB_OUT; never hardcode a session path.
OUT="${PQF_SB_OUT:-$REPO/build-secureboot}"
KEY="${PQF_SB_KEY:-$REPO/keys/pqf-dev-bootkey.pem}"
BOOTLOADER="${PQF_SB_BOOTLOADER:-$REPO/c/bootloader/build-tiny-ar/pqf_bootloader.uf2}"

SEALED="$OUT/pqf_bootloader_signed.uf2"
OTP_ALL="$OUT/otp_all.json"
OTP_KEY="$OUT/otp_key.json"
OTP_ENABLE="$OUT/otp_enable.json"

say()  { printf '\n== %s ==\n' "$1"; }
die()  { printf '\nFAIL: %s\n' "$1" >&2; exit 1; }

need_bootsel() {
    picotool info >/dev/null 2>&1 && return 0
    die "no RP-series device in BOOTSEL. Put the token in BOOTSEL first
     (./c/hid/reboot bootsel, or hold BOOT and tap RESET)."
}

# Refuse to write to a board that is not the one being provisioned.
# picotool reports a hardware-unique chipid; PQF_SB_CHIPID pins it.
check_chipid() {
    local got
    got=$(picotool info -a 2>/dev/null | awk '/chipid:/{print $2}')
    [ -n "$got" ] || die "could not read chipid"
    printf '   chipid: %s\n' "$got"
    if [ -n "${PQF_SB_CHIPID:-}" ] && [ "$got" != "$PQF_SB_CHIPID" ]; then
        die "chipid $got does not match PQF_SB_CHIPID=$PQF_SB_CHIPID.
     This is a different board than the one you meant. Refusing to write."
    fi
}

# Refuse to make the dev boot key permanent.
#
# keys/pqf-dev-bootkey.pem is committed, so its private half is public.
# Burning ITS hash into OTP is the one mistake here that cannot be walked
# back by any means: the row is one-way, the board will thereafter only
# accept bootloaders signed by a key everyone has, and there is no second
# slot to correct it with. The board still works -- it just has no secure
# boot, permanently, while reading as a board that does.
#
# So the dev key is fine for `seal` and `flash` (both reversible) and
# refused for `key` and `enable` (neither is). PQF_SB_ALLOW_DEV_KEY=1 is
# there for deliberately sacrificing a bench board, which is how the
# provisioning path in docs/SECUREBOOT.md was validated in the first place.
check_not_dev_key() {
    local fp
    fp=$(python3 -c '
import hashlib, subprocess, sys
der = subprocess.run(["openssl","ec","-in",sys.argv[1],"-pubout","-outform","DER"],
                     capture_output=True).stdout
pt = der[-65:]
print(hashlib.sha256(pt).hexdigest() if pt[:1] == b"\x04" else "")
' "$KEY" 2>/dev/null)
    # Fail closed: an unreadable key must not pass as "not the dev key".
    [ -n "$fp" ] || die "could not fingerprint $KEY (openssl ec failed); refusing to continue"
    [ "$fp" = "bf552bf213e80f49b38038f65372808528aef987a18a7cae858721c18bffd993" ] || return 0
    if [ "${PQF_SB_ALLOW_DEV_KEY:-0}" = "1" ]; then
        printf '\n   !! burning the PUBLISHED DEV boot key, because PQF_SB_ALLOW_DEV_KEY=1.\n'
        printf '      This board is being spent. It can never have real secure boot.\n\n'
        return 0
    fi
    die "refusing to burn the published dev boot key ($KEY) into OTP.

     Its private half is in this repository, so a board provisioned with it
     accepts a bootloader signed by anyone -- permanently, with no way back.
     The OTP row is one-way and there is no second key slot to fix it with.

     Generate a real key offline: see 'Production key ceremony' in
     docs/SECUREBOOT.md, then re-run with PQF_SB_KEY=<that key>.

     To spend this board on purpose, set PQF_SB_ALLOW_DEV_KEY=1."
}

# otp_key.json is whatever the last `seal` wrote, possibly under another
# PQF_SB_KEY. Before its hash goes into silicon, prove it is this key's.
check_otp_key_is_key() {
    python3 - "$KEY" "$1" <<'PY'
import subprocess, hashlib, json, sys
r = subprocess.run(["openssl","ec","-in",sys.argv[1],"-pubout","-outform","DER"],
                   capture_output=True)
der = r.stdout
if r.returncode != 0 or len(der) < 65 or der[-65] != 0x04:
    sys.exit("   could not read the public key from " + sys.argv[1])
want = bytes(json.load(open(sys.argv[2]))["bootkey0"]).hex()
got = hashlib.sha256(der[-64:]).hexdigest()      # sha256(x||y), no 0x04
print("   bootkey0 in", sys.argv[2], "is", "this key's hash" if got == want
      else "NOT this key's hash")
sys.exit(0 if got == want else 1)
PY
    [ $? -eq 0 ] || die "$1 was not sealed with $KEY -- re-run '$0 seal' with the right PQF_SB_KEY"
}

# The hash already in OTP must be this key's before secure boot is
# switched on; otherwise the board is locked to whatever key an earlier
# `key` stage burned.
check_silicon_key_is_key() {
    local dump="$OUT/otp_dump.bin"
    picotool otp dump --output "$dump" >/dev/null 2>&1 \
        || die "could not dump OTP to check the burned key"
    python3 - "$KEY" "$dump" <<'PY'
import subprocess, hashlib, sys
r = subprocess.run(["openssl","ec","-in",sys.argv[1],"-pubout","-outform","DER"],
                   capture_output=True)
der = r.stdout
if r.returncode != 0 or len(der) < 65 or der[-65] != 0x04:
    sys.exit("   could not read the public key from " + sys.argv[1])
want = hashlib.sha256(der[-64:]).digest()
d = open(sys.argv[2], "rb").read()
flat = b"".join(d[j:j+2] for j in range(0, len(d), 4))
if flat.find(want) < 0:
    sys.exit("   the BOOTKEY0 in silicon is NOT this key's hash")
print("   BOOTKEY0 in silicon is this key's hash")
PY
    [ $? -eq 0 ] || die "refusing to enable secure boot: the key in OTP is not $KEY"
}

stage_seal() {
    say "seal -- sign the bootloader, derive the OTP rows"
    [ -f "$KEY" ] || die "no boot key at $KEY (see docs/SECUREBOOT.md to make one)"
    [ -f "$BOOTLOADER" ] || die "no bootloader at $BOOTLOADER -- build it first"
    mkdir -p "$OUT"
    # picotool edits an existing OTP json rather than replacing it, so
    # start from clean or you inherit a previous run's rows.
    [ -f "$OTP_ALL" ] && rm -f "$OTP_ALL"

    picotool seal --sign "$BOOTLOADER" "$SEALED" "$KEY" "$OTP_ALL" \
        || die "picotool seal failed"
    grep -q '"signature"\|signature' <<<"$(picotool info "$SEALED" 2>&1)" \
        || echo "   (note: could not confirm 'signature: verified' from picotool info)"

    # Split into the harmless half and the terminal half. Programming the
    # key changes nothing about how the board boots; only crit1 does.
    python3 - "$OTP_ALL" "$OTP_KEY" "$OTP_ENABLE" <<'PY'
import json, sys
src, keyf, enf = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(src))
key = {k: v for k, v in d.items() if k in ("bootkey0", "bootkey1", "bootkey2",
                                           "bootkey3", "boot_flags1")}
en  = {k: v for k, v in d.items() if k == "crit1"}
if "bootkey0" not in key: sys.exit("seal produced no bootkey0 -- did --sign run?")
if "secure_boot_enable" not in en.get("crit1", {}):
    sys.exit("seal produced no crit1.secure_boot_enable")
json.dump(key, open(keyf, "w"), indent=2)
json.dump(en,  open(enf,  "w"), indent=2)
print("   key rows    :", ", ".join(sorted(key)))
print("   enable rows :", ", ".join(sorted(en)))
print("   bootkey0    :", bytes(d["bootkey0"]).hex())
PY
    [ $? -eq 0 ] || die "could not split the OTP json"

    # Independent check of the hash picotool wants burned. This is the
    # last point at which a wrong key is still free to fix.
    python3 - "$KEY" "$OTP_ALL" <<'PY'
import subprocess, hashlib, json, sys
der = subprocess.run(["openssl","ec","-in",sys.argv[1],"-pubout","-outform","DER"],
                     capture_output=True).stdout
pt = der[-65:]
assert pt[0] == 0x04, "unexpected public key encoding"
want = bytes(json.load(open(sys.argv[2]))["bootkey0"]).hex()
got  = hashlib.sha256(pt[1:]).hexdigest()      # sha256(x||y), no 0x04
print("   independent sha256(x||y):", got)
print("   ", "MATCH -- the hash is this key's" if got == want
      else "MISMATCH -- do NOT program this")
sys.exit(0 if got == want else 1)
PY
    [ $? -eq 0 ] || die "boot key hash did not verify"
    printf '\n   sealed bootloader: %s\n' "$SEALED"
    printf '   next: %s key\n' "$0"
}

stage_key() {
    say "key -- program the boot key hash into OTP (ONE-WAY)"
    [ -f "$OTP_KEY" ] || die "run '$0 seal' first"
    check_not_dev_key
    check_otp_key_is_key "$OTP_KEY"
    need_bootsel; check_chipid
    echo "   This is irreversible, but it does NOT change how the board boots:"
    echo "   secure boot stays off until 'enable'. A board with a key and no"
    echo "   secure boot still runs anything."
    picotool otp load -t json "$OTP_KEY" || die "otp load failed"

    say "read back"
    picotool otp get BOOT_FLAGS1 2>&1 | grep -E "^ROW|VALUE|KEY_VALID \(" | head -3

    # `picotool otp get BOOTKEY0` does not print the stored bytes in a
    # form worth diffing, so dump the array and pull the row out. This
    # is the check that matters: a key hash that programmed with a bit
    # wrong is indistinguishable from a good one until secure boot is
    # already on, at which point the board no longer boots.
    local dump="$OUT/otp_dump.bin"
    picotool otp dump --output "$dump" >/dev/null 2>&1 \
        || die "could not dump OTP to verify the key"
    python3 - "$dump" "$OTP_KEY" <<'PY'
import json, sys
dump, keyf = sys.argv[1], sys.argv[2]
want = bytes(json.load(open(keyf))["bootkey0"])
d = open(dump, "rb").read()
# 4 bytes per row in the dump; ECC rows carry 2 data bytes in the low half.
flat = b"".join(d[j:j+2] for j in range(0, len(d), 4))
i = flat.find(want)
if i < 0:
    sys.exit("   BOOTKEY0 NOT FOUND IN OTP -- the key did not program")
print(f"   BOOTKEY0 at OTP row 0x{i//2:04x}")
print(f"   stored: {flat[i:i+32].hex()}")
print(f"   expect: {want.hex()}")
print("   MATCH -- the hash is in silicon, byte for byte")
PY
    [ $? -eq 0 ] || die "boot key did not verify after programming"
    printf '\n   next: %s flash\n' "$0"
}

stage_flash() {
    say "flash -- install the sealed bootloader (reversible)"
    [ -f "$SEALED" ] || die "run '$0 seal' first"
    need_bootsel; check_chipid
    picotool load "$SEALED" || die "load failed"
    echo "   loaded. Reboot and confirm the token still works BEFORE 'enable' --"
    echo "   this is the image the bootrom will be verifying."
    printf '\n   next: verify the token by hand, then: %s enable\n' "$0"
}

stage_enable() {
    say "enable -- turn secure boot ON (TERMINAL)"
    [ -f "$OTP_ENABLE" ] || die "run '$0 seal' first"
    check_not_dev_key
    if [ "${I_MEAN_IT:-}" != "1" ]; then
        cat <<EOF

   Refusing to run without I_MEAN_IT=1.

   After this the bootrom will only boot images signed by
     $KEY
   and this is not undoable. Also, permanently:
     - the RISC-V (Hazard3) cores are disabled on this part
     - an unsealed or wrongly-sealed bootloader will not boot

   Confirm first that:
     [ ] '$0 flash' installed the SEALED bootloader, and the token booted
     [ ] BOOTSEL still works -- it is the only recovery if this goes wrong
     [ ] you can still reach DFU

   Then: I_MEAN_IT=1 $0 enable
EOF
        exit 2
    fi
    need_bootsel; check_chipid
    check_silicon_key_is_key
    picotool otp load -t json "$OTP_ENABLE" || die "otp load failed"
    printf '\n   done. %s verify\n' "$0"
}

stage_verify() {
    say "verify"
    need_bootsel
    picotool info -a 2>&1 | grep -iE "chipid|secure boot|available cpus|debug enable"
    echo "   -- OTP --"
    picotool otp get CRIT1 2>&1 | grep -E "^ROW|VALUE|SECURE_BOOT_ENABLE"
    picotool otp get BOOT_FLAGS1 2>&1 | grep -E "^ROW|VALUE|KEY_VALID"
    picotool otp get BOOT_FLAGS0 2>&1 | grep -E "^ROW|VALUE|DISABLE_BOOTSEL"
}

case "${1:-}" in
    seal)   stage_seal   ;;
    key)    stage_key    ;;
    flash)  stage_flash  ;;
    enable) stage_enable ;;
    verify) stage_verify ;;
    *) sed -n '2,32p' "$0"; exit 1 ;;
esac
