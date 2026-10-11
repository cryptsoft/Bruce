#!/usr/bin/env python3
# pqf_sign.py -- sign Bruce firmware images for the DFU bootloader.
#
# The bootloader (c/bootloader/) only installs images carrying a valid
# ECDSA-P256 signature over the image header; this tool produces that
# header. The wire format is defined in c/common/pqf_image.h -- the two
# files must change in lockstep.
#
#   keygen        make a new P-256 signing key (PEM, unencrypted)
#   export-pubkey emit the public key as a C header for the bootloader
#   sign          app.bin -> app.dfu  (4 KiB header sector || image)
#   verify        host-side check of a signed image
#   info          dump a signed image's header
#   fingerprint   identify a key, and say whether it is a published dev key
#
# Typical flow:
#   tools/pqf_sign.py keygen --key keys/pqf-dev-fw.pem
#   tools/pqf_sign.py export-pubkey --key keys/pqf-dev-fw.pem \
#       --out c/bootloader/src/pqf_boot_pubkey.h --name dev
#   tools/pqf_sign.py sign --key keys/pqf-dev-fw.pem \
#       --in build/bruce_c.bin --out bruce_c.dfu \
#       --fw-version 2 --board feitian_rp2350
#   dfu-util -D bruce_c.dfu
#
# THE DEV KEYS ARE NOT SECRET. keys/pqf-dev-fw.pem is in the repository on
# purpose, so anyone can build and install a dev image without a ceremony.
# The cost of that is exact: a bootloader carrying the dev public key will
# install firmware signed by anybody who has cloned this tree. It is a
# development convenience with no security property at all, and the one
# thing that must never happen is shipping it by accident.
#
# So the fingerprints of both published dev keys are pinned below, and
# every command that could put one somewhere permanent says so loudly.
# `--production` turns that warning into a refusal; see docs/SECUREBOOT.md
# for the ceremony that produces a key this tool will accept.
#
# Requires: python3 + the `cryptography` package.
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import hashlib
import os
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature

MAGIC = 0x57465150            # "PQFW" little-endian
HDR_VERSION = 1
HDR_SECTOR = 4096             # header occupies one flash sector
HDR_STRUCT = 256              # populated bytes within the sector
SIGNED_LEN = 64               # header[0:64] is the signed region
SIG_DER_MAX = 190             # sig_der field size in pqf_image_hdr_t
ALG_ECDSA_P256 = 1 << 0
IMAGE_MAX_LEN = 0x1E0000 - HDR_SECTOR   # PQF_IMAGE_MAX_LEN

BOARD_IDS = {
    "any": 0,
    "tiny2350": 1,
    "xiao_rp2350": 2,
    "feitian_rp2350": 3,
    "waveshare_rp2350_lcd_1_47": 4,
    "spotpear_rp2350_lcd_1_28": 5,
}
BOARD_NAMES = {v: k for k, v in BOARD_IDS.items()}

# SHA-256 over the uncompressed public point (0x04 || X || Y) of each key
# committed to this repository. Pinning the PUBLIC half is deliberate: it
# identifies a dev key even when the private half has been copied, renamed,
# re-encoded, or moved outside keys/ -- which is exactly how one would end
# up in a production build without anybody meaning it.
DEV_KEY_FINGERPRINTS = {
    "98e16f33c06fc710b2d44a6183b8bccc8b3a0c1e2e2a44fb5ac97988e834735c":
        "keys/pqf-dev-fw.pem (P-256 firmware signing key)",
    "bf552bf213e80f49b38038f65372808528aef987a18a7cae858721c18bffd993":
        "keys/pqf-dev-bootkey.pem (secp256k1 secure-boot key)",
}


def fingerprint(pubkey):
    """Stable identity for a key: SHA-256 of its uncompressed point."""
    pt = pubkey.public_bytes(serialization.Encoding.X962,
                             serialization.PublicFormat.UncompressedPoint)
    return hashlib.sha256(pt).hexdigest()


def dev_key_name(pubkey):
    """The registry entry for this key, or None if it is not a dev key."""
    return DEV_KEY_FINGERPRINTS.get(fingerprint(pubkey))


def check_not_dev(pubkey, what, production):
    """Warn -- or under --production, refuse -- for a published dev key.

    Called from every command that puts a key somewhere it outlives the
    invocation: into a signed image, or into the bootloader's header.
    """
    name = dev_key_name(pubkey)
    if name is None:
        return
    if production:
        sys.exit(
            f"\nREFUSING: {what} with {name}.\n"
            f"  The private half of that key is published in this repository, so\n"
            f"  anything it signs can be forged by anyone. --production requires a\n"
            f"  key generated offline -- see 'Production key ceremony' in\n"
            f"  docs/SECUREBOOT.md.\n")
    print(
        f"\n  !! DEVELOPMENT KEY !!\n"
        f"  {what} with {name}.\n"
        f"  Its private half is in the repository: this signature proves nothing\n"
        f"  and stops nobody. Fine for a bench board, never for a shipped one.\n"
        f"  Pass --production to make this a hard error.\n",
        file=sys.stderr)


def load_any_ec_key(path):
    """Load an EC private key of any curve -- `fingerprint` accepts both
    the P-256 firmware key and the secp256k1 boot key."""
    try:
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except (ValueError, TypeError) as e:
        sys.exit(f"{path}: not a readable unencrypted PEM private key ({e})")
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        sys.exit(f"{path}: not an EC private key")
    return key


def load_private_key(path):
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or \
            not isinstance(key.curve, ec.SECP256R1):
        sys.exit(f"{path}: not a P-256 (secp256r1) private key")
    return key


def build_signed_region(image, fw_version, board_id):
    return struct.pack(
        "<IIIIII8s32s",
        MAGIC, HDR_VERSION, len(image), fw_version, board_id,
        ALG_ECDSA_P256, b"\x00" * 8, hashlib.sha256(image).digest(),
    )


def parse_header(blob):
    if len(blob) < HDR_STRUCT:
        sys.exit("file too short for a pqf image header")
    (magic, hdr_version, image_len, fw_version, board_id, alg_mask,
     _reserved, image_sha) = struct.unpack("<IIIIII8s32s", blob[:SIGNED_LEN])
    (sig_len,) = struct.unpack("<H", blob[SIGNED_LEN:SIGNED_LEN + 2])
    sig_der = blob[SIGNED_LEN + 2:SIGNED_LEN + 2 + sig_len]
    return {
        "magic": magic, "hdr_version": hdr_version, "image_len": image_len,
        "fw_version": fw_version, "board_id": board_id, "alg_mask": alg_mask,
        "image_sha256": image_sha, "sig_len": sig_len, "sig_der": sig_der,
        "signed_region": blob[:SIGNED_LEN],
    }


def cmd_keygen(args):
    if os.path.exists(args.key) and not args.force:
        sys.exit(f"{args.key} exists; pass --force to overwrite")
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    os.makedirs(os.path.dirname(args.key) or ".", exist_ok=True)
    fd = os.open(args.key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    nums = key.public_key().public_numbers()
    print(f"wrote {args.key}")
    print(f"  pub.x = {nums.x:064x}")
    print(f"  pub.y = {nums.y:064x}")


def cmd_export_pubkey(args):
    key = load_private_key(args.key)
    check_not_dev(key.public_key(),
                  "baking a key into the bootloader", args.production)
    nums = key.public_key().public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")

    def c_array(b):
        lines = []
        for i in range(0, len(b), 8):
            lines.append("    " + ", ".join(f"0x{v:02x}" for v in b[i:i + 8]) + ",")
        return "\n".join(lines)

    guard = "PQF_BOOT_PUBKEY_H"
    fp = fingerprint(key.public_key())
    is_dev = 1 if dev_key_name(key.public_key()) else 0
    dev_note = ("""
 * THIS IS THE PUBLISHED DEVELOPMENT KEY. Its private half is committed to
 * the Bruce repository, so a bootloader built from this header installs
 * firmware signed by anyone at all. PQF_BOOT_PUBKEY_IS_DEV is 1 below, and
 * c/bootloader/src/main.c refuses to compile a PQF_PRODUCTION build against
 * it -- that guard is the only thing standing between a bench convenience
 * and a shipped token that trusts the world.
 *""" if is_dev else """
 * Non-development key. Keep the private half offline; the ceremony that
 * produced it is in docs/SECUREBOOT.md.
 *""")
    body = f"""/* pqf_boot_pubkey.h -- firmware-signing public key ("{args.name}").
 *
 * GENERATED by tools/pqf_sign.py export-pubkey -- do not edit by hand.
 * This key gates which firmware images the DFU bootloader will install
 * (and boot).
 *
 * key fingerprint (SHA-256 of 04||X||Y):
 *   {fp}
 *{dev_note}
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef {guard}
#define {guard}

#include <stdint.h>

#define PQF_BOOT_PUBKEY_NAME "{args.name}"

/* 1 when the key above is one of the dev keys published in the Bruce
 * repository. main.c turns this into a build failure under PQF_PRODUCTION. */
#define PQF_BOOT_PUBKEY_IS_DEV {is_dev}

static const uint8_t pqf_boot_pubkey_x[32] = {{
{c_array(x)}
}};

static const uint8_t pqf_boot_pubkey_y[32] = {{
{c_array(y)}
}};

#endif /* {guard} */
"""
    with open(args.out, "w") as f:
        f.write(body)
    print(f"wrote {args.out} (key '{args.name}')")


def cmd_sign(args):
    key = load_private_key(args.key)
    check_not_dev(key.public_key(), "signing a firmware image", args.production)
    with open(args.infile, "rb") as f:
        image = f.read()
    if not image:
        sys.exit(f"{args.infile}: empty image")
    if len(image) > IMAGE_MAX_LEN:
        sys.exit(f"{args.infile}: {len(image)} bytes exceeds the "
                 f"{IMAGE_MAX_LEN}-byte app slot")

    signed = build_signed_region(image, args.fw_version,
                                 BOARD_IDS[args.board])
    sig = key.sign(hashlib.sha256(signed).digest(),
                   ec.ECDSA(Prehashed(hashes.SHA256())))
    if len(sig) > SIG_DER_MAX:
        sys.exit("DER signature unexpectedly large")

    hdr = signed + struct.pack("<H", len(sig)) + sig
    hdr += b"\x00" * (HDR_STRUCT - len(hdr))          # struct padding
    hdr += b"\xff" * (HDR_SECTOR - HDR_STRUCT)        # erased-flash pad
    with open(args.out, "wb") as f:
        f.write(hdr + image)
    print(f"wrote {args.out}: image {len(image)} bytes, "
          f"fw_version {args.fw_version}, board {args.board}, "
          f"sig {len(sig)} bytes DER")
    print(f"  signed by:   {fingerprint(key.public_key())}")


def verify_blob(blob, pubkey):
    hdr = parse_header(blob)
    if hdr["magic"] != MAGIC:
        return hdr, "bad magic"
    if hdr["hdr_version"] != HDR_VERSION:
        return hdr, "bad header version"
    image = blob[HDR_SECTOR:HDR_SECTOR + hdr["image_len"]]
    if len(image) != hdr["image_len"]:
        return hdr, "file shorter than image_len"
    if hashlib.sha256(image).digest() != hdr["image_sha256"]:
        return hdr, "image SHA-256 mismatch"
    try:
        pubkey.verify(hdr["sig_der"],
                      hashlib.sha256(hdr["signed_region"]).digest(),
                      ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        return hdr, "ECDSA signature INVALID"
    return hdr, None


def cmd_verify(args):
    key = load_private_key(args.key)
    with open(args.infile, "rb") as f:
        blob = f.read()
    hdr, err = verify_blob(blob, key.public_key())
    if err:
        sys.exit(f"{args.infile}: {err}")
    print(f"{args.infile}: signature OK "
          f"(fw_version {hdr['fw_version']}, "
          f"board {BOARD_NAMES.get(hdr['board_id'], hdr['board_id'])}, "
          f"image {hdr['image_len']} bytes)")
    name = dev_key_name(key.public_key())
    print(f"  signed by:   {fingerprint(key.public_key())}"
          + (f"\n  WHICH IS:    {name} -- a published dev key" if name else ""))


def cmd_info(args):
    with open(args.infile, "rb") as f:
        blob = f.read()
    hdr = parse_header(blob)
    print(f"magic:       {'PQFW' if hdr['magic'] == MAGIC else hex(hdr['magic'])}")
    print(f"header ver:  {hdr['hdr_version']}")
    print(f"image_len:   {hdr['image_len']}")
    print(f"fw_version:  {hdr['fw_version']}")
    print(f"board:       {BOARD_NAMES.get(hdr['board_id'], hdr['board_id'])}")
    print(f"alg_mask:    {hdr['alg_mask']:#x}")
    print(f"image sha:   {hdr['image_sha256'].hex()}")
    print(f"sig ({hdr['sig_len']} B):  {hdr['sig_der'].hex()}")


def cmd_fingerprint(args):
    key = load_any_ec_key(args.key)
    pub = key.public_key()
    fp = fingerprint(pub)
    name = dev_key_name(pub)
    print(f"{args.key}")
    print(f"  curve:       {key.curve.name}")
    print(f"  fingerprint: {fp}")
    if name:
        print(f"  DEV KEY:     {name}")
        print("  This key is published. It is suitable for a bench board and")
        print("  for nothing else.")
        sys.exit(3 if args.strict else 0)
    print("  not a published dev key")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate a P-256 signing key")
    k.add_argument("--key", required=True, help="output PEM path")
    k.add_argument("--force", action="store_true")
    k.set_defaults(fn=cmd_keygen)

    e = sub.add_parser("export-pubkey", help="emit bootloader C header")
    e.add_argument("--key", required=True)
    e.add_argument("--out", required=True)
    e.add_argument("--name", default="dev", help="key label baked in")
    e.add_argument("--production", action="store_true",
                   help="refuse a published dev key instead of warning")
    e.set_defaults(fn=cmd_export_pubkey)

    s = sub.add_parser("sign", help="sign an app .bin into a .dfu image")
    s.add_argument("--key", required=True)
    s.add_argument("--in", dest="infile", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--fw-version", type=int, required=True)
    s.add_argument("--board", choices=sorted(BOARD_IDS), default="any")
    s.add_argument("--production", action="store_true",
                   help="refuse a published dev key instead of warning")
    s.set_defaults(fn=cmd_sign)

    v = sub.add_parser("verify", help="verify a signed image on the host")
    v.add_argument("--key", required=True)
    v.add_argument("--in", dest="infile", required=True)
    v.set_defaults(fn=cmd_verify)

    i = sub.add_parser("info", help="dump a signed image header")
    i.add_argument("--in", dest="infile", required=True)
    i.set_defaults(fn=cmd_info)

    f = sub.add_parser("fingerprint",
                       help="identify a key; --strict exits 3 for a dev key")
    f.add_argument("--key", required=True)
    f.add_argument("--strict", action="store_true",
                   help="exit non-zero if this is a published dev key, so a "
                        "release script can gate on it")
    f.set_defaults(fn=cmd_fingerprint)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
