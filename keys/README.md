# keys/

The two files here are **development keys**, committed on purpose so that
dev builds reproduce without a ceremony. This page says what they are,
what the tooling does when it sees them, and why a production key must
never join them; it assumes the DFU bootloader and secure-boot pages,
[`docs/DFU.md`](../docs/DFU.md) and [`docs/SECUREBOOT.md`](../docs/SECUREBOOT.md).

| file | curve | job |
|---|---|---|
| `pqf-dev-fw.pem` | P-256 | firmware signing -- the bootloader verifies app images against it |
| `pqf-dev-bootkey.pem` | secp256k1 | secure boot -- the RP2350 mask ROM verifies the bootloader against its hash in OTP |

Their private halves are public. A board provisioned with either one does
not have secure boot; it has a signature check that anyone who has cloned
this repository can satisfy. That is the correct trade for a bench board
and is never acceptable on a shipped one.

The tooling knows both keys by fingerprint and will say so:

```bash
python3 ../tools/pqf_sign.py fingerprint --key pqf-dev-fw.pem
```

- `pqf_sign.py sign` and `export-pubkey` warn; `--production` refuses.
- `tools/secureboot-provision.sh` refuses to burn the dev boot key into
  OTP at all -- that row is one-way and there is no second slot.
- The bootloader will not compile with `-DPQF_PRODUCTION=1` against a
  dev key.

**Do not put a production key in this directory.** `.gitignore` ignores
everything here except these two files by name, and a pre-commit hook
scans staged content for private keys -- but both are backstops. A
production key belongs on a machine that does not have this repository
checked out. See *Production key ceremony* in `docs/SECUREBOOT.md`.
