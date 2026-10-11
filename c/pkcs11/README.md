# pqf-pkcs11 -- the token as a PKCS#11 random number source

A PKCS#11 (Cryptoki) module whose only real capability is
`C_GenerateRandom`: bytes come from the Bruce token's entropy
source -- the RP2350's ring-oscillator TRNG, or a quantum RNG when one
is attached to the token's I2C bus (see
[`docs/HARDWARE.md`](../../docs/HARDWARE.md#qrng-over-i2c-optional))
-- pulled over USB with the vendor CTAP HID command `CTAPHID_CMD_RNG`
(0x50 -- see `c/firmware/src/ctaphid.h` for the wire contract). An
inexpensive token becomes an entropy source for anything that speaks
PKCS#11.

This page is for someone building or integrating the module. It
assumes a token running either firmware
([`docs/GETTING-STARTED.md`](../../docs/GETTING-STARTED.md)) and a C
compiler on the host; the Rust equivalent is
[`crates/pkcs11/`](../../crates/pkcs11/README.md).

No authentication, no objects, no mechanisms. The full v2.40 API
surface is present in the function list; everything outside the RNG
path answers `CKR_FUNCTION_NOT_SUPPORTED`.

## Layout

| File            | What                                                          |
|-----------------|---------------------------------------------------------------|
| `pqf_pkcs11.c`  | The whole module. C90, single file.                           |
| `cryptoki.h`    | Platform-macro wrapper; include this, never oasis/ directly.  |
| `oasis/`        | OASIS PKCS#11 v3.01 headers, vendored verbatim (OASIS IPR).   |
| `smoke.c`       | No-device smoke test (`make test`).                           |
| `proof.c`       | Demo: proves the entropy is the token's (`make proof`, `-i` adds the unplug/replug test). |

The USB transport is the vendored pqhid library in `../hid` (Linux
hidraw / macOS IOKit / Windows SetupAPI backends).

## Build

```
make            # pqf-pkcs11.dylib (macOS) / pqf-pkcs11.so (Linux)
make test       # dlopen smoke test, no token needed
```

## Use

Token attached, firmware with `CTAPHID_CMD_RNG` flashed:

```
$ pkcs11-tool --module ./pqf-pkcs11.dylib --list-slots
Slot 0 (0x0): Bruce USB CTAP HID slot
  token label        : Bruce (C port)
  token flags        : rng, token initialized, readonly
  ...

$ pkcs11-tool --module ./pqf-pkcs11.dylib --generate-random 32 | xxd
```

Via the OpenSSL pkcs11 provider ([latchset/pkcs11-provider](https://github.com/latchset/pkcs11-provider)),
which registers the token as a `PKCS11-RAND` random generator. OpenSSL
only routes `RAND_bytes` through a provider RNG when the config's
`random` section says so, and the provider must load its PKCS#11
module eagerly or the RNG isn't registered in time:

```
# token-rand.cnf
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
random = random_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = /path/to/pkcs11-provider/pkcs11.dylib
pkcs11-module-path = /path/to/Bruce/c/pkcs11/pqf-pkcs11.dylib
pkcs11-module-load-behavior = early
activate = 1

[random_sect]
random = PKCS11-RAND
```

```
$ OPENSSL_CONF=token-rand.cnf openssl list -random-generators
  ...
  PKCS11-RAND @ pkcs11
$ OPENSSL_CONF=token-rand.cnf openssl rand -hex 32
d4c05a7cc71bf6261c6cfe989685b129e0de1daf673f35633617f49e0334a7b4
```

Both firmware ports implement the command (C:
`c/firmware/src/ctaphid.c`; Rust: `crates/firmware/src/ctaphid.rs`),
wire-compatible: empty payload -> 57 bytes, or a 2-byte big-endian
count of 1..1024 per transaction. `pqhid_rng()` chunks larger
requests, so `C_GenerateRandom` sizes are unbounded in practice.

## Model

- **Slot = enumerated token.** `C_GetSlotList` rescans the USB bus on
  every call, so hot-plug is picked up by applications that re-list.
  Slot IDs are indices into the latest scan and are not stable across
  replug (v1 simplification).
- **Session = open HID handle.** `C_OpenSession` runs the CTAP HID
  INIT handshake; each session gets its own channel, so concurrent
  sessions multiplex cleanly. `C_CloseSession` / `C_Finalize` release
  the device.
- **`C_SeedRandom` is a no-op** returning `CKR_OK`: the token's entropy
  source takes no external seed material.
- **No locking.** Intended for single-threaded consumers
  (`pkcs11-tool`, `openssl rand`). `CK_C_INITIALIZE_ARGS` locking
  flags are accepted but not acted on -- a v1 limitation.

## Trust note (what this is and isn't)

The RNG command is unauthenticated by design and the transport is
plain USB HID: this gives you a *hardware entropy source*, not an
attested one. A consumer should mix the output into its own pool
(OpenSSL does) rather than trust it raw -- the same posture as any
USB TRNG dongle.
