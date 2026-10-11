# pqf-pkcs11 (Rust) -- the token as a PKCS#11 random number source

The Rust sibling of the C module in [`c/pkcs11/`](../../c/pkcs11/README.md):
a host-side PKCS#11 module that serves the Bruce token's entropy
to anything that speaks Cryptoki. This page is for someone building or
integrating it; it assumes a token running either firmware and the
pinned Rust toolchain from
[`docs/GETTING-STARTED.md`](../../docs/GETTING-STARTED.md). Same
behaviour as the C module, same wire command; different foundation:

|            | C module (`c/pkcs11`)        | This crate (`crates/pkcs11`)     |
|------------|------------------------------|----------------------------------|
| ABI types  | vendored OASIS v3.01 headers | [`cryptoki-sys`] crate           |
| transport  | `libpqhid` (`c/hid`)         | `pqf-ctaphid` (`crates/ctaphid-client`) |
| output     | `pqf-pkcs11.dylib`/`.so`     | `libpqf_pkcs11.dylib`/`.so`      |

Only `C_GenerateRandom` does real work: bytes are pulled from the
token's entropy source (the RP2350's ring-oscillator TRNG, or a
quantum RNG when one is attached -- see
[`docs/HARDWARE.md`](../../docs/HARDWARE.md#qrng-over-i2c-optional))
over USB via the vendor command `CTAPHID_CMD_RNG` (0x50). No
authentication, no objects, no mechanisms.
The full Cryptoki v2.40 function list is present so any application
accepts the module; everything outside the RNG path returns
`CKR_FUNCTION_NOT_SUPPORTED` (the generated stubs in
`src/unsupported.rs`).

## Build

Host-only cdylib -- excluded from the workspace default set, so pass the
host triple:

```
cargo build -p pqf-pkcs11 --release \
    --target $(rustc -vV | awk '/host/{print $2}')
# -> target/<host>/release/libpqf_pkcs11.dylib
```

## Use

Point any PKCS#11 consumer at the built `.dylib`/`.so` -- it is
drop-in interchangeable with the C module:

```
DYLIB=target/<host>/release/libpqf_pkcs11.dylib

pkcs11-tool --module $DYLIB --list-slots
pkcs11-tool --module $DYLIB --generate-random 32 | xxd

# OpenSSL pkcs11 provider -- same recipe as the C module, only the
# module path changes. See c/pkcs11/README.md for the full openssl.cnf.
OPENSSL_CONF=token-rand.cnf openssl rand -hex 32
```

The C proof program validates this module too (they share the ABI):

```
cd c/pkcs11 && make proof
./proof /path/to/libpqf_pkcs11.dylib        # identity / liveness / quality
./proof -i /path/to/libpqf_pkcs11.dylib     # + unplug/replug test
```

## Model

Identical to the C module: slot == enumerated token (`C_GetSlotList`
rescans the USB bus each call for hot-plug; slot IDs are indices into
the latest scan, not stable across replug); each session owns its own
opened HID handle (its own CTAP HID channel); `C_SeedRandom` is an
accepted no-op. Unlike the C module, all state sits behind a single
`Mutex`, so this one is thread-safe even though the intended consumers
are single-threaded.

[`cryptoki-sys`]: https://crates.io/crates/cryptoki-sys
