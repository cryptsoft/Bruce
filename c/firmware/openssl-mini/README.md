# openssl-mini -- vendored OpenSSL primitives for the C firmware

A self-contained snapshot of just the OpenSSL crypto primitives the
`bruce` C firmware needs, lifted from upstream OpenSSL 3.5.0-dev
and made to build standalone (no `libcrypto.so`, no autoconf, no
`openssl/macros.h` cascade).

Released under the Apache License, Version 2.0 -- the same licence as
upstream OpenSSL. The full text is in [`LICENSE-APACHE-OPENSSL`](LICENSE-APACHE-OPENSSL);
each vendored source file preserves its original OpenSSL copyright
notice at the top.

## Layout

```
openssl-mini/
|-- LICENSE-APACHE-OPENSSL    verbatim from upstream
|-- README.md                  this file
|-- ML-DSA-LOWMEM.md           local deviations in src/ml_dsa/ (read
|                              before re-vendoring that tree)
|-- include/
|   |-- pqf_crypto.h           public API -- what the firmware sees
|   |-- openssl/sha.h          minimal shim (SHA-256 only)
|   |-- openssl/crypto.h       shim -- just OPENSSL_cleanse
|   |-- openssl/opensslconf.h  shim -- empty (no feature gates)
|   |-- openssl/opensslv.h     shim -- version macros
|   |-- internal/deprecated.h  shim -- empty
|   |-- internal/endian.h      verbatim from upstream
|   |-- crypto/sha.h           shim -- one fwd decl
|   +-- crypto/md32_common.h   verbatim from upstream
|-- src/
|   |-- sha256.c               verbatim from upstream
|   |-- sha_local.h            verbatim from upstream
|   +-- pqf_sha256.c           pqf_* wrapper around upstream API
+-- test/
    |-- Makefile               host-side test runner
    +-- test_sha256.c          FIPS 180-2 known-answer tests
```

## Vendored vs shim

| File | Source | Notes |
|---|---|---|
| `src/sha256.c` | OpenSSL `crypto/sha/sha256.c` | byte-for-byte, copyright intact |
| `src/sha_local.h` | OpenSSL `crypto/sha/sha_local.h` | byte-for-byte |
| `include/crypto/md32_common.h` | OpenSSL `include/crypto/md32_common.h` | byte-for-byte |
| `include/internal/endian.h` | OpenSSL `include/internal/endian.h` | byte-for-byte |
| `include/openssl/sha.h` | minimal shim | declares only `SHA256_CTX` + the SHA-256 functions sha256.c defines -- the upstream header pulls `openssl/macros.h`, `openssl/e_os2.h`, etc., which we don't need |
| `include/openssl/crypto.h` | minimal shim | one symbol: `OPENSSL_cleanse` = `memset` |
| `include/openssl/opensslconf.h` | minimal shim | empty -- none of the upstream conditionals affect SHA-256 |
| `include/openssl/opensslv.h` | minimal shim | version macros |
| `include/internal/deprecated.h` | minimal shim | empty -- used as a gate, not a code dependency |
| `include/crypto/sha.h` | minimal shim | one fwd decl (`ossl_sha256_192_init`) |

Most vendored .c / templated .h files compile unmodified; the shims
make them standalone. The exceptions are listed in the next section.

## Local modifications to vendored sources

Two exceptions to "compiles unmodified". First, **`src/ml_dsa/` has
been modified**. The level-87 signing path did not fit the RP2350's SRAM, so
the FIPS 204 core was changed to expand the `k * l` matrix A a row at a
time instead of materialising it, to fuse the matrix multiply's
accumulator, and to stop building the encoded key pair on a path that
only signs. Signature and public-key bytes are unchanged -- the KAT
suite cross-checks them against BouncyCastle and passes identically
before and after.

Every deviation, why it is there, the `PQF_MLDSA_LOWMEM` build option
that governs the one case with a CPU trade, the measured heap / stack /
`.text` effect, and a re-vendoring checklist are in
[`ML-DSA-LOWMEM.md`](ML-DSA-LOWMEM.md). Read it before refreshing
`src/ml_dsa/` from upstream.

Second, four files carry small hooks that are not in upstream.
`src/bn/bn_exp.c`, `src/bn/bn_gcd.c` and `src/ec/ec_mult.c` call
`pqf_yield()` once per loop step of the modular exponentiation, the
modular inversion and the scalar multiplication: a weak no-op by
default, which the single-core build points at the USB pump so a long
signature does not starve the host. `src/ec/ecdsa_ossl.c` has
`pqf_ecdsa_dbg()` trace points at the nonce-retry stages, a weak no-op
used by the bring-up diagnostics.

Third, one upstream security fix is backported. This subset carries no
dedicated P-256 implementation (upstream's `ecp_nistz256` and
`ecp_nistp256` are not vendored), so every ECDSA signature goes through
the generic Montgomery ladder in `src/ec/ec_mult.c`, the path OpenSSL's
CVE-2026-54872 is about: the ladder's scalar padding did work that
depended on the secret nonce's magnitude. The fix from OpenSSL 3.5.9
(commit `3f7e1363`) is applied as upstream wrote it: `bn_set_top_fixed()`
in `src/bn/bn_intern.c`, its prototype in `include/crypto/bn.h`, and the
two pins in `ossl_ec_scalar_mul_ladder()`. Signature bytes are unchanged;
the P-256 host suite passes as before. Whether timing leaks on the
RP2350 has not been measured either way.

No other vendored source in this directory carries local changes.
Each of the sixteen modified files says so in a notice under its
OpenSSL header, as section 4(b) of the Apache License requires of
changed files.

## Build into the firmware

Add the source files to `c/firmware/CMakeLists.txt`:

```cmake
add_executable(bruce_c
    ...
    openssl-mini/src/sha256.c
    openssl-mini/src/pqf_sha256.c
    ...
)
target_include_directories(bruce_c PRIVATE
    ...
    openssl-mini/include
    openssl-mini/src
    ...
)
```

The firmware calls only the `pqf_*` symbols declared in
`include/pqf_crypto.h`; the upstream names stay an implementation
detail of `openssl-mini/`.

## Host tests

```sh
$ cd c/firmware/openssl-mini/test
$ make test
```

Runs FIPS 180-2 known-answer vectors plus streaming-consistency
checks against the vendored SHA-256. Should report `0 failure(s)`.

## Adding a primitive

Phase C-4 shipped SHA-256 first, then HMAC-SHA-256, AES-256-CBC, the
BN tree, and P-256 ECDSA / ECDH on the same vendor-and-shim pattern;
Phase C-8 added SHA-512 (the ECDSA hedged nonce), SHA-3 / Keccak-1600
(the SHAKE XOF), and the ML-DSA-44/65/87 tree the same way. The
pattern is the recipe for any future primitive.

**Everything in this directory is Apache-2.0** -- the whole tree, not
just the vendored files. The upstream sources keep their own OpenSSL
copyright notices verbatim; the project-original code here (the pqf_*
wrappers, the EVP shim, the DER codec, the EC stubs and the host tests)
is (c) Cryptsoft Pty Ltd under the same licence, so the directory is
uniform and can be lifted out as a unit.

The repository as a whole is Apache-2.0 too ([`LICENSE`](../../../LICENSE),
[`THIRD_PARTY.md`](../../../THIRD_PARTY.md)); what sets this directory
apart is only that it is self-contained, so it can be lifted out and
used on its own.
