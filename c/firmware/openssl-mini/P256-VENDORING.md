# P-256 vendoring plan (Phase C-4d / C-4e)

The SHA / HMAC / AES vendoring pattern in this directory worked
because each algorithm sits in one self-contained .c file with a
small handful of `#include "internal/..."` lines we could replace
with thin shim headers. **P-256 doesn't fit that model**: OpenSSL's
ECDSA / ECDH is implemented on top of `EC_GROUP` / `EC_POINT` /
`BIGNUM`, all of which depend on the `libcrypto` infrastructure
(error stack, memory glue, ASN.1 buffers, BIO) that the rest of the
library brings.

Per the Phase C-4 decision, we're going to vendor it anyway -- same
verbatim-source approach, just with a bigger header-shim surface.
This file documents the work breakdown so the next session can pick
up cleanly.

## Status (checkpoint)

What's been started already in `openssl-mini/`:

| Path | Status |
|---|---|
| `include/crypto/bn_conf.h` | shim -- selects SIXTY_FOUR_BIT_LONG / THIRTY_TWO_BIT by `__LP64__` |
| `include/internal/cryptlib.h` | shim -- OPENSSL_malloc, ERR_raise stubs, common error reasons |
| `include/internal/constant_time.h` | upstream verbatim |
| `include/internal/common.h` | upstream verbatim |
| `include/openssl/bn.h` | upstream verbatim -- pulls macros.h / types.h cascade still |
| `src/bn/bn_lib.c` | upstream verbatim -- does NOT yet compile against shims |
| `src/bn/bn_local.h` | upstream verbatim |

`bn_lib.c` currently fails at:

```
src/bn/bn_local.h:21: fatal error: 'crypto/bn_conf.h' not found
```

(That one is now fixed; the next error after re-running the compile
will reveal the next missing dep.)

## Next sessions

### Session 2 -- BN compile-clean

Iterate `cc -c src/bn/bn_lib.c` and add shim headers per the error
output. Expected additions (rough order):

- `include/openssl/macros.h` -- `OSSL_DEPRECATEDIN_3_0` markers etc.
- `include/openssl/types.h` -- `BN_ULONG`, `BIGNUM`, `BN_CTX` typedefs
- `include/openssl/configuration.h` -- feature flags (empty / minimal)
- `include/openssl/bnerr.h` -- error code defines
- `include/openssl/rand.h` -- `RAND_bytes` / `RAND_priv_bytes_ex` (will
  bridge to the firmware's TRNG via `src/pqf_rand.c` later)
- `include/internal/e_os.h` -- `ossl_inline`, platform detection
- `include/internal/nelem.h` -- `OSSL_NELEM`
- `include/internal/numbers.h` -- UINT64_MAX, INT_MAX etc.
- `include/internal/safe_math.h` -- overflow-checked arithmetic
- `include/crypto/bn.h` -- `ossl_bn_*` internal helpers
- `include/crypto/cryptlib.h` -- additional OPENSSL_* internal hooks

Then add the rest of BN's source files. Tracking list (15-ish):

```
src/bn/bn_lib.c        -- already vendored
src/bn/bn_add.c        -- BN_add / BN_sub
src/bn/bn_mul.c        -- BN_mul
src/bn/bn_div.c        -- BN_div / BN_mod
src/bn/bn_mod.c        -- BN_mod_add / BN_mod_mul / BN_mod_sub
src/bn/bn_exp.c        -- BN_mod_exp
src/bn/bn_gcd.c        -- BN_mod_inverse
src/bn/bn_shift.c      -- BN_lshift / BN_rshift
src/bn/bn_word.c       -- BN_add_word / BN_mul_word
src/bn/bn_conv.c       -- BN_bn2bin / BN_bin2bn
src/bn/bn_rand.c       -- BN_rand_range (needs the firmware's TRNG)
src/bn/bn_ctx.c        -- BN_CTX_new / BN_CTX_get
src/bn/bn_sqr.c        -- BN_sqr
src/bn/bn_mont.c       -- Montgomery multiplication (needed for ECDSA)
src/bn/bn_blind.c      -- blinding (used during signing)
src/bn/bn_recp.c       -- reciprocal multiplication
src/bn/bn_asm.c        -- fallback math routines (no asm path)
src/bn/bn_const.c      -- known constants
```

### Session 3 -- EC framework + P-256

Once BN compiles + links a minimal `test_bn` (BN_set_word + BN_add
round-trip):

```
src/ec/ec_lib.c          -- EC_GROUP / EC_POINT plumbing
src/ec/ec_curve.c        -- named curve table (NIST P-256)
src/ec/ec_key.c          -- EC_KEY management
src/ec/ec_cvt.c          -- EC_GROUP factory functions
src/ec/ecp_smpl.c        -- generic GF(p) point ops
src/ec/ecp_nistp256.c    -- P-256-specific 64-bit C implementation
src/ec/ec_oct.c          -- point encoding / decoding
src/ec/ecp_oct.c         -- point encoding (prime field)
src/ec/ec_check.c        -- curve validation
src/ec/ec_mult.c         -- generic scalar multiplication
src/ec/ec_kmeth.c        -- key-method registration
```

Plus headers:

```
include/openssl/ec.h     -- EC public API
include/crypto/ec.h      -- internal EC helpers
include/openssl/objects.h, openssl/obj_mac.h -- OID identifiers (need
                                                only the EC curve OIDs)
src/ec/ec_local.h        -- internal EC types
```

### Session 4 -- ECDSA + ECDH glue + pqf_p256

```
src/ec/ecdsa_sign.c
src/ec/ecdsa_vrf.c
src/ec/ecdsa_ossl.c
src/ec/ecdh_ossl.c
src/ec/ecdh_kdf.c

src/pqf_p256.c           -- new: pqf_p256_keypair / pqf_ecdsa_sign /
                            pqf_ecdsa_verify / pqf_ecdh_shared
test/test_p256.c         -- NIST CAVP test vectors
```

### Session 5 -- embedded wire-up + Phase C-5 start

Once host tests pass:
- Add the new sources to `c/firmware/CMakeLists.txt`.
- Cross-compile + size-check on Cortex-M33.
- Move on to Phase C-5 (MakeCredential + GetAssertion ES256).

## Why not just clean-room?

Asked + decided in conversation: vendoring OpenSSL's actual P-256
code keeps the firmware on a well-tested codebase that's audited by
many eyes. Clean-room ECDSA / scalar-multiplication code has a long
history of subtle side-channel + correctness bugs; we'd rather take
the up-front vendoring cost than maintain hand-written crypto.

## Apache-2.0 attribution

Every vendored source file keeps its original
`Copyright ... The OpenSSL Project Authors` header verbatim. The full
licence text is in `LICENSE-APACHE-OPENSSL` at this directory's root.

**This whole directory is Apache-2.0**, including the project-original
code: the shims, the `pqf_*` wrappers in `src/pqf_*.c`, the DER codec and
the EC stubs are all SPDX `Apache-2.0`, (c) Cryptsoft Pty Ltd. They were
Apache-2.0 until they were relicensed to match the tree they live
in, so the directory is uniform and can be lifted out and used on its
own. Code outside this directory is unaffected -- see the carve-out in
`THIRD_PARTY.md`.
