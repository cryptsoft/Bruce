# HMAC domain separation (both ports MUST match byte-for-byte)

The normative list of domain-separation labels for every HMAC the
firmware keys on its master MAC key. The Rust and C ports implement it
independently and must agree byte for byte; the host suites of both
ports pin these strings. The labels live in
`crates/firmware/src/credential_id.rs` (Rust) and
`c/firmware/src/credential.c` (C). This page is for anyone touching
either derivation, or writing a verifier or test that recomputes them;
the credentialID layout the labels protect is in
[PROTOCOL.md](PROTOCOL.md#encrypted-credential-id-161-bytes), the
provenance is a finding of the static audit in
[notes/audit/AUDIT_FINDINGS.md](notes/audit/AUDIT_FINDINGS.md), and the
tree itself starts at [GETTING-STARTED.md](GETTING-STARTED.md).

## Why explicit labels
Three independent secrets are derived by HMAC-SHA-256 keyed on the **single**
device master MAC key (`key_handle_hmac_key` in Rust / `s_mac_key` in C):

1. **credentialID integrity tag** -- `HMAC(macKey, version||iv||ciphertext)`
2. **hmac-secret `cred_random`** -- per-uv per-credential secret
3. **`largeBlobKey`** -- per-credential AEAD key returned to the RP

Before the labels were introduced they were separated only by *incidental*
input-length / suffix differences (C had a partial `"pqf-hmac-secret"` prefix
on cred_random and a `"lbk"` suffix on largeBlobKey; Rust had **no** tags at
all). A future `CRED_ID_LEN` or suffix change could have made two inputs
collide -> the same key reused for two purposes. The Rust and C `cred_random`
inputs also **diverged** (C prefixed, Rust did not), so the two ports were not
true mirrors.

## The labels
Every HMAC keyed on the master MAC key prepends a distinct ASCII domain label
as the **first bytes** of the HMAC message. These are the EXACT byte strings
(ASCII, **no** NUL terminator), **identical in both ports** -- the `DOMAIN_*`
constants of `credential_id.rs` and `credential.c`:

| Purpose          | Constant name           | Bytes (ASCII)          | Len |
|------------------|-------------------------|------------------------|-----|
| integrity tag    | `DOMAIN_CRED_ID`        | `pqf-cred-id`          | 11  |
| cred_random      | `DOMAIN_CRED_RANDOM`    | `pqf-hmac-secret`      | 15  |
| largeBlobKey     | `DOMAIN_LARGE_BLOB_KEY` | `pqf-large-blob-key`   | 18  |
| overflow key tag | `DOMAIN_RK_OVERFLOW`    | `pqf-rk-overflow`      | 15  |

These four diverge within the first 5 bytes (`c` / `h` / `l` / `r` at index 4)
and none is a prefix of another, so no two HMAC inputs can EVER be equal
regardless of credentialID length or content -> rigorous, length-independent
separation.

The fourth exists only in builds with overflow discoverable-credential sectors
(`PQF_RESIDENT_EXTRA_SECTORS > 0`, [BUILD.md](BUILD.md#axis-7-optional-discoverable-credential-capacity)):
`tag = LE32(HMAC(macKey, DOMAIN_RK_OVERFLOW)[0..4])`, the label alone as the
message, stored in each overflow sector's header so a sector written under
earlier master keys reads as empty. It is defined next to its one user rather
than with the three above: `DOMAIN_RK_OVERFLOW` in
`crates/firmware/src/ctap2.rs`, the same bytes in `refresh_tag()` in
`c/firmware/src/resident_store.c`. The two ports never read each other's
overflow sectors (their key sectors differ), so only the label, not the
tag value, is shared.

## Exact HMAC inputs
1. **Integrity tag** -- applied in BOTH encrypt and decrypt (it MUST stay
   symmetric, or NO credential will verify):
   `tag = HMAC(macKey, DOMAIN_CRED_ID || version || iv || ciphertext)`
   i.e. `DOMAIN_CRED_ID` prepended to the signed region (`blob[..N]`,
   where `N` is 129 for the 161-byte credentialID -- read the real constant,
   do not hard-code it).
2. **cred_random**:
   `cr = HMAC(macKey, DOMAIN_CRED_RANDOM || credentialId || uv_byte)`
   `uv_byte` = `0x01` if uv_present else `0x00`.
3. **largeBlobKey**:
   `lbk = HMAC(macKey, DOMAIN_LARGE_BLOB_KEY || credentialId)`
   (the C port's former trailing `"lbk"` suffix is gone; the label is the
   prefix.)

`credentialId` = the full 161-byte blob, exactly as it appears on the wire.

## alg-discriminator invariant (documented and asserted; behaviour unchanged)
v1 ES256-vs-hybrid is inferred from an all-zero `mldsa_seed` test. This stays
(it is authenticated by the integrity tag, so not externally exploitable) and
is made explicit in both ports:
- On encrypt of a **hybrid** credential an all-zero seed is refused: the Rust
  encoder asserts `mldsa_seed != [0u8; 32]` (`debug_assert!` in
  `credential_id.rs`); the C `credential_make()` draws the seed, forces it
  non-zero and returns `-1` if it is ever zero. A hybrid cred minted with an
  all-zero seed would otherwise be mis-decoded as ES256 on decrypt.
- Comments at both the encrypt and decrypt sites state that the
  all-zero-seed => ES256 mapping is an internal, HMAC-authenticated
  discriminator, not a wire guarantee.

## Cross-port parity (REQUIRED)
Both ports use the identical domain bytes + identical input layout above, so
the `cred_random` / `largeBlobKey` / integrity derivations are true
byte-for-byte mirrors of each other.

## Invalidation / schema
Introducing the labels changed all three HMAC outputs, so credentialIDs minted
before them fail the integrity check and their hmac-secret / largeBlob outputs
changed -> the change was **credential-invalidating** (a wipe + re-register).
The credentialID **wire format is unchanged** (still 161 bytes, same field
layout), so **no flash schema / store-version bump was required** in either
port.

## Tests
Both host suites pin the derivations and run under `tools/host-tests.sh`
([BUILD.md](BUILD.md#host-test-suites)):

**Rust** -- `crates/firmware-hosttest/tests/credential_id.rs`. The firmware is a
`no_std` binary crate that `cargo test` cannot reach directly, so the
`pqf-firmware-hosttest` crate pulls the real modules in by `#[path]` with the
TRNG stubbed (`cargo test -p pqf-firmware-hosttest --target "$(rustc -vV |
awk '/^host:/{print $2}')"`). It covers:
- (a) encrypt -> decrypt round-trip recovers the `CredentialSource` (ES256 AND
  hybrid, including the cred_protect and large_blob_key fields);
- (b) **domain distinctness**: for a fixed `(macKey, credentialId)`, the
  integrity tag, `cred_random(uv=0)`, `cred_random(uv=1)` and `largeBlobKey`
  are pairwise distinct, every derived secret changes with the device key,
  and a one-bit change in the id changes every derived secret;
- (c) flipping any single byte of the blob -> `decrypt` returns `BadHmac`
  (truncation and extension are rejected likewise);
- (d) the rp_id_hash binding still rejects a cross-RP credentialId, and the
  ES256 case carries an all-zero ML-DSA seed.

**C** -- `c/firmware/test/test_domain.c`, wired into the `c/firmware/test`
Makefile (`make test`), with the same round-trip, pairwise-distinctness,
single-byte-tamper and cross-RP checks. Both suites run at 0 failures.

## Scope
The change touched only the three HMAC inputs, the alg-discriminator assert
and the tests: not the credentialID field layout, the flash store, or any
unrelated derivation.
