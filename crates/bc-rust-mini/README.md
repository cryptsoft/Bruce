# bc-rust-mini -- vendored Bouncy Castle Rust crates for the firmware

A self-contained snapshot of just the Bouncy Castle Rust crates the
`pqc-fido` Rust firmware needs: ML-DSA (FIPS 204, the low-memory
variant), SHA-2, SHA-3 / SHAKE, HMAC, HKDF, the Hash DRBG, and the
trait and utility crates they stand on. It is the Rust-side counterpart
of [`c/firmware/openssl-mini/`](../../c/firmware/openssl-mini/README.md):
the tree builds with nothing cloned beside it.

Upstream is <https://github.com/bcgit/bc-rust>. The snapshot is taken
from a branch that carries a small `#![no_std]` patch for embedded
consumers (`getrandom` behind a `std` feature on the RNG crate, `alloc`
instead of `std` collections) on top of upstream's `release/0.1.3alpha`
-- bc-rust 0.1.3, which has the ML-DSA bound-keeping fix for crafted
inputs (<https://eprint.iacr.org/2026/1032>, upstream PR #137). Upstream
is moving toward `no_std` itself (the low-memory ML-DSA and utils crates
already are), so the patch shrinks with each rebase; it is not in
upstream yet. The exact branch, commit and date are in
[`UPSTREAM`](UPSTREAM), written by the script that refreshes this
directory.

Released under the Bouncy Castle Licence, which is the MIT licence
text with the Legion of the Bouncy Castle copyright line -- verbatim in
[`LICENSE.md`](LICENSE.md). The vendored crates carry no `license`
field in their manifests, so [`deny.toml`](../../deny.toml) clarifies
each one to MIT by name, pointing at that file.

## Layout

```
bc-rust-mini/
|-- Cargo.toml             nested workspace root (kept by hand; see below)
|-- LICENSE.md             verbatim from upstream
|-- README.md              this file
|-- UPSTREAM               branch / commit / date of the snapshot
+-- crypto/
    |-- core/                  Digest / KeyMaterial / signer traits
    |-- mldsa-lowmemory/       ML-DSA-44/65/87 keygen + sign, streaming
    |-- sha2/                  SHA-256 (also the DRBG's hash)
    |-- sha3/                  SHA-3 + Keccak-1600, SHAKE XOF for ML-DSA
    |-- rng/                   Hash DRBG (SP 800-90A); no_std with std off
    |-- hmac/                  generic HMAC; the SHA-2 instantiations are in sha2/
    |-- hkdf/                  generic HKDF; HKDF_SHA256 is in sha2/
    |-- utils/                 constant-time helpers, secret wrappers
    |-- hex/                   dev-dependency of the suites above only
    +-- core-test-framework/   dev-dependency of the suites above only
```

## Who links what

| Consumer | Crates (all `default-features = false`) |
|---|---|
| `crates/firmware` | mldsa-lowmemory, core, sha2, utils |
| `crates/signer-core` | mldsa-lowmemory, core, sha2 |
| `crates/fw-secure` | mldsa-lowmemory, core (via signer-core too) |
| `crates/firmware-hosttest` | the same set as the firmware |

`sha3` and `rng` come in transitively through `mldsa-lowmemory`, and
`hmac` and `hkdf` through `sha2` (since bc-rust 0.1.3 the SHA-256 HMAC
and HKDF types live there). `default-features = false` is what keeps
the firmware bare-metal: the ML-DSA crate's default `std` feature
reaches `bouncycastle-rng/std`, which pulls `getrandom`, which has no
backend on `thumbv8m.main-none-eabihf`. With it off, seeds and signing
nonces are supplied by the firmware (`keygen_from_seed`,
`sign_*_deterministic_out`). The other vendored crates have no
features.

## Not a workspace member, on purpose

The outer workspace (`../../Cargo.toml`) lists this directory under
`exclude`, and this directory is a workspace root of its own, because
the vendored manifests inherit `edition` and their sibling dependencies
from one (`edition.workspace = true`, `bouncycastle-core.workspace =
true`) -- exactly as upstream lays them out. `Cargo.toml` here is
upstream's root trimmed to the crates present; keep the two in step
when refreshing.

The firmware therefore consumes these crates purely as path
dependencies, which is what it did when they lived in a sibling
checkout: their dev-dependencies (`criterion`, `serde_json`, the test
framework) never enter the firmware's `Cargo.lock`, and the outer
`[profile.release.package."bouncycastle-*"]` optimisation overrides
still apply, since profile overrides select by package name, not by
membership.

## Vendored vs modified

Every source file is byte-for-byte upstream **except for comments and
the spelling of a few string literals**. This repository is ASCII only
(see `docs/BUILD.md`, "ASCII only"), and upstream writes FIPS 204
notation into its comments -- mathematical italic letters, Greek, the
arrow and membership signs. The vendoring script transliterates those
with a fixed map: mathematical alphanumerics fold to plain letters,
Greek letters become their names (`rho`, `mu`, `gamma`), operators
become their ASCII spellings (`<-`, `in`, `<=`, `||`, `xor`, `bot`),
and the alarm emoji and the decorative ones are dropped. A non-ASCII
character inside a string literal (upstream has a handful in test
assertion messages) becomes its `\u{XXXX}` escape, which leaves the
string's value unchanged. The script refuses to finish if a non-ASCII
character sits anywhere else, or is in a comment and missing from its
map, so no identifier or test vector is ever changed. The `diff`
against upstream is comments and those escapes only.

No code, feature, manifest or test is modified. If a change to the
vendored code ever becomes necessary, make it upstream (or on the
no_std branch) and re-vendor; do not patch here.

## Refreshing

```sh
tools/vendor-bc-rust.sh /path/to/bc-rust     # default: ../bc-rust
```

The script records the checkout's branch and commit in `UPSTREAM`,
replaces `crypto/*` and `LICENSE.md`, transliterates comments, and runs
the ASCII check. Then:

1. Compare `Cargo.toml` here with the checkout's root `Cargo.toml`
   (the workspace `version` and `edition`, any new sibling a vendored
   crate now inherits) and update by hand.
2. `cargo build --release` and `tools/host-tests.sh rust` from the
   repository root.
3. `cd crates/bc-rust-mini && cargo test --target "$(rustc -vV | awk '/host/{print $2}')"`
   to run the vendored suites (the host triple because the root
   `.cargo/config.toml` defaults builds under it to the embedded target;
   needs the crates.io dev-dependencies, so a network).
4. Update the provenance row in `THIRD_PARTY.md` if the branch or
   licence changed.
