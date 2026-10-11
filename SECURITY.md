# Security policy

This page is for anyone who finds a security problem in Bruce, and
for anyone deciding what this release does and does not promise. It
assumes nothing else; the design behind each statement is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/SECUREBOOT.md](docs/SECUREBOOT.md),
[docs/TRUSTZONE.md](docs/TRUSTZONE.md) and the audit records under
[docs/notes/](docs/notes/README.md).

## What this release is

Bruce is a research and engineering firmware. It is wire-compatible
with the OpenSK reference implementation and verified end to end against
Chrome and Firefox, but it is **not** FIPS-validated, **not**
FIDO-certified, and **not** hardened against side-channel attacks. Use
it to learn, to prototype relying-party software against, and to
exercise post-quantum authentication flows. Do not make it the only
line of defence on an account that matters.

## Reporting a vulnerability

Please report security problems privately, not in a public issue or
pull request.

- Use GitHub's private vulnerability reporting for this repository:
  "Report a vulnerability" under the repository's Security tab. It
  opens a private advisory that only the maintainers can see.
- Say which port (Rust or C) and which board profile, the build options
  (the `pqf-*` markers from `picotool info -a <image>` name them), and,
  where you can, a host test or a capture that reproduces the problem.

The maintainers will acknowledge the report, work with you on a fix, and
agree with you when it is published. Fixes land as ordinary commits with
a dated note in [docs/TESTING.md](docs/TESTING.md). There is no bug
bounty.

## Known limitations and deliberate properties

The following are documented properties of this release, not
vulnerabilities in it. A report that one of them is so will be
acknowledged, but it will not change the release. The first group are
design decisions; the second are known gaps that an experimental
firmware carries openly rather than silently.

### Deliberate

- **The committed signing keys are public development keys.**
  `keys/pqf-dev-fw.pem` (firmware signing, P-256) and
  `keys/pqf-dev-bootkey.pem` (secure boot, secp256k1) are committed on
  purpose so that development builds reproduce without a ceremony.
  Their private halves are public. A board provisioned with either one
  has a signature check that anyone with this repository can satisfy,
  not secure boot. The tooling recognises both by fingerprint:
  `tools/pqf_sign.py --production` refuses them; the bootloader refuses
  to compile as a production image (`cmake -DPQF_PRODUCTION=ON`)
  against them; and `tools/secureboot-provision.sh` refuses to burn the
  dev boot key into OTP, checks that the hash it is about to burn
  belongs to the key it was given, and checks the hash already in
  silicon against that key before it turns secure boot on. Never ship
  an image signed with them. [keys/README.md](keys/README.md) and
  [docs/SECUREBOOT.md, "Production key ceremony"](docs/SECUREBOOT.md#production-key-ceremony)
  say how a real key is handled: on a machine that does not have this
  repository checked out.
- **Firmware update is open by default.** The bootloader ships verifying
  against the dev key, its anti-rollback check is off until a
  production key ceremony turns it on, and `DFU_DETACH` is not gated on
  a touch. So host software that can talk to a token can install any
  firmware signed with the published key, and that firmware can read
  the token's secrets. This is the development configuration;
  [docs/DFU.md](docs/DFU.md) and [docs/SECUREBOOT.md](docs/SECUREBOOT.md)
  describe the production one.
- **The U2F batch attestation key is a development value.** The key and
  certificate in `crates/firmware/src/u2f.rs` are shared by every build
  that enables the opt-in `u2f` feature, so they cannot tell one token
  from another. A default build does not include them. See
  [THIRD_PARTY.md](THIRD_PARTY.md#pre-generated-u2f-batch-attestation-cert--key).
- **The host-issued reboot into BOOTSEL** (`CTAPHID_CMD_REBOOT`) waits
  for a touch only on boards that have a power-on BOOTSEL of their own.
  On the Feitian RP2350 USB-C token, and on any build made with
  `reboot_no_up`, software on a host that can talk to the token can put
  it into boot mode without a gesture, where its flash is open.
  [docs/REBOOT.md](docs/REBOOT.md) explains the trade.
- **The on-token GDB stub** (`gdb_stub` feature) is an unauthenticated
  read, write and execute primitive over USB. It is off by default and
  must never ship enabled; see [docs/GDB_DEBUG.md](docs/GDB_DEBUG.md).
- **The TrustZone build's dev escape** (`TZ_DEV_ESCAPE=1 ./build-tz.sh`)
  lets the Non-secure world reboot the chip into BOOTSEL. It is off in
  a default build; see [docs/TRUSTZONE.md](docs/TRUSTZONE.md).
- **Credentials are only as secret as the token's flash.** Without the
  secure-boot and TrustZone work described in
  [docs/SECUREBOOT.md](docs/SECUREBOOT.md) and
  [docs/TRUSTZONE.md](docs/TRUSTZONE.md), boot mode exposes the
  credential store and the master keys to anyone holding the token.
- **No side-channel hardening.** The ML-DSA and ECDSA implementations
  are the vendored Bouncy Castle Rust crates and the vendored OpenSSL
  3.5 subset, used as they come. Timing and power leakage have not been
  measured. One known item is addressed: the OpenSSL subset has no
  dedicated P-256 code, so the C port's ECDSA runs through the generic
  scalar-multiplication ladder that OpenSSL's CVE-2026-54872 (a timing
  side channel in that path's scalar padding) is about; the fix from
  OpenSSL 3.5.9 is backported into `c/firmware/openssl-mini/`.
- **The composite COSE algorithm ids are provisional, and the
  construction behind them is not the draft's.** `-54`, `-55` and
  `-56` are the ids requested in
  `draft-ietf-jose-pq-composite-sigs-04`, not yet assigned; a relying
  party that pins them may have to follow a later revision. The
  signatures are the OpenSK PQC fork's construction (P-256 at every
  level, an EC2 key with the ML-DSA key at `-4`, the label-prefix
  combiner), so a verifier written to the draft cannot check them. See
  [docs/PROTOCOL.md](docs/PROTOCOL.md#cose-algorithm-identifiers) and
  its "Deviations from draft -04".

### Known gaps

- **A torn flash write locks the token until it is reset.** Both ports
  keep the credential-id master keys in their own sector and the PIN,
  counter and configuration in another. Once a PIN has been set, a
  write to the second sector interrupted by a power loss makes the
  token boot PIN-blocked: user verification, credential management and
  any new PIN are refused until an authenticatorReset, which rotates
  the master keys and so retires every credential id the token issued.
  The PIN is never lost to such a write, but the resident credentials
  in that sector are, and the owner has to reset the token and register
  again. Before 2026-10-11 the same event booted the token with no PIN
  while the old credential ids still decrypted; see
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#flash-schema-evolution).
- **An attached QRNG is used on its own.** When a quantum RNG answers on
  the I2C bus, its conditioned output is used as is and the on-chip
  TRNG only completes any shortfall; the two sources are not mixed. The
  vendor command `CMD_RNG` serves generator output to any host that
  asks.
- **PIN/UV auth tokens do not expire.** A token minted by `ClientPIN`
  stays valid until the next power cycle or the next PIN operation; the
  specification's time-based expiry is not implemented.
- **`hmac-secret` without user presence.** Both ports answer an
  `hmac-secret` request on an assertion made with `up=false`, so a
  host can obtain the credential's secret without a touch.
- **`authenticatorReset` has no power-on window.** The specification's
  rule that a reset must arrive within ten seconds of power-on is not
  enforced; the user-presence gate is the only check.
- **Assertions without presence write flash.** An assertion for a
  discoverable credential made with `up=false` still advances the
  persisted signature counter, so a host can wear the store's sector
  without a touch.
- **The Rust heap can be exhausted before authentication.** Request
  parsing allocates from the shared heap before any PIN or presence
  check, so a host can drive the firmware out of memory with crafted
  requests. An allocation failure aborts the firmware; a replug
  recovers it, and nothing in flash is touched.

The two audit records under [docs/notes/audit/](docs/notes/README.md)
are point-in-time documents; they have not been re-verified finding by
finding, and the list above, not those records, is the statement of
what is open in this release.

## Supported versions

Only the current `main` branch is supported. There are no maintained
release branches.
