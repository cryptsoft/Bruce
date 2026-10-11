# Bruce: device crypto capabilities

The one-page summary of what the `bruce` authenticator does and
does not do, for someone deciding whether it fits. It assumes nothing;
the path to a running token is [GETTING-STARTED.md](GETTING-STARTED.md),
the build options are in [BUILD.md](BUILD.md), and the detail behind
every line here is in [PROTOCOL.md](PROTOCOL.md),
[ARCHITECTURE.md](ARCHITECTURE.md) and [HARDWARE.md](HARDWARE.md).

RP2350 (Pico 2 class) USB FIDO2/WebAuthn authenticator. Dual Cortex-M33 at 125 MHz (or the chip's two Hazard3 RISC-V cores), 520 KiB SRAM, on-chip TRNG. Two wire-compatible firmware ports (Rust, `crates/firmware`, and C, `c/firmware`), each a complete CTAP 2.1 authenticator, each running on the same five RP2350 boards (Pimoroni Tiny 2350, Seeed Studio XIAO RP2350, Feitian RP2350, Waveshare RP2350-LCD-1.47, Spotpear RP2350-LCD-1.28; see [HARDWARE.md](HARDWARE.md)). One clone is the whole build: every third-party crate and every vendored crypto source is in the tree; the C port's one external dependency is pico-sdk, located through `PICO_SDK_PATH`.

## Signature scheme

An assertion for a credential registered under one of the composite algorithms below is a hybrid signature: ECDSA P-256 plus FIPS 204 ML-DSA over the same data (a credential the relying party registered as plain ES256 signs with ECDSA alone). The two halves are bound, not concatenated: the ECDSA signature is folded into the ML-DSA u, so the ML-DSA half cannot be verified without the exact ECDSA signature.

| COSE alg ID | Algorithm | Availability |
| --- | --- | --- |
| `-7` | ES256 (ECDSA P-256) | always |
| `-8` | EdDSA (Ed25519) | optional build feature |
| `-54` | Hybrid ES256 + ML-DSA-44 (`MLDSA44-ES256`) | build feature `mldsa44` |
| `-55` | Hybrid ES256 + ML-DSA-65 (`MLDSA65-ES256`) | build feature `mldsa65` (default) |
| `-56` | Hybrid ES256 + ML-DSA-87 (`MLDSA87-ES384`; paired with P-256 here) | build feature `mldsa87` |

Note: `-54`/`-55`/`-56` are the *composite* PQ/T code points requested in `draft-ietf-jose-pq-composite-sigs-04`, which name both halves -- the right shape for this construction. They are still provisional. Earlier revisions labelled the same construction `-51`/`-52`/`-53` (draft -02's request; RFC 9864 has since assigned those to ESP384 / ESP512 / Ed448) and, before that, with the pure ML-DSA ids `-48`/`-49`/`-50` (RFC 9964), so a credential from either era differs only in its label. See [PROTOCOL.md](PROTOCOL.md#cose-algorithm-identifiers), including where this construction deviates from the draft. All three composite ids are advertised in `getInfo` whichever variant is compiled in, so the advertised list does not identify the build.

## FIPS 204 parameter sets

All three build and run; one is compiled in per build.

| Parameter set | NIST category | Public key | Signature |
| --- | --- | --- | --- |
| ML-DSA-44 | 2 | 1,312 B | 2,420 B |
| ML-DSA-65 (default) | 3 | 1,952 B | 3,309 B |
| ML-DSA-87 | 5 | 2,592 B | 4,627 B |

Each hybrid response also carries the ECDSA P-256 signature (~70-72 B DER).

## Memory and performance

- Streamed ML-DSA (the Bouncy Castle low-memory implementation, vendored under `crates/bc-rust-mini`, in the Rust port): ~8 KiB peak RAM at signing, vs ~85 KiB naive. Peak barely grows with security level. The C port's ML-DSA is OpenSSL 3.5's, vendored under `c/firmware/openssl-mini`, with a streaming-A policy that engages at level 87.
- ML-DSA-65 keygen + sign: ~1.0-1.3 s on Cortex-M33 at 125 MHz. Signing runs on core 1; core 0 pumps CTAP HID KEEPALIVE every ~50 ms.
- Measured end to end: MakeCredential ~1.16 s, GetAssertion ~0.87 s (Arm); ~1.6-2.1 s on the Hazard3 RISC-V cores.

## Keys and credentials

- Key generation seeded from the on-chip ring-oscillator TRNG -- or, when a quantum RNG is attached on the QW/ST I2C connector, from that chip first (SHA-256 conditioned, 64 raw -> 32) with the TRNG completing any shortfall. Both ports, all three instruction-set shapes.
- Stateless credentials: key material and policy live in a 161-byte encrypted, HMAC-authenticated credential ID openable only by the device master key. Nothing per-credential is stored on the device (resident keys optional).

## Arm TrustZone-M isolation

A third firmware configuration ([TRUSTZONE.md](TRUSTZONE.md), built with `./build-tz.sh`) splits the authenticator across the Cortex-M33's TrustZone-M boundary:

- **Non-secure world**: the attacker-facing surface (USB stack, CTAPHID framing, CBOR parsing), with no access to key material.
- **Secure world**: master keys, TRNG, flash store, and all crypto. Reachable only through a small set of gateway functions (one SG veneer per CTAP2 command); every Non-secure buffer is range-checked before the Secure side touches it.
- Result: a memory-safety bug in the parser or USB path cannot read or forge with the device keys.
- Complemented by ACCESSCTRL: the Secure image opens only USBCTRL, CLOCKS and RESETS to the Non-secure world, so the TRNG, OTP and SHA-256 peripherals stay Secure-only. Note that they stay Secure by ACCESSCTRL's *reset default* rather than by an explicit write -- nothing in the tree asserts it, so a change that opened one would not be caught.
- Status: complete and silicon-validated. The master key, credential store, TRNG, PIN state, monotonic counter and the ML-DSA signer (on a Secure-only core 1) are all behind the gateway, carrying the full CTAP2 surface -- MakeCredential, GetAssertion, GetNextAssertion, ClientPIN, CredentialManagement, Config, and the credProtect / credBlob / hmac-secret / minPinLength extensions. Gateway hardening is in: every Non-secure pointer is range-checked with `TestTarget::check_range`, Secure scratch is zeroized with volatile writes, and a SecureFault wipes scratch and resets rather than halting. The Non-secure image runs a fail-closed boundary self-test before USB init, so **the token enumerating at all is the assertion**.
- Constraint: TrustZone-M is Arm-only. It cannot be combined with running the RP2350's RISC-V cores; that is an RP2350 spec constraint, so the TrustZone and RISC-V configurations are separate builds.

## Limitations

- Not FIPS-validated or certified; the ML-DSA implementation is alpha.
- Not hardened against side channels.
- Dev-only batch attestation key/cert.
