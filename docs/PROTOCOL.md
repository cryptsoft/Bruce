# Protocol reference

Everything bytes-on-the-wire about `bruce`: what the token accepts, what it emits, and how the cryptographic constructions tie together. It is written for someone implementing a relying party, a verifier, or another authenticator who wants to match this one byte for byte without reading any Rust or C, and it assumes familiarity with CTAP 2.1 and WebAuthn. To build and drive a token start at [GETTING-STARTED.md](GETTING-STARTED.md); [USAGE.md](USAGE.md) explains the same fields from the user's side, [ARCHITECTURE.md](ARCHITECTURE.md) how the firmware produces them, and [HMAC-DOMAINS.md](HMAC-DOMAINS.md) the domain-separation labels the derivations below depend on.

Contents:

- [CTAP HID transport](#ctap-hid-transport)
- [CTAP2 commands](#ctap2-commands)
- [CTAP1 / U2F: implemented, disabled at the transport](#ctap1--u2f-implemented-disabled-at-the-transport)
- [getInfo](#getinfo)
- [MakeCredential](#makecredential)
- [GetAssertion](#getassertion)
- [Hybrid signature](#hybrid-signature)
- [Encrypted credential ID (161 bytes)](#encrypted-credential-id-161-bytes)
- [hmac-secret](#hmac-secret)
- [credProtect](#credprotect)
- [credBlob](#credblob)
- [PIN protocols](#pin-protocols)
- [Channel ID rules](#channel-id-rules)
- [Reset](#reset)

Where this document says "OpenSK", we mean the [OpenSK PQC fork](https://github.com/google/OpenSK)'s `libraries/crypto/src/hybrid.rs` and `src/ctap/credential_id.rs` -- the wire format is identical at the framing level. Our **plaintext** layout inside the credentialID diverges from OpenSK's CBOR-padded 192 B -> fixed 112 B (see [Encrypted credential ID](#encrypted-credential-id-161-bytes) below) because OpenSK's 322-char base64url result overflowed a relying party's `VARCHAR(255)` column. Everything else -- hybrid signing, mu derivation, PIN protocols -- is OpenSK-compatible.

> **Applies to both implementations.** The Rust firmware and the C
> port (`c/firmware/`) speak this exact protocol surface at full
> parity -- same commands, extensions, error-code discipline, getInfo
> shape, hybrid signature format, AND the same 161-byte credentialID
> layout (`maxCredentialIdLength` = 161 on both). Two deliberate
> differences: a distinct AAGUID per port (each a random UUID of its
> own, so an RP can tell them apart) and the LCD
> status panels (Rust-only). U2F is off in both (the Rust ships an
> unreachable `u2f.rs`; the C has none). One unintended difference:
> the ports use different per-signature nonces inside the hybrid
> signature, so the signature *bytes* differ even though the format
> and the verification procedure do not -- see
> [Per-port nonce inputs](#per-port-nonce-inputs).

## CTAP HID transport

Implemented in `crates/firmware/src/ctaphid.rs` (Rust) and `c/firmware/src/ctaphid.c` (C). Standard CTAP HID over USB. 64-byte interrupt frames in / out on a single channel. Command bytes below are shown with the initialisation bit (`0x80`) set, as they appear on the wire:

| Cmd byte | Name      | Behaviour                                                                                     |
| ---      | ---       | ---                                                                                           |
| `0x86`   | `INIT`    | Allocates a fresh channel ID, replies with protocol version 2 + capabilities byte             |
| `0x81`   | `PING`    | Echoes the payload back verbatim                                                              |
| `0x83`   | `MSG`     | U2F (CTAP1) -- **refused** with a CTAPHID `ERROR` response, code `0x01` (`ERR_INVALID_CMD`). See the CTAP1 section below for why. |
| `0x90`   | `CBOR`    | CTAP2 envelope -- payload is `cmd_byte || cbor` (see "CTAP2 commands" below)                   |
| `0xBB`   | `KEEPALIVE` | We emit these every ~50 ms while a slow CTAP2 command is in flight; processing = `0x01`     |
| `0x91`   | `CANCEL`  | Aborts the in-flight CBOR command on that channel; CANCEL itself gets no reply, the cancelled command answers `CTAP2_ERR_KEEPALIVE_CANCEL` (0x2D). The Rust firmware watches for it during the hybrid sign; the C port cannot interrupt a sign already running on core 1 (a CANCEL arriving mid-sign is answered `ERR_CHANNEL_BUSY` and the sign completes) |
| `0x88`   | `WINK`    | Flashes the green LED (LED boards) / pulses the status LED (C port)                           |
| `0xD0`   | `RNG` (vendor) | Bytes from the token's entropy source -- see [Vendor RNG command](#vendor-rng-command) below |
| `0xD2`   | `RNG_STATUS` (vendor) | Which entropy source is serving, with counters -- see [Vendor RNG status command](#vendor-rng-status-command) below |
| `0xD1`   | `REBOOT` (vendor) | Reboot into BOOTSEL or warm -- see [Vendor reboot command](#vendor-reboot-command) below |

INIT response capabilities byte (`buf[16]`): `0x0D` = `WINK (0x01) | CBOR (0x04) | NMSG (0x08)`. `NMSG` advertises "no U2F" so hosts skip the CTAP1 fallback and use CTAP2 directly.

### Vendor RNG command

`CTAPHID_CMD_RNG`, command number `0x50` (`0xD0` on the wire with the init bit) -- inside the `0x40..0x7F` range CTAP reserves for vendor use. Both ports implement it, wire-compatible.

```
request payload:   (empty)                -> 57 random bytes (one init frame's worth)
                   count: u16 big-endian  -> `count` random bytes, 1 <= count <= 1024
response payload:  exactly that many bytes from the token's entropy picker:
                   SHA-256-conditioned QRNG output when a chip is
                   attached (docs/HARDWARE.md), on-die TRNG output otherwise
errors:            ERR_INVALID_LEN  (payload not 0 or 2 bytes)
                   ERR_INVALID_PAR  (count 0 or > 1024)
```

No authentication, no user-presence gesture, no PIN: the entropy is not a secret, and the intended consumer (the PKCS#11 module in [`c/pkcs11/`](../c/pkcs11/), OpenSSL's pkcs11 provider, `pkcs11-tool --generate-random`) mixes it into its own pool rather than trusting it raw. The host-side client is `pqhid_rng()` in [`c/hid/pqhid.h`](../c/hid/pqhid.h), which chunks larger requests into 1024-byte transactions.

### Vendor RNG status command

`CTAPHID_CMD_RNG_STATUS`, command number `0x52` (`0xD2` on the wire). Both ports implement it, wire-compatible. QRNG and TRNG output are indistinguishable by inspection, so this is how a host learns which source the token is drawing from -- including the case where a QRNG answered at boot and has since been unplugged.

```
request payload:   (empty)                      anything else -> ERR_INVALID_LEN
response payload:  29 bytes
  [0]       source   0 = TRNG, no QRNG answered at boot
                     1 = QRNG live, first in the queue
                     2 = QRNG answered at boot but has been written off since
                         (unplugged or failed repeatedly); TRNG serving now
                     3 = firmware built without QRNG support (C, PQF_QRNG=OFF)
  [1..5)    qrng_bytes      u32 big-endian, bytes served by the QRNG since boot
  [5..9)    fallback_bytes  bytes served by the on-die TRNG since boot
  [9..13)   packets         QRNG packets read
  [13..17)  header_err      packets dropped for a bad header
  [17..21)  health_err      packets dropped for a set health flag
  [21..25)  bus_err         I2C transactions that failed or timed out
  [25..29)  short_requests  requests the QRNG could not complete
```

A lost chip is detected on the first request that fails after the unplug (one status read on the bus decides), so the report reflects the request that discovered it. The host client is `pqhid_rng_status()` in [`c/hid/pqhid.h`](../c/hid/pqhid.h); `make -C c/hid rng && ./c/hid/rng` prints the report alongside a timed draw.

### Vendor reboot command

`CTAPHID_CMD_REBOOT`, command number `0x51` (`0xD1` on the wire with the init bit) -- also in the `0x40..0x7F` vendor range. Both ports implement it, wire-compatible. It lets a host put the token into the RP2350 USB bootloader for reflashing (or warm-reboot it) without a physical BOOTSEL button -- see [`docs/REBOOT.md`](REBOOT.md) for the full story and the [buttonless-lockout warning](REBOOT.md#warning-buttonless-tokens-can-be-locked-out-of-bootsel).

```
request payload:  1 byte  mode
                    0x00  warm reboot back into the firmware
                    0x01  reboot into BOOTSEL (USB mass storage / DFU)
response payload: none -- the device re-enumerates away on success
errors:           ERR_INVALID_LEN  (payload not exactly 1 byte)
                  ERR_INVALID_PAR  (mode not 0x00 or 0x01)
                  ERR_OTHER        (user-presence gate declined or timed out)
```

Whether the command waits for a **test of user presence** is a **per-board policy**, the same in both ports and for both modes: `HAS_USER_BUTTON && HAS_POWER_ON_BOOTSEL && !reboot_no_up && !test_no_user_button`. Where it holds -- the Tiny 2350 and the Feitian RP2350 in a default build -- the gate is the same gesture as `MakeCredential` (the BOOT button, or the Tiny's GP0 pad); on decline/timeout (~10 s) the firmware answers `ERR_OTHER` and stays running. Everywhere else the reboot happens at once: on the buttonless boards, and by design on the Feitian RP2350 USB-C token, which has no power-on BOOTSEL and so no other way back into the bootloader. The table and the reasoning are in [REBOOT.md](REBOOT.md#user-presence). On success the device disconnects and re-enumerates, so **no response frame is sent** -- the host clients (`pqhid_reboot()` / `hid::Device::reboot()`) are fire-and-forget and don't wait for one.

On the two button boards the gate can be compiled out **for this command only** with `-DPQF_REBOOT_NO_UP=ON` (C) / `--features reboot_no_up` (Rust) -- a flash-station convenience that leaves FIDO user presence for `MakeCredential` / `GetAssertion` untouched; on the other boards it changes nothing. Each image records its policy as the picotool feature `pqf-reboot=touch` or `pqf-reboot=no-touch` ([BUILD.md](BUILD.md#identifying-an-image-before-flashing-it)). Host clients: `pqhid_reboot()` in [`c/hid/pqhid.h`](../c/hid/pqhid.h) and `hid::Device::reboot()` in the in-tree client [`crates/ctaphid-client`](../crates/ctaphid-client/src/hid/mod.rs), plus the `c/hid/reboot` and `cargo run -p pqf-ctaphid --example reboot` CLIs.

## CTAP2 commands

Implemented in `crates/firmware/src/ctap2.rs` (Rust) and `c/firmware/src/ctap2.c` (C). CBOR envelopes carried over CTAP HID `CMD_CBOR` (`0x90`). First payload byte selects the subcommand:

| Cmd    | Name                                | Implemented? | Notes                                                                |
| ---    | ---                                 | ---          | ---                                                                  |
| `0x01` | `authenticatorMakeCredential`       | yes           | See [MakeCredential](#makecredential) below                          |
| `0x02` | `authenticatorGetAssertion`         | yes           | See [GetAssertion](#getassertion) below                              |
| `0x04` | `authenticatorGetInfo`              | yes           | See [GetInfo](#getinfo) below                                        |
| `0x06` | `authenticatorClientPIN`            | yes           | Both PIN protocols v1 and v2 -- see [PIN protocols](#pin-protocols). Includes subcmd `0x09 getPinUvAuthTokenUsingPinWithPermissions` (RP-scoped + bit-flagged tokens) |
| `0x07` | `authenticatorReset`                | yes           | Wipes the credential index AND rotates the credentialID master keys  |
| `0x08` | `authenticatorGetNextAssertion`     | yes           | Pops the next credential from a stateful iterator after a multi-credential GetAssertion |
| `0x09` | `authenticatorBioEnrollment`        | no           | Out of scope -- RP2350 has no fingerprint sensor                      |
| `0x0a` | `authenticatorCredentialManagement` | yes           | 7 subcommands (`getCredsMetadata`, `enumerateRPs{Begin,GetNext}`, `enumerateCredentials{Begin,GetNext}`, `deleteCredential`, `updateUserInformation`). All gated on `cm` permission bit. |
| `0x0b` | `authenticatorSelection`            | yes           | Bare `CTAP2_OK` -- host picks us in multi-device flows                |
| `0x0c` | `authenticatorLargeBlobs`           | yes           | 2 KiB global blob array in a dedicated flash sector. Writes authenticated under `lbw` permission |
| `0x0d` | `authenticatorConfig`               | yes           | `enableEnterpriseAttestation` (no-op stored), `toggleAlwaysUv`, `setMinPINLength`, `vendorPrototype` (returns invalid-cmd) |
| `0x40+` | vendor-specific                    | no           | Returns `CTAP2_ERR_INVALID_COMMAND`                                  |

Status codes and their names are taken from CTAP 2.1 sec. 6.3 -- `CTAP2_OK = 0x00`. Notable error-code discipline distinctions:

  - **`0x33 CTAP2_ERR_PIN_AUTH_INVALID`** vs **`0x36 CTAP2_ERR_PUAT_REQUIRED`**: `0x36` is returned only when `pinUvAuthParam` is *absent* and a PIN is set; `0x33` is returned when `pinUvAuthParam` is *present* but verification fails (no active token / wrong permissions / wrong HMAC / invalid protocol). This distinction matters for Chrome's WebAuthn silent discovery probe -- see commit `a1c7b71`.

## CTAP1 / U2F: implemented, disabled at the transport

> **Status: unreachable by design.** The CTAPHID layer advertises
> `NMSG` and refuses `CMD_MSG` with `ERR_INVALID_CMD`, so the U2F
> module (`crates/firmware/src/u2f.rs`) cannot be reached over USB.
> Why: browsers that detect
> a working U2F path prefer it for plain ES256 registrations and
> return `fmt="fido-u2f"` attestation, which PQC-aware RPs reject --
> refusing `CMD_MSG` forces the
> CTAP2 path and `fmt="packed"` everywhere. The module is kept in the
> tree (and documented here) in case a deployment ever wants legacy
> U2F back: it is compiled only behind the `u2f` cargo feature (off by
> default, so its hard-coded development batch attestation key stays
> out of production binaries), and re-enabling is that feature plus
> one dispatch arm and clearing the `NMSG`
> bit. The C port contains no U2F module at all.

When wired up, CTAP HID `CMD_MSG` (`0x83`) carries U2F APDUs per FIDO U2F Raw Message v1.2. Three INS values:

| INS    | Name           | Notes                                                                                          |
| ---    | ---            | ---                                                                                            |
| `0x01` | `REGISTER`     | Fresh ECDSA-P256 user keypair; keyhandle is our standard 161 B CTAP2 credentialID. Signs response with the hardcoded dev batch attestation key + cert (see [`THIRD_PARTY.md`](../THIRD_PARTY.md)) |
| `0x02` | `AUTHENTICATE` | P1 control byte: `0x07` check-only (returns `0x6985`), `0x03` enforce-UP+sign, `0x08` don't-enforce-UP+sign. Counter is a volatile `AtomicU32` (resets on power cycle) |
| `0x03` | `VERSION`      | Returns ASCII `U2F_V2`                                                                         |

Other INS values return `0x6D00` (INS_NOT_SUPPORTED). Non-zero CLA returns `0x6E00` (CLA_NOT_SUPPORTED). All non-success responses use the standard ISO 7816 SW = `0x9XXX` framing.

Keyhandles use the **same 161 B CTAP2 credentialID format** as `authenticatorMakeCredential` issues. A U2F-registered keyhandle works under CTAP2 `GetAssertion` if the RP later upgrades to WebAuthn, and vice versa, as long as the application parameter (U2F) / `rp.id` hash (CTAP2) matches.

## getInfo

The full response map. Keys are CBOR unsigned integers per CTAP 2.1 sec. 6.4 Table 6:

| Key    | Field                         | Value we emit                                                                                                                    | Why                                                                                                          |
| ---    | ---                           | ---                                                                                                                              | ---                                                                                                          |
| `0x01` | `versions`                    | `["FIDO_2_0", "FIDO_2_1"]`                                                                                                                   | Both are advertised. The 2.1 surface this build actually ships -- `credMgmt`, `authnrCfg`, `largeBlobs`, permissions-scoped PIN/UV tokens, `credProtect`, `credBlob`, `minPinLength` -- is what `FIDO_2_1` contracts for here; `authenticatorBioEnrollment` stays out of scope (no sensor) |
| `0x02` | `extensions`                  | `["credBlob", "credProtect", "hmac-secret", "largeBlobKey", "minPinLength"]`                                                                     | Canonical CBOR ordering (length, then lexicographic). `largeBlobKey` is advertised by name as well as via the `largeBlobs` option, so WebAuthn L3 clients that discover off the extension list find it |
| `0x03` | `aaguid`                      | 16 bytes -- default `ef80634d-5f41-4a62-b14f-5a6944096a0b` (this project's own id), overridable at build time                                              | See [BUILD.md](BUILD.md#aaguid-override)                                                                      |
| `0x04` | `options`                     | `{rk: true, up: true, plat: false, alwaysUv: <bool>, credMgmt: true, authnrCfg: true, clientPin: <bool>, largeBlobs: true, pinUvAuthToken: true, setMinPINLength: true}` | `clientPin` reflects whether a PIN is set; `alwaysUv` reflects the AuthenticatorConfig toggle. `ep` is deliberately **absent** rather than false: advertising it at all signals an enterprise-attestation guarantee this device cannot honour. `pinUvAuthToken` and `setMinPINLength` are the discovery signals for features both ports implement |
| `0x05` | `maxMsgSize`                  | `7609`                                                                                                                            | CTAP HID hard cap: `57 + 128 x 59`. Tight fit for ML-DSA-87 hybrid + Ed25519 + 161 B credId in one MakeCred response |
| `0x06` | `pinUvAuthProtocols`          | `[1, 2]`                                                                                                                          | v1 default, v2 per FIPS-cert requirement                                                                      |
| `0x07` | `maxCredentialCountInList`    | `8`                                                                                                                               | Max allowList entries we'll search                                                                            |
| `0x08` | `maxCredentialIdLength`       | `161`                                                                                                                             | The compact encrypted credentialID (both v1 and v2 formats are 161 B)                                         |
| `0x09` | `transports`                  | `["usb"]`                                                                                                                         |                                                                                                              |
| `0x0a` | `algorithms`                  | `[{-56}, {-55}, {-54}, optional {-8}, {-7}]`                                                                                      | All three composite PQ/T hybrid variants always advertised regardless of which one this build implements (defeats Chrome's `kNoCommonAlgorithms` short-circuit). `-8` (Ed25519) only when `ed25519` feature is on. `-7` (ES256) is the universal floor. These are the ids the device actually mints -- see [COSE algorithm identifiers](#cose-algorithm-identifiers). |
| `0x0b` | `maxSerializedLargeBlobArray` | `2048`                                                                                                                            | Global blob array ceiling                                                                                     |
| `0x0c` | `forcePINChange`              | `<bool>`                                                                                                                          | Set by AuthenticatorConfig `setMinPINLength{forceChangePin: true}`, persisted, cleared by a successful `changePIN`. While set, `getPinToken` / `getPinUvAuthTokenUsingPinWithPermissions` refuse an `mc`/`ga` token with `0x37` |
| `0x0d` | `minPINLength`                | `4` (or AuthenticatorConfig override)                                                                                              | Floor `client_pin::sub_set_pin` enforces                                                                      |
| `0x0e` | `firmwareVersion`             | `1`                                                                                                                               | Monotonic per release                                                                                         |
| `0x0f` | `maxCredBlobLength`           | `32`                                                                                                                              | Per-credential blob ceiling                                                                                   |

Also emitted: `0x10 maxRPIDsForSetMinPINLength` (the `minPinLengthRPIDs` cap) and `0x14 remainingDiscoverableCredentials` (free resident slots: 6 in the Rust port and 7 in the C port on a fresh default build, 7 more per extra credential sector in a build with `PQF_RESIDENT_EXTRA_SECTORS`, see [BUILD.md](BUILD.md#axis-7-optional-discoverable-credential-capacity)). Keys we *don't* emit: `0x11 preferredPlatformUvAttempts`, `0x12 uvModality`, `0x13 certifications`, `0x15 vendorPrototypeConfigCommands` -- CTAP 2.1 *optional* keys that describe built-in user verification and certification state this device does not have.

### COSE algorithm identifiers

The hybrid construction is labelled with the **composite** PQ/T code points requested in `draft-ietf-jose-pq-composite-sigs-04` (10 September 2026), not the RFC 9964 *pure* ML-DSA code points:

| ML-DSA level | Composite id (what we emit)  | CBOR    | Pure ML-DSA id (**not** us) | Selected by                                        |
| ---          | ---                          | ---     | ---                         | ---                                                |
| ML-DSA-44    | `-54` (`MLDSA44-ES256`)      | `38 35` | `-48`                       | cargo feature `mldsa44` / `-DPQF_HYBRID_VARIANT=44` |
| ML-DSA-65    | `-55` (`MLDSA65-ES256`)      | `38 36` | `-49`                       | cargo feature `mldsa65` / `-DPQF_HYBRID_VARIANT=65` (default) |
| ML-DSA-87    | `-56` (`MLDSA87-ES384`)      | `38 37` | `-50`                       | cargo feature `mldsa87` / `-DPQF_HYBRID_VARIANT=87` |

A composite id names *both* halves, which is exactly what the credential is: an ECDSA-P256 key and an ML-DSA key signing the same message. Each id is a two-byte CBOR negative integer (`0x38` then the argument), the same length as the ids it replaced, so no message size moved.

**The ids are provisional.** The draft still reads "TBD, request -54" (and -55, -56); IANA has not registered them. Each port therefore defines each level's id exactly once -- `crates/signer-core/src/mldsa_alg.rs` (`COSE_ALG_MLDSA44_ES256` / `_MLDSA65_ES256` / `_MLDSA87_ES384`, shared by the firmware, the TrustZone Secure image and both host-test crates) and `c/firmware/src/hybrid.h` (the same three names) -- so the next relabel is a one-line change per level. The host client (`crates/ctaphid-client/src/ctap2/types.rs`, `ALG_HYBRID_MLDSA44/65/87`) and the scripts under `tools/` cannot link the firmware and keep their own single copy.

**How the labels got here.** Draft -02 requested `-51/-52/-53` for these three composites, and the firmware emitted them. RFC 9864 (October 2025) then assigned `-51` to ESP384, `-52` to ESP512 and `-53` to Ed448, so draft -04 requests `-54/-55/-56` instead, and the firmware now emits those. Before the composite ids, the firmware emitted the pure ids `-48/-49/-50` for the same construction. So a credential or a captured trace can show any of three labels for the same credential: `-48/-49/-50` (oldest), `-51/-52/-53`, or `-54/-55/-56` (current). Only the label changed each time: the signing construction, the key encodings and the concatenation order are identical.

The COSE id is **not stored** in any credential: both ports recover it on decrypt from the credential id's version byte and whether its ML-DSA seed slot is zero, and the TrustZone Secure image stores an internal algorithm byte, not the COSE id. A credential registered under an older label keeps working and is simply reported with the current id; a relying party that stored the old id alongside the public key has to be told the new one. The firmware does **not** accept `-51/-52/-53` in `pubKeyCredParams` any more -- they now name ESP384 / ESP512 / Ed448 -- so a request offering only one of them is refused like any other unsupported algorithm (`CTAP2_ERR_UNSUPPORTED_ALGORITHM`), or falls through to ES256 if the request also offers `-7`.

### Deviations from draft -04

This construction predates the draft and is labelled with the draft's ids because they are the closest registered-or-requested names, not because it implements the draft's algorithm. The differences, all unchanged by the relabel:

- **ML-DSA-87 pairs with P-256.** The draft's `-56` is ML-DSA-87 with ECDSA P-384 (`MLDSA87-ES384`); this firmware uses P-256 at every level, so the classical half is weaker than the label says. Kept because it costs no second curve implementation and both ports agree on it.
- **Key shape.** The credential's COSE_Key is an EC2 key (`kty 2`, `crv 1`, `-2` X, `-3` Y) with the ML-DSA public key added at label `-4`, rather than the draft's AKP key type.
- **Signature and combiner.** The signature is `ecdsa_der || mldsa_sig` -- classical first -- and the two halves are bound by the OpenSK 32-byte label-prefix combiner (ECDSA over `SHA-256(LABEL || msg)`, ML-DSA over `LABEL || msg || ecdsa_der`), not the draft's `M' = Prefix || Label || 0x00 || PH(M)` with `mldsaSig || classical` ordering.
- **The signed bytes are unchanged by this relabel.** The construction and the message format are identical; the only integers that moved are the COSE_Key's label 3 and `attStmt.alg`. A GetAssertion signs exactly the bytes it signed before (its authData carries no key); a new registration's attestation covers an authData whose embedded COSE_Key now carries the new id, one byte different. A verifier that implements this firmware's construction needs no change beyond accepting the new id.

### `kNoCommonAlgorithms` defence

Chrome's `MakeCredentialRequestHandler` intersects the RP's `pubKeyCredParams` with the device's `algorithms` (key `0x0a`). Empty intersection -> Chrome short-circuits with `NotAllowedError` **before sending any CTAP frame**. A PQC-aware relying party may request only the composite ids (no ES256 fallback), so to keep Chrome from rejecting an `mldsa44`-built or `mldsa65`-built device against such an RP, we advertise all three composite variants unconditionally. The MakeCredential picker still selects only an algorithm this firmware genuinely implements -- if the RP only requested a variant we don't have, the picker falls through to ES256 (or, with `ed25519` feature, Ed25519). RPs without an ES256 / Ed25519 fallback in their `pubKeyCredParams` will see `CTAP2_ERR_UNSUPPORTED_ALGORITHM` at MakeCred time (rather than the silent kNoCommonAlgorithms exclusion before).

The advertised list must stay in step with the ids the picker accepts, and it did not survive the first relabel (pure to composite) intact: `getInfo` went on publishing the pure ids `-50/-49/-48` after the picker had moved to the composite ones. A host that trusts `getInfo` -- Chrome does -- then asks for a pure id, the device declines it, and the registration silently degrades to ES256, so the PQC path is unreachable from any conformant host. The C port now builds the advertised list from named constants that a `_Static_assert` ties to `PQF_HYBRID_COSE_ALG`, so a future variant added to `hybrid.h` without a matching list entry fails to compile. Both ports' host tests also pin the advertised list to the exact wire values (`-56, -55, -54`, then `-7`) and check that none of `-48..-53` appears, so the draft -04 relabel cannot leave `getInfo` behind in the same way.

## MakeCredential

CTAP 2.1 sec. 6.1. Input parameters (CBOR map keys):

| Key  | Field                  | Required? | We use it for                                                                                       |
| ---  | ---                    | ---       | ---                                                                                                 |
| `0x01` | `clientDataHash`       | yes       | Signed verbatim in the attestation; PIN auth (v1) HMACs over it                                     |
| `0x02` | `rp`                   | yes       | We hash `rp.id` into the rp_id_hash (embedded in the credentialID for cross-RP replay defence)      |
| `0x03` | `user`                 | yes       | `user.id`, `user.name` and `user.displayName` are all persisted in the flash slot, so `credentialManagement` can enumerate them. `user.id` is required, 1-64 B  |
| `0x04` | `pubKeyCredParams`     | yes       | We pick the first entry whose `alg` is `-7` (ES256) or our compile-time `COSE_ALG_HYBRID_MLDSA`     |
| `0x05` | `excludeList`          | checked   | Each entry is trial-decrypted; a match refuses with `CTAP2_ERR_CREDENTIAL_EXCLUDED` (0x19). The answer is given **after** user presence, so the list cannot be used to probe the token silently |
| `0x06` | `extensions`           | optional  | `hmac-secret` (bool), `credProtect` (1/2/3), `credBlob` (<=32 B)                                     |
| `0x07` | `options`              | parsed    | `rk` selects a discoverable credential; `up: false` is refused with `INVALID_OPTION` (0x2C); `uv: true` with no satisfiable UV is refused with `UNSUPPORTED_OPTION` (0x2B) when no PIN is set, or `PUAT_REQUIRED` (0x36) when one is |
| `0x08` | `pinUvAuthParam`       | conditional | Required only when a PIN is set on the device                                                     |
| `0x09` | `pinUvAuthProtocol`    | conditional | Must accompany 0x08; we accept 1 or 2                                                              |

Response map:

```
{
  0x01: "packed",                          # attestation format
  0x02: authData (bstr),                   # see authData layout below
  0x03: {                                  # attestation statement
    "alg": -7  or  -54/-55,                # ML-DSA-87 builds attest with -7 -- see note
    "sig": ecdsa_der || mldsa_sig          # hybrid: concatenated, no length prefix
                                           # ES256: just the DER ECDSA sig
  }
}
```

`attStmt.alg` normally equals the credential's alg -- an RP is not required to accept a weaker attestation over a hybrid credential, and conformant verifiers refuse the mismatch. ML-DSA-87 is the one exception: the full dual attStmt measures 7617 B against the 7609 B CTAPHID structural ceiling, so an `mldsa87` build self-attests with ECDSA-P256 only (`alg -7`, ~72 B signature). The credential is still hybrid -- the ML-DSA public key rides in `authData` and ML-DSA signs every GetAssertion -- but an RP has to opt into that registration shape. `test_hybrid_msgsize.c` pins which shape each level emits.

### authData layout

```
[0..32]  rp_id_hash = SHA-256(rp.id)
[32]     flags  =  UP (0x01)
                | UV (0x04)     iff PIN auth happened
                | AT (0x40)     attested credential data included
                | ED (0x80)     extension data included (if any)
[33..37] signature counter (big-endian u32; first MakeCred = 1)
[37..53] AAGUID (16 B)
[53..55] credentialIdLength (big-endian u16) = 161
[55..216] credentialId (161 B) -- see "Encrypted credential ID" below
[216..]  COSE_Key + extensions (CBOR)
```

### COSE_Key

ES256-only credential:

```
{ 1: 2,       # kty = EC2
  3: -7,
 -1: 1,       # crv = P-256
 -2: X (32 B),
 -3: Y (32 B) }
```

Hybrid credential (same shape, plus `-4` for the ML-DSA pubkey):

```
{ 1: 2,
  3: -54 | -55 | -56,
 -1: 1,
 -2: X (32 B),
 -3: Y (32 B),
 -4: ML-DSA pubkey bytes (1312 / 1952 / 2592 B) }
```

`kty = 2` (EC2) for **both** variants -- matches OpenSK's COSE encoder. Some browsers' COSE parsers reject negative `kty` values, so we don't use a custom one for the hybrid case.

### MakeCredential extensions output

CBOR-encoded after the COSE_Key. Emitted only when the input asked for the extension *and* we accepted it. Sorted lex (per the canonical-CBOR-ish ordering OpenSK uses):

```
{
  "credBlob": true|false,           # only present if input had credBlob;
                                    # value reflects whether we stored it
  "credProtect": 1|2|3,             # only present if input set credProtect
  "hmac-secret": true,              # only present if input asked for it;
                                    # presence means we'll honour the
                                    # extension on later GetAssertions
}
```

## GetAssertion

CTAP 2.1 sec. 6.2. Input parameters:

| Key  | Field                  | Required? | Notes                                                                              |
| ---  | ---                    | ---       | ---                                                                                |
| `0x01` | `rpId`                 | yes       | We hash it; cross-checks against the embedded rp_id_hash in the credentialID       |
| `0x02` | `clientDataHash`       | yes       | Signed verbatim                                                                    |
| `0x03` | `allowList`            | optional  | We pick the first entry that decrypts, whose rp_id_hash matches, **and** whose credProtect policy the current UV state satisfies |
| `0x04` | `extensions`           | optional  | `credBlob: true` to echo the stored blob; `hmac-secret: {...}` salt protocol         |
| `0x05` | `options`              | parsed    | `up` and `uv` are honoured; an unsatisfiable `uv: true` is refused as on MakeCredential |
| `0x06` | `pinUvAuthParam`       | conditional | Required only when a PIN is set                                                  |
| `0x07` | `pinUvAuthProtocol`    | conditional | 1 or 2                                                                            |

If `allowList` is non-empty we walk it and take the first entry that decrypts, whose embedded rp_id_hash matches, and whose credProtect policy is satisfied by the current UV state -- a credProtect-3 entry without UV is skipped rather than ending the search, so it cannot mask a later usable credential. A present-but-unparseable `allowList` is a malformed request, not an absent one. If `allowList` is empty we scan the resident-credential index for entries with a matching rp_id_hash -- the rk-discoverability flow.

Response map:

```
{
  0x01: { type: "public-key", id: credentialId (161 B) },
  0x02: authData (bstr),                # see below
  0x03: signature (bstr)                # hybrid: ecdsa_der || mldsa_sig
                                        # ES256: ecdsa_der
  0x04: { id: user_id (bstr) }          # only when we have a stored user handle
}
```

### authData for GetAssertion

Shorter than MakeCred (no attested credential data):

```
[0..32]   rp_id_hash
[32]      flags = UP (0x01)
                | UV (0x04)  iff PIN auth happened
                | ED (0x80)  iff extension output is present
[33..37]  signature counter (incremented from the previous use)
[37..]    extensions output (if any)
```

### GetAssertion extensions output

```
{
  "credBlob":   bstr,        # stored credBlob bytes -- only when input had credBlob: true
  "hmac-secret": bstr,       # AES-256-CBC( shared_secret, output_1 [|| output_2] )
                             # output_i = HMAC-SHA-256( cred_random, salt_i )
}
```

`cred_random` derivation is **deterministic** per credential + uv state -- see [hmac-secret](#hmac-secret).

## Hybrid signature

The mathematical contract. The signed-message format below -- the `LABEL` prefix, what each half covers, and the wire concatenation -- is byte-identical to OpenSK's `libraries/crypto/src/hybrid.rs::sign_rfc6979` and identical in both of our ports. The ML-DSA randomizer `rnd` is now also identical in both ports. The remaining per-port difference is the ECDSA nonce `k`; see [Per-port nonce inputs](#per-port-nonce-inputs).

```
LABEL = [u8; 32] =
  [43, 253,  32, 250,  19,  51,  24, 237,
  138,  49,  47, 182,   4, 194, 133, 183,
  177, 218, 115,  58,  92, 117,  45, 172,
  156,   5, 214, 176, 248, 103,  55, 216]

# msg = authData || clientDataHash (assembled by MakeCred / GetAssert)

# --- ECDSA half --------------------------------------------------------------
prehash    = SHA-256( LABEL || msg )                                  # 32 B
ecdsa_sig  = ECDSA-P-256 sign with RFC-6979 deterministic k,          # per-port
             over prehash, returning (r, s)
ecdsa_der  = DER( SEQUENCE { INTEGER r, INTEGER s } )                 # 70..72 B

# --- ML-DSA half -------------------------------------------------------------
tr         = SHAKE-256( pk_encode(mldsa_pk), 64 )                     # 64 B
mu         = SHAKE-256( tr || 0x00 || 0x00 || LABEL || msg ||
                         ecdsa_der , 64 )                              # 64 B
rnd        = 0^32                                                     # 32 B, both ports
mldsa_sig  = MLDSA::sign_mu_deterministic( mldsa_sk, mu, rnd )         # 2420 / 3309 / 4627 B

# --- wire format -------------------------------------------------------------
wire = ecdsa_der || mldsa_sig                                          # no length prefix
```

The `0x00 || 0x00` between `tr` and `LABEL` inside the mu is FIPS 204 sec. 7.1 Algorithm 2's "ctx" framing for an empty CTAP context. We call `MuBuilder::do_init(&tr, Some(b""))` and the lowmem crate emits those two bytes for us before our `LABEL || msg || ecdsa_der` triple-update.

### Per-port nonce inputs

Everything above holds for both ports except the ECDSA nonce `k`. Neither `k` nor `rnd` appears on the wire.

```
                Rust firmware                     C firmware
k     RFC 6979 deterministic            hedged: ossl_bn_gen_dsa_nonce_fixed_top()
      (p256 sign_prehash)               -- a SHA-512 chain over the padded private
                                        key, 64 fresh TRNG bytes and the message
                                        digest, so an RNG failure is not immediately
                                        fatal. Varies per CALL, not per (key, message).
rnd   0^32                              0^32
```

`k` reaches the C port's hedged path because the firmware signs through `ECDSA_do_sign()`
with a non-NULL digest and `nonce_type == 0` (`ecdsa_ossl.c`); only `nonce_type == 1`
selects RFC 6979, and only a NULL digest selects a bare
`ossl_bn_priv_rand_range_fixed_top()`.

`rnd` was converged on 0^32 in both ports. The Rust port previously used
`SHA-256(LABEL || msg || ecdsa_der)`, which was equally secure but matched no published
vector. Since `rnd` only defends against fault and DPA attacks that exploit repeated
identical signing, and a message-derived `rnd` is exactly as repeatable as a zero one,
that formula bought nothing over the FIPS 204 sec. 5.2 deterministic variant. Genuine hedging
would require a live TRNG draw at signing time, which neither port does.

Consequences:

- **The ports still emit different signature bytes** for the same message and keys, because
  `k` still differs. `mu` covers `ecdsa_der`, so a different ECDSA half changes `mu`, which
  changes `rho'`, which changes the ML-DSA half too. Converging `rnd` did not make the ports
  byte-identical; converging `k` as well would.
- **What converging `rnd` did buy** is that both ports now use the same, published ML-DSA
  variant. Given the same `(seed, mu)` both produce the byte-exact FIPS 204 / ACVP
  deterministic signature, which is checkable against published vectors on either side --
  `c/firmware/openssl-mini/test/test_mldsa.c` does exactly that for the C port.
- **Verification and interop are unaffected**, as they were before. `rnd` only feeds `rho'`
  inside the signer, and ML-DSA.Verify takes no `rnd` argument -- `ossl_ml_dsa_verify()` has
  no `rand` parameter, and `hybrid_verify()` passes only the public keys, the message and the
  signature. ECDSA verification likewise never sees `k`. **Credentials registered before this
  change keep working**: the seed, the public key and the verification path are all untouched.
- **Still open: whether to converge `k`.** Doing so means choosing between RFC 6979
  (reproducible, matches the Rust port) and the hedged nonce (resists fault attacks better,
  matches the C port). Unlike `rnd`, this one is a real security trade rather than a free
  standardisation win.

A verifier reads the wire as:

```
# 1. Parse the DER ECDSA signature from the start. ECDSA-P-256 always
#    fits in a single-byte DER length, so the total DER length is:
ecdsa_len = blob[1] + 2          # 70..72
ecdsa_der = blob[..ecdsa_len]
mldsa_sig = blob[ecdsa_len..]    # exactly 2420 / 3309 / 4627 bytes

# 2. Verify each half against its public key. Both must pass.
ecdsa_pk.verify( LABEL || msg, ecdsa_der )         # SHA-256 happens inside verify
ML_DSA.verify(  mldsa_pk, LABEL || msg || ecdsa_der , mldsa_sig )
```

The verifier passes `LABEL || msg` (and additionally `|| ecdsa_der` for ML-DSA) -- *not* the prehash -- because both verify functions hash internally per their FIPS / RFC reference.

## Encrypted credential ID (161 bytes)

The credentialID is **the** carrier of every key bit. Decrypting it under the device's master keys recovers everything needed to sign for that credential. Both the Rust and C firmware use this identical layout.

```
offset  length  field
 0       1     version    = 0x01
 1      16     IV         = 16 random bytes (per credential)
17     112     ciphertext = AES-256-CBC( aes_key, IV, plaintext )
129     32     hmac       = HMAC-SHA-256( hmac_key, "pqf-cred-id" || bytes[0..129] )
total: 161 bytes
```

The `"pqf-cred-id"` prefix (11 ASCII bytes, no terminator) is the integrity tag's domain label; it is applied identically on encrypt and decrypt in both ports ([HMAC-DOMAINS.md](HMAC-DOMAINS.md)).

Plaintext (112 B = 7 AES blocks, no padding):

```
[0..32]    ecdsa_scalar
[32..64]   mldsa_seed     (all-zero iff alg == ES256)
[64..96]   rp_id_hash
[96]       cred_protect   (policy 1/2/3; 0 => level 1)
[97]       flags          (bit 0 = minted with largeBlobKey; bits 1-7 reserved)
[98..112]  reserved (zero)
```

`alg` is *inferred* by constant-time zero-check of `mldsa_seed`: all-zero -> ES256, otherwise hybrid. A real ML-DSA seed being all-zero is a 2^-256 event -- unambiguous in practice. The `cred_protect` byte is carried here (not just in the flash slot) so the policy is enforceable on non-resident / evicted credentials -- a credProtect-3 credential is refused without UV even when presented in an allowList (CTAP 2.1 sec. 12.1.1). The `flags` byte at `[97]` is carried for the same reason: bit 0 records whether the credential was minted with the `largeBlobKey` extension, so GetAssertion can return its `largeBlobKey` for a non-resident credential that has no flash slot to read it from (WebAuthn L3 / CTAP 2.1 sec. 6.1.3). Both bytes are covered by the credentialID HMAC. Credentials issued before the flag existed carry `[97] == 0` and decrypt as "no largeBlobKey", so the format stays backward compatible.

**Why this shape and not OpenSK's CBOR-with-padding-to-192?** Base64url of 241 B = 322 chars and overflows the `VARCHAR(255)` `credential_id` column of the relying party it was first tested against. 161 B -> 215 chars in base64url, fits with 40 chars of slack. (The format was 145 B / 96-B plaintext before the credProtect byte was added; grew one AES block to carry it.)

The two master keys live in a flash sector of their own (the Rust firmware's `KEY_OFFSET` sector, separate from the PIN/credential sector since store schema v11 so that a torn routine write can never lose them; the C port keeps its device keys in its own sector likewise -- see [ARCHITECTURE.md](ARCHITECTURE.md#flash-schema-evolution)):

- `key_handle_aes_key: [u8; 32]` -- randomly generated on first boot; rotated only by `authenticatorReset`
- `key_handle_hmac_key: [u8; 32]` -- same lifecycle. Every HMAC keyed on it carries a domain label; the labels are normative in [HMAC-DOMAINS.md](HMAC-DOMAINS.md)

`authenticatorReset` rotates both keys *and* wipes the flash credential index (every sector of it, the optional overflow sectors included), so a credentialID cached at an RP becomes un-decryptable (HMAC fails) and the device responds `CTAP2_ERR_NO_CREDENTIALS`.

### Version byte: v1 vs v2

`credential_id[0]` selects how the plaintext is interpreted. Both versions share the identical 161-byte envelope and the same 112-byte plaintext layout -- only the meaning of the two 32-byte key slots differs.

| Version | Algorithms                             | `ecdsa_scalar` `[0..32]` | `mldsa_seed` `[32..64]`                                     |
| ---     | ---                                    | ---                      | ---                                                          |
| `0x01`  | ES256, OpenSK PQC hybrid               | ECDSA-P-256 scalar       | ML-DSA seed (all-zero => ES256)                               |
| `0x02`  | Ed25519 (`ed25519` feature, off by default) | Ed25519 seed        | reserved -- **must** be zero; non-zero => `BadFormat` on decrypt |

The version byte is part of the HMAC input, so a v1 and a v2 credential with otherwise identical ciphertext carry distinct tags. Builds *without* the `ed25519` feature reject `0x02` at decrypt time as `BadFormat`, and the host falls back to whatever ES256 / hybrid credentials it has on file. `maxCredentialIdLength` stays `161` either way. Encode forces the reserved slot to zero rather than copying it, so it can never mint a blob its own decode would reject -- see `crates/firmware/src/credential_id.rs`.

### Cross-RP replay defence

The embedded `rp_id_hash` is re-checked on decrypt: if it doesn't match the rp.id in the current request, we return `RpMismatch` and the dispatch surfaces `CTAP2_ERR_NO_CREDENTIALS`. An attacker who hosts site A and obtains a credentialID for site A can't replay it as a credential for site B -- even though the HMAC validates (same device), the embedded rp_id_hash gives them away.

## hmac-secret

CTAP 2.1 sec. 12.5. The workhorse extension: RP supplies a salt, device returns `HMAC(cred_random, salt)`. RPs use the result as a key for symmetric encryption of server-side blobs.

### `cred_random` derivation

OpenSK persists `cred_random` per credential. We derive it deterministically so we don't have to store anything extra in the credentialID or in the flash slot (which would only help resident creds):

```
cred_random_no_uv   = HMAC-SHA-256( key_handle_hmac_key,
                                    "pqf-hmac-secret" || credentialId || 0x00 )
cred_random_with_uv = HMAC-SHA-256( key_handle_hmac_key,
                                    "pqf-hmac-secret" || credentialId || 0x01 )
```

The ASCII prefix is the domain label that keeps this derivation distinct from the credentialID integrity tag and the `largeBlobKey`, which share the key ([HMAC-DOMAINS.md](HMAC-DOMAINS.md)). The result is stable across power cycles, works for non-resident credentials, and an attacker who steals the device gets nothing without the master HMAC key.

### MakeCredential

Input map (under `extensions`):

```
"hmac-secret": true
```

Output (in authData extensions output):

```
"hmac-secret": true     # acknowledges we'll honour future GetAssertion queries
                        # for this credential
```

### GetAssertion

Input map (under `extensions`):

```
"hmac-secret": {
  1: keyAgreement,        # host's ephemeral COSE_Key (kty=2, crv=1, x, y)
  2: saltEnc,             # v1: 32 or 64 bytes (one or two salts), AES-CBC
                          #   zero-IV under shared_secret
                          # v2: 48 or 80 bytes -- 16-byte IV || ciphertext
  3: saltAuth,            # v1: HMAC-SHA-256( shared_secret, saltEnc )[..16]
                          # v2: full 32-byte HMAC under the v2 hmac_key
  4: pinProtocol          # optional, defaults to 1; 1 and 2 are accepted
}
```

Both ports run this PIN-protocol-aware (CTAP 2.1 sec. 12.5.5): the shared-secret derivation, the saltAuth truncation, the saltEnc framing and the output framing all follow the protocol named in `pinProtocol`, exactly as in [PIN protocols](#pin-protocols). The v1 case:

1. ECDH(`our_session_sk`, `host_pk`) -> `handshake_x` (raw 32 B X coord).
2. `shared_secret = SHA-256(handshake_x)` (v1; for v2 the HKDF-derived `aes_key` / `hmac_key` pair).
3. Verify `saltAuth == HMAC(shared_secret, saltEnc)[..16]` (v2: the full 32 bytes).
4. AES-256-CBC zero-IV decrypt `saltEnc` -> one or two 32-byte salts (v2: strip the leading 16-byte IV first).
5. Select `cred_random_no_uv` (since we never have UV without PIN, this matches FIDO conformance for the default case) or `cred_random_with_uv` (when PIN auth succeeded on this request).
6. `output_i = HMAC-SHA-256(cred_random, salt_i)` for each salt.
7. AES-256-CBC zero-IV encrypt `output_1 [|| output_2]` under `shared_secret` (v2: a fresh random IV, prepended).
8. Emit in authData extensions output:

```
"hmac-secret": <ciphertext bytes>   # v1: 32 or 64 B; v2: 48 or 80 B
```

## credProtect

CTAP 2.1 sec. 12.1.1. Set on MakeCredential, enforced on GetAssertion.

| Policy | Meaning                                                              | Our enforcement                                                                                            |
| ---    | ---                                                                  | ---                                                                                                        |
| 1      | `userVerificationOptional`                                           | Always allow                                                                                               |
| 2      | `userVerificationOptionalWithCredentialIDList`                       | Require either `allowList` non-empty OR UV successful. Otherwise `CTAP2_ERR_NO_CREDENTIALS`                |
| 3      | `userVerificationRequired`                                           | Require UV successful. Otherwise `CTAP2_ERR_PUAT_REQUIRED`                                                 |

MakeCredential input (under `extensions`):

```
"credProtect": 1 | 2 | 3
```

MakeCredential output (in authData extensions output):

```
"credProtect": 1 | 2 | 3     # echoes the stored policy
```

The policy byte is carried **inside the credentialID** (plaintext byte `[96]`, covered by the credentialID HMAC) as well as in the flash slot, so the policy is enforced for non-resident credentials too: a credProtect-3 credential presented in an `allowList` is refused without UV. See [Encrypted credential ID](#encrypted-credential-id-161-bytes).

## credBlob

CTAP 2.1 sec. 12.4. RP supplies an opaque <= 32 B blob at MakeCred; device echoes it back at GetAssert when asked.

MakeCredential input:

```
"credBlob": <bstr, <= 32 B>
```

MakeCredential output:

```
"credBlob": true | false      # accepted iff length <= 32 AND there's a flash slot
```

GetAssertion input:

```
"credBlob": true              # request the echo
```

GetAssertion output (when credential has a stored blob):

```
"credBlob": <stored bstr>
```

`credBlob` shares its storage with credProtect -- same per-credential flash slot -- and is similarly only available for resident credentials.

## PIN protocols

### v1 (CTAP 2.1 sec. 6.5.4)

```
shared_secret  = SHA-256( ECDH(our_session_sk, host_pk).x )
                                          # 32 B, used as BOTH AES and HMAC key

aes_cbc:        IV = zero, no padding, len(plaintext) % 16 == 0
hmac:           HMAC-SHA-256(shared_secret, msg)[..16]    # 16 B truncated

newPinEnc:      AES-256-CBC( shared_secret, IV=0, padded_pin )
                where padded_pin is the UTF-8 PIN, right-padded with
                zeros to 64 bytes
pinHashEnc:     AES-256-CBC( shared_secret, IV=0, SHA-256(pin)[..16] )
                                                          # 16 B
pinUvAuthParam: HMAC-SHA-256( pin_uv_auth_token, msg )[..16]
                                                          # 16 B
```

Where `msg` is `clientDataHash` for MakeCred and GetAssert, `newPinEnc` for setPIN, `newPinEnc || pinHashEnc` for changePIN, `pinHashEnc` for getPinToken.

### v2 (CTAP 2.1 sec. 6.5.6)

```
aes_key   = HKDF-Expand( HKDF-Extract("", ECDH.x), b"CTAP2 AES key",  32 )
hmac_key  = HKDF-Expand( HKDF-Extract("", ECDH.x), b"CTAP2 HMAC key", 32 )

aes_cbc:        IV = 16 random bytes, prepended to the ciphertext
hmac:           HMAC-SHA-256(hmac_key, msg)                # full 32 B

newPinEnc:      IV(16) || AES-CBC(aes_key, IV, padded_pin) = 80 B total
pinHashEnc:     IV(16) || AES-CBC(aes_key, IV, SHA-256(pin)[..16]) = 32 B total
pinUvAuthParam: HMAC-SHA-256(pin_uv_auth_token, msg)        # 32 B
```

### Internal abstraction

`crates/firmware/src/client_pin.rs` exposes a `pub enum SharedSecret { V1([u8; 32]), V2 { aes_key, hmac_key } }` with `encrypt`, `decrypt`, `authenticate`, `verify` methods so the four subcommand handlers and `hmac-secret` don't branch on protocol internally.

### Subcommands

| Subcommand          | Code   | Implements                                                                                              |
| ---                 | ---    | ---                                                                                                     |
| `getPinRetries`     | `0x01` | Returns retries left (out of 8) as `0x03`, plus `powerCycleState` as `0x04` -- a **Boolean**, true once the per-power-cycle consecutive-failure lockout has tripped |
| `getKeyAgreement`   | `0x02` | Returns our ephemeral ECDH public key as a COSE_Key                                                     |
| `setPIN`            | `0x03` | Initial PIN; only allowed when no PIN is set yet                                                         |
| `changePIN`         | `0x04` | New PIN; requires the encrypted old-PIN-hash                                                            |
| `getPinToken`       | `0x05` | Returns a fresh 32-byte token encrypted under the shared secret; sets `token_active = true` for session |
| `getPinUvAuthTokenUsingPinWithPermissions` | `0x09` | Mints a token carrying the requested permission bits and, when supplied, an RP-id scope. Both are checked at every use site |

PIN retries decrement on every wrong attempt and reset to 8 on success. After 0 retries the device returns `ERR_PIN_BLOCKED` (0x32) and refuses to even compute the shared secret until the next `authenticatorReset`. On top of that persistent counter both ports keep a **volatile** consecutive-failure counter (CTAP 2.1 sec. 6.5.5.6): three wrong PINs in one power cycle return `ERR_PIN_AUTH_BLOCKED` (0x34) until the device is replugged. There is no timed lockout.

## Channel ID rules

CTAP HID channels:

- `0xffffffff` is the broadcast channel -- only `INIT` is legal there.
- `INIT` on the broadcast channel allocates a fresh ID from a monotonic counter starting at 1 -- we never reuse one. `INIT` on an **already-allocated** channel is a resynchronisation: it keeps that channel's CID and resets its reassembly state, per CTAP HID sec. 11.2.9.1.3.
- A CTAP2 envelope from `cid_A` can only be cancelled by a `CANCEL` from `cid_A`.
- We accept frames concurrently across channels but only process one CTAP2 command at a time -- the second one's CBOR completes but its response is sent only after the first finishes.

## Reset

The `reset` example (or any client sending `authenticatorReset`) triggers `CTAP2_RESET_CMD` (`0x07`). We:

1. Wipe every credential slot to STATE_EMPTY, and erase any overflow credential sectors (`PQF_RESIDENT_EXTRA_SECTORS`).
2. Regenerate `key_handle_aes_key` and `key_handle_hmac_key` from TRNG.
3. Wipe PIN state (`pin_set = 0`, `retries_left = PIN_MAX_RETRIES`).
4. Persist the new header + empty slots.

Effect: every credential ever issued by this device becomes un-decryptable (the master keys rotated) AND the credential index is empty.

Reset requires a **test of user presence** (CTAP 2.1 sec. 6.6) in every port -- without a confirmed gesture it refuses with `CTAP2_ERR_OPERATION_DENIED` (0x27) and the PIN and credentials are left intact. The spec additionally wants Reset gated on "power-on within 10 seconds"; we relax that one (no real-time clock in this build), so possession plus a deliberate touch is the gate.
