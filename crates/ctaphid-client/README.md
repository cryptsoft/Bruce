# `pqf-ctaphid`: the host-side client, and the test tools built on it

This crate is the host counterpart of the firmware. It speaks CTAP 2.1
to a FIDO2 authenticator over USB HID and comes with a set of examples
that are the project's test tools: `probe`, `register`, `reset`,
`bench` and the rest of the table below are what the docs mean by "the
in-tree client".

It exists to develop and test the two firmwares in this tree. It is a
clean-room implementation of the CTAP 2.1 surface (every command 0x01
to 0x0D, both PIN protocols, the WebAuthn client-data hashing), but it
is not a general-purpose FIDO library: USB HID only, one device at a
time, no UI, and the vendor extensions it knows are `bruce`'s own.

Three layers, bottom up:

1. **`hid`** -- the CTAPHID transport: enumerate FIDO devices, open
   one, the INIT handshake, framing and reassembly of multi-packet
   messages, KEEPALIVE handling (swallowed, but counted in `Stats`).
   The per-OS report I/O is `hidapi`; everything above the 64-byte
   report is in-tree. Every `hidapi` call runs on one worker thread,
   because its macOS backend keeps CoreFoundation state that must not
   be touched from two threads (that used to kill the process, and
   `tests/thread_safety.rs` guards it).
2. **`ctap2`** -- one module per CTAP 2.1 command: a typed request
   struct in, CBOR over `CTAPHID_CBOR`, a typed response out, the
   status byte mapped to `ctap2::Error`.
3. **`session`** -- `register()` and `authenticate()`: the WebAuthn
   shaped one-shot flows (getInfo, mint a `pinUvAuthToken` if a PIN is
   set, compute `clientDataHash`, send, parse `authData`).

Platforms: macOS (IOKit), Linux (hidraw) and Windows. On Windows 10
1903 and later the OS reserves FIDO-usage-page HID devices for its own
WebAuthn stack, so opening one needs an **elevated (Administrator)**
prompt; enumeration works unelevated. That is Windows policy, not a
limitation of this crate.

## Building and running an example

The crate builds for the host, but `.cargo/config.toml` sets the
default build target for the whole tree to `thumbv8m.main-none-eabihf`
(the firmware), and this crate is not in the workspace's default
members. So every `cargo` command for it names the host triple; set it
once per shell:

```bash
export HOST_TARGET="$(rustc -vV | awk '/host/{print $2}')"
cargo run -p pqf-ctaphid --example probe --target "$HOST_TARGET"
cargo run -p pqf-ctaphid --example reboot --target "$HOST_TARGET" -- warm   # arguments after --
./client.sh probe                 # the same, from the repository root: ./client.sh <example> [args]
./client.sh reboot warm
cargo test -p pqf-ctaphid --test thread_safety --target "$HOST_TARGET"        # no token needed
```

Linux needs `libudev-dev` and `pkg-config` for the `hidapi` wrapper,
and the udev rules from [`tools/udev/`](../../tools/udev/99-bruce.rules)
so an ordinary user can open the token (install steps in
[GETTING-STARTED.md](../../docs/GETTING-STARTED.md#23-linux-only-let-ordinary-users-open-the-token)).

Once a PIN is set on the token, the examples read it from the
environment -- there is no interactive prompt, so they stay usable
from scripts:

```bash
BRUCE_PIN=1234 ./client.sh register
```

## The examples

"Touch" is on boards with a real presence gesture (Tiny 2350, Feitian);
the other boards confirm presence on their own. Arguments go after
`--`.

| Example | What it does | Arguments | Touch | Changes the token |
| --- | --- | --- | --- | --- |
| `probe` | Enumerate, open the first FIDO device, INIT, a PING round trip, then `authenticatorGetInfo` printed field by field. The first thing to run on a freshly flashed board. | none | no | no |
| `list_all` | Every HID device on the bus, FIDO or not, for working out why a token is not being seen. | none | no | no |
| `register` | One `session::register()` with a synthetic challenge; prints the credential id, the algorithm and the `authData` flags. | none; `BRUCE_PIN` if a PIN is set | yes | registers one non-resident credential |
| `pqc_roundtrip` | Register with the client's default `pubKeyCredParams` (-56, -55, -54, -7) so the token picks the hybrid it was built with, then GetAssertion; verifies both halves (ECDSA-P256 and ML-DSA) on the host and prints which level ran. The proof that the post-quantum path executed. | none; `BRUCE_PIN` | yes | registers one non-resident credential |
| `alg_roundtrip` | Same, against one explicitly named COSE algorithm; default `-8` (EdDSA), which no default list ever requests. | `[alg]`; `BRUCE_PIN` | yes | registers one non-resident credential |
| `bench` | Wall-clock timing of hybrid MakeCredential / GetAssertion over N rounds: min / median / max, response size, KEEPALIVE count, signature verified. The project's measurement of record; build with `--release`. | `-n/--iterations N`, `--alg 44\|65\|87\|es256\|any`, `--rp-id`, `--origin`, `--device <match>`, `-l/--list`, `--self-test` (offline, no device), `-h`; `BRUCE_PIN` | must not block: a buttonless board, or a C image built `-DPQF_TEST_NO_USER_BUTTON=ON` (dev only, never ship it); otherwise tap twice per round | registers one non-resident credential per round |
| `keepalives` | Register, then authenticate, counting the KEEPALIVE frames during each: wall time, mean period, longest silence. The witness for the single-core builds. Exit 0, or 3 presence denied, 2 PIN required, 1 other. | none; `BRUCE_PIN` | yes | registers one non-resident credential |
| `pin_set` | PIN-protocol v2 smoke test: getInfo, getPinRetries, setPin, getPinRetries again, mint a `pinUvAuthToken`. The token must have no PIN yet. | none | no (ClientPIN is not presence-gated) | sets the PIN to `1234` |
| `pin_persistence` | Proves the retry budget lives in flash and the per-boot soft block does not: three wrong PINs, reset the token, check both, then the right PIN restores the budget. Shells out to `c/hid/reboot warm` (build it with `make -C c/hid`); needs a `reboot_no_up` image, or `PQF_MANUAL_CYCLE=1` to be prompted for a replug instead. | `<pin>` | no | burns three retries (restored on success); reboots the token |
| `reset` | `authenticatorReset`: every credential, the PIN and its counter, the master keys, the alwaysUv flag. No undo. If the token answers OperationDenied or UserActionTimeout, replug and rerun within ~10 s. | `[product-substring]` | yes | **wipes the token** |
| `reboot` | The vendor reboot into BOOTSEL (default) or warm back into the firmware. Fire-and-forget: the token drops off the bus, so confirm with `picotool info`. | `[bootsel\|warm] [product-substring]` | yes, unless the image was built with `REBOOT_NO_UP` or the board is buttonless | reboots; nothing stored changes |
| `tz_test` | The TrustZone image's suite: presence gate, signature counter, resident credentials, ClientPIN, the raw button probe. One handle serves both CTAP2 and the dev vendor commands. Picks the device whose product string contains `TZ-NS`. | `[--press] [--pin] [--latch on\|off] [--churn] [--count] [device-path]` | injected over vendor 0x42, unless `--press` waits for a real finger | registers resident credentials; `--churn` fills and churns the store; `--pin` **leaves a PIN set** (it ends as `5678`) |
| `tz_cm` | credentialManagement enumeration against the TrustZone build, printing the CTAP status byte of every step. `--cp3` probes credProtect level 3 on non-resident credentials; `--wipe` empties the resident store, which is how a TrustZone bench board is returned to a known state (that port has no `authenticatorReset`, and its store survives reflashing). | `[--pin S] [--wipe] [--cp3] [device-path]`; the PIN defaults to `123456` | the UP-gated steps need presence: latch it with `tz_test --latch on`, or press | `--wipe` deletes every resident credential; `--cp3` registers two non-resident ones |

## Vendor commands

CTAP reserves command numbers 0x40 to 0x7f for vendors. Beyond standard
CTAP, the crate and its examples use these `bruce` commands:

| Number | Firmware name | Client API | Used by |
| --- | --- | --- | --- |
| 0x50 | `CTAPHID_CMD_RNG` | `hid::Device::rng` -- raw TRNG bytes, up to 1024 per transaction, larger reads split; no presence gesture | no example; the CLI is `c/hid/rng` |
| 0x51 | `CTAPHID_CMD_REBOOT` | `hid::Device::reboot(RebootMode::Bootsel \| Warm)` -- gated behind a touch unless the image was built with `REBOOT_NO_UP` | `reboot`; `pin_persistence` (through `c/hid/reboot`) |
| 0x42 | `CMD_UP_INJECT` (TrustZone dev builds) | `hid::Device::vendor(0x42, ..)` -- empty payload is one simulated touch, `0x01` latches presence on, `0x02` off | `tz_test` |
| 0x44 | `CMD_UP_PROBE` (TrustZone dev builds) | `vendor(0x44, ..)` -- register probe: the pad's CTRL readback and the raw `QSPI_CSN` bit | `tz_test` |
| 0x45 | `CMD_LAST_CBOR` (TrustZone dev builds) | `vendor(0x45, ..)` -- echo of the last CBOR request the Non-secure side saw | `tz_test` |

`Device::vendor` is the untyped path for anything in the vendor range;
the firmware answers on the same command byte and the reply payload
comes back. The reboot command, its presence gate and the warning about
buttonless tokens are in [REBOOT.md](../../docs/REBOOT.md); the
TrustZone dev commands and why they exist are in
[TRUSTZONE.md](../../docs/TRUSTZONE.md#the-dev-escape), and their
firmware side is `crates/fw-nonsecure/src/main.rs`.

## Module map

```
src/lib.rs                      crate root; re-exports pqf-cbor's Value and the cbor_* macros
src/hid/mod.rs                  enumerate(), list_all(), Device (open + INIT, send_msg / recv_msg,
                                ping, wink, cancel, rng, reboot, vendor), Capabilities, Stats;
                                the single hidapi worker thread
src/hid/frame.rs                64-byte report framing, Cmd (the on-wire command bytes, including
                                the vendor 0xd0 / 0xd1), the CID and size constants
src/hid/error.rs                transport errors
src/ctap2/mod.rs                cbor_call() dispatch, the command bytes, CBOR accessor helpers
src/ctap2/get_info.rs           authenticatorGetInfo (0x04)
src/ctap2/make_credential.rs    authenticatorMakeCredential (0x01)
src/ctap2/get_assertion.rs      authenticatorGetAssertion (0x02)
src/ctap2/get_next_assertion.rs authenticatorGetNextAssertion (0x08)
src/ctap2/client_pin.rs         authenticatorClientPIN (0x06): retries, setPin, changePin, tokens
src/ctap2/pin_protocol.rs       PIN protocol v1 and v2 (ECDH, AES-CBC, HMAC, HKDF)
src/ctap2/reset.rs              authenticatorReset (0x07)
src/ctap2/selection.rs          authenticatorSelection (0x0B)
src/ctap2/credential_management.rs  authenticatorCredentialManagement (0x0A)
src/ctap2/large_blobs.rs        authenticatorLargeBlobs (0x0C)
src/ctap2/config.rs             authenticatorConfig (0x0D)
src/ctap2/types.rs              RelyingParty, User, PubKeyCredParam, CredentialDescriptor,
                                AuthOptions; COSE alg ids (-7, -8, -54, -55, -56)
src/ctap2/error.rs              Status (the CTAP status bytes) and Error
src/session.rs                  register() / authenticate(), client_data_hash(), the AuthData
                                parser, PinSource
tests/thread_safety.rs          concurrent enumeration must not abort the process; no token needed
examples/                       the tools in the table above
```

The CBOR codec is the sibling crate `pqf-cbor` (`crates/cbor`), shared
with the firmware. The C counterpart of this crate is
[`c/hid`](../../c/hid/README.md).
