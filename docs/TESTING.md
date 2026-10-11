# Testing

This page is two things. The first part is the reproducible procedures:
the build sanity checks, the wall-clock benchmark, the browser check,
the host test suites, the client examples that drive an attached token,
and the scripts that sweep a board through every port and ML-DSA level.
The rest is the validation record: what has actually been run on
silicon, dated, with the numbers each run produced and the post-mortems
of the runs that went wrong. Sections were appended as the work
happened, so the record reads in the order it was written rather than
strictly by date; every section carries its own date, and where a later
run overturned an earlier one the earlier text is kept with a marker
(**SUPERSEDED**, "since fixed", "correction") rather than rewritten.
The numbers quoted are the runs that produced them, not a
specification: compare like with like (port, ML-DSA level, instruction
set, board) before reading one as a regression.

It is for anyone who wants to repeat a measurement, trace a claim made
elsewhere in these docs back to the run that made it, or know what only
silicon can prove and what the host suites already cover. If you have
not built and flashed the firmware yet, start with
[GETTING-STARTED.md](GETTING-STARTED.md#8-check-that-it-works), which
walks through the first `probe`, `register` and `pqc_roundtrip`;
[BUILD.md](BUILD.md#host-test-suites) covers the host suites; and the
client examples themselves live in
[`crates/ctaphid-client/examples/`](../crates/ctaphid-client/examples/).
The CTAP 2.1 conformance figures quoted throughout (76 passed / 2
failed and the like) come from an external conformance suite that is
not part of this repository.

Records dated before 2026-09-30 show the composite ids as `-51/-52/-53`
(ML-DSA-44/65/87); since the
[relabel to draft -04](#2026-09-30-composite-cose-ids-relabelled-to-draft--04)
the same builds emit `-54/-55/-56`. Those records are left as run.

## The tools

Everything on this page is driven by these:

| Tool | What it does |
| --- | --- |
| `./build.sh`, `./build-c.sh` | Build the Rust / C firmware (`MLDSA=44\|65\|87`, board name as the argument; [BUILD.md](BUILD.md)). |
| `tools/host-tests.sh [rust\|c]` | Every test that needs no token: the four Rust host crates, the C suites, the key guard, the ASCII check. |
| `cargo run -p pqf-ctaphid --example <name> --target "$HOST_TARGET"` | The client examples (crate `pqf-ctaphid`), which need a token attached. |
| `tools/silicon-sweep.sh` | Both ports at all three levels on one board: each rebuilt from source, flashed, and driven with `alg_roundtrip` and `pqc_roundtrip`. About half an hour. |
| `tools/validate-wire-format.sh c\|rust` | The wire-format corrections (largeBlobs, credential management, config, allowList) on a presence-enforcing build. |
| `tools/silicon-remaining.sh [gdb\|trustzone\|gadget\|all]` | The hardware stages still owed after the 2026-08-17 run: GDB stub, TrustZone split, network gadget. |

The examples build for the host, so the host target has to be spelled
out; set it once per shell, and give a PIN-protected token its PIN in
the environment:

```bash
export HOST_TARGET="$(rustc -vV | awk '/host/{print $2}')"
export BRUCE_PIN=1234        # only once a PIN is set; there is no prompt
```

| Example | What it does |
| --- | --- |
| `probe` | Enumerate, CTAPHID INIT, PING, and print `authenticatorGetInfo`. |
| `register` | One registration with the token's preferred algorithm (the hybrid on every build); prints the credential id, algorithm and flags. |
| `pqc_roundtrip` | Register and authenticate with whichever hybrid the build mints, verify the ECDSA half on the host and check the ML-DSA half's size, report the level. |
| `alg_roundtrip <cose-alg>` | The same against one named algorithm (`-8` for Ed25519, `-7` for ES256, `-54`/`-55`/`-56` for a composite). |
| `pin_set` | PIN-protocol smoke test on a PIN-less token: retries, setPIN, a minted `pinUvAuthToken`. |
| `pin_persistence` | Whether the retry budget survives a reboot and the per-boot soft block clears on one. |
| `reset` | `authenticatorReset`: credentials, PIN, master keys. No undo. |
| `bench` | The wall-clock benchmark; `--self-test` runs its verifier with no token. |
| `keepalives` | KEEPALIVE count and the longest silence per operation, the witness for the single-core builds. |
| `tz_test`, `tz_cm` | The TrustZone image's own suite, and its credential-management probe. |
| `reboot`, `list_all` | Reboot a token into BOOTSEL or warm; list every HID device on the bus. |

## Contents

- [The tools](#the-tools) -- the scripts and client examples everything below is driven by
- [Build sanity](#build-sanity) -- both wrappers, the raw cargo forms, the compile-error guards
- [Wire test + benchmark: `examples/bench`](#wire-test--benchmark-examplesbench) -- the timing path of record, its published baseline, the two attestation shapes
- [Phase smoke tests](#phase-smoke-tests)
- [Chrome end-to-end](#chrome-end-to-end)
- [Host tests: one command](#host-tests-one-command) -- `tools/host-tests.sh`, then what each host suite covers, module by module, and the silicon runs of 2026-09-15 to 09-17 (the QRNG, the BOOT button, the single-core signer)
- [Silicon re-validation, 2026-09-01](#silicon-re-validation-2026-09-01) -- `tools/silicon-sweep.sh` after the host-coverage sweep, the TrustZone run, and the remaining host suites (the mailbox, the BOOTSEL sampler, the presence gate, USB descriptors, the transport, the wire-format corrections, the Secure world)
- [2026-10-11: a lost PIN blocks, and the release review's other findings](#2026-10-11-a-lost-pin-blocks-and-the-release-reviews-other-findings) -- the PIN-armed word in both ports (on silicon too: the blocked boot and the reset that clears it), flash.sh's blank-board and reboot-marker refusals, strict DER in the host verifier
- [2026-09-30: composite COSE ids relabelled to draft -04](#2026-09-30-composite-cose-ids-relabelled-to-draft--04) -- `-51/-52/-53` to `-54/-55/-56`, host results; hardware items pending
- [2026-09-30: configurable discoverable-credential capacity](#2026-09-30-configurable-discoverable-credential-capacity) -- `PQF_RESIDENT_EXTRA_SECTORS` in both ports, host results, the build matrix and the first hardware run
- [The first production USB-C token, 2026-10-02](#the-first-production-usb-c-token-2026-10-02) -- blank on arrival, a 2 MiB die, `tools/flash-usbc.sh` PASS, register and login through the pad
- [The USB-C token procedure, rehearsed on the USB-A Feitian, 2026-09-23](#the-usb-c-token-procedure-rehearsed-on-the-usb-a-feitian-2026-09-23) -- `tools/flash-usbc.sh`, both ports, four passes, and the stubbed failure paths
- [Hybrid attestation is emitted at 44 and 65, measured](#hybrid-attestation-is-emitted-at-44-and-65-measured) -- 2026-08-26
- [Leaving a mixed image bricks the next Arm one](#leaving-a-mixed-image-bricks-the-next-arm-one) -- 2026-08-26
- [C port: publicKey in enumerateCredentials, all three configs](#c-port-publickey-in-enumeratecredentials-all-three-configs) -- 2026-08-26
- [Rust port: the u2f/NMSG gating, all three ISAs](#rust-port-the-u2fnmsg-gating-all-three-isas)
- [The bootloader's REBOOT_TO_ARM needed nothing](#the-bootloaders-reboot_to_arm-needed-nothing)
- [Rust mixed, all three levels, after the ramfunc gating](#rust-mixed-all-three-levels-after-the-ramfunc-gating) -- 2026-08-26
- [Silicon validation status (2026-08-17, Feitian RP2350)](#silicon-validation-status-2026-08-17-feitian-rp2350) -- the full port x ISA x level matrix, then the DFU record from 2026-08-18 to 08-25 (bootloader bring-up, the feature sweep, anti-rollback, power loss, RISC-V and mixed over DFU, `copy_to_ram`, the ROM chain), and real-browser WebAuthn
- [Previously listed as "future tests" -- all three already exist](#previously-listed-as-future-tests----all-three-already-exist) -- and what is genuinely still unwritten

> WARNING: **Button boards block on a physical tap.** On the Tiny 2350 and
> Feitian RP2350 (BOOT button, or the Tiny's GP0 pad) every
> MakeCredential / GetAssertion waits up to 10 s for a fresh
> press-and-release before signing -- scripted tests against those
> boards need a human tapping the button, or they fail with
> `CTAP2_ERR_USER_ACTION_TIMEOUT` (0x27). The other boards (and the C
> host-test harness, which installs no presence hook) auto-confirm and
> run unattended.

## Build sanity

The wrappers are the everyday path; each checks its prerequisites before
it builds and leaves a UF2 in the repository root:

```bash
./build.sh                    # Rust: Tiny 2350, ML-DSA-65 -> bruce.uf2
MLDSA=44 ./build.sh           # or 87; a board name as the argument
./build-c.sh                  # C: same board names and knobs -> bruce-c.uf2
MLDSA=87 ./build-c.sh feitian_rp2350
```

Underneath, from a clean clone, all four of these should compile without errors. Warnings about unused constants (`PAGE_SIZE`, `STATE_TOMBSTONE`, etc.) are expected -- they're reserved for future schemata.

```bash
# Default = mldsa65
cargo build --release

# Other two variants
cargo build --release --no-default-features --features mldsa44
cargo build --release --no-default-features --features mldsa87

# AAGUID override
BRUCE_AAGUID=cafebabecafebabecafebabecafebabe cargo build --release
```

Compile-error guards we expect to fire:

```bash
# Both flagged as mutually-exclusive
cargo build --release --no-default-features --features mldsa44,mldsa87
# ->  Bruce: pick exactly ONE of the `mldsa44`, `mldsa65`, `mldsa87`
#    cargo features. They're mutually exclusive.

# No variant at all
cargo build --release --no-default-features
# ->  Bruce: enable exactly ONE of the `mldsa44`, `mldsa65`, `mldsa87`
#    cargo features (default = `mldsa65`).

# Bad AAGUID
BRUCE_AAGUID=tooshort cargo build --release
# ->  evaluation panicked: BRUCE_AAGUID must be exactly 32 hex characters
```

## Wire test + benchmark: `examples/bench`

`crates/ctaphid-client/examples/bench.rs` drives an attached token
through MakeCredential + GetAssertion over raw CTAP HID, times both,
and verifies what comes back. It is also the **only** timing path the
project has: the firmware carries no cycle counter and prints nothing
over CDC, so this host wall-clock number -- USB stack included -- is the
measurement of record for any memory or cache work.

It:

1. Enumerates the FIDO usage page and opens the first device (`--device` picks, `--list` shows).
2. Runs `CTAPHID_INIT`, then reports the channel, the negotiated capability bits, and the device version.
3. Runs `authenticatorGetInfo` and reports the AAGUID, versions, and advertised algorithms.
4. Mints a `pinUvAuthToken` if the device has a PIN set (see [PIN](#pin) below).
5. Sends a `MakeCredential` offering `-56 / -55 / -54 / -7` in that order, so the device picks the strongest hybrid alg it implements. `--alg` forces one.
6. Parses the response: credentialID, COSE_Key (with the hybrid pubkey at label `-4`), attestation statement.
7. Verifies the attestation -- see [the two attestation shapes](#the-two-attestation-shapes).
8. Sends a `GetAssertion` for that credential and verifies the assertion the same way.
9. Repeats for `-n` rounds and reports min / median / max.

Signature verification splits the wire format `ecdsa_der || mldsa_raw`
at `blob[1] + 2`, verifies the ECDSA half cryptographically with the
`p256` crate against `HYBRID_LABEL || authData || clientDataHash`, and
checks the ML-DSA half **structurally only** -- correct length for the
level (2420 / 3309 / 4627) and not all-zero. Full ML-DSA verification
would mean taking an ML-DSA dependency into the host client; in a real
deployment the relying party does that, and length-plus-non-degeneracy
already catches the truncated or all-zero signature that a memory
optimisation would plausibly produce.

> WARNING: **Unattended runs need user presence not to block.** A board with
> a button makes every MakeCredential / GetAssertion wait up to 10 s
> for a fresh press-and-release, so an unattended run either fails
> with `CTAP2_ERR_USER_ACTION_TIMEOUT` (0x27) or measures a human.
> **C port:** build with `-DPQF_TEST_NO_USER_BUTTON=ON`. **Rust port:**
> build with the `test_no_user_button` feature
> ([BUILD.md](BUILD.md#other-features)); `tools/silicon-sweep.sh` does
> exactly that. Pair it with `reboot_no_up` and the token can be
> reflashed between levels without a finger either (that is how the
> [published baseline](#published-baseline) was taken). Benchmark a
> board whose button is wired -- the Feitian RP2350 -- so the number is
> the one a real token would give.
>
> `PQF_TEST_NO_USER_BUTTON` and `test_no_user_button` auto-confirm
> user presence outright -- the one gesture that stops a web page from
> silently exercising a credential. A build carrying either is a
> **development build**: never ship it, and never leave it on a key
> holding real credentials. (The C flag replaced `PQF_BENCH_AUTO_UP`,
> deleted in `1c5cd07`.)

### Run

```bash
cargo run --release -p pqf-ctaphid --example bench \
    --target $(rustc -vV | awk '/host/{print $2}') -- -n 10
```

Build `--release`: a debug build spends long enough in ECDSA
verification to blur the numbers it is meant to be measuring.

Output from the 2026-09-27 ML-DSA-65 run behind the
[published baseline](#published-baseline) (the twenty-round pass). It
predates the [2026-09-30 relabel](#2026-09-30-composite-cose-ids-relabelled-to-draft--04):
a current build prints `Algs : -56, -55, -54, -7` and `alg -55`, and
the project's own AAGUID (`ef80634d...`) in place of the OpenSK sample.

```
Device   : 1209:f1d0 "Feitian RP2350 PQC"     <- the Rust vendor id of the time; cafe now
CID      : 00000002  (CTAPHID v2, device v0.1.0)
Caps     : 0x0d (cbor=true wink=true nmsg=true)
AAGUID   : 664d9f6784a2412a9ff7b4f7d8ee6d05
Versions : FIDO_2_0, FIDO_2_1
Algs     : -53, -52, -51, -7
maxMsgSize: 7609

RP       : bruce.example (https://bruce.example)
Rounds   : 20

--- round 1/20 ---
  MakeCredential : 5659B in 1.24s (keepalives=176)
  credentialId: 161 bytes, alg -52 (ECDSA-P256 + ML-DSA-65, pubkey 1952B)
  ok MakeCred attestation: ECDSA-P256 verifies (DER 71B + ML-DSA-65 3309B)
  ok MakeCred attestation: ML-DSA-65 sig length / non-zero OK
  GetAssertion   : 3609B in 0.84s (keepalives=142)
  ok GetAssert: ECDSA-P256 verifies (DER 70B + ML-DSA-65 3309B)
  ok GetAssert: ML-DSA-65 sig length / non-zero OK
--- round 2/20 ---
  MakeCredential : 5658B in 1.08s (keepalives=130)
...

Summary over 20 successful round(s):
  MakeCredential : min 0.99s  median 1.47s  max 2.62s   (n=20)
  GetAssertion   : min 0.69s  median 0.90s  max 2.41s   (n=20)

ALL ROUNDS PASS
```

Exit status is 0 only if every round completed and every signature
verified. Any round that fails is reported and the run exits non-zero.

What the lines mean:

- **`MakeCredential : 5659B in 1.24s (keepalives=176)`** -- the response payload was 5659 bytes and the full round trip took 1.24 s. The KEEPALIVE count is the number of `0xBB` HID frames the device emitted while signing; core 0 pumps them every few milliseconds while core 1 signs (about 150 a second on this run), so the count grows with the signing time, and a non-zero count confirms the multicore offload is alive rather than the host simply blocking.
- **`credentialId: 161 bytes, alg -52`** -- the Phase-2 compact stateless credentialID, and the hybrid alg the device chose.
- **`ok ... ECDSA-P256 verifies (DER 71B + ML-DSA-65 3309B)`** -- the wire format split at the DER length and the `p256` crate accepted the classical half against the COSE_Key's X/Y point. The DER half is 70 or 71 bytes depending on whether r and s need a leading zero, which is also why response sizes wander by a byte or two between rounds.
- **`ok ... ML-DSA-65 sig length / non-zero OK`** -- the PQC half is 3309 bytes (FIPS 204 sec. 4 Table 2) and not degenerate.

### Published baseline

Reference numbers to compare a change against: **Rust firmware, Arm
(both cores), the USB-A Feitian RP2350**, measured host-side over USB
with `bench -n 10` on 2026-09-27. Every image was built
`mldsaNN,board_feitian_rp2350,test_no_user_button,reboot_no_up` (so the
sweep ran unattended -- see the warning above) from the tree that
vendors bc-rust 0.1.3alpha, and loaded after a `picotool erase -a`.
Every round passed and every signature verified.

| Level | Operation | Response | min / median / max |
| --- | --- | --- | --- |
| ML-DSA-44 | MakeCredential | 4129-4131 B | 0.68 / 0.81 / 1.02 s |
| ML-DSA-44 | GetAssertion | 2720-2722 B | 0.46 / 0.62 / 0.77 s |
| ML-DSA-65 | MakeCredential | 5658-5660 B | 0.97 / 1.09 / 2.70 s |
| ML-DSA-65 | GetAssertion | 3609-3611 B | 0.69 / 0.98 / 3.36 s |
| ML-DSA-87 | MakeCredential | 2987-2989 B | 0.44 / 0.45 / 0.47 s |
| ML-DSA-87 | GetAssertion | 4927-4929 B | 1.00 / 1.31 / 2.58 s |

Reading the table:

- **Gate on the minimum and the median; the maximum is ML-DSA itself.**
  FIPS 204 signing is a rejection loop -- a candidate is discarded and
  the loop retried whenever a bound check fails -- so a signature costs
  the floor (one pass) plus a geometric tail. A second ML-DSA-65 run of
  twenty rounds put its slow rounds at positions 5, 16, 19 and 20 with
  the floor unchanged (MakeCredential 0.99 / 1.47 / 2.62 s, GetAssertion
  0.69 / 0.90 / 2.41 s): scattered, not drift. A regression shows up as
  a raised minimum or median, not as one slow round.
- **ML-DSA-87 MakeCredential does not time an ML-DSA-87 signature.** At
  that level the attestation is ES256 only ([the two attestation
  shapes](#the-two-attestation-shapes)), so MakeCredential is key
  generation plus one ECDSA signature. GetAssertion carries the
  4627-byte ML-DSA-87 signature and is that level's signing figure.
- **The earlier reference row is superseded.** It read 5530 B in 1.16 s
  for MakeCredential and 3617 B in 0.87 s for GetAssertion at ML-DSA-65,
  taken with the pre-`bench` smoke script; today's medians are faster
  and the MakeCredential response is 129 bytes larger.

The sweep runs hands-free from a token sitting in BOOTSEL. Per level:

```bash
cargo build --release -p bruce --no-default-features \
    --features mldsa65,board_feitian_rp2350,test_no_user_button,reboot_no_up \
    --target thumbv8m.main-none-eabihf
picotool uf2 convert -t elf target/thumbv8m.main-none-eabihf/release/bruce \
    bench-65.uf2 --family rp2350-arm-s
picotool erase -a && picotool load -x bench-65.uf2   # erase first: FLASHING.md, "Intermittent dark device"
# a few seconds later the token enumerates as "Feitian RP2350 PQC"; then
cargo run --release -p pqf-ctaphid --example bench --target "$HOST_TARGET" -- -n 10
cargo run --release -p pqf-ctaphid --example reboot --target "$HOST_TARGET" -- bootsel
until picotool info -a 2>/dev/null | grep -q 'Device Information'; do sleep 1; done
```

The token had no PIN set, so `bench` ran without `BRUCE_PIN`.
Finish by flashing an image without `test_no_user_button`; the one
left on the token that day was `mldsa65,board_feitian_rp2350,reboot_no_up`.

Numbers only compare like-for-like. Port (C vs Rust), ML-DSA level,
core architecture (Arm / RISC-V / mixed), and XIP-vs-`copy_to_ram`
placement each move them substantially -- and the response size moves
with the ML-DSA level regardless of any timing change. Keep to one
board across a comparison: the **Feitian RP2350** is the reference for
on-silicon timing, not the Spotpear LCD build.

### Offline self-test

The verification logic, the DER reader, the hybrid split, the COSE_Key
reader, the request CBOR shapes and the statistics can all be checked
without a token attached:

```bash
cargo run -p pqf-ctaphid --example bench \
    --target $(rustc -vV | awk '/host/{print $2}') -- --self-test
```

It generates a real P-256 key, signs a labelled message, and pushes it
through the same verify path the live run uses, including the
negative cases (wrong message, all-zero ML-DSA half, truncated ML-DSA
half, ES256 attestation offered at the wrong level). No device is
opened. Exits non-zero on any failure.

### The two attestation shapes

Which attestation a hybrid MakeCredential returns depends on the
build's ML-DSA level, and the benchmark checks the right one
(commit `347bdb0`):

| Level | `attStmt.alg` | Signature | Verified as |
| --- | --- | --- | --- |
| 44, 65 | the credential's hybrid alg (`-54` / `-55`) | `ecdsa_der \|\| mldsa_raw` | ECDSA over `LABEL \|\| msg`, ML-DSA half checked structurally |
| 87 | `-7` (ES256) | ECDSA DER only | ECDSA over `msg`, **no** LABEL |

At level 87 the full dual attStmt measures 7617 B against a 7609 B
CTAPHID structural ceiling, so the attestation alone downgrades to
plain packed ES256. The credential stays hybrid -- the ML-DSA public
key still rides in `authData` and ML-DSA still signs every
GetAssertion. The benchmark **rejects** an ES256 attestation at level
44 or 65, since there is no size justification for it there and a
conformant verifier refuses it too.

Note the ECDSA halves are not interchangeable: the hybrid half signs
`SHA-256(LABEL || msg)`, packed ES256 signs `SHA-256(msg)`.

### PIN

If a PIN is set, put it in the environment -- there is no interactive
prompt, so the run stays usable unattended:

```bash
BRUCE_PIN=1234 cargo run --release -p pqf-ctaphid --example bench \
    --target "$HOST_TARGET" -- -n 10
```

Without it the device answers `0x36` (`ERR_PUAT_REQUIRED`) and the
benchmark says so. To clear the PIN and credentials instead:

```bash
cargo run -p pqf-ctaphid --example reset \
    --target "$(rustc -vV | awk '/host/{print $2}')"   # clears PIN + credentials, rotates master keys
sleep 1                  # let the device persist
```

### Still worth adding

- ~~Full ML-DSA verification via `oqs-python`~~ -- done for the TrustZone
  tests with `dilithium_py`, which is pure Python and needs no liboqs
  build, so the dependency tradeoff turned out to be cheap. Worth
  pulling into the main host suite. (Do **not** `import oqs` casually:
  it tries to download and build liboqs on first import.)
- `hmac-secret` round-trip (same salt across two assertions -> same output).
- A `--json` output mode so CI can diff two runs mechanically instead of by eye.
- Percentile output (p99) rather than just max, for quoting the spread of
  ML-DSA sign times: the min / median / max that `bench` reports over
  `-n` rounds is the only sign-jitter measurement so far, and there is
  no dedicated sign-jitter test.

## Phase smoke tests

Quick sanity checks per phase, all read off the `probe` example's `getInfo` dump unless stated:

| Phase     | Check                                                       | Expected output                                                                        |
| ---       | ---                                                         | ---                                                                                    |
| Phase 1   | Multicore signing keeps host alive                          | `MakeCredential` completes < 5 s under Chrome; `chrome://device-log` shows KEEPALIVEs |
| Phase 2   | Stateless 161-byte credentialID                              | `maxcredlen: 161`                                                                      |
| Phase 3   | Multi-alg                                                    | Any variant advertises four entries -- `-56 / -55 / -54 / -7` -- so expect three x `algorithms: unknown` then `es256` (libfido2 doesn't know the composite ids) |
| Phase 4   | Extensions advertised                                        | `extension strings: credBlob, credProtect, hmac-secret`                                |
| Phase 5   | PIN protocols                                                | `pin protocols: 1, 2`                                                                  |
| Phase 5fu | v2 pinUvAuthParam accepted                                   | the `pin_set` example to set PIN, then any MakeCredential under Chrome doesn't fail       |
| Phase 6   | minPinLength / forcePINChange / maxCredBlobLength / wink     | `minpinlen: 4`, `pin change required: false`, `maxcredblob: 32`, `caps: 0x0d (wink, ...)` |

## Chrome end-to-end

A relying party that accepts the composite COSE algorithms `-54 / -55 / -56` and does not filter on AAGUID can register the default build (mldsa65 + default AAGUID) out of the box (one that only trusts the OpenSK PQC reference list needs `BRUCE_AAGUID` set to the OpenSK sample id, [BUILD.md](BUILD.md#aaguid-override)). End-to-end verification:

1. Build + flash the default (`mldsa65`) firmware: `./build.sh`, then
   `./flash.sh` with the board in BOOTSEL.
2. Run the `reset` example to reset to a clean state:
   `cargo run -p pqf-ctaphid --example reset --target "$HOST_TARGET"`.
3. Open the RP's registration page.
4. Register a new passkey. Chrome prompts for a PIN -- set it.
5. Confirm the LED state: blue blink -> blue+red while signing -> blue blink. Red persists for ~1 s; this is the multicore hybrid sign.
6. Log out, then log back in. The assertion flow runs in another ~1 s.
7. Use a different browser (or incognito) and confirm the same credential authenticates correctly.

If anything fails, [docs/USAGE.md](USAGE.md#troubleshooting) has the common failure modes.

## Host tests: one command

```bash
tools/host-tests.sh            # everything; `rust` or `c` for half
```

Four Rust crates and twenty-one C test programs, and none of them run the same
way. The Rust crates are **not** in the workspace default set -- the
default target is the firmware, which has no test harness -- so each
needs an explicit host triple. `pqf-signer-core` additionally needs a
variant feature and is run once per level, because the constants under
test are exactly what the feature selects. `pqf-pkcs11` has four tests
that must run alone on a single thread.

Getting any of that wrong prints `ok` having run nothing, which is worse
than failing, and is the reason this is a script rather than a line in a
README.

| suite | count |
|---|---|
| `pqf-cbor` | 25 |
| `pqf-gdbstub-core` | 47 |
| `pqf-signer-core` x 3 levels | 7 each |
| `pqf-pkcs11` | 27 + 4 serial |
| C firmware (21 programs) | 73 checks in `test_gdbstub` alone, 77 in `test_qrng` |

### The sealed credential id

`crates/firmware-hosttest` -- 253 checks, no board.

Every credential this token mints lives inside its own id, encrypted
under a device-wide key: the ECDSA scalar, the ML-DSA seed, the rpId
hash, the credProtect policy. The relying party stores that blob and
hands it back on every login, so the id is at once the key store, the
access-control record, and the only material an attacker with a stolen
credential list has to work with.

The C port has proved the tamper property since Phase C-11
(`test_domain.c`): *every* single-byte flip of the sealed blob is
rejected, not merely one. The Rust port made no such claim. It does now
-- **1288 mutations, every bit of every one of the 161 bytes, all
rejected** -- and the round-trip test in the same file is what keeps that
honest, since a decrypt that always failed would satisfy the tamper test
and fail the round trip.

Also pinned: a credential minted for one relying party is refused at
another even with a valid HMAC, and editing any ciphertext byte to try
to change the sealed rpId hash fails the tag. Truncation and extension
are rejected as malformed. A credential from a different device -- either
master key -- is refused. The id is 161 bytes, which matters because
base64url of it is 215 characters and relying parties with a
`VARCHAR(255)` credential_id column exist; the test asserts the budget
rather than the constant.

The derived secrets get their own checks, because `cred_random` and the
largeBlobKey are both HMACs under the same key over the same credential
id and only domain separation keeps them apart. If that were ever
dropped, a relying party's largeBlobKey would equal a secret it can
already obtain through hmac-secret. So: the two differ, the UV and
non-UV variants of `cred_random` differ, both change with the device
key, and a one-bit change anywhere in the id changes both.

### CTAP2 dispatch -- the front door

12 checks. `handle_cbor` takes whatever the host sent, reads the first
byte, and routes; everything downstream depends on it. Until now only
the conformance suite (an external CTAP 2.1 conformance suite, not part
of this repository) exercised it, driving well-formed commands at a real
token.

All ten dispatched commands answer with a well-formed status byte when
given no parameters -- an error is a fine answer, a panic is not, and a
panic here takes the transport core down. Truncated CBOR bodies, six
shapes across six commands, are refused rather than indexed past. Seven
thousand bytes of `0xff` do not parse as a credential request. And the
two refusals are distinct on purpose: an empty request has no command
byte to look at and is `CTAP1_ERR_INVALID_COMMAND`, while a byte the
table does not carry is `CTAP2_ERR_NOT_IMPLEMENTED`, so a client can
tell "I sent nothing" from "you do not do that".

`authenticatorSelection` is checked from both sides -- it answers OK on a
confirmed gesture and `CTAP2_ERR_USER_ACTION_TIMEOUT` when the host
reports none. That gate is the reason this token stopped hijacking every
registration, and nothing had been holding it in place.

The harness also checks *itself*: the stub signer returns the documented
shape, can be made to fail so the firmware's error path is reachable, and
gives different bytes for different credentials -- otherwise a later
"these differ" test would pass vacuously.

**One thing worth copying.** The device lock names its own misuse.
Every module under test owns process-global state, so a test holds a
lock for its whole body and `cargo test` runs the rest in parallel around
it -- blocking there is normal. What is not normal is a second acquire on
a thread that already holds it, which can never resolve; that is a test
bug, and it used to stop the suite dead with no output. The holder's
thread id is now recorded, so the self-deadlock reports itself and
ordinary contention still just waits. It caught one of mine in phase 3.

**And the lock is only worth having if every test takes it.** Three of
these dispatch tests drove the stub signer -- a process global -- without
it, and were quietly racing every `Device::new()` in the crate, which
resets that signer. It surfaced once, as a flake, in the phase-4 run:
two tests failed inside `tools/host-tests.sh` and passed on the next attempt.
A flake is worse than a failure, because the natural response to it is a
rerun. Fixed by taking the lock, then confirmed with twelve consecutive
clean runs of the whole crate rather than one.

**A second kind of leak, found in phase 5.** largeBlobs assembles a
write across transactions in a process-global staging buffer, and
`rp235x_hal::reset()` wipes the simulated die without touching it. So a
test that left a write half-assembled handed the next one a device with
something already in flight, and a test asserting "nothing is in flight"
passed or failed on the order the harness happened to run in -- it looked
like a firmware bug for about ten minutes. The shared `Device` now
clears that state on construction, over the wire rather than with a test
hook in the firmware: a write declaring a total below the legal minimum
resets the buffer on its way to refusing.

### getInfo, Selection and Reset

30 checks. getInfo is what every relying party and every browser reads
before deciding what this token can do, and nothing was pinning it:
the conformance suite reads it and checks a handful of fields, not the map. Each
wrong answer is either a capability that goes permanently unused or a
ceremony that fails after the user has already been prompted.

So: FIDO_2_1 is advertised (without it browsers take the legacy
security-key path); the five implemented extensions are all listed; the
AAGUID is 16 bytes and not all-zero; the nine capability options match
what the firmware implements; `clientPin` tracks whether a PIN is
*actually set*, checked both ways, since it is the one entry here that
is state rather than capability and so the one that can drift. The
advertised `maxMsgSize` is checked against the transport arithmetic it
comes from (57 + 128 x 59 = 7609), the credential-id length against the
format constant, and the largeBlob ceiling against the sector. getInfo is
also checked to still *fit* in the size it advertises -- it has grown with
every feature, and past 7609 the transport would truncate it and no
client could read anything at all.

Reset is the other half. CTAP 2.1 sec. 6.6 says it destroys all device data,
and the failure mode for an incomplete one is a token that looks
factory-fresh while still holding the previous owner's state. The checks
cover the PIN (and that getInfo notices), the largeBlob array in its own
sector, the live pinUvAuthToken and its permissions, the config policy
(alwaysUv, a raised minimum PIN length), and that a reset device still
answers afterwards.

**The one worth knowing about:** reset *rotates* the credential master
keys rather than only wiping the slots -- and it has to. A credential id
is a sealed blob the host holds, so a host that cached one before the
reset can still present it after; only rotating the keys it was sealed
under makes it undecryptable. Both keys, and on the die, or the next boot
restores them. That is now a test rather than a comment.

### MakeCredential and GetAssertion -- the two ceremonies

44 checks. These two are the token; everything else configures,
enumerates or resets what they produce, and between them they are 1400
of `ctap2.rs`'s 2956 lines. The only thing exercising them until now was
the conformance suite driving a real board.

The signing is stubbed, so what these cover is what the token *decides*
-- which algorithm, which credential, whether to refuse, what shape comes
back -- never whether a signature verifies. That stays a silicon claim.

**Registration.** Each of the four required parameters is refused when
absent, and a clientDataHash that is not exactly 32 bytes is refused at
five lengths -- accepting a short one lets a caller choose how much of the
signed message it fixes. `up=false` is refused as `INVALID_OPTION` (a
registration without a gesture is how a token becomes a background
signing oracle), `uv=true` with no PIN as `UNSUPPORTED_OPTION`, and a
refused gesture leaves no credential behind. Only `rk=true` consumes a
slot. Two registrations for one RP get different credential ids.

**Algorithm choice** is checked in five directions, including the two
halves of the advertised-versus-usable gap: a composite this build cannot
mint falls through to ES256 when both are offered, and is refused
outright when it is not. The check is written against
`COSE_ALG_HYBRID_MLDSA` rather than a hard-coded level, so it holds on a
44, 65 or 87 build.

**excludeList** refuses a re-registration of this token's own credential,
ignores another token's, and survives six malformed entry shapes.

**Extensions.** credProtect is echoed for each of the three levels the
spec defines, and -- the part that matters -- *enforced*: a level-3
credential is not discoverable without UV, and a level-2 one answers only
when its id is supplied. No extension data comes back when none was asked
for, which CTAP 2.1 sec. 12.1 makes a MUST because the ED flag changes how
the whole structure is parsed. credBlob at exactly the advertised maximum
is stored; anything larger is reported `false` rather than truncated.

**Assertion.** The rpId scoping is checked from both sides -- a credential
must not answer for another relying party *even when its id is supplied*,
which is the cross-site bypass. A forged credential id misses; so does a
genuine one with a single bit flipped, at four positions. The signature
counter is checked to strictly increase across four assertions, since a
counter going backwards is what tells a relying party the token has been
cloned. The UV flag stays clear without a PIN. GetNextAssertion is
refused both with no preceding assertion and after a single-credential
one.

### The PIN protocol

46 checks. 1187 lines, and the only thing between a malformed request and
every credential on the token: two protocol versions, an ECDH handshake
per attempt, two independent retry counters, and a permission model that
decides what a minted token may then authorise.

**What the test client shares, and what that costs.** It does its own
ECDH with `p256` and its own CBOR, but derives session keys through the
firmware's own `SharedSecret` rather than reimplementing
SHA-256/HKDF/AES-CBC/HMAC a second time -- so a *symmetric* error, both
sides using the same wrong HKDF info string, would not show up. Three
checks narrow that: v1 is proved to be SHA-256(ECDH.x) computed
separately from the raw ECDH output, the two protocols are proved to
derive different keys and different tag lengths, and v2 framing is proved
to carry a fresh IV per call (v1's zero IV is the protocol; a fixed v2 IV
would make an encrypted PIN comparable across attempts).

**The two counters, which are the point.** They are easy to describe and
easy to get subtly wrong, and both were previously unexercised:

- the *persistent* budget of 8, checked to step by exactly one per wrong
  PIN across all eight -- off by one either way is a real defect, too few
  and the token locks early, too many and the guess budget is larger than
  advertised;
- the *volatile* per-boot block at 3, checked to trip on the fourth
  attempt, to leave persistent retries intact, to still admit a correct
  PIN on the third try (or a mistyped PIN costs the user a replug), and
  to clear on a power cycle;
- exhausting all 8 blocks the PIN permanently -- the correct PIN is
  refused, and changePIN does not work around it;
- a *successful* attempt restores the full budget, and a **mangled
  request does not cost a retry**. That distinction matters: a wrong PIN
  is a guess and must be rationed, but a bad `pinUvAuthParam` is not
  evidence of guessing, and charging for it would let a passive attacker
  lock the user out knowing nothing at all.

Also pinned: the key-agreement key rotates after every failure, so a
shared secret from before a wrong guess no longer works -- an attacker
cannot pre-compute a batch of encrypted guesses against one secret.
setPIN is refused a second time, refused below the four-code-point floor,
refused with a bad auth param, and refused at six wrong `newPinEnc`
lengths. A v1 auth param does not authenticate a v2 request. changePIN is
refused when no PIN is set, which is the guard that stops a `pinHashEnc`
decrypting to the all-zero stored hash from setting a PIN with no
authentication at all.

Permissions: the legacy `getPinToken` grants mc+ga and is checked *not*
to grant credential management, largeBlobWrite or authenticatorConfig; a
scoped token grants only what was asked for; an RP-scoped token is
refused for another relying party; an unscoped one is device-wide;
bioEnroll is refused because this device advertises no such option.

### Credential management, largeBlobs and authenticatorConfig

65 checks across the three commands that live behind a
`pinUvAuthToken`. Each is checked from both sides of its gate: refused
with no token, with a forged parameter, and with a token carrying the
wrong permission -- then exercised properly once authorised.

**Credential management** (23) is how a browser lists a user's passkeys
and deletes one, so it enumerates and destroys the most sensitive state
on the device. Every RP is enumerated exactly once and two accounts at
one site stay one entry in the RP list; deleting removes a credential
*everywhere* -- the slot, the RP listing, and its ability to
authenticate -- rather than only hiding it from the management UI; a
freed slot returns to the pool, without which enough churn fills the
device permanently. A foreign credential id misses, six malformed id
shapes are refused without destroying anything, and an RP-scoped token
cannot read device-wide state (or one site could count and list every
other site the user has).

**largeBlobs** (23). Two things make it worth care. The read path takes
an attacker-controlled offset and length **with no authentication at
all** -- the only place on this device where that is true -- so the clamp
is checked at the values that would wrap a 32-bit add, where a plain add
would slice with `start > end` and panic. And writes assemble across
transactions in a staging buffer, so the fragment sequence is state a
malformed run can steer: a partial write must not replace what is
already stored, a continuation with nothing in flight is refused, and a
fragment at the wrong offset is refused at four wrong offsets. The write
gate is checked in both directions, including that a `pinUvAuthParam`
for one fragment does not authorise another.

**authenticatorConfig** (19) sets persistent device policy, and two of
its three settings are one-way by design. alwaysUv toggles and getInfo
agrees; the minimum PIN length is raised, cannot be lowered, and -- the
check that makes the subcommand more than a number in a struct -- is then
*enforced by the PIN path*, with a seven-character PIN refused under a
minimum of eight. A `pinUvAuthParam` for one subcommand does not
authorise another, so observing a harmless setMinPINLength cannot be
replayed as a toggleAlwaysUv. And a successful PIN change invalidates
outstanding tokens, which had never been checked anywhere.

### Ed25519, and the TRNG driver

**Ed25519 (16 checks, feature-gated).** The one algorithm path in this
firmware that can be *verified* on the host rather than measured.
Everywhere else the signing is stubbed and a test can only assert shape;
here `ed25519_dalek` is the real implementation, so a signature made in
the suite can actually be checked.

That is used for what it is good for: a signature verifies under the key
derived from the same seed, and fails under another key, a flipped
message byte, or a flipped signature byte in either half. Signing is
proved deterministic -- RFC 8032 sec. 5.1.6, and the reason this algorithm
needs no entropy at signing time and cannot leak a key through a
repeated nonce the way ECDSA can. Derivation is proved pure across eight
calls, since a credential id stores only the seed and rebuilds the key on
demand. The COSE key is checked label by label (`kty`=OKP, `alg`=-8,
`crv`=6, 32-byte `x`), round-tripped through CBOR, and then -- the
end-to-end shape -- **a verifier is rebuilt from the COSE blob alone and
used to check a later assertion**, which is exactly what a relying party
does and which nothing else here closes.

**The TRNG driver (13 checks).** This is the root of trust: every
credential key, every IV, every `pinUvAuthToken`. On hardware it almost
always works first time, which is precisely the problem -- the paths that
matter most are the ones silicon never takes.

`halsim` now carries a scriptable noise source, so three properties that
were previously only comments in `trng.rs` can be run:

- a block whose health bits are set is **discarded and retried**, not
  handed back as random -- the comment says "MUST", and this is the only
  place that can check it;
- a source that never asserts `EHR_VALID` **bails on its poll limit**
  rather than hanging the calling core;
- after its bounded retries the driver **panics rather than producing
  weak keys**. If that ever stops panicking the failure becomes silent,
  and a token with a broken noise source would mint credentials from
  uninitialised memory. Both dead-source cases are `#[should_panic]`.

Also pinned: the EHR is unpacked little-endian; a request smaller than a
block leaves the rest buffered instead of discarding it; a request
spanning blocks stays in order; and eight consecutive blocks are all
distinct -- the driver's stated contract is that each byte is handed out
*exactly once*, and reuse would give two credentials the same key
material.

### The QRNG driver and the entropy picker

The optional quantum RNG on I2C goes ahead of the TRNG when one
is attached (`crates/firmware/src/qrng.rs` + `entropy.rs`;
`c/firmware/src/pqf_qrng.c` + `pqf_rand.c`). The chip cannot be on the
host, and that is the point: on hardware the driver almost always sees
a healthy part, so the paths that matter most are the ones silicon
never runs. Both ports write the protocol against a small bus seam
(`qrng::Bus` / `pqf_qrng_hw.h`) that the test scripts, and both link
the *real* driver and the *real* picker.

**Rust (`tests/real_qrng.rs`, 17 checks)** and **C (`test_qrng.c`, 77
checks)** cover the same ground:

- an empty bus is decided by the NAK: the pins are released, PD is never
  toggled, and every byte comes from the fallback -- whose deterministic
  stub stream is what makes "the TRNG was not consulted" a statement
  about bytes when the chip *is* present;
- a chip that ACKs but never reads ready is treated as absent, after a
  bounded wait and a PD power-cycle;
- output is **SHA-256 over exactly 64 accepted raw bytes**, pinned to
  the FIPS 180-4 `"abc"` vector so the hash is known to be SHA-256 and
  not merely self-consistent, and hashing the packets *with* their
  header and health bytes gives a different answer -- framing never
  reaches the conditioner;
- a bad header or a set health nibble drops that packet whole and costs
  one extra read; nine rejects in a row abandon the draw;
- small requests drain the buffered hash and every byte is served once;
  a request spanning two draws stays in order;
- a bus that dies half way through a request keeps the completed draw
  and the **TRNG completes the tail**, split 32/32 in the counters;
- eight short requests in a row write the chip off -- bus released, name
  reads `TRNG`, and a written-off chip is never asked again -- while a
  transient fault that recovers resets the counter;
- (C) the `RAND_priv_bytes` / `_ex` entry points all route through the
  same picker, `NULL` and negative lengths are refused, a zero-length
  request touches nothing; (Rust) the `RngCore` impl draws through the
  picker in order.

The RP2350 transport itself (`qrng::hw`, `pqf_qrng_hw.c`) is not host-
testable; it was covered on silicon the day it was written:

**Silicon, 2026-09-15 -- Tiny 2350 with the QRNG on its QW/ST
connector (I2C0, GP12/GP13).** Six images, all built from this tree with
the auto-confirming presence gate so the run needed no hands:

| image | QRNG found | 1 KiB `CMD_RNG` | errors |
|---|---|---|---|
| C, Arm | yes (`[rng] src=QRNG`) | 336 ms | hdr 0 / hlth 0 / bus 0 / short 0 |
| C, pure RISC-V | yes | 336 ms | 0 / 0 / 0 / 0 |
| C, mixed (RISC-V blob) | yes, `core1=RISCV-BLOB` | 336 ms | 0 / 0 / 0 / 0 |
| Rust, Arm | yes (product string ` QRNG`) | 332 ms | -- |
| Rust, pure RISC-V | yes | 332 ms | -- |
| Rust, mixed | yes | 332 ms | -- |

The timing is the witness that does not depend on a banner: a 1 KiB
draw is 32 SHA-256 blocks of four 18-byte packets each at 100 kHz, and
the on-die TRNG would answer the same request in a few milliseconds. On
the C images the heartbeat counters attributed every byte since boot to
the QRNG (`fallback=0`) and the packet count matched the bytes served
exactly (4 packets per 32 bytes). On the mixed C image a full conformance-suite
run -- six hybrid signatures on the Hazard3 blob, each fed 32 bytes of
QRNG-first entropy through the mailbox -- finished with 7,552 QRNG bytes
served, zero fallbacks and zero bus errors; its two failing checks were
the deliberate ML-DSA-44/87 over-advertisement on a level-65 build, not
entropy. Not covered: the TrustZone Secure world still mints from its
own TRNG copy.

**Silicon, 2026-09-16 -- the Tiny 2350's BOOT button as the presence
input.** Both ports now read the Tiny's BOOT button through the QSPI
chip-select sampler the Feitian uses (`board/bootsel.rs`, `bootsel.c`).
Checked on the same Tiny, every image built with the real gate and
`reboot_no_up` / `PQF_REBOOT_NO_UP` so reflashing needed no hands:

| image | untouched MakeCredential | pressed | sampler while idle |
|---|---|---|---|
| C Arm | `OperationDenied` after 10 s, wait counters flat | confirmed, `UP=true`, one 20 ms debounced press counted | 17,000 samples, 0 high, 0 edges |
| C pure RISC-V | -- | confirmed, one press counted | 17,000 samples, 0 / 0 |
| C mixed | `OperationDenied` after 10 s, flat | -- | 16,900 samples, 0 / 0 |
| Rust Arm | `OperationDenied` after 10 s | confirmed, `UP=true` | -- |
| Rust pure RISC-V | `OperationDenied` after 10 s | -- | -- |
| Rust mixed | `OperationDenied` after 10 s | -- | -- |

The `PQF_UP_DEBUG` counters are the discriminator: an idle board that
never reads pressed, a gated wait that stays flat while nobody touches
it, and a wait that ends after exactly ten consecutive pressed samples
when someone does. A first run that confirmed without a request to
press turned out to be the author pressing on the blink, which the
counters showed as one clean press per operation; the deliberate
hands-off rerun timed out. The QRNG path was unchanged throughout.

### The single-core signer and the yield hook

`-DPQF_SINGLE_CORE=ON` (C port) runs the signer inline on core 0 and
relies on the vendored crypto calling `pqf_yield()` often enough for
`src/core0_signer.c` to emit a `KEEPALIVE` every 25 ms from inside the
math. That is a claim about loop structure, and `test_yield.c` (26
checks) checks it with the shipping code: the real `core0_signer.c`, the
real `hybrid.c` and the real openssl-mini, with the clock replaced by a
counter the test advances 1 ms per yield call (`-DPQF_YIELD_HOST`).

- A hybrid sign yields well over a thousand times, the tick fires once
  per ~25 ms of yields (checked against the callback count, with no two
  ticks more than 27 ms apart), the worst gap inside the op is one clock
  step with the tick's own duration accounted separately, the op is
  filed under its kind, and the signature it produced verifies under
  `hybrid_verify`.
- A P-256 key generation yields about five hundred times (one per
  Montgomery-ladder step plus one per step of the affine-conversion
  inversion) and an ECDSA sign at least two hundred; the ML-DSA
  public-key derivation yields at least fifty.
- The flash-op guard runs its callback and parks nobody; a hook with no
  tick installed does nothing rather than crash.

**Silicon, 2026-09-17 -- Tiny 2350, QRNG on QW/ST, ML-DSA-65.** The
figure that matters is the heartbeat's worst blind spot: the longest
stretch of any inline op between two yield calls, tick time excluded,
i.e. the longest a host could ever wait for a `KEEPALIVE`. Both
single-core images ran the full conformance suite (76 passed, the two failures
being the deliberate ML-DSA-44/87 over-advertisement) with the QRNG
serving every byte and no fallbacks:

| image | ops | ticks | one tick | worst gap: hybrid sign | P-256 keygen | ECDSA sign | ML-DSA pubkey |
|---|---|---|---|---|---|---|---|
| single-core Arm | 18 | 493 | 9 us | 3.8 ms | 2.4 ms | 2.5 ms | 0.8 ms |
| single-core RISC-V | 18 | 472 | 14 us | 3.1 ms | 2.3 ms | 2.5 ms | 0.6 ms |

Getting there took two more rounds of yields than the loop structure
suggested, and the instrumentation is what found them. The first run
showed a constant 43.8 ms blind spot in every op regardless of kind.
Yields in the modular exponentiation and binary inversion loops (the
Fermat field inversion behind affine conversion, the order inversion in
ECDSA, the Montgomery set-up) took it to 33.4 ms. The rest was the
**QRNG draw**: an ECDSA hedged nonce asks for 64 bytes, which is two
SHA-256 blocks of four I2C packets each, and nothing inside that read
yielded. One yield per packet in `pqf_qrng.c` (single-core builds only)
brought every kind under 4 ms. The per-kind counters exist because the
first two figures could not say which op was responsible.

The dual-core builds still carry the yield calls, resolved to a weak
no-op that the openssl-mini KAT suite and the mixed-mode blob link the
same way -- so the same crypto sources serve every build and the hook
costs a no-op call where it is not wanted.

**Rust: the timer instead of the hook.** `--features single_core` has
no yield calls to count -- `bc-rust` is untouched and its sign is one
opaque call -- so its witness is the host. `Core1Signer::sign_here`
(signer-core, `tests/invariants.rs`) is checked on the host at all three
levels: it parks a result where `take_result` looks, the ECDSA half
verifies under the key the scalar defines, the ML-DSA half is
byte-identical across two runs, and an oversized message is refused
without leaving state behind. `tools/host-tests.sh` also builds the
feature for both instruction sets, the only code in the firmware that
arms a timer interrupt and drives USB from it.

On silicon the witness is the client's transport counters: the CTAPHID
layer swallows `KEEPALIVE` frames so callers never see them, and counts
them on the way through together with the longest silence between two
frames from the device (`Stats::max_gap`, the figure a client watchdog
would act on). `cargo run -p pqf-ctaphid --example keepalives` registers,
authenticates against the new credential, and prints both per operation.

**Silicon, 2026-09-17 -- Tiny 2350, QRNG on QW/ST, ML-DSA-65, timer at
25 ms.** Product string `Tiny 2350 PQC QRNG 1CORE` on both images, the
QRNG serving `CMD_RNG` at the usual 332 ms per 1024 bytes, the full
conformance suite at the level-65 baseline (77/76 passed, the two failures
being the deliberate ML-DSA-44/87 over-advertisement). Five register+login
rounds per image, two of them with the PIN the suite leaves behind:

| image | makeCredential: wall | keepalives | mean gap | max gap | getAssertion: wall | keepalives | mean gap | max gap |
|---|---|---|---|---|---|---|---|---|
| single-core Arm | 1.2-2.5 s | 28-78 | 32-42 ms | 80-84 ms | 0.9-1.5 s | 21-47 | 33-43 ms | 80-84 ms |
| single-core RISC-V | 1.2-2.4 s | 26-78 | 31-45 ms | 80-88 ms | 1.0-2.1 s | 24-68 | 31-41 ms | 80-84 ms |
| dual-core Arm (control) | 1.2-2.0 s | 97-302 | 6.6-12.1 ms | 196-208 ms | 0.9-1.3 s | 96-177 | 7.1-9.7 ms | 196-212 ms |

The mean gap sits above the 25 ms period because the wall time and the
count cover the whole operation, including the stretches where the token
is not signing. The 80 ms worst gap, identical on both instruction sets
and on every run, is not the timer's: every `getAssertion` bumps a
signature counter and every `makeCredential` records its slot, and the
flash store rewrites its whole 4 KiB sector for any change. The erase
and the program step are each a locked region with XIP suspended and
therefore interrupts masked (`ramfunc::flash_op_locked`), because a
vector fetched from a floated flash would fault; the alarm pends through
the erase and fires the moment interrupts return, so the figure is the
erase alone on this die, and the program step gets its own keepalive
in front.

The dual-core control puts that in perspective. Its wait loop pumps a
three-frame burst per iteration while core 1 signs, hence the 7-12 ms
mean, but nothing pumps through core 0's own sector rewrite -- erase
and program back to back -- or the response assembly around it, and its
worst gap is about 200 ms on every operation. That figure predates this
work (Chrome evidently tolerates it) and is worth a look of its own; the
point here is that the timer build's worst silence is the shorter of the
two, because an interrupt covers every stretch the dual-core loop does
not.

**The whole matrix, 2026-09-17 -- Tiny 2350, QRNG on QW/ST.** Every port,
core count, instruction set and ML-DSA level: 30 images, each flashed
and put through the same sequence. The client's default algorithm list
(`pqc_roundtrip`, which lets the token's own picker choose and so mints
the level's composite), a plain ES256 credential (`alg_roundtrip -7`),
two register+login rounds with the keepalive counters, and a full
conformance-suite run, whose composite check verifies the strongest algorithm that
actually mints; the two failures on every row are the deliberate
ML-DSA-44/87 over-advertisement. The dual-core rows are the regression
control for the single-core work: their sources changed only by the
weak no-op yield symbol (C) and by cfg-gated code (Rust).

| image | product string says 1CORE | PQC round trip (alg minted) | plain ES256 | keepalives per op / worst gap | conformance passed/failed | composite verified by the suite |
|---|---|---|---|---|---|---|
| Rust single Arm 44 | yes | MLDSA44-ES256 | ok | 20+ / 84.2 ms | 76/2 | MLDSA44-ES256(-51) |
| Rust single Arm 65 | yes | MLDSA65-ES256 | ok | 30+ / 80.1 ms | 76/2 | MLDSA65-ES256(-52) |
| Rust single Arm 87 | yes | MLDSA87-ES384 | ok | 15+ / 80.1 ms | 76/2 | MLDSA87-ES384(-53) |
| Rust single RISC-V 44 | yes | MLDSA44-ES256 | ok | 20+ / 84.2 ms | 76/2 | MLDSA44-ES256(-51) |
| Rust single RISC-V 65 | yes | MLDSA65-ES256 | ok | 32+ / 88.3 ms | 76/2 | MLDSA65-ES256(-52) |
| Rust single RISC-V 87 | yes | MLDSA87-ES384 | ok | 15+ / 88.1 ms | 76/2 | MLDSA87-ES384(-53) |
| C single Arm 44 | n/a (CDC banner) | MLDSA44-ES256 | ok | 15+ / 59.9 ms | 77/2 | MLDSA44-ES256(-51) |
| C single Arm 65 | n/a (CDC banner) | MLDSA65-ES256 | ok | 27+ / 136.1 ms | 76/2 | MLDSA65-ES256(-52) |
| C single Arm 87 | n/a (CDC banner) | MLDSA87-ES384 | ok | 53+ / 148.2 ms | 76/2 | MLDSA87-ES384(-53) |
| C single RISC-V 44 | n/a (CDC banner) | MLDSA44-ES256 | ok | 23+ / 135.9 ms | 76/2 | MLDSA44-ES256(-51) |
| C single RISC-V 65 | n/a (CDC banner) | MLDSA65-ES256 | ok | 33+ / 136.1 ms | 76/2 | MLDSA65-ES256(-52) |
| C single RISC-V 87 | n/a (CDC banner) | MLDSA87-ES384 | ok | 43+ / 136.2 ms | 76/2 | MLDSA87-ES384(-53) |
| Rust dual Arm 65 | no | MLDSA65-ES256 | ok | 96+ / 100.2 ms | 77/2 | MLDSA65-ES256(-52) |
| Rust dual Arm 44 | no | MLDSA44-ES256 | ok | 68+ / 204 ms | 76/2 | MLDSA44-ES256(-51) |
| Rust dual Arm 87 | no | MLDSA87-ES384 | ok | 4+ / 200.3 ms | 76/2 | MLDSA87-ES384(-53) |
| Rust dual RISC-V 65 | no | MLDSA65-ES256 | ok | 126+ / 208.3 ms | 76/2 | MLDSA65-ES256(-52) |
| Rust dual RISC-V 44 | no | MLDSA44-ES256 | ok | 73+ / 208.1 ms | 76/2 | MLDSA44-ES256(-51) |
| Rust dual RISC-V 87 | no | MLDSA87-ES384 | ok | 4+ / 208.2 ms | 76/2 | MLDSA87-ES384(-53) |
| Rust dual mixed 65 | no | MLDSA65-ES256 | ok | 100+ / 212 ms | 76/2 | MLDSA65-ES256(-52) |
| Rust dual mixed 44 | no | MLDSA44-ES256 | ok | 85+ / 204.3 ms | 76/2 | MLDSA44-ES256(-51) |
| Rust dual mixed 87 | no | MLDSA87-ES384 | ok | 4+ / 204 ms | 76/2 | MLDSA87-ES384(-53) |
| C dual Arm 65 | n/a | MLDSA65-ES256 | ok | 124+ / 212.1 ms | 77/2 | MLDSA65-ES256(-52) |
| C dual Arm 44 | n/a | MLDSA44-ES256 | ok | 102+ / 304.1 ms | 76/2 | MLDSA44-ES256(-51) |
| C dual Arm 87 | n/a | MLDSA87-ES384 | ok | 277+ / 500.1 ms | 76/2 | MLDSA87-ES384(-53) |
| C dual RISC-V 65 | n/a | MLDSA65-ES256 | ok | 106+ / 304.1 ms | 76/2 | MLDSA65-ES256(-52) |
| C dual RISC-V 44 | n/a | MLDSA44-ES256 | ok | 101+ / 304.4 ms | 76/2 | MLDSA44-ES256(-51) |
| C dual RISC-V 87 | n/a | MLDSA87-ES384 | ok | 270+ / 460.2 ms | 76/2 | MLDSA87-ES384(-53) |
| C dual mixed 65 | n/a | MLDSA65-ES256 | ok | 132+ / 492.1 ms | 76/2 | MLDSA65-ES256(-52) |
| C dual mixed 44 | n/a | MLDSA44-ES256 | ok | 125+ / 492 ms | 76/2 | MLDSA44-ES256(-51) |
| C dual mixed 87 | n/a | MLDSA87-ES384 | ok | 143+ / 492 ms | 76/2 | MLDSA87-ES384(-53) |

Two things the table says beyond pass/fail. First, the single-core worst
gaps: 80-88 ms for Rust on both instruction sets and every level (the
sector erase, as above), 60-148 ms for C, where the sector rewrite is one
flash-safe callback -- erase and program together, with no yield inside.
Second, the dual-core worst gaps are longer than either: 100-210 ms for
Rust and 200-500 ms for C, level 87 the worst. To be sure the single-core
commits had not caused that, the C dual-core Arm images at levels 65 and
87 were rebuilt from the commit they are based on -- before any
single-core change -- and run through the same sequence: 292-300 ms and
480-492 ms respectively, against 204-212 ms and 488-500 ms after, with
the same conformance-suite figures and the same keepalive counts; the Rust
dual-core Arm level-65 image from the same pre-change commit measured
96-104 ms against 92-100 ms after, again with identical conformance-suite
figures. The dual-core behaviour is unchanged and the long silences
predate this work. They are
the flash-store rewrite plus the stretches of core-0 work the pump never
reaches (at level 87 the public-key derivation and the response
assembly), and they deserve a pass of their own: Chrome tolerates them
today, but the single-core builds are now the images with the shortest
host-visible silence.

**Presence gating on the single-core builds, 2026-09-17.** Everything
above auto-confirms user presence, so the one path the single-core work
touches that the matrix never exercised is the real presence wait: on
the Rust side the `host` closure holds the timer's guard for the whole
wait and pumps `KEEPALIVE-UPNEEDED` itself every 50 ms, on the C side
the wait loop sits inside the inline dispatch. Four images at ML-DSA-65
built without the auto-confirm flag, so that every operation waits up
to 10 s for the Tiny's BOOT button, each run twice: once with nobody
near the token (the expected answer is `CTAP2_ERR_OPERATION_DENIED`
after 10 s) and once with a press per operation. The per-boot USB
serial was recorded around each untouched run to catch a reboot.

| image | untouched | during the 10 s wait: keepalives / mean / worst | pressed |
|---|---|---|---|
| Rust single-core Arm | denied at 10.3 s | 208 / 49.6 ms / 76.0 ms | register + login ok |
| C single-core Arm | denied at 10.0 s | 200 / 50.2 ms / 52.3 ms | register + login ok, twice |
| Rust dual-core RISC-V | denied at 10.05 s | 201 / 50.0 ms / 52.4 ms | ok on the third attempt, the first two untouched and denied |
| C dual-core RISC-V | denied at 10.05 s | 200 / 50.2 ms / 52.2 ms | register + login ok |

No serial changed, so no image rebooted across a presence wait. The
cadence during the wait is the 50 ms `UPNEEDED` pump on every image,
single or dual core; on the Rust single-core image the timer sat out the
wait as designed, and the 76 ms worst gap there is the erase from the
credential write that follows the press, not the wait. The runs also
reproduced the trap the earlier presence validation recorded: an
untouched run that confirms after two or three seconds of blinking is
the author pressing on the blink, and only a run with an explicit
hands-off agreement counts. One untouched attempt on the C image failed
with a host-side transport error three seconds in, while the board was
being re-plugged by hand; it did not recur across the seven runs that
followed on that image.

## Silicon re-validation, 2026-09-01

Run after the host-coverage sweep touched firmware. The changes were only
attribute gating -- `.data.ramfunc` made `cfg_attr`-conditional on the
board targets in `ramfunc.rs`, `fw-secure/flash.rs` and
`fw-secure/bootsel.rs`, plus `ram_nop`'s inline asm -- so the emitted
code should be byte-identical on target. "Should be identical" is exactly
the claim worth checking: had a section attribute silently stopped
applying, RAM-resident code would have moved to flash, and the failure
would appear only in an XIP-down window.

`tools/silicon-sweep.sh`, six configurations, all clean:

| config | conformance | extended | roundtrip |
|---|---|---|---|
| C / ML-DSA-44 | 77 / 0 | 84 / 0 | 2490 B, MLDSA44-ES256 |
| C / ML-DSA-65 | 76 / 0 | 84 / 0 | 3380 B, MLDSA65-ES256 |
| C / ML-DSA-87 | 76 / 0 | 84 / 0 | 4698 B, MLDSA87-ES384 |
| Rust / ML-DSA-44 | 77 / 0 | 84 / 0 | 2490 B, MLDSA44-ES256 |
| Rust / ML-DSA-65 | 76 / 0 | 84 / 0 | 3379 B, MLDSA65-ES256 |
| Rust / ML-DSA-87 | 76 / 0 | 84 / 0 | 4699 B, MLDSA87-ES384 |

A composite was verified against a real ML-DSA signature in every one,
and each was reflashed from source rather than reusing a build. The
ML-DSA-44 rows run one extra check because the suite exercises an
additional path at that level; the one-byte differences between ports at
65 and 87 are DER length encoding on the ECDSA half varying with r/s, not
a divergence.

### TrustZone, same day

The `tz_test` example: **0 failures** -- including the chip-select override,
which is the silicon counterpart of the `bootsel_sampler.rs` host suite
(`OEOVER=2 DISABLE, CSN=1 released`).

Two things about that run are worth writing down, because both look like
firmware faults and neither is.

**The conformance suite run for `-52` gives 10 passed / 14 failed against the
TrustZone image, not the 65 / 0 / 4 recorded above.** Every failure is
an `authenticatorSelection` or a `MakeCredential` -- the presence gate refusing
with nothing touching the pad. `tz_test` injects presence per operation
and passes; the 65/0/4 figure needs presence *latched*, which this run
did not reproduce. The TZ result is sound, but it is not the same
measurement.

**`tz_test` fails on a second consecutive run.** `no gesture ->
MakeCredential refused` passes the first time and fails after, because
the injected presence leaks between runs. A warm reboot does not clear
it; only a full BOOTSEL round-trip does. So a repeat run reads as a
broken presence gate when the gate is fine. Reset properly between runs.

### Three tooling bugs found doing this, none in firmware

Recorded because each produced a failure that read as a hardware or
firmware fault:

- **The readiness probe was the test.** `wait_up()` ran the full conformance
  suite to decide whether a board had re-enumerated, which demands every
  conformance check pass and takes ten-plus seconds a call. It reported
  `DID NOT RE-ENUMERATE` for a token that was answering.
- **`flash-tz.sh` handed cargo's extensionless ELF to `picotool`**, which
  dispatches on file extension. It printed `secure load FAILED` when the
  real message was "does not have a recognized file type".
  `tools/flash-fw.sh` documents this exact trap and stages through a
  `.elf` path; the TrustZone flasher never did. Fixed, along with its
  fixed six-second BOOTSEL sleep, which was a race.
- **A pipeline hid an aborted flash.** `cmd | tee | tail` reports
  `tail`'s status, so a script sailed past a failed flash and then blamed
  the token for not answering.

### What is deliberately not covered, and why

The sweep stopped here on purpose rather than running out. Each of these
was looked at and rejected for a reason worth recording, so the next
person does not re-derive it:

| module | lines | why not |
|---|---|---|
| `crates/firmware/src/arch.rs` | 12 | A `pub use` of `pqf_signer_core::arch`. A test would assert that a re-export re-exports. |
| `crates/firmware/src/core1_launch.rs` | 255 | Both public entry points are `#[cfg(target_arch)]`-gated to arm/riscv32 and the handshake they share is private, so on a host the file compiles to nothing. Reaching it means relaxing cfg gates or adding a test hook to firmware -- a worse trade than leaving it to silicon. |
| `crates/firmware/src/core1_signer.rs` | 32 | A thin wrapper over `pqf-signer-core`, which has its own tests at all three ML-DSA levels. |
| `crates/firmware/src/gdbstub.rs` | 497 | Protocol layer covered by `pqf-gdbstub-core` (47 checks) plus a silicon run with a real `gdb`. |
| `crates/fw-secure/src/trng.rs` | 205 | Byte-identical to the firmware copy; covered by its 13 checks plus a drift test that fails if they diverge. |
| `c/firmware/src/core1_signer_riscv.c` | 429 | Ten SDK headers deep (OTP ARCHSEL, PSM, the FIFO launch handshake). Its testable surface is the mailbox, which `test_core1_signer.c` already covers through the same `core1_signer.h` API. |
| `c/firmware/src/bootsel.c` | 109 | Hardware. Its Rust twin is tested with the same properties (`bootsel_sampler.rs`), including the OEOVER restore. |
| `c/firmware/src/board.c`, `xip_stats.c` | 174, 65 | GPIO and cache counters. Nothing to assert that is not the hardware itself. |
| `main.c`, `main.rs`, `fw-secure/main.rs` | 608, 1080, 1744 | Initialisation and the event loop. The logic they call is tested; what remains is wiring, and testing it would mean re-implementing it. |

Two of those -- `core1_launch.rs` and `arch.rs` -- were on an earlier
"cheapest first, no seam needed" list of mine. Both were wrong: a grep
for external `use` lines filtered out `use crate::hal`, and the cfg gates
were not checked at all. Recorded because an audit that has been wrong
once is worth showing the shape of.

### The cross-core mailbox

68 checks with cross-core dispatch, 64 without. Core 0 publishes a
request, raises a flag, and spins pumping USB keepalives until core 1
answers; core 1 wakes, does several seconds of ML-DSA work, and publishes
a result. It is the path every signature takes and nothing had checked it
off-silicon.

Core 1 is a thread here -- not the real thing, no separate instruction
stream and no XIP -- but it makes the mailbox a genuine two-party
protocol, which a single-threaded stub cannot. The crypto is real: this
links the same openssl-mini stack as the other C suites, so a round trip
really does produce a signature.

**Built twice, and the difference is the finding.** Without
`PQF_SIGN_ARENA`, `core1_p256_keygen` and `core1_p256_sign` run
**locally on core 0** and never reach the mailbox at all -- the `#if` in
`core1_signer.c` sends them straight to `pqf_p256_keygen`. The first run
of this suite missed that and reported sixty-odd passing checks, two of
which were measuring a code path that was not running. Both
configurations ship, so both are built, and the two checks that only
mean something with the arena say so and skip rather than passing
vacuously.

What it covers: a keygen round trip returns data rather than leaving the
output zeroed (a mailbox reporting success without publishing looks
exactly like that); successive keygens differ, since a stale result would
give every credential the same key; back-to-back requests each get their
own answer, because the state machine has to return to `ST_IDLE` and one
signature serving two ceremonies is the failure if it does not; every
request signals the other core, since core 1 waits in `wfe` and a missing
`sev` leaves it asleep while core 0 spins; and the long-operation tick
fires during the wait, which is what keeps CTAPHID keepalives flowing
through a multi-second signature -- without it the host times the
transaction out and the browser reports a dead key.

The flash-op park is checked to run its callback exactly once, to leave
the signer working afterwards, to survive eight in a row, and to
interleave with signing ten times -- which is the real sequence on every
GetAssertion, since a counter write precedes every signature.

### The alignment-safe memcmp and strcmp

16,158 checks. `pqf_align_str.c` exists because of **real silicon
freezes**: Raspberry Pi's prebuilt newlib for riscv-toolchain-15 is built
with GCC's default `__riscv_misaligned_slow` model, so its optimised
`memcmp` and `strcmp` issue word-sized loads with no alignment check. The
RP2350's Hazard3 cores do not support misaligned access at all -- such a
load traps with `mcause=4`. Whether a given CBOR string or crypto buffer
happened to be 4-aligned was data-dependent, so the traps presented as
*random freezes*, silicon-confirmed 2026-07-14 mid-browser
MakeCredential.

The replacements keep a word-at-a-time fast path for the mutually
aligned case and run bytewise otherwise. That is two paths through each
function, selected by the low two bits of two pointers -- so the suite
sweeps **all sixteen alignment combinations** rather than testing the
aligned case and hoping. For `memcmp` it also walks the differing byte
through every position at every length up to 40, because the fast path
breaks out on a word mismatch and resolves bytewise, and the byte that
differs must still decide the ordering.

The oracle is the host libc: 20,000 random comparisons at random
alignments must agree on sign. That is where a subtle word-loop error
shows up that hand-picked cases miss.

Three properties get their own checks because of what they mean here.
Bytes are compared as **unsigned** -- the classic mistake makes `0x80`
sort below `0x00`, and the things being compared are credential ids,
hashes and rpIds. `strcmp` must **stop at the terminator**, checked with
a poisoned tail so a four-byte read past it changes the answer. And a
prefix must never compare equal: `example.com` and `example.com.evil`
are different sites, and rpId comparison is what scopes a credential.

Compiled with `__riscv` defined, since the file is an empty translation
unit on any other target.

### The two TRNG drivers, and not duplicating their tests

`crates/fw-secure/src/trng.rs` and `crates/firmware/src/trng.rs` are the
**same file, copied** -- byte-identical once comments are stripped. That
is not wrong in itself: the Secure world and the FIDO firmware are
separate images and neither can depend on the other's crate. But a copy
is only safe while both copies stay the same, and this module is the root
of trust for *both* images.

So rather than duplicating the thirteen behavioural checks, there is one
test asserting the two files are the same code, and a second asserting
the file those checks live in still exists so the pointer cannot rot. A
fix applied to one copy and not the other now fails a test instead of
quietly leaving the bug in the other world.

The drift test reports the **first diverging line**, not just "they
differ", so the failure names what changed. It was verified by
introducing a divergence (`MAX_ATTEMPTS` 16 -> 8) and confirming it
failed at the right line, then restoring it -- a test that has never been
seen to fail is a test nobody should trust.

### The BOOTSEL sampler

10 checks. `pressed()` reads the BOOTSEL button, which on this chip
shares a pin with the flash chip select -- so to see it, the sampler
floats CS by writing OEOVER, waits, reads the pad, and puts OEOVER back.

**The restore is the whole safety property**, and its failure is the
worst kind. Leave OEOVER at DISABLE and the flash chip select stays
floated: XIP is dead, the next instruction fetch is undefined, and the
device wedges with no error anywhere. The module's own comment says this
code is "tiny and hot enough to sit in the XIP cache, so it usually works
-- the worst kind of latent bug".

So: the override is put back, with the button up *and* down (a restore on
only one branch is a device that wedges depending on whether the user is
holding it -- an intermittent nobody would connect to this code), and
across 64 consecutive samples, since the sampler runs on a timer in the
idle loop rather than once.

Only the OEOVER bits are touched -- `gpio_ctrl` carries the pad's function
select and other overrides, and clobbering those would reconfigure the
flash chip-select pin itself. The polarity is checked both ways: BOOTSEL
pulls the shared pin low, and inverted, a build that reboots on BOOTSEL
would never stay up. And the reading follows the pad across calls rather
than latching, or the button would work once per boot.

Interrupts are checked in both directions, including that a caller
already inside a critical section stays masked -- the same discipline as
the flash guard, and for the same reason: an ISR fetched from XIP while
CS is floated is the exact fault being guarded against.

What a test cannot see here is the *instant* of the float -- the firmware
writes through raw pointers into simulated cells, so the before and after
are observable and the moment between them is not. That part stays a
silicon claim.

### The Secure world's flash guard

7 checks on `with_core1_parked` and `flash_op`, the TrustZone side's
equivalent of the guard tested above. Its own comment records that it was
**missed when core 1 arrived** -- the flash path was written when the
Secure image ran one core, and launching core 1 for the ML-DSA signer did
not revisit it. A guard that exists because its absence was a real bug is
worth checking.

**The case that would hang the token is the interesting one.** The key
store and the signature counter both write flash during bring-up, *before*
core 1 is launched. Parking a core that has not started would wait forever
on an acknowledgement nobody will send -- a token that never finishes
booting. `CORE1_RUNNING` guards that, and the check needs its own test
binary, because that flag is one-way and can only be observed unset once
per process.

With core 1 up, the guard is checked to park before the operation and
release after; to wait on the **acknowledgement** rather than its own
request (core 1 may still be fetching its idle loop from XIP, and that
fetch during an XIP-down window is the undefined behaviour the whole
guard exists to prevent -- simulated core 1 is slowed to 50 ms so the two
events order confidently); to leave nothing parked; and to survive eight
back-to-back operations, since the guard waits for core 1 to *leave* its
spin loop before returning. The QMI window restore is checked the same way
as the Non-secure port's.

Core 1 is a thread here -- not the real thing, no XIP and no second
instruction stream, but it exercises the handshake as two independent
parties, which a single-threaded stub cannot.

**Two harness bugs, both shaped like the firmware bug they were testing
for.** Stopping the simulated core 1 between tests hung the suite, because
`CORE1_RUNNING` never goes back to false and a thread that has exited
never acknowledges -- precisely the deadlock the guard exists to avoid.
And the boot-time case shared a process with the others, so it depended on
test ordering. One long-lived core 1 and a separate binary fixed both.

`cortex_m` is now shimmed for the host (`cortexmsim`), modelling the
interrupt mask for real -- `flash.rs` restores the caller's state, and a
caller already inside a critical section must stay masked -- and counting
`sev`, since a missing one on silicon means core 1 sleeps through a park
request while core 0 spins.

One firmware change, the same one already applied to the Non-secure
`ramfunc.rs`: `.data.ramfunc` gated to the board targets. Both TrustZone
images still build.

### The user-presence gate

18 checks on `wait_for_up` -- the security boundary of the whole device.
Every registration and every assertion passes through it, and its job is
to be certain a human touched the token *for this operation*. It had
never been tested: on hardware it is exercised by a finger, which cannot
check the cases that matter.

**The one worth having:** a single continuous hold must not satisfy two
operations. The loop tracks `saw_release` precisely so a finger left on
the pad cannot authorise a second ceremony the user never agreed to --
which is how a hostile page would get a signature out of one touch. That
is now a test, along with its complement: releasing and pressing again
*is* accepted, or the token would need a replug between operations.

Also pinned: a brush shorter than `PQF_UP_HOLD_US` is not consent, and
the boundary is probed from both sides -- just under is refused, just over
is accepted -- so the threshold is shown to be applied rather than the
press merely noticed. An untouched token times out rather than hanging
until unplugged. KEEPALIVEs are paced, checked at both ends: too few and
the host gives up, one per loop iteration and it floods the endpoint (20
in a second, which is right). And the LED, which is the entire
user-facing signal that a touch is wanted -- rapid blink is the *only*
blinking pattern in the model, since idle and busy are both solid -- is
checked to blink while waiting, end solid on confirm (the multi-second
signature that follows would otherwise look like a dead token), and end
off on timeout.

The clock and the button are both driven by the test
(`test/pico/time.h`), so a timeout takes microseconds instead of ten
seconds. `wait_for_up` is static and is reached the way the firmware
reaches it -- through the `ctap2_user_presence_hook` that
`fido_hid_install_tick` installs.

**One harness bug worth naming**, because it produced a plausible-looking
failure: the scripted button transitions were re-evaluated on every poll
rather than fired once, so whichever was checked last won forever. A
legitimate release-then-press read as a refusal. Test-scripting bugs that
mimic real defects are the expensive kind.

### USB descriptors -- the bytes read before anything works

400 checks across four build configurations (81 base, 115 with the GDB
stub, 85 with DFU runtime, 119 with both). Nothing had ever looked at
them.

Descriptors are the first thing that happens on every plug-in, and the
one part of the firmware where a mistake is **silent**: an inconsistent
descriptor does not crash, it makes the device enumerate wrongly, or not
at all, or work on one host and not another. The gadget plan noted iOS is
intolerant of malformed composite descriptors; so is Windows, differently.

They are built from TinyUSB macros with a hand-written
`CONFIG_TOTAL_LEN` and hand-assigned interface and endpoint numbers,
which is exactly the arrangement that drifts -- add an interface, forget
the total, and the host reads a truncated configuration. So the suite
**walks the real emitted bytes** rather than re-deriving what they ought
to be, and runs against every combination of the optional interfaces,
because that is where the total would drift.

What it checks: the descriptors sum to exactly `wTotalLength`;
`bNumInterfaces` matches how many are actually present *and*
`ITF_NUM_TOTAL`; interface numbers run 0..n-1 with no gaps or repeats,
since the host indexes rather than searches; no endpoint address is used
twice (two functions sharing one enumerates fine and then misroutes);
endpoint 0 never appears in a configuration; `bMaxPower` is inside the
bus budget. The HID interface declares a report-descriptor length equal
to the array it will actually hand over. And the report descriptor
declares **usage page 0xF1D0, usage 0x01** -- how every host, and this
project's own `enumerate()`, picks the token out of a bus full of HID.
Get that wrong and the device is invisible to every client.

Strings are checked to resolve: every index the device and interface
descriptors name exists, index 0 is a well-formed en-US language list,
and an index past the table returns NULL rather than reading off the end
-- that number comes from the host. The per-boot serial randomisation is
checked to actually change and to stay a well-formed string descriptor.

`test/host_tusb_config.h` mirrors `../tusb_config.h` and differs in one
line: `OPT_OS_NONE` instead of `OPT_OS_PICO`, because the Pico OSAL pulls
in the whole SDK. Everything the descriptor macros compute lengths from
is copied exactly -- change one without the other and the test would be
validating a descriptor the firmware never emits.

### The flash-op guard

10 checks on `flash_op_locked`, which wraps every flash write the token
makes. Two jobs, and both have cost real time on silicon.

It parks core 1 in RAM **before** suspending XIP, because a core still
fetching its idle loop from flash during an erase faults. And it
snapshots the QMI window-0 read configuration around the operation,
because the boot ROM's `flash_enter_cmd_xip()` leaves XIP in slow
single-bit 03h serial mode on the way out, discarding the fast quad
setup boot stage 2 installed. A signature-counter write precedes every
signature, so without putting it back every post-write instruction fetch
pays -- 1327 cycles per 8-byte cache line, which turned a ~1.3 s
ML-DSA-65 signature into ~13 s. pico-sdk has the same gap on RP2350.

**That restore is now a regression test.** The simulated `op` does
exactly what the ROM does -- drops the window back to slow serial -- and
the suite checks all three registers come back, that the restore is
unconditional rather than "only if it changed" (there is no way to tell
from outside whether the ROM touched it), and that it happens on every
call. A restore skipped on the second back-to-back write would present
as a signature that is fast once and slow afterwards, which is exactly
how the original bug looked.

The park handshake is checked for **order**, which is the safety
property: the trace must show core 1 acknowledging before the op runs,
and leaving its spin loop after. Core 1 is simulated as cooperative, so
this says nothing about the dual-core race itself -- only about the
sequence, which is where the bug was. Interrupt masking is checked both
ways, including that a caller already inside its own critical section
stays masked, which is why the mask is saved rather than simply cleared.

One firmware change was needed and it is the same one `signer-core`
already carries: `#[link_section = ".data.ramfunc"]` is now
`#[cfg_attr(any(target_arch = "arm", target_arch = "riscv32"), ...)]`.
Identical on both board targets; omitted off-target, because that is not
a section name a host linker accepts.

### Two modules that are not host-testable, and why

Worth writing down so nobody re-derives it:

- **`core1_launch.rs` (255).** Looks free -- but both public entry points
  are `#[cfg(target_arch = "riscv32")]` / `#[cfg(target_arch = "arm")]`,
  and the handshake they share is private. On the host the file compiles
  to nothing. Reaching it would mean relaxing cfg gates or adding a test
  hook to firmware, which is a worse trade than leaving it to silicon.
- **`arch.rs` (12).** A `pub use` of `pqf_signer_core::arch`. There is
  nothing there to test that `signer-core`'s own checks do not already
  cover; a test would assert that a re-export re-exports.

### U2F, and the core-1 sign arena

**U2F (24 checks, feature-gated).** Off by default, and it has form: the
command was once *structurally unreachable* -- the CTAPHID dispatch
refused `CMD_MSG` while getInfo advertised `NMSG` unconditionally, so
building the feature linked a hardcoded attestation key and nothing
else. That is the kind of thing a test finds and a demo does not.

It is an ISO 7816 APDU surface, not CBOR, and the only one here with no
PIN and no CTAP2 error codes. Covered: the envelope (CLA, unknown INS,
truncated APDUs, an `Lc` that disagrees with the body at seven values,
and that every response ends in a status word with no payload left
behind after a failure); registration shape and its 64-byte request;
handle binding -- a handle must not authenticate under another
application id, which is U2F's cross-site bypass; a tampered handle
refused at four bit positions; `check-only` reporting ownership the way
the spec spells it (`0x6985` for a handle we own, which reads backwards
and which a device answering `0x9000` would make every browser skip the
ceremony over); and the counter strictly increasing.

`tools/host-tests.sh` runs it with `--features u2f` explicitly. Without that
the file compiles to nothing and the runner prints a cheerful `ok`
having run zero tests.

**One deviation recorded.** The user-presence byte is returned as `0x01`
unconditionally, including for the `0x08` "don't enforce presence" mode
where by construction nobody touched anything. That is deliberate and
commented in the firmware -- some clients do not tolerate the spec's
`0x00`, legacy YubiKey firmware included. The blast radius is small and
worth stating: `0x08` is only reached when the *host* asked for a silent
signature, so the party told "a human was present" is the same party
that asked for no human. It is still a security-relevant field carrying
a value that is not true.

**The core-1 sign arena (35 checks).** `core1_arena.c` is small and does
one thing -- route allocation to one of two allocators -- but it exists
because the two cores sharing one produced both an out-of-memory wedge
at ML-DSA-87 and a core-0/core-1 malloc race, and it has a history of
biting.

The rule worth a test is subtle: **allocation routes by core, but free
and realloc route by pointer**, because a block can be allocated on one
core and released on the other. Getting that backwards hands an arena
pointer to newlib's `free`, or a newlib pointer to the arena's -- heap
corruption either way, surfacing somewhere else entirely. Both
directions are checked, for `free` and for `realloc`, with contents
verified intact across a grow.

Also: a reset reclaims the *whole* arena (measured by exhausting it
twice and comparing, since a reset that reclaimed most of it would make
the second signature of a session fail while the first worked -- a
miserable intermittent); an oversized request fails cleanly and is
recorded rather than panicking on a core with no debugger attached; and
the high-water mark follows allocations and never falls back, since that
is the number the arena is sized from on silicon.

The test infers arena membership from what the allocator hands out
rather than reusing the firmware's own range check, so the two are not
the same code agreeing with itself. `hardware/structs/sio.h` is a
two-line shim giving the test a settable `cpuid` -- the only hardware
`core1_arena.c` reads.

### The C port's CTAP-HID transport, and what mirroring found

117 checks. `c/firmware/src/ctaphid.c` was 564 lines with no host
coverage at all -- at the time the largest untested file in either port,
and the layer every byte from the host passes through before anything
else looks at it, reachable by anything that can send USB frames.
(That title now belongs to `c/firmware/src/flash_store.c`, 529 lines,
which the C test harness replaces wholesale with a 124-line RAM stub --
so the real QSPI store is not merely untested but never compiled on the
host. The Rust equivalent has 17 tests against a simulated die.) The Rust port's
suite already existed; this mirrors it, which was the point. **Two
independent implementations of one wire format should agree, and where
they do not, one of them is wrong.** They disagreed in four places.

Two seams were needed: `PQF_CTAPHID_HOST` already existed but froze the
clock at zero, which made the reassembly timeout unreachable -- it now
calls a clock the test drives, so a stalled transaction can actually be
timed out. `pqf_board_reboot` is recorded rather than performed, which
makes `CMD_REBOOT`'s mode validation testable.

**Two bugs in the C port.** It served CID 0 and it served non-INIT
commands on the broadcast channel. sec. 11.2.3: "Channel ID 0 is reserved and
0xffffffff is reserved for broadcast commands, i.e. at the time of
channel allocation." Both are shared by every host that has not yet been
allocated a channel, so serving anything but INIT there runs a
transaction on a channel with no owner: two hosts interleave with no
arbitration, and a response goes to whoever else is listening. A
credential assertion could have been answered onto a channel a second
process was also using. Now `CTAP1_ERR_INVALID_CHANNEL`, matching the
Rust port.

**Two bugs in the Rust port**, both about spurious continuations.
sec. 11.2.5.4 is specific: "Spurious continuation packets appearing without a
prior initialization packet will be ignored." The Rust port answered
`ERR_INVALID_SEQ` when nothing was in flight, and answered
`ERR_CHANNEL_BUSY` to a continuation from another channel -- because its
arbitration check ran over all frames, not just the init frames that
start a transaction. Arbitration is now narrowed to init frames, and the
continuation path takes the reassembly slot only after checking whose it
is.

**A correction.** The Rust suite's note used to say the spurious-
continuation behaviour was "a deliberate deviation... both ports answer
ERR_INVALID_SEQ". That was wrong about the C port, which ignored them
correctly all along. Writing the mirror is what surfaced it; a claim
about the other port that nothing checks is just an assumption with a
comment around it.

**And a claim of mine that did not survive.** Working through this I
asserted the Rust `take()` let any host drop another channel's in-flight
message with one frame. It did not -- arbitration caught it first, and
the test now checks that property directly rather than the bug I thought
I had found. The restructured code keeps the guard anyway, so reordering
the two checks cannot reintroduce it.

### The three unreachable commands -- fixed

`credMgmt`, `largeBlobs` and `authnrCfg` were all advertised in getInfo
and could not be driven by any conformant client. Three phases turned
them up one at a time; they are one bug, and they landed together.

**What was wrong.** CTAP 2.1 sec. 6.8 and sec. 6.11 number the parameters
`subCommand` 0x01, `subCommandParams` 0x02, **`pinUvAuthProtocol` 0x03**
(unsigned) and **`pinUvAuthParam` 0x04** (byte string). Both firmware
ports had the last two swapped, in both commands. Because the data types
differ as well as the keys, a conformant request matched neither arm:
protocol and param both stayed absent and every subcommand answered
`CTAP2_ERR_PUAT_REQUIRED`. sec. 6.10 numbers largeBlobs `get` 0x01, `set`
0x02, `offset` 0x03; both ports had those three rotated by one, and
wrote the pinUvAuth prefix as `0x0c 0x02` where the spec has `h'0c00'`
-- a literal zero, not the `set` parameter's key.

**Why nothing caught it.** Four in-house implementations agreed with
each other. Both firmware ports, the client library's C and Rust request
builders -- whose header cites `large_blobs.rs` *by line number* -- and
a software authenticator from the same client library, which carried the
same swap in its own credential-management parser. Every test on every
side passed. Two in-house implementations agreeing is not evidence of
conformance when one was written from the other; four is not either.

**The fix**, in one change across firmware and client: the parsers in
`crates/firmware/src/{large_blobs,credential_management,authenticator_config}.rs`
and `c/firmware/src/` equivalents, the client library's C and Rust
request builders for largeBlobs, credential management and config, the
software authenticator's parser, and every test on both sides. The client
field order was re-sorted too, since renumbering `get`/`set`/`offset`
would otherwise have left the map keys descending.

The three tests that recorded the deviations are kept rather than
deleted, flipped to assert the conformant request now *works*. Each
builds the exact byte shape a browser sends, by hand rather than through
the shared helper, so they stay a check on the wire format even if the
helper changes.

**Silicon-validated 2026-08-31, both ports, on a Feitian RP2350.**

Every ML-DSA level, both ports -- six configurations:

| level | C port | Rust port |
|---|---|---|
| ML-DSA-44 (`-51`) | 76 passed, 0 failed | 77 passed, 0 failed |
| ML-DSA-65 (`-52`) | 76 passed, 0 failed | 77 passed, 0 failed |
| ML-DSA-87 (`-53`) | 76 passed, 0 failed | 76 passed, 0 failed |

plus `--extra --dangerous` at 84/0 on both ports and `pqc_roundtrip` OK
on both (3380 B and 3379 B signatures). The composite named by `--alg`
was verified against real ML-DSA signatures in every one of the six.

**Why all six and not just the one that shipped.** The parsers do not
vary by ML-DSA level, so a single level "obviously" covers the rest --
and *reasoning from inspection is exactly what produced this bug*. Four
in-house implementations agreed with each other for months on the
strength of the same kind of argument. Running it was twenty minutes.

**The part that matters most was measured on a presence-enforcing
build.** The first pass ran against `PQF_REBOOT_NO_UP` -- FIDO user
presence fully enforced, only `CMD_REBOOT` ungated -- and on that image,
with nobody touching the button:

- `largeBlobs` went 8/8 including both read-backs;
- `authenticatorConfig setMinPINLength` passed;
- `getCredsMetadata`, `enumerateRPsBegin` and
  `enumerateCredentialsBegin` all passed.

None of those need a gesture, so all three corrected commands are
validated under the configuration that ships. Every remaining failure on
that run was `CTAP2_ERR_OPERATION_DENIED` on `MakeCredential` -- the
presence gate doing its job with no finger on it -- which left no
credentials for the enumeration checks to find. A second pass with
`PQF_TEST_NO_USER_BUTTON` populated them and took both ports to zero
failures. **That second build proves nothing about presence and is not
offered as doing so**; it exists only to get credentials into the store
unattended.

`tools/validate-wire-format.sh c|rust` is that run, packaged. It also
refuses to flash a board whose `picotool info` program name is not this
project's firmware -- not a theoretical guard: when a board finally
appeared in BOOTSEL it was a board from an unrelated project that
happened to be on the same host, and the script as first written would
have erased it.

### A trap worth naming: the default build did not rebuild the suite

The first silicon run reported `largeBlobs write succeeds` **passing**
and `read-back matches` **failing** -- which reads exactly like a
half-working fix, and is the most misleading shape a result can take.

It was a stale binary. The client library's top-level `make` builds the
static library and answers "Nothing to be done"; the conformance suite
binary has its own rule and is not in the default target. The binary on
disk was five days old and still spoke the *old* numbering, so against
corrected firmware its reads returned zero bytes and "succeeded".

Rebuild the suite binary explicitly and check its timestamp before
believing a result. Deleting its three `.o` files was not enough either;
the top-level target does not reach them.

### The stale binary was the experiment

The run above is also, by accident, the before/after comparison -- read
in the mirror.

That first pass drove a **spec-numbered firmware with an old-numbered
client**. The incompatibility it exposed is the same one a conformant
browser would have hit against the old firmware, because incompatibility
is symmetric:

| | old client vs new firmware (measured) |
|---|---|
| largeBlobs read | "succeeds", returns zero bytes |
| `setMinPINLength` | `CTAP2_ERR_MISSING_PARAMETER` |
| credential enumeration | `totalRPs=0` |

That is the failure signature the fix was predicted to remove, observed
on hardware. It was mistaken for a build annoyance at the time; it is
the strongest single piece of evidence in this section.

**What a browser would still add, and what it would not.** Real-browser
WebAuthn was confirmed by the author on 2026-08-17 and covers
registration and login -- and nothing in these corrections touches those
paths: the three renumbered commands play no part in a ceremony, and the
allowList fix only changes behaviour for entries that do not parse as
credential descriptors, which a browser never sends. The one path still
unwitnessed by a browser is passkey *management*, which was unreachable
before the fix and so could not have been covered by that run either.
`tools/browser/largeblob-check.html` drives it if anyone wants it.

**Closed 2026-09-01: the author reports passkey management working
correctly.** Recorded as a confirmation by hand rather than as a test run
here, which is the honest provenance -- but it is the same kind of
evidence the registration/login confirmation rests on, and it is no
longer an open item.

**Confirmed by the author on 2026-08-31**, on the fixed firmware,
against their own live site: real-browser WebAuthn works. That is the
after-side check item 2 asked for, made the way it counts -- a real
relying party, a real browser, a real token -- rather than a test page.

Taken with the before-side evidence above (old numbering against new
firmware reproducing the predicted failure signature on hardware), the
wire-format corrections are confirmed from both directions by a client
that was not written from this firmware. Item 2 is closed.

### A fail-open in credential selection -- fixed

CTAP 2.1 sec. 6.2 branches on the *parameter*: "If the allowList parameter
is present and is non-empty, locate all denoted credentials... If an
allowList is not present, locate all discoverable credentials", and an
empty result is `CTAP2_ERR_NO_CREDENTIALS`.

The Rust port branched on the *parsed list*. `filter_map` dropped every
entry that was not a map carrying a byte-string `id`, and the emptiness
test then read a present allowList as an absent one -- so the token
answered with whichever discoverable credential it held for that rpId,
not the one the relying party named. On a token holding passkeys for two
accounts at one site, that silently switched which account
authenticated. A conforming server catches it by checking the returned
credential id, so it was never automatically exploitable, but the whole
safety net was on the server.

The C port was already correct and was the reference. The fix separates
presence from parse success. The test that recorded the fallback is
flipped, and a new one guards the case that must *not* change: a
present-but-empty allowList still finds discoverable credentials, which
is what a browser sends for a passwordless login.

### Two small deviations found in phase 4

Neither is a security issue -- the refusal happens either way. Both are
conformance, and both are recorded as tests that flip when fixed.

**Zero permissions answers the wrong code.** CTAP 2.1 sec. 6.5.5.7: "if the
authenticator receives a permissions parameter with value 0, return
CTAP1_ERR_INVALID_PARAMETER" (0x02). This answers 0x14, the code for a
parameter that was never sent -- so a platform cannot tell "you sent
nothing" from "you sent zero". A one-line fix. (The *absent* case is
correct at 0x14, and is now its own test.)

**An undefined permission bit is refused rather than ignored.** sec. 6.5.5.7:
"Undefined permissions present in the permissions parameter are ignored"
-- a platform naming a bit from a later revision should still get a token
for the bits this device understands. This refuses the whole request. The
direction is the safe one and it is deliberate (the `SUPPORTED_PERMS`
comment says the check is against the full u64 so a high bit cannot be
dropped by the u8 narrowing), but it turns a future permission bit into a
hard failure rather than a degraded one, and that interop cost grows with
the spec.

### A deviation found in phase 3 -- a malformed allowList falls back

CTAP 2.1 sec. 6.2 branches on the *parameter*: "If the allowList parameter is
present and is non-empty, locate all denoted credentials... If an
allowList is not present, locate all discoverable credentials", and an
empty applicable list is `CTAP2_ERR_NO_CREDENTIALS`.

**The Rust port branches on the parsed list instead.** `filter_map`
silently drops every entry that is not a map carrying a byte-string `id`
(`ctap2.rs:2547`), and `if !allow_list_ids.is_empty()` then reads a
present allowList as an absent one -- so the token answers with whichever
discoverable credential it holds for that rpId, which is not the
credential the relying party named.

On a token holding passkeys for two accounts at one RP, that silently
switches which account authenticates. A conforming server checks the
returned credential id against the user it asked for, so this is not
automatically exploitable -- but the entire safety net is on the server,
and the token is choosing a credential nobody asked for. It is a
fail-open in credential selection.

**The C port does not do this.** `have_allow` there is
`pqfido_cbor_is_array(allow) && pqfido_cbor_array_size(allow) > 0`
(`c/firmware/src/ctap2.c:1087`) -- branching on the raw CBOR, exactly as
the spec says. So the correct behaviour already exists in this repo, in
the sibling port, which is what makes the fix obvious and small.

Recorded as two tests: one for the half that holds (with nothing
discoverable, a malformed allowList correctly misses, and none of five
shapes panics) and one that pins the fallback and fails once it is fixed.

### A deliberate deviation -- the composite outranks the RP's first choice

Not a bug; a product decision that nothing had written down.

CTAP 2.1 sec. 6.1 says the authenticator "chooses the first occurrence of an
algorithm identifier supported by this authenticator", and
`pubKeyCredParams` is "ordered from most preferred to least preferred".
This device scans for its composite first whatever position it holds, and
only falls back to ES256 when no composite is offered -- the `is_pqc` pass
in `ctap2.rs:1876`.

So an RP that sends `[ES256, composite]` meaning "ES256 please, composite
if you must" gets the composite. That is the point of the product, but it
does override a stated preference, and it is the kind of thing a
conformance run reports without explaining. Now it is a test with the
reasoning attached.

### A deviation found on the way -- largeBlobs

**Since fixed** -- see "The three unreachable commands" above, which this
was the first sighting of. Kept because how it was found is the reusable
part.

CTAP 2.1 sec. 6.10.2 numbers the `authenticatorLargeBlobs` parameters
`get`=0x01, `set`=0x02, `offset`=0x03. Both firmware ports numbered them
`offset`=0x01, `get`=0x02, `set`=0x03 -- the same three keys rotated --
and wrote the pinUvAuth prefix as `0x0c 0x02` where the spec has
`h'0c00'`.

The in-tree client matched the firmware; its largeBlobs request builder
cites `large_blobs.rs` by line number in its header. So every test on both
sides passed while no conformant platform could read the array at all: a
browser sending `{get: 17, offset: 0}` was parsed as `{offset: 17}` with
no `get`, and answered `CTAP2_ERR_MISSING_PARAMETER`. getInfo advertised
`largeBlobs: true` throughout.

It was found the same way as the composite-algorithm gap: **by asking
what a stranger would send, rather than what our own client sends.**
That is the whole method, and it turned up two more instances of the
same bug in later phases.

### CTAPHID framing, and the flash store

The same harness reaches two more modules.

**CTAPHID (23 checks).** This is the layer every byte from the host
passes through before anything else looks at it, reachable by anyone who
can send USB frames -- no PIN, no presence, nothing. The conformance suite
touches it only as a side effect of doing real CTAP2 work, so the malformed and
hostile cases had never been covered: out-of-order continuations, a
declared length past the maximum, a message of exactly the maximum,
channel arbitration, and a stalled reassembly timing out and freeing the
slot rather than wedging the device with one frame.

Two of those tests record **deliberate deviations from the spec**, found
by writing the strict expectation first and then checking both ports:

- A stray continuation with nothing in flight draws `ERR_INVALID_SEQ`.
  CTAP HID sec. 11.2.5 says such packets "will be ignored". Both ports
  answer, so it is a shared choice rather than a slip in one.
- A CID the authenticator never issued is honoured. Neither port tracks
  allocation -- the C port has no `ERR_INVALID_CHANNEL` path at all. The
  simplification is cheap here because arbitration is by the *active*
  CID and there is one transaction slot, and it buys something: a client
  that remembers its CID across a device reboot keeps working, which on
  a token that reboots this often is the common case.

Both are pinned as the behaviour that ships, so neither gets "fixed" by
someone reading only the spec.

**The flash store (17 checks).** Three sectors -- credentials, the device
master keys, the largeBlob array -- against the same simulated NOR die the
Secure world uses. The master keys are the root of everything: every
credential id is sealed under them, so corrupting that sector orphans
every passkey on the token. Checked: erased flash is never read back as
a valid key sector or image; a rewrite replaces rather than ANDing (NOR
can only clear bits, so writing over a live sector without erasing gives
a key that is neither old nor new); every slot the layout claims is
usable; and the three sectors do not disturb each other, which matters
because they are adjacent and each is written with a sector erase.

**A discrepancy that surfaced doing it.** The simulated die had to grow
from 2 MiB to 4 MiB, because the non-TrustZone Rust firmware puts its
credential store at `4 MiB - 4096`. The Feitian's die is 2 MiB -- that
was the root cause of the DFU work, "a 2 MiB die addressed as 4 MiB" --
so on real hardware those offsets alias down by wrapping. It works, and
it is not obviously intended. The C port derives its offset from
`PICO_FLASH_SIZE_BYTES` rather than hard-coding one.

### The Secure world, against a simulated die

`crates/fw-secure-hosttest` -- 84 checks, no board.

`fw-secure` is 5328 lines holding the credential store, the monotonic
counter, the PIN retry logic and the key store, and it had **no tests at
all**. It cannot have any directly: it is a bin crate for
`thumbv8m.main-none-eabihf` with `cmse_nonsecure_entry` veneers, its own
linker script and its own lockfile, so `cargo test` can never reach it.

The seam turned out to be narrow. `credstore.rs` and `counter.rs` touch
the machine in exactly two places -- `crate::flash::flash_op` and six
`rom_data` calls -- and read flash through a single pointer helper. So the
real source files are pulled in by `#[path]`, `flash_op` becomes "run the
closure", and `rom_data` becomes a simulated die. One `#[cfg]` seam per
module points the XIP window at the simulator instead of `0x10000000`;
the board build is unchanged and still links.

The simulator models NOR semantics properly -- **a program may only clear
bits, never set them** -- because the store's invalidate-without-erasing
scheme rests on exactly that. It also counts erases and programs, so a
design that claims to avoid them can be held to it.

**It immediately contradicted two things this repo had written down**,
both of which had been asserted from a single hardware observation rather
than measured:

- The compaction work said one sector is "always kept blank as a spare,
  so usable capacity is 56, not 64". Measured: distinct credentials fill
  **all 64 slots** and the store refuses on the 65th. Compaction stays
  reachable because dead records free slots *within* sectors, not because
  a sector is held in reserve.
- The lazy-counter work recorded "+2 across three reboots" from silicon.
  The harness reproduces that exact scenario -- one signature, three
  reboots, one signature -- and measures **1 then 66**. Either that run
  was measuring something other than the raw counter or its arithmetic
  was wrong. The real improvement is 192 down to 65, plus idle reboots
  that write nothing at all, which the harness also pins.

Neither is a behaviour change. Both are cases where a hardware run
established *that* something worked and was then written up as *how*.

**The PIN store and key store came out clean**, which is worth saying as
plainly as the failures. Fourteen of the 31 checks cover the retry
budget, and it holds under every attack the harness can model: the spent
count is on the die before `put` returns, so pulling power after a wrong
guess does not refund it; a reboot does not restore it; it saturates at
zero rather than wrapping to 255; a correct PIN resets it; and an erase
of one ping-pong sector never takes the only copy of it. The key store
refuses to hand back erased flash as a master key, and two successive
stores yield one of the two values rather than a bitwise AND of both --
which is what programming over live NOR would give.

None of that was previously tested at all. The conformance suite exercises
the happy path and a single wrong PIN end-to-end; it cannot reach the eighth
attempt, and it certainly cannot pull power between the comparison and
the write.

### What the other four modules cover

The same `#[path]` trick reaches the rest of the Secure world, and only
`upgate` needed a new seam -- its microsecond clock, which is a settable
counter on the host so a test can sit exactly on a boundary instead of
waiting and hoping.

**The presence gate (13 checks).** A held button does not confirm: the
rule is release-then-press, so anything resting on the pad -- a case, a
pocket -- cannot authorise operations with nobody there. A confirmation
is spendable exactly once. Opening a window discards an earlier
confirmation, so a caller cannot bank a touch and spend it on an
operation the user never saw. A timed-out window stays timed out. The
window boundary is where it says it is: open at exactly `WINDOW_US`,
closed one microsecond later. And the injected test gesture is a
one-shot, so a harness cannot arm it once and have every later window
confirm itself.

None of that supersedes the real press on silicon, which stays the only
evidence that the sampler can see a finger.

**The CBOR writer and response builders (18 checks).** Everything the
Non-secure world sees is encoded here, and a malformed byte is a client
that rejects the response rather than anything that looks like a crash.
Shortest-form integers at every boundary, negative integers as major
type 1 -- the COSE ids are all negative, and `-55` has to be `0x38 0x36`
or every relying party sees the wrong algorithm -- definite-length
containers, and the overflow contract: once the buffer is full every
later write is a no-op, so a caller can write a whole structure and
check once at the end. `getInfo` refuses a buffer it cannot fill rather
than emitting a prefix, which would be a token that appears to support
nothing.

**The ClientPIN protocol (22 checks).** The tests play the client's half
for real -- P-256 key agreement against the token's own point, AES-256-CBC
with a zero IV, HMAC-SHA-256 -- because faking any of it would prove only
that the token agrees with itself. A corrupt `pinUvAuthParam` is
refused, an off-curve key-agreement point is refused, a ciphertext that
is not a whole number of blocks is refused, a PIN under four code points
or not valid UTF-8 is refused, and a second client's key agreement
cannot verify the first's ciphertext.

The interesting part is the **two independent limits**, which is where
the tests originally got it wrong. Three consecutive failures inside one
boot soft-block the PIN -- and because the counter is incremented before
it is tested, the third failure is both counted and refused, so there
are two plain invalid-PIN answers, not three. While soft-blocked the
token refuses even the correct PIN, and refuses without spending further
lifetime retries. A power cycle clears the soft block but not the
budget: rebooting buys three more tries, not a fresh eight. Guess three,
power-cycle, repeat, and the eight-attempt budget still runs out and
blocks for good.

### Two crates that could not be tested at all

`pqf-signer-core` **did not compile for the host**. `arch.rs` had an Arm
arm and a RISC-V arm and no fallback, so `irq_save_disable` returned an
uninitialised binding on any other target (E0381), and two functions
carried `#[link_section = ".data.ramfunc"]` -- an ELF section name, which
Mach-O rejects outright. Both are now conditional on the two real
targets. RAM residency is unaffected and still checked: `nm` puts
`pqf_signer_park_spin` and `pqf_signer_idle_wait` at `0x2000xxxx` on
both Arm and RISC-V builds.

`pqf-gdbstub-core` had **no tests**, while the C port's stub has had 73
host checks since the GDB stub was written. The engine is the half its own manifest calls
the place the bugs live. It now has 47, with the same section headings
as `test_gdbstub.c` so the two can be read side by side.

### hidapi is confined to one thread

All `hidapi` use in `pqf-ctaphid` goes through a single worker thread
that owns the `HidApi` and every open `HidDevice`. Callers hold an opaque
handle and talk to it over a channel; nothing else in the tree touches
`hidapi`, and no `HidDevice` crosses a thread boundary.

That is not tidiness. `hidapi`'s macOS backend keeps CoreFoundation
state -- an `IOHIDManager` and its device cache -- behind the C library's
globals, and CF objects are not safe to touch from more than one thread.
Enumerating from two threads, *even strictly one after the other under a
mutex*, corrupted it and the process died inside
`__CFCheckCFInfoPACSignature` with `EXC_BREAKPOINT`: no panic, no
message, and every test that had already passed still printed as having
passed. Locking does not help, because the problem is thread affinity
rather than concurrency -- an earlier attempt that funnelled everything
through one long-lived `Mutex<HidApi>` crashed identically.

It mattered beyond the test suite. `pqf-pkcs11` accepts
`CKF_OS_LOCKING_OK` and documents itself as safe to call from multiple
threads; an application that listed slots from two of them took the
process down. Four of its tests had to be `#[ignore]`d to get a green
run. They are un-ignored now and pass in parallel, and
`crates/ctaphid-client/tests/thread_safety.rs` guards the regression
directly -- eight threads released together off one barrier, plus the
thread-per-unit-of-work shape the harness itself uses.

The cost is that concurrent `Device`s serialise on the worker. That is
what the platform requires, and it is the honest trade: before, they did
not serialise and the process died instead.

**A regression here does not fail politely.** It aborts the test binary,
so the symptom is a run that ends early with tests unaccounted for, not
a red line.

## 2026-10-11: a lost PIN blocks, and the release review's other findings

A final review before publication found the torn-write PIN reset that
SECURITY.md listed as a known gap still open, and four smaller things.
All five are fixed; host and silicon results below.

**A torn main-sector write no longer removes the PIN.** The master keys
survive any routine write in their own sector; the PIN did not, so a
power loss in the middle of a main-sector write booted a token with no
PIN while every credential id it had issued still decrypted, and anyone
holding it could set a PIN of their own and get user-verified
assertions. Now the first setPIN also programs one word in the key
sector's second page (program-only: no erase, and the keys' page is not
touched), and a token that boots with that word set and no PIN in its
store comes up PIN-blocked -- PIN set, 0 retries -- until
authenticatorReset erases the key sector and rotates the keys. A PIN set
by an older build is armed on the first boot. Both ports
(`flash_store::arm_pin` and `CredStore::load` in Rust, `arm_pin` and
`flash_store_init` in C). In the Rust port the review of this path found
a second way in: the main sector's header page was programmed in one
pass, and `read_sector` accepted it once the magic and version were
down, so a cut a few bytes further on left the PIN set with an erased
retry counter, which loads as the full count -- eight more guesses per
well-timed cut. The magic is now programmed alone, after the rest of
the header, so a cut anywhere before it is complete reads as no main
sector, which the PIN-armed word then turns into PIN-blocked. The C
port's store page is CRC-checked and never had that hole.

- `crates/firmware-hosttest/tests/pin_armed.rs`, 7 tests: arming leaves
  the keys' page byte for byte and programs nothing but its word; a lost
  main sector boots PIN-blocked, refuses the old PIN, a new setPIN and
  changePIN, and stays blocked across a routine write and a reboot;
  reset clears it, rotates the keys and lets a new PIN arm the word
  again; a wrong-PIN attempt (one main-sector write) is cut at every
  byte of the header-page passes and a sample of the slot pages, and the
  token always comes back with 7 retries or PIN-blocked, never PIN-less
  and never with 8; a setPIN cut anywhere leaves either no PIN and no
  word or a PIN that the next boot arms; a torn write on a token that
  never had a PIN is not blocked; a PIN from an older build is armed at
  boot. With the blocked branch removed, 3 of the 7 fail; with the
  header programmed in one pass again, 2 fail.
- `c/firmware/test/test_flash_store.c`, 4 new groups, 74 checks in the
  suite: arming erases nothing and is not repeated; a routine commit cut
  after every possible byte count (0 to 256) lands whole or boots
  PIN-blocked, never PIN-less, the keys untouched; a wipe clears the
  blocked state, rotates the keys and erases the word; no PIN means no
  block; an older build's PIN is armed at boot. With the blocked branch
  removed, 3 checks fail.
- On silicon, the Rust image on the Feitian RP2350 (2026-10-11,
  `RK_SECTORS=5 ./build.sh feitian_rp2350`, flashed after a full
  erase), every step:
  - setPIN, then the key sector read back in boot mode: the PIN-armed
    word is `00000000`, the rest of its page is erased, and the keys'
    page is unchanged;
  - a power cycle: the main sector's header (magic, version 12, the
    PIN hash, PIN set, 8 retries) reads back intact and the PIN is
    accepted, so the two-pass header with the magic last survives a
    power loss;
  - the main sector erased in boot mode, the state a torn write
    leaves: the token boots PIN-blocked -- `clientPin` true, 0
    retries, getPinToken `CTAP2_ERR_PIN_BLOCKED` (0x32), a new setPIN
    `CTAP2_ERR_PIN_AUTH_INVALID` (0x33);
  - authenticatorReset, confirmed with a press: no PIN, 8 retries; and
    after a power cycle the key sector holds new master keys and an
    erased PIN-armed word, and the token comes back with no PIN and 8
    retries, not blocked again.

  The C image's change is host-tested only.

**flash.sh's two bypasses are closed.** A board in BOOTSEL with no image
marker -- blank, or not from this tree, which is also what a blank USB-C
token looks like -- went straight to `picotool load`; it is now refused
until `--board <id>` names it, a USB-C id is refused, and the named board
must be the one the image was built for. On a board carrying a USB-C
image, only an image marked `pqf-reboot=no-touch` is accepted: an image
with no reboot marker, or one this script does not know, used to get
through. `tools/test-flash-guards.sh` (21 checks, run by
`tools/host-tests.sh`) drives `flash.sh` against a mock `picotool` and
checks the exit status and whether `load` ran, for the refusals and for
the ordinary flashes that must still go through; the previous `flash.sh`
fails 11 of them.

**The host verifier parses DER strictly.** `pqf_ctaphid::hybrid` read a
negative ASN.1 INTEGER as the unsigned scalar with the same bytes, so a
malformed signature still verified. It now uses the RustCrypto `ecdsa`
crate's own parser (`Signature::from_der`; the `pkcs8` feature of
`p256`, whose crates were already in `Cargo.lock`), as does the `bench`
example's copy. Five unit tests, now run by `tools/host-tests.sh`,
include the reviewer's case -- a valid signature with `r`'s `0x00` pad
removed -- for a plain and for a hybrid signature; the bench self-test
checks it too (34 checks).

**`tools/validate-wire-format.sh` finds the token over HID.** It waited
for `/dev/cu.usbmodem*`, which the Rust image never creates (no CDC
interface), and which an unrelated serial device would satisfy. It now
polls `c/hid/reboot --list`, which matches only this project's FIDO
device, both to find a running token and after flashing; and it runs
`PQF_CONFORMANCE_CMD` once, reporting the status of the output it shows.
Not re-run on silicon here.

**Documentation.** `tools/browser/README.md` no longer presents the
before/after browser comparison as runnable: its `before` image needs a
commit from the development history, which this single-commit
repository does not carry. The README opens with a compatibility
warning: the hybrid credentials use the draft's COSE ids but the OpenSK
construction (P-256 at every level, an EC2 key, the label-prefix
combiner), so a verifier written to the draft cannot check them.

## 2026-09-30: composite COSE ids relabelled to draft -04

**The change.** RFC 9864 (October 2025) assigned `-51` to ESP384, `-52`
to ESP512 and `-53` to Ed448 -- the three ids this firmware had been
emitting for its hybrid credentials, as requested in
draft-ietf-jose-pq-composite-sigs-02. Draft -04 (10 September 2026) now
requests `-54` / `-55` / `-56` for ML-DSA-44 / 65 / 87 with ECDSA, and
both ports emit those and nothing else:

| Level | Was | Now | CBOR was -> now | Defined in (Rust / C) |
| --- | --- | --- | --- | --- |
| ML-DSA-44 | `-51` | `-54` | `38 32` -> `38 35` | `COSE_ALG_MLDSA44_ES256`, `crates/signer-core/src/mldsa_alg.rs` / `c/firmware/src/hybrid.h` |
| ML-DSA-65 | `-52` | `-55` | `38 33` -> `38 36` | `COSE_ALG_MLDSA65_ES256`, same files |
| ML-DSA-87 | `-53` | `-56` | `38 34` -> `38 37` | `COSE_ALG_MLDSA87_ES384`, same files |

The ids are still provisional, so each port now defines each level once
and derives everything else from it: getInfo, the `pubKeyCredParams`
picker, label 3 of the credential COSE_Key, `attStmt.alg`, the
TrustZone Secure image (`crates/fw-secure/src/ctap.rs` takes its id
from `pqf-signer-core`), the Waveshare LCD's alg-list colouring, and the
host tests. The host client (`ALG_HYBRID_MLDSA44/65/87` in
`crates/ctaphid-client/src/ctap2/types.rs`), `tools/silicon-sweep.sh`,
`tools/validate-wire-format.sh` and `tools/browser/largeblob-check.html`
cannot link the firmware and keep one named copy each. What did not
change: the pure ML-DSA ids `-48/-49/-50`, ES256 / ESP256 `-7` / `-9`,
Ed25519 `-8`, the signed-message construction, the combiner, the
ML-DSA-87 + P-256 pairing, and every length -- each id is two CBOR bytes
before and after, and no size constant or `maxMsgSize` moved.

The COSE id is not stored anywhere: both ports derive it on decrypt
from the credential id's version byte and whether the ML-DSA seed slot
is zero, resident slots hold only the 161-byte id, and the Secure image
stores an internal algorithm byte. A credential registered before the
relabel keeps working and is reported as `-54/-55/-56`. `-51/-52/-53`
in `pubKeyCredParams` are now treated like any unsupported algorithm.

**Host results (all three levels, both ports):**

- `tools/host-tests.sh`: all passed (ML-DSA-65 default configuration;
  `Bruce logic (host)` 415 passed, `fw-secure storage` 247 passed).
- `pqf-firmware-hosttest` with `--no-default-features --features
  mldsa44` / `mldsa65` / `mldsa87`: 415 / 415 / 415 passed. New tests:
  the advertised list is exactly `-56, -55, -54, -7` (plus `-8` with
  `ed25519`) and contains none of `-48..-53`; each of `-51, -52, -53,
  -48, -49, -50` alone is refused with `CTAP2_ERR_UNSUPPORTED_ALGORITHM`
  (0x26), and in front of `-7` yields an ES256 credential attested `-7`;
  this build's own composite is labelled with its draft -04 id in the
  COSE_Key and, at 44 and 65, in `attStmt.alg` (87 attests `-7`).
- `pqf-fw-secure-hosttest` at 44 / 65 / 87: 246 + 1 failed / 247 / 247.
  The one failure at 44, `handle_cred_mgmt_can_carry_a_full_composite_public_key`,
  hard-codes a 1952-byte ML-DSA-65 key and fails identically on the
  commit before the relabel; `tools/host-tests.sh` runs this crate only
  at 65.
- C host suite (`make -C c/firmware/test test`, `CC="cc
  -DPQF_HYBRID_VARIANT=NN"`) at 44 / 65 / 87: 554 / 554 / 553 `ok:`
  lines from the CHECK-based binaries, every other binary reporting 0
  failures; `test_ctap2` gained the same getInfo and old-label checks as
  the Rust suite. At 44 `test_yield` reports 1 failure ("keygen yielded
  fewer than 50 times", 32 yields for ML-DSA-44), which also fails
  identically before the relabel.
- Wire parity: getInfo from both ports' host harnesses is 351 bytes
  before and after, differing in exactly three bytes (the three alg
  arguments, `0x34 0x33 0x32` -> `0x37 0x36 0x35`), and the `0x0a`
  algorithms array is byte-identical between the Rust and C ports. A
  hybrid MakeCredential's COSE_Key starts `a6 01 02 03 38 35|36|37 20 01
  21 58 20` in both ports, with the same `-3` / `-4` headers and lengths
  (1394 / 2034 / 2674 bytes at 44 / 65 / 87); ES256 responses are
  byte-identical before and after in the deterministic Rust harness.

**Builds:** Rust, every board x level x {Arm, RISC-V}, plus mixed
(`core1_riscv`), `ed25519` and TrustZone (fw-secure + fw-nonsecure) at
every level: 45 of 45. C Arm, every board x level: 18 of 18. C pure
RISC-V: no pico-sdk-supported riscv32 GCC was available; built with an
Espressif `riscv32-esp-elf` GCC 13.2 as a compile check only, 12 of 18
(44 and 65 on every board); 87 fails to link on every board with
undefined `__tls0_base` / `__tls1_base`, identically on the commit
before the relabel -- a toolchain mismatch, not this change. Those
RISC-V images are not for flashing.

**Hardware, Feitian RP2350 USB-A (2 MiB), 2026-09-30:**

- `bench -n 10`, Rust dual-core Arm,
  `mldsaNN,board_feitian_rp2350,test_no_user_button,reboot_no_up`,
  each image loaded after `picotool erase -a`. All rounds pass; `Algs`
  reads `-56, -55, -54, -7` on every image, and the credential ids come
  back as `alg -54` / `-55` / `-56`:

  | level | MakeCredential min / median / max | GetAssertion min / median / max |
  |---|---|---|
  | 44 | 0.69 / 0.78 / 1.14 s (4129-4131 B) | 0.46 / 0.62 / 0.79 s |
  | 65 | 0.97 / 1.27 / 2.39 s (5658-5659 B) | 0.69 / 1.27 / 2.16 s |
  | 87 | 0.44 / 0.45 / 0.47 s (2987-2989 B) | 1.00 / 1.06 / 2.22 s |

  The ML-DSA-87 response is 2987-2989 B, the same as on 2026-09-27
  under `-53`: `-53` and `-56` are both two CBOR bytes, so the dual
  attStmt this build declines to send is still 7617 B (with a 71-byte
  ECDSA DER), over the 7609-byte ceiling.
- C port, `feitian_rp2350`, ML-DSA-65
  (`PICO_XOSC_STARTUP_DELAY_MULTIPLIER=64`): `probe` lists
  `-56, -55, -54, -7`.
- A credential made before the relabel still works. The pre-relabel
  Rust ML-DSA-65 image (HEAD `242b86c`) registered a passkey in Chrome
  154 against the pre-relabel relying party (verified `alg=-52`). The
  new image was then loaded without an erase: PIN and passkey kept,
  and the login VERIFIED on the same server (both halves, 3379-byte
  signature, signCount 4). The relying party's CBOR viewer with its
  legacy-composite-ids switch, on that registration and the new image's
  login: "stored alg -52, read as -55, both halves: verifies", with
  the conformance suite's warning; without the switch the registration
  is refused.
- Chrome 154, the relabelled relying party, Auto (`-56, -55, -54, -7`): at 65,
  registration VERIFIED `alg=-55`, login by username and by passkey
  VERIFIED; at 44, registration `alg=-54` and login VERIFIED.
- Firefox, same server: with the build's id chosen alone, registration
  and login VERIFIED at 65 (`-55`, packed attestation, both halves). With
  Auto, Firefox registered **ES256** at 65 and at 44: the firmware picks
  its hybrid whenever it is offered, so Firefox removes `-56, -55, -54`
  from the list before it reaches the token when `-7` is also offered.
  Under `-52` Firefox had refused the key outright (it read `-52` as
  ESP512). A relying party that wants a hybrid credential from Firefox
  has to offer the one id.
- The token's discoverable store filled at six passkeys during this run
  (the Rust port's default capacity), which stopped the Firefox `-54`
  registration; see the next section.
- Chrome 154 at ML-DSA-87, Auto: registration VERIFIED `alg=-56`
  (ES256 attestation, as designed at 87), login VERIFIED with a
  4699-byte signature (ECDSA DER || ML-DSA-87). The image was the
  27-slot build of the next section, loaded without an erase over the
  default-layout store: PIN kept, and this was the token's seventh
  passkey. Firefox was not run at ML-DSA-87.

## 2026-09-30: configurable discoverable-credential capacity

What changed: the number of discoverable-credential (passkey) slots is a
build-time option in both ports, `PQF_RESIDENT_EXTRA_SECTORS=N` (Rust:
environment variable; C: CMake cache variable; both wrappers:
`RK_SECTORS=N`), 0..8, default 0. Each extra sector holds 7 more
passkeys below the master-key sector: Rust `6 + 7N`, C `7 + 7N`. The
main sectors, their header and `SECTOR_VERSION` are unchanged, so a
default build is today's layout byte for byte. Design and the
enlarge / shrink rules are in
[BUILD.md](BUILD.md#axis-7-optional-discoverable-credential-capacity);
the sector format in
[ARCHITECTURE.md](ARCHITECTURE.md#overflow-resident-credential-sectors).

**Host, Rust** (`crates/firmware-hosttest/tests/resident_capacity.rs`,
14 tests, run at `N = 0` and at `N = 3`; `tools/host-tests.sh` runs the
whole crate at both):

- Byte identity at the default: the main sector written from a fixed
  image, and the key / large-blob / main sectors after a PIN and six
  registrations through `CredStore`, hash to the SHA-256 values taken
  from the firmware **before** the option existed. The six-registration
  hash is the same at `N = 3`, and no overflow sector is written by six
  passkeys.
- Enlarging over a store a default build really wrote: the default run
  saves its die (PIN set, six passkeys, two of them used) under
  `target/tmp`; the `N = 3` run boots it, mints a token with the old
  PIN, finds all six with their counters, and adds a seventh to overflow
  sector 0 without rewriting the main sector.
- Filling all 27 slots: `getInfo 0x14` and `getCredsMetadata` count down
  to 0, the 28th account gets `CTAP2_ERR_KEY_STORE_FULL`, re-registering
  an existing account in the last sector replaces it in place, and after
  a reboot every sector's passkeys sign and credential management
  enumerates all 27 relying parties.
- A GetAssertion counter bump on an overflow slot is one erase, of that
  sector only; the counter persists across a reboot. Delete and
  `updateUserInformation` on overflow credentials persist and rewrite
  only their sector; the freed slot is reused.
- `authenticatorReset` erases every overflow sector. A sector left behind
  by a reset in a build that did not know about it (new keys, main
  sector wiped) reads as empty; a sector copied to another index is
  refused.
- Torn writes, with a power-loss model added to the simulated die
  (every program and erase after the cut is dropped): 13 tear points
  across the slot pass and the header pass. The torn sector reads as
  empty until every slot byte and the whole header are down, then as the
  complete new content; the main, key, large-blob and other overflow
  sectors never change, and the PIN and the main sector's passkeys
  survive. Changing the write order back to header-with-slots makes the
  tear at 1000 bytes fail, so the test detects the ordering. A torn
  main-sector write (a PIN change) leaves the overflow passkeys usable.
- The suite also passes at `N = 1`, `2` and `8`.

Result: `Bruce logic (host)` 429 passed at `N = 0` and 429 at
`N = 3` (415 before this change plus the 14 new tests).

**Host, C** (`c/firmware/test`): `test_resident_flash` runs the real
`resident_store.c` flash branch over the simulated die, built as
`-rk0` (6 checks: the primary sector hashes to the value taken before
the option, and the die is saved) and `-rk3` (95 checks: boots the
`-rk0` die with its PIN and seven passkeys, fills all 28, one sector per
mutation, counter / rename / delete persistence, wipe, the stale sector
after a foreign reset, the wrong index, and the same 13 tear points with
a whole-write power-loss model added to `host_flash_die.c`).
`test_resident`, `test_credmgmt`, `test_ctap2` and `test_config` are
also built with three overflow sectors (`-rk3`, 65 / 28 / 92 / 58
checks). The whole C suite additionally passed built with
`-DPQF_RESIDENT_EXTRA_SECTORS=3` throughout; `test_config` now checks
`getInfo 0x14` against the configured capacity (7 at the default).

`tools/host-tests.sh`: all host tests passed.

**Builds:**

- Rust, every board x {Arm, RISC-V} at ML-DSA-65, at `N = 0` and
  `N = 3`, plus Feitian at 44 and 87 on both instruction sets, mixed
  (`core1_riscv`), `single_core` on both instruction sets, and `N = 8`
  (Arm, RISC-V, mixed at 87): 41 of 41. The markers read
  `pqf-rk-slots=6` / `27` / `62`; the linker's `_reserved_flash_start`
  moves from `0x103FD000` to `0x103FA000` (`0x101FD000` to `0x101FA000`
  on the Feitian profiles, which bound FLASH to 2 MiB) at `N = 3`.
  `PQF_RESIDENT_EXTRA_SECTORS=9`, a non-number, and `N > 0` with
  `PQF_APP_OFFSET=1` are refused.
- C Arm, every board at 65 plus Feitian 44 and 87, at `N = 0` and
  `N = 3`, and Feitian 87 at `N = 8`: 17 of 17, markers `pqf-rk-slots=7`
  / `28` / `63`, reservation 16 / 28 / 48 KiB. C pure RISC-V, compile
  check only with the Espressif `riscv32-esp-elf` GCC 13.2 (no
  pico-sdk-supported riscv32 GCC here): every board at 65 plus Feitian
  44, at `N = 0` and `N = 3`, 14 of 14; level 87 not attempted (it does
  not link with this toolchain, see
  [the relabel section](#2026-09-30-composite-cose-ids-relabelled-to-draft--04)).
  `N > 0` with `PQF_BOOTLOADER=ON`, and `N = 9`, are refused at
  configure time.
- RAM: Rust holds the slots on the heap, 4,060 B per sector (the main
  loop's stack frame is unchanged at about 10 KiB); C adds about
  5.1 KiB of `.bss` per sector (Feitian 65: newlib heap 228 KiB at
  `N = 0`, 214 KiB at `N = 3`; 87: 301 / 286 / 261 KiB at `N = 0 / 3 /
  8`).

**On hardware, 2026-09-30.** The Rust ML-DSA-87 image with three
overflow sectors (`mldsa87,board_feitian_rp2350`, real presence button,
touch-gated reboot, `pqf-rk-slots=27`, sha256 `ed8ddb7c...`) was loaded
without an erase onto the Feitian RP2350 USB-A, whose default-layout
store held a PIN and six passkeys (the store was full). The PIN was kept
(`clientPin: true`), and Chrome 154 then registered a seventh passkey and
logged in with it (`alg=-56`, both halves verified). The Rust ML-DSA-44
image of the same build (`b8d87955...`) was not flashed. The C port's
option was tested on the host only.

## The first production USB-C token, 2026-10-02

The first sealed Feitian RP2350 USB-C token, flashed and used by the
procedure in [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token).
Until this run everything about the token's hardware was inherited from
the USB-A board and one USB-C sample; these are the first measurements
on a production token.

On arrival: blank, in boot mode by itself (no program; the first 4 KiB
of flash read `0xFF`), RP2350 in the QFN60 package, the same boot ROM
revision as the USB-A board, secure boot off, debug enabled, every OTP
boot-flag row at zero. `picotool` reports the flash as 2048 KiB once
something is in it (on a blank die it prints no size). The boot-mode
USB serial is the chip id. On macOS a new token first appears in
`ioreg` as `RP2350 Boot` with no interfaces, invisible to `picotool`
(`tools/flash-usbc.sh` says "no token found"), until the "Allow
accessory to connect?" prompt is accepted; later boots did not ask
again.

| Image | Rehearsal on the USB-A Feitian | `tools/flash-usbc.sh` on the token | The pad |
| --- | --- | --- | --- |
| Rust `./build.sh feitian_rp2350_usbc`, ML-DSA-65, 6 slots (sha256 `2b16b4fc...`) | PASS, then register and login with presses | PASS: up as FIDO in 4 s, boot mode with no touch in 2 s, back in 1 s | register and login through the pad, first attempt |
| The same with `RK_SECTORS=8` and a `USB_PRODUCT` name, ML-DSA-65, 62 slots (sha256 `79e34f58...`) | PASS, then register and login with presses | PASS | register and login through the pad, first attempt |

So the pad is on QSPI_SS and the shared sampler reads it: FIDO presence
works on the production token exactly as on the USB-A board's button,
and the reboot into boot mode needs no touch, as the profile promises.
The second image was left on the token (no PIN, no passkeys). The C
image was not flashed on this token.

Still not measured on a production token: whether the LED behaves as
the profile assumes (GP25, active-high), whether holding the pad while
plugging in does anything, and whether the SWD pads are reachable.
[FLASHING.md, what is not yet known](FLASHING.md#what-is-not-yet-known-about-this-token)
keeps the list.

## The USB-C token procedure, rehearsed on the USB-A Feitian, 2026-09-23

The `feitian_rp2350_usbc` profile and `tools/flash-usbc.sh`
([the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token)), run on the Feitian USB-A board --
the same RP2350A on the same reference design, whose button the
profile reads as the pad. No USB-C token was involved.

Images: Rust `./build.sh feitian_rp2350_usbc` (sha256 `b834d6df...`)
and C `./build-c.sh feitian_rp2350_usbc` (`f1fe3099...`), both marked
`pqf-board=feitian_rp2350_usbc`, `pqf-reboot=no-touch`,
`pqf-fido-up=touch`. The board started on a touch-gated Rust
`feitian_rp2350` image, so the first entry into boot mode took one
press; nothing after that did.

| Pass | Image | Token found as | Erase 2 MiB | Load + verify | Up as FIDO | Way back, no touch | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Rust | RP2350 in boot mode | ok | ok | 1 s, `Feitian USB-C PQC` | boot mode in 1 s, back in 1 s | PASS |
| 2 | C | running `Feitian USB-C PQC`, rebooted with no touch in 1 s | ok | ok | 1 s, `Bruce (C port)` | 1 s, 1 s | PASS |
| 3 | Rust | running `Bruce (C port)`, rebooted with no touch in 1 s | ok | ok | 1 s | 1 s, 2 s | PASS |
| 4 | Rust (the script after review fixes) | running `Feitian USB-C PQC`, no touch, 1 s | ok | ok | 1 s | 1 s, 1 s | PASS |

Passes 2 and 3 are the port switch that preceded the intermittent dark
device ([FLASHING.md](FLASHING.md#intermittent-dark-device-after-flashing-erase-first));
with the erase in front, both came up first time. After pass 4, `probe`
read a healthy `getInfo` (`FIDO_2_0`, `FIDO_2_1`, algorithms
`-53/-52/-51/-7`, `maxMsgSize` 7609) and `clientPin: false` -- the PIN
went with the erase, as documented.

`--check` refused both `feitian_rp2350` images (wrong board, and
`pqf-reboot=touch`) and every hand-made bad file (no markers, RISC-V,
mixed families, TrustZone Non-secure, a write past 2 MiB, a truncated
UF2, a `.bin`). The failure paths that cannot safely be produced on
silicon -- a failed erase, load or verify, an image that never
enumerates, a hang on the second boot, a way back that is ignored, two
candidates, an RP2040 -- were run against stub `picotool` and
`c/hid/reboot` and each stopped with its documented exit code.

Not covered, because it needs the token itself: the pad on QSPI_SS, the
LED, the die size, what the tokens arrive with
([FLASHING.md, what is not yet known](FLASHING.md#what-is-not-yet-known-about-this-token)).
A register and login through the pad was not part of this run. The
first production token covered the pad, the die size and what it
arrives with on 2026-10-02
([above](#the-first-production-usb-c-token-2026-10-02)).

## Hybrid attestation is emitted at 44 and 65, measured

The attStmt algorithm equals the credential's own hybrid algorithm at
ML-DSA-44 and -65, so the attestation signature is the full dual
(ECDSA-DER || ML-DSA). ML-DSA-87 is the sole exception and the reason is
the transport, not a policy choice: the dual attStmt takes the response
to 7617 B, eight bytes over the CTAPHID 7609 B ceiling, so at 87 alone
the attStmt is an ECDSA-P256 self-attestation. The ML-DSA public key
still rides in authData and still signs every GetAssertion.

**The conformance suite's `attestation verifies` line is the measurement,
not a formality.** Its verifier takes the hybrid branch only when
`attStmt.alg == coseKey->algorithm`; it accepts an ES256 attStmt for a
hybrid credential *only* at level 87, and returns a policy error
for one at 44 or 65 -- on the stated grounds that the dual signature fits
there, so a downgrade has no size justification. A firmware sending
ES256 at those levels would therefore fail, loudly.

Measured on the Feitian 2026-08-26:

| level | run | attestation |
|---|---|---|
| ML-DSA-44 (`--alg -51`) | 77 passed, 0 failed | `[PASS] MLDSA44-ES256: attestation verifies` |
| ML-DSA-65 (`--alg -52`) | 77 passed, 0 failed | `[PASS] MLDSA65-ES256: attestation verifies` |

Real-browser WebAuthn is confirmed working at both levels.

## Leaving a mixed image bricks the next Arm one

Measured 2026-08-26, twice, at the cost of two dark tokens:

| from | to | result |
|---|---|---|
| Rust Arm | Rust pure RISC-V | fine |
| Rust pure RISC-V | Rust **mixed** | fine |
| Rust **mixed** | C Arm | **dark** |
| C Arm | C pure RISC-V | fine |
| C pure RISC-V | C **mixed** | fine |
| C **mixed** | Rust Arm | **dark** |

Both failures are transitions *out of a **mixed** image*, and neither
`picotool erase -a` nor a power cycle prevents them. Transitions out of
**pure** RISC-V are fine -- twice.

That distinction matters and refines what was previously written down as
"a RISC-V launch leaves ARCHSEL state". In a pure RISC-V image the
bootrom does the switch, because the IMAGE_DEF asks for it, and the
bootrom puts it back. In a mixed image the *firmware* sets ARCHSEL for
core 1 at runtime to launch the Hazard3 blob; the bootrom never knows,
so nothing undoes it. The next pure-Arm image then comes up with core 1
still a RISC-V core and hangs before USB -- no HID, no BOOTSEL, no tty,
nothing on the bus, and it looks exactly like a defect in whatever you
just flashed.

**Before loading an Arm image after a mixed one:**

```bash
picotool reboot -a -c arm     # then load
```

If it is already dark, that is a BOOT+RESET; there is no software route
back.

## C port: publicKey in enumerateCredentials, all three configs

`20e3035` added publicKey (0x08) to the C port's enumerateCredentials
response. It landed after the DFU 18/18 run and had only ever been
exercised on one configuration. Validated 2026-08-26 on the Feitian,
the conformance suite run for `-52` against test builds of each:

| config | result |
|---|---|
| C Arm | 77 passed, 0 failed, 2 skipped |
| C pure RISC-V | 77 passed, 0 failed, 2 skipped |
| C mixed | 77 passed, 0 failed, 2 skipped |

with these green on every one:

```
[PASS] enumerated credential 0 (ES256) carries a matching COSE key (got ES256)
[PASS] enumerated credential 1 (MLDSA65-ES256) carries a matching COSE key (got ES256)
[PASS] enumeration covers both resident credentials with matching COSE keys
```

The hybrid credential emitting its **ES256 half** is the point: nothing
recomputes a 2 KB ML-DSA public key per enumerated credential.

The C pure RISC-V result is worth its own line given that configuration's
history -- it was broken on silicon for four days in July and fixed in
`a4328c8`. It now passes the same 77 checks as Arm.

## Rust port: the u2f/NMSG gating, all three ISAs

`e20c0e1` gated the u2f feature and stopped advertising `CAPABILITY_NMSG`
unconditionally. Also post-18/18, also single-config until now:

| config | INIT caps | PQC round trip |
|---|---|---|
| Rust Arm | `0x0d`, nmsg=true | -52, 3379 B |
| Rust pure RISC-V | `0x0d`, nmsg=true | -52, 3380 B |
| Rust mixed | `0x0d`, nmsg=true | -52, 3381 B |

Signature length is 3309 plus a 70-72 byte ECDSA DER, so each of those
is a real post-quantum signature and not an ES256 fallback.

## The bootloader's REBOOT_TO_ARM needed nothing

`4d4ddbd` looked like a third post-18/18 change owing validation. It is
not: it landed at 14:20 on 2026-08-24 and `e105efd`, which recorded DFU
coverage as 18 of 18, landed at 14:33 the same day. The 18/18 run was
made *with* that commit in the bootloader. Check timestamps before
re-running a matrix.

## Rust mixed, all three levels, after the ramfunc gating

`park_spin` and `idle_wait` are the cross-core park handshake, and their
`link_section` attributes became conditional on 2026-08-26 so the crate
could be compiled for the host. `nm` confirms both still land in SRAM
(`0x2000023e` / `0x2000025e`) on Arm and RISC-V alike, and all three
levels were then round-tripped on the Feitian:

| level | signature | = ML-DSA + ECDSA DER |
|---|---|---|
| ML-DSA-44 | 2492 B | 2420 + 72 |
| ML-DSA-65 | 3381 B | 3309 + 72 |
| ML-DSA-87 | 4699 B | 4627 + 72 |

Each is a real hybrid signature produced on core 1 -- the Hazard3 blob in
a mixed build -- so the park handshake is exercised by every one.

## Silicon validation status (2026-08-17, Feitian RP2350)

What has actually been run on hardware, and what has not. Kept here
because "the suite passed" turned out to mean much less than it looked
like -- see the caveat under the matrix.

### Full port x ISA x level matrix -- PQC path exercised

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| C -- Arm | -51, 2491 B | -52, 3380 B | -53, 4697 B |
| C -- pure RISC-V | -51, 2491 B | -52, 3380 B | -53, 4697 B |
| C -- mixed | -51, 2490 B | -52, 3379 B | -53, 4699 B |
| Rust -- Arm | -51, 2491 B | -52, 3380 B | -53, 4698 B |
| Rust -- pure RISC-V | -51, 2491 B | -52, 3379 B | -53, 4697 B |
| Rust -- mixed | -51, 2490 B | -52, 3380 B | -53, 4699 B |

Signature = ECDSA DER (70-72 B, varies with leading zeros) plus the
ML-DSA half (2420 / 3309 / 4627), so the sizes are the check that a real
post-quantum signature was produced. Driven by
`cargo run -p pqf-ctaphid --example pqc_roundtrip`.

**Do not use the conformance suite alone to claim PQC coverage.** It
hard-codes MLDSA65-ES256, so on a 44 or 87 build the device answers
CTAP2_ERR_UNSUPPORTED_ALGORITHM, every hybrid check is skipped, and the
suite still reports a near-perfect score having exercised only ES256.
Twelve of eighteen configurations were once reported as passing on that
basis. The suite remains the right tool for the CTAP surface
(credential management, largeBlobs, PIN); it is the wrong tool for
proving the crypto ran.

### Also validated on hardware

- Conformance suite 60/60 at ML-DSA-65 on C (Arm, RISC-V, mixed) and Rust.
  56/1 at 44 and 87, the one failure being the hard-coded-65 case above.
- Composite COSE ids `-53 -52 -51 -7` advertised on every configuration.
- Shipping build (no test flags): boots, enumerates, and returns
  CTAP2_ERR_OPERATION_DENIED for MakeCredential with no touch -- the user
  presence gate is enforced.
- ML-DSA-87 + `-DPQF_COPY_TO_RAM=1`: 56/1, and about twice as fast as
  the XIP + arena default.
- ML-DSA-87 sign arena high-water **42,712 B** peak over four signs
  (`-DPQF_XIP_STATS=ON`), and an XIP cache hit rate of 98.73%.
  `PQF_SIGN_ARENA_BYTES` was 240 KiB against that; it is now **96 KiB**,
  validated on silicon with four consecutive level-87 register+
  authenticate round trips, zero OOM events and no high-water creep.
  Frees 147,456 bytes of SRAM (.bss 334,852 -> 187,384).

### Validated on silicon, second pass (same day, after a BOOT + RESET)

- **The GDB stub -- done.** 73 host protocol checks, then the real
  thing: `arm-none-eabi-gdb` attached to the token's second CDC
  interface, halted via the ARMv8-M DebugMonitor, read PC/SP/LR out of a
  genuine exception frame, set an **FPB hardware breakpoint that fired**,
  and unwound it symbolically --
  `tud_task` <- `pqf_usb_task` (fido_hid.c:61) <- `main` (main.c:291) --
  then released the comparators and detached cleanly. That is the
  DebugMonitor + FPB path the host harness can only stub. Note the GDB
  channel is the HIGHER-numbered tty of the two the stub build exposes.
- **TrustZone-M split (M1-M3) -- done.** Built from the Secure and
  Non-secure crates (`crates/fw-secure`, `crates/fw-nonsecure`, via
  `./build-tz.sh`) and flashed NS-then-Secure. The host sees
  `1209:f1dc  Bruce TZ-NS (M3)` (the Rust vendor id of the time; the
  image is `cafe:f1dc` now), capabilities 0x0d, a 19-byte CTAPHID
  **PING round-tripping** through the Secure `sg_echo` veneer, and
  getInfo (`FIDO_2_0`, aaguid `664d9f67...`) served by `sg_get_info`. M1 is
  implied by all of it: none of that reaches the host unless the SAU
  attribution, the S->NS handoff and the SG veneer calls all work. M4
  (secrets fully Secure) and M5 remained at the time of this run; the
  current milestone status is in [TRUSTZONE.md](TRUSTZONE.md). The split
  then lived on its own branch: the S/NS crates were merged to main
  once (c9accdb) and deliberately reverted back off it (d835f07) while
  M4/M5 were outstanding. They have since been merged for good and are
  in this tree, which is what `tools/silicon-remaining.sh` builds.
  **The M3 image is a bring-up firmware with no CMD_REBOOT and no CDC
  BOOTSEL hook, so it strands the token** -- a physical BOOT + RESET is
  the only way back.

- **USB network gadget -- done.** Enumerates as `PQC FIDO network
  gadget`, serves DHCP (host got `192.168.7.2`), answers ICMP
  (`ping 192.168.7.1` 3/3, 0.775 ms) and serves its HTTP status endpoint
  (`{"device":"bruce-gadget",...,"transport":"usb-ncm"}`). An earlier
  entry here called it broken; that was a premature measurement taken
  before the link came up -- see `c/gadget/README.md`. Note it strands the
  token: no FIDO interface, no BOOTSEL path.

### The DFU bootloader -- validated on silicon 2026-08-18

Firmware installed **entirely over USB DFU** and chain-loaded into a
working authenticator, then proved with a real post-quantum round trip:

```
dfu-util -a 0 -D app-signed.bin
  Download [=========================] 100%   210008 bytes
  dfuMANIFEST status(0) -> dfuIDLE
FIDO IS UP   versions: FIDO_2_0 FIDO_2_1   algorithms: -53 -52 -51 -7
MakeCredential  negotiated -52 (MLDSA65-ES256)
GetAssertion    signature 3380 bytes        <- matches the C/Arm/65 row
```

Getting there took four defects, each of which had a plausible wrong
explanation attached to it first. Recorded because the failure modes are
non-obvious and the wrong theories were expensive:

1. **The flash map addressed 4 MiB of a 2 MiB die.** Staging at
   `0x200000` aliased to `0x000000`, so the first sector of every
   download erased the bootloader's own vector table underneath itself.
   Addresses past the end of the device do not fault -- they wrap. See
   the box in `docs/DFU.md`.
2. **A DFU app must be linked XIP, not `copy_to_ram`.** The bootloader
   launches with an in-place vector-table jump, which cannot honour a
   picobin LOAD_MAP; level 65 defaults to `copy_to_ram`, so
   `-DPQF_APP_OFFSET` silently produced an unlaunchable image.
   `PQF_APP_OFFSET` now forces it off.
3. **A verified-but-unbootable app bricked the token.** The bootloader
   jumped into it on every power-up, so there was no FIDO, no DFU and no
   BOOTSEL. It now arms a watchdog before branching; the app checks in
   via `pqf_boot_checkin()`, and a missed check-in drops the chip back
   into DFU. Recovering a bad image is the bootloader's whole purpose,
   so this was the one hole it could not have.
4. **The app was handed a core with interrupts masked.** The jump
   masked IRQs and never restored them. On Arm the firmware's USB is
   interrupt-driven, so the image booted, reached `main()` and then
   never enumerated -- indistinguishable from a brick, while actually
   running fine. Now `msr MSP / cpsie i / bx`.

### DFU feature sweep -- silicon, 2026-08-19

Fixing the wedge proved the bootloader could install an image. It did
not prove the feature. These are the four that close that gap, all run
unattended in one sitting, from a throwaway sweep script:

| Test | Result |
|---|---|
| Cold-boot chain-load, 5 consecutive | **5 pass, 0 dark** -- BOOTSEL -> `picotool reboot` -> bootloader -> app, with credentials already in the store |
| PQC round trip over the installed image | `-52` MLDSA65-ES256, 3380-byte signature |
| **`dfu-util -e` on a RUNNING token** | **pass** -- `appIDLE`, "Device really in Run-Time Mode", detaches into the bootloader. This is the flow the top of `docs/DFU.md` promises, and until this run it had never once executed: every earlier DFU session entered the bootloader through an EMPTY app slot instead. |
| Corrupt image rejected | `dfuERROR status(7)` = errVERIFY on a single flipped bit; the installed app is left untouched |
| Launch guard | An app that verifies but never boots (a deliberate `while(1)` shim) triggers the guard, and the token **recovers itself into DFU** rather than bricking. Trace `E32` = "launched, never reached main()". |

A caveat kept deliberately: an earlier cold boot DID go dark, once, and
that is **not attributed**. It has not reproduced (5/5 since, on the
same firmware and bootloader), and the board has a documented
intermittent dark-after-flash of roughly 1 in 9, which is the likeliest
explanation -- but no measurement proves it, so it is not claimed as
fixed. What did change is the consequence: the launch guard turns a
recurrence into a reboot into DFU instead of a token that needs
BOOT+RESET.

### Rust pure RISC-V over DFU -- all three levels PASS

| Config | alg | signature | slot `fw_version` |
|---|---|---|---|
| Rust RISC-V ML-DSA-44 | `-51` | 2491 B | 401 |
| Rust RISC-V ML-DSA-65 | `-52` | 3380 B | 442 |
| Rust RISC-V ML-DSA-87 | `-53` | 4697 B | 441 |

That completes **18 of 18** port x ISA x level configurations over DFU.

**An earlier revision of this section reported 65 and 87 as failing, and
proposed a level-specific runtime-heap cause. That was wrong on both
counts -- there was never a firmware defect.** Every failure came from
the test harness, in two distinct ways, and the wrong conclusion is kept
here because the failure mode is so convincing:

1. **A helper reflashed a stale bootloader between configs.** It loaded
   a build predating the `REBOOT_TO_ARM` fix (122768 B; the current
   build is **126996 B**), silently reintroducing the ARCHSEL hang that
   fix exists to prevent. Every config after the first was launched by a
   bootloader that could not recover the chip from the previous RISC-V
   run. **Check the bootloader binary size before trusting a sweep.**
2. **A guard shaped `inb && picotool ...` skipped the write** when the
   device sat in DFU rather than BOOTSEL -- and the next line then
   reported a failure for an image that was never flashed. One
   "standalone also fails" datum was exactly this.

The claimed heap cause does not survive inspection either: the
app-offset and standalone builds are **identical in RAM** -- same `.bss`
(523520 bytes), same `HEAP_MEM` at `0x20000300`, same text size -- and
differ only in flash addresses.

**The rule that actually resolved it:** when a config fails, reproduce
it on a *verified-clean chip with a known-current bootloader* before
concluding anything about the image. Erase fully, flash a
freshly-built bootloader, confirm the slot contents, and only then
judge. Staged that way, all three levels passed first time.

### Run the conformance suite for a named algorithm, or you under-test by a third

**Naming the algorithm plus the option flags is the invocation that
exercises everything.** Measured on the Rust ML-DSA-65 build, 2026-08-25:

| invocation | result |
|---|---|
| default run | 76 passed, 2 failed (the two advertised-not-implemented composites) |
| run for `-52` | **76 passed, 0 failed**, 2 skipped |
| extended run for `-52` | **84 passed, 0 failed**, 2 skipped |

Historically the default run was far worse than those two failures
suggest -- 57 passed / 9 failed -- and not because it *reported* more, but
because it **never ran nineteen further checks**. The suite tries
MLDSA87 and MLDSA44 MakeCredentials, which a single-variant build cannot
mint, and the resident-credential branch minted credential 1 with the
strongest *advertised* composite. That MakeCredential failed, so
`numberOfCredentials`, `GetNextAssertion` and the enumeration checks
were counted as failures rather than executed.

The extended run adds the legacy `getPinToken`, a `changePIN` round
trip, and `authenticatorConfig` `toggleAlwaysUv`, toggled twice and
restored (verified: `alwaysUv=false` afterwards). All pass, and all
were previously untested.

That cascade is gone as of the suite's "separate advertised from
usable" change. The suite now keys every downstream section off the strongest
composite that actually *minted*, rather than the strongest one
advertised, so the resident-credential branch runs against `-52` and
credMgmt, largeBlobs, discoverable assertions and `GetNextAssertion` all
execute. A default run against an ML-DSA-65 build went from **57 passed
/ 8 failed to 76 / 2**, the two being exactly the two composites that
are advertised and not implemented -- each with a line explaining that a
client cannot tell a deliberate pad from a picker that disagrees with
its own advertisement.

**The failure that used to be "deliberate" is now simply absent.**
"authenticator selects the strongest advertised algorithm,
MLDSA87-ES384 (-53)" asserted something this design intentionally
violates: getInfo advertises all three composites so browser pre-flight
does not silently exclude the token, while the build mints only its own.
The check now expects the strongest composite the round trips proved
real, which is `-52` here. It still fails a device that advertises a
composite, mints it, and then negotiates something weaker -- the
silent-downgrade check is unchanged, only its bar moved from advertised
to proven. See `pick_alg()` in `ctap2.c` for the firmware half.

So the honest coverage statement for a single-variant build is
**a run for its composite: 76 passed, 0 failed**, or a default run at
76/2 where the two are the over-advertisement itself. Quote the
named-algorithm figure.

### Optional Rust features and the conformance suite on Rust -- silicon 2026-08-24

**The conformance suite against a DFU-installed Rust image: 57 passed, 9 failed**,
`MLDSA65-ES256` verified. The C-port run was 56/10.

**Running the same suite on both ports paid for itself.** The failure
sets are identical except one, which the C port fails and Rust passes:

```
C only:  [FAIL] enumerated credential 0 (ES256) carries a parseable COSE key
Rust:    [PASS] enumerated credential 0 (ES256) carries a matching COSE key (got ES256)
```

**FIXED 2026-08-24 -- C is now 57/9, identical to Rust.** The key was not
malformed, it was **absent**: `credential_management.c` omitted
publicKey (0x08) entirely, on the stated grounds that a hybrid
credential would need its ~1-2 KB ML-DSA public key recomputed, and that
this "matched the Rust base". Both halves were wrong. CTAP 2.1 sec. 6.8.3
lists publicKey in the enumerateCredentials response, and the Rust port
emits the **ES256 half** for every credential, hybrid included
(`es256_cose_public_key`), so no ML-DSA is ever recomputed.

C now does the same: recover the scalar from the credential's own
credentialID, derive the P-256 point, emit a plain ES256 COSE_Key. It
costs one scalar multiplication per enumerated credential (~2.4 s from
XIP on the mixed build, per `credential.h`), so it degrades to omitting
the key if derivation fails rather than failing the whole enumeration.

**A single-port run could not have found this.** Both ports scored
"near-perfect with a handful of known-deliberate failures", and only
diffing the two failure sets showed one port had an extra, real defect.

**`u2f` feature -- was structurally unreachable; now works.** Enabling it
compiled the U2F module and a `U2fMessage` handler in `main.rs`, but
nothing could ever reach them: `ctaphid.rs` refused `CMD_MSG` with
`ERR_INVALID_CMD` **unconditionally**, and advertised `CAPABILITY_NMSG`
**unconditionally**. So the feature's only effect was to link a
hardcoded dev batch-attestation key into the binary. Both are now gated
on the feature; default builds are byte-for-byte unchanged in behaviour
(NMSG kept, CMD_MSG still refused -- which is deliberate, see the comment
in `complete`: without NMSG browsers prefer U2F and RPs get
`fmt="fido-u2f"` instead of `"packed"`).

Verified on hardware with a U2F client: register with attestation
**VERIFIED** (`fmt="fido-u2f"`, alg -7, the dev batch attestation cert), check-only
recognising a real key handle and rejecting a corrupted one, and two
authentications with the counter advancing 1 -> 2, both signatures
verified.

**`ed25519` feature -- works as shipped.** getInfo advertises `-8`
alongside the composites (`-53 -52 -51 -8 -7`), and a MakeCredential
requesting **only** `-8` succeeds with `fmt="packed"` and a GetAssertion
signature of exactly **64 bytes** -- the Ed25519 signature size. Costs
~47 KiB of flash (168 KiB -> 215 KiB) for `ed25519-dalek`.

Neither feature is reachable from the conformance suite (its algorithm
selector accepts only composites) or from `pqc_roundtrip` (which sends the default list), so
`crates/ctaphid-client/examples/alg_roundtrip.rs` was added to target a
named COSE algorithm:

```bash
cargo run -p pqf-ctaphid --example alg_roundtrip --target "$HOST_TARGET" -- -8
```

### DFU coverage: 18 of 18 -- COMPLETE, silicon 2026-08-24

Added this round: **C mixed 44 and 87** (`-51` 2490 B; `-53` 4699 B with
`core1=RISCV-BLOB` confirmed) and **Rust mixed 44 and 87** (`-51`
2491 B; `-53` 4698 B). Each verified by reading the installed
`fw_version` back out of the app slot.

**All 18 port x ISA x level combinations now install over DFU and sign**
-- C and Rust, each on Arm / pure RISC-V / mixed, at ML-DSA-44/65/87.
Every one verified by reading the installed `fw_version` back out of the
app slot, not by enumeration alone.

Rust pure RISC-V closed last: 44 (`-51` 2492 B), 65 (`-52` 3380 B,
slot fw 251) and 87 (`-53` 4698 B, slot fw 300).

**These three were first recorded as failing, and that was wrong.** The
cause was the ARCHSEL hazard below, not the images:

- Standalone Rust RISC-V 65 and 87 both run and sign perfectly when
  written at `0x10000000` with no bootloader, which ruled out the
  firmware.
- All three images are structurally identical to the bootloader's
  parser -- one marker at `0x138`, `cpu=1`, valid `ENTRY_POINT`.
- Once `REBOOT_TO_ARM` recovery was in the bootloader, 44 and 65 passed;
  87 needed a clean chip (`erase -a` + fresh bootloader) as well.

The lesson is the ordering one: **every RISC-V launch leaves the chip in
a state that makes the NEXT Arm-side step unreliable**, and the whole
test harness runs Arm-side. Erase and reflash between ISA switches, or
retry before believing a failure.

Diagnostic note: the watchdog breadcrumb cannot distinguish these cases
on its own. `try_boot_app()` returns before setting any trace when
`verify_slot` fails, and it is not called at all when the DFU-request
magic is set -- so a stale value persists and reads as though the last
recorded path just happened.

### Rust port over DFU at every level -- silicon 2026-08-21

| Config | alg | signature | slot `fw_version` |
|---|---|---|---|
| Rust ML-DSA-44 | `-51` | 2492 B (2420 + 72) | 130 |
| Rust ML-DSA-65 | `-52` | 3380 B (3309 + 71) | (earlier run) |
| Rust ML-DSA-87 | `-53` | 4697 B (4627 + 70) | 131 |

Each confirmed by reading the installed `fw_version` back out of the app
slot, with the USB product string (`Feitian RP2350 PQC`) distinguishing
the Rust port from the C one (`Bruce (C port)`).

**Operational gap: the Rust port has no DFU runtime interface.** The C
port built with `PQF_BOOTLOADER=ON` exposes a DFU *runtime* interface,
so `dfu-util -e` detaches a running token straight into the bootloader.
The Rust port does not implement that, so `dfu-util -e` silently does
nothing once a Rust image is running and the next install appears to
fail with "no DFU". Route a Rust token through BOOTSEL instead:

```bash
./c/hid/reboot bootsel      # needs a PQF_TEST_NO_USER_BUTTON build
picotool erase -a && picotool load -x pqf_bootloader.uf2
dfu-util -a 0 -D app-signed.bin
```

So a Rust-flashed token cannot currently be field-updated over DFU
without a BOOTSEL round trip, while a C-port token can. If Rust field
updates matter, the equivalent of `PQF_DFU_RUNTIME_IF` needs
implementing on the Rust side -- that is a missing feature, not a bug.
(Since closed: the Rust `dfu_runtime` feature, see
[BUILD.md](BUILD.md#other-features).)

### ML-DSA-87 with copy_to_ram AND the sign arena -- silicon 2026-08-21

Level 87 used to be forced onto the slow XIP path: CMake disqualified
the arena whenever `copy_to_ram` was requested, and the two were treated
as mutually exclusive. That was correct when the arena was 240 KiB -- a
~292 KiB copied image plus 240 KiB leaves nothing for stacks in 520 KiB
of SRAM. **The arena has been 96 KiB since the shrink, so the pair now
fits**, and the exclusion had simply never been revisited.

Measured on the built image: `s_arena` is 0x18000 (exactly 96 KiB) and
the total RAM footprint is **386 KiB of 520**, ~134 KiB spare.

| L87 build (installed over DFU) | alg | signature | wall clock |
|---|---|---|---|
| `copy_to_ram` + 96 KiB arena | `-53` | 4697 B | **2.11 s** |
| XIP + arena | `-53` | 4699 B | 3.53 s |

**1.67x** on a full register + authenticate round trip with USB overhead
included. Four consecutive signs on the copy_to_ram build all completed
at 4698 B -- worth checking, because an undersized arena does not error,
it produces a signature that never completes.

The CMake guard is now size-aware rather than a blanket refusal: it
computes the arena size and only refuses above 160 KiB, where the fit
stops being comfortable. The linker remains the real arbiter.

Two status messages were corrected at the same time, both of which had
outlived the code: one printed "image runs from XIP" while copy_to_ram
was enabled, and another claimed level 87 + copy_to_ram "runs on plain
newlib malloc instead of the arena" -- true only while copy_to_ram
disqualified the arena, which it no longer does.

**Not changed: the default.** Level 87 still selects XIP unless
`-DPQF_COPY_TO_RAM=1` is passed. Making SRAM the default at 87 is a
shipping-behaviour decision, not a test result.

### The conformance suite against a DFU-installed image -- silicon 2026-08-21

The CTAP 2.1 surface had never been exercised on firmware installed over
DFU; every earlier DFU check was getInfo plus one PQC round trip. Run
against a C/Arm/ML-DSA-65 `copy_to_ram` image installed over DFU
(`fw_version` 110), the conformance suite reports:

```
passed 56, failed 10, skipped 0
PQ/T composites advertised: MLDSA87-ES384(-53) MLDSA65-ES256(-52) MLDSA44-ES256(-51)
PQ/T composites verified:   MLDSA65-ES256(-52)
```

Passing: ClientPIN (set, token, retries), Selection, BioEnrollment,
Config, non-resident and resident MakeCredential/GetAssertion at the
build's own level, credential management, largeBlobs including a
near-cap blob, and cleanup. **A real ML-DSA-65 signature was verified**,
so the post-quantum path ran rather than an ES256 fallback.

**All 10 failures are one root cause, and it is deliberate.** getInfo
advertises all three composites while a single-variant build can only
mint its own, so `MLDSA87-ES384` and `MLDSA44-ES256` MakeCredentials
fail and everything downstream cascades -- the second resident
credential never exists, so "numberOfCredentials 2", `GetNextAssertion`
and the enumeration checks all fail from that one cause.

`pick_alg()` in `ctap2.c` deliberately refuses to match a composite id
this build cannot mint: doing so would mint the build's variant under a
code point naming a different parameter set, so the COSE_Key alg, the
credentialID's recorded alg and the ML-DSA public-key length would all
contradict the label and every verifier would reject the assertion.
Falling through gives `CTAP2_ERR_UNSUPPORTED_ALGORITHM` (0x26), which is
what CTAP 2.1 sec. 6.1 specifies and is *visible* to the host -- unlike
Chrome's silent pre-flight `kNoCommonAlgorithms` exclusion, which is the
whole reason all three are advertised.

So on a single-variant build, 10 failures is the expected score. To see
a clean run you would need a device that can mint all three, which no
current build does. Do not "fix" this by trimming the advertised list
without re-checking the browser pre-flight behaviour it exists for.

**Correction to an earlier note in this document:** the conformance suite
was described as unable to test anything but a hard-coded MLDSA65 and as
never exercising negotiation. That is wrong -- it takes a named-algorithm
target and it does check that the authenticator selects the strongest
advertised composite. The earlier claim came from reading `algCount = 1`
in one helper and generalising to the whole program.

### RISC-V over DFU at every level -- silicon 2026-08-21

| Config | alg | signature | slot `fw_version` |
|---|---|---|---|
| RISC-V ML-DSA-44 | `-51` | 2490 B (2420 + 70) | 102 |
| RISC-V ML-DSA-65 | `-52` | 3379 B (3309 + 70) | 97 |
| RISC-V ML-DSA-87 | `-53` | 4697 B (4627 + 70) | 101 |

All installed over DFU through the block-loop annex, each confirmed by
reading the installed `fw_version` back out of the app slot rather than
trusting that *something* enumerated.

**44 and 87 first reported as FAILING, and that was device state, not
the images.** Worth writing down, because it is a false negative that
looked entirely convincing:

- **Anti-rollback was silently refusing installs.** `PQF_BOOT_ANTI_ROLLBACK`
  was ON in the bootloader in use, versions had climbed to 98-101, and
  anything lower came back `status(2)` = `PQF_IMG_ROLLBACK`. The test
  script was filtering dfu-util's output, so the refusal was invisible
  and the run simply looked like "the app never booted".
- **The trace lags one boot.** `E32-S65534` reads as "image seen as
  Arm", but the breadcrumb is captured at boot and reported in the NEXT
  boot's serial, so it was a stale record of an earlier Arm launch. To
  read the current boot's trace, force one more reset and read again.
- After `picotool erase -a` and a clean annex bootloader, the identical
  images worked first time.

**Recovering a token whose firmware hangs before USB.** The firmware
breadcrumb located the real fault as `E64-S0008` -- stage 8,
`core1_signer_init()` -- so the app was reaching `main()` and dying at
the core-1 launch, not failing to start. With no CTAPHID there is no
`reboot bootsel`, but a **BOOTSEL shim** gets the device back with no
button press: a ~5 KB app that calls `reset_usb_boot()` immediately,
before anything touches core 1. Sign it above the installed
`fw_version` (anti-rollback applies to it too) and DFU it in:

```bash
# main.c: int main(void){ reset_usb_boot(0,0); while(1) tight_loop_contents(); }
# linked at 0x10021000, signed, then:
dfu-util -a 0 -D shim-signed.bin      # -> lands in BOOTSEL
```

### All three DFU gaps closed -- independent re-verification 2026-08-21

| Item | Result |
|---|---|
| `copy_to_ram` over DFU, ML-DSA-44 | `-51`, 2490 B |
| **RISC-V over DFU** | `-52`, 3379 B, installed over DFU, slot confirmed `fw 97` |
| Mixed-ISA over DFU | `-52`, 3381 B, `core1=RISCV-BLOB` confirmed |

All hands-free: `./c/hid/reboot bootsel` reaches BOOTSEL in software from
any `PQF_TEST_NO_USER_BUTTON` build, and C builds with `PQF_BOOTLOADER=ON`
detach to DFU with `dfu-util -e`.

**Do not confirm a launch by enumeration alone.** "A FIDO device is up"
is satisfied by *any* app in the slot, including the one you were trying
to replace -- that produced a false "RISC-V running" here when the Arm
baseline was still installed. Read the installed `fw_version` back out of
the app slot instead:

```bash
picotool save -r 0x10020000 0x10021000 slot.bin -t bin   # bytes 12..15 = fw_version
```

Two further traps from that run: `/tmp` was cleaned mid-run and took
the built images with it, while a signing helper that redirected stderr
to /dev/null hid the failure; and a `to_bootsel` helper that installs a
known app to reach BOOTSEL will overwrite the very slot you are about to
inspect. Use `./c/hid/reboot bootsel` directly when the slot contents
matter.

### copy_to_ram over DFU -- working, silicon 2026-08-20

A `copy_to_ram` image installs over DFU, chain-loads through the
bootloader's in-place vector jump, and signs:

| build | round trip | wall clock |
|---|---|---|
| copy_to_ram (fw 70) | OK, `-52`, 3380 B | **2.48 s** |
| XIP, same firmware (fw 71) | OK, `-52`, 3380 B | 3.41 s |

**The restriction that forbade this was wrong, and worth understanding
because of how it survived.** `PQF_APP_OFFSET` used to force
copy_to_ram OFF on the theory that an in-place vector jump cannot
honour a picobin LOAD_MAP. Two errors in one:

- a pico-sdk copy_to_ram image carries **no LOAD_MAP** -- parse the block
  loop and it holds only `IMAGE_TYPE`;
- the flash->SRAM copy is done by **crt0**, walking a linker-emitted
  table (`__ram_text_source__` / `__ram_text_start__` /
  `__ram_text_end__`, `pico_crt0/crt0.S`). The reset vector stays in
  flash, so the in-place jump enters crt0 and the copy happens exactly
  as it would after a bootrom launch.

The dark token that prompted the restriction was really the bootloader
handing the app a core with `PRIMASK` still set, so the interrupt-driven
USB never enumerated. That was fixed later (`msr MSP / cpsie i / bx`),
but the copy_to_ram restriction was never re-examined -- a wrong
conclusion outliving the evidence that produced it.

**On the speed claim.** 2.48 s vs 3.41 s is **1.37x on wall clock** for
a full register + authenticate round trip at ML-DSA-65, USB overhead
included. That is not the "about twice as fast" figure quoted elsewhere
in this document: that one is the ML-DSA-**87** sign operation in
isolation against the XIP + arena build. Both can be true; they measure
different things. Quote the one that matches what you are measuring.

### Full DFU sweep across ports, ISAs and levels -- silicon, 2026-08-19/20

Every configuration that CAN be DFU-installed, installed and driven to a
real post-quantum signature. The signature length is checked against the
ML-DSA level, so a silent ES256 fallback cannot score a pass.

| Config | Result |
|---|---|
| C -- Arm -- 44 / 65 / 87 | **PASS** `-51` 2491 B, `-52` 3379 B, `-53` 4697 B |
| Rust -- Arm -- 44 / 65 / 87 | **PASS** `-51` 2492 B, `-52` 3380 B, `-53` 4697 B |
| C -- pure RISC-V -- 44 / 65 / 87 | **BLOCKED** -- installs and verifies, never enumerates |
| Rust -- pure RISC-V -- 44 / 65 / 87 | superseded -- see "Rust pure RISC-V over DFU" below |
| C / Rust -- mixed ISA | **NOT INSTALLABLE** -- see below |

#### RISC-V cannot be launched by this bootloader

Six for six, both ports, all three levels, while every Arm config
passes. That is architectural, not flaky.

The bootloader hands control to the app with `msr MSP / cpsie i / bx` --
an **Arm-only** sequence. RISC-V has no VTOR and no MSP, and switching
the RP2350 between Cortex-M33 and Hazard3 is an **ARCHSEL** decision
only the bootrom makes, via `rom_chain_image()`. An Arm in-place vector
jump cannot perform it, so a RISC-V image is installed perfectly,
verifies perfectly, and then nothing runs.

The launch guard caught all six and returned the token to DFU each time,
so this costs nothing but a reinstall -- six consecutive unattended
recoveries, which is the strongest evidence yet that the guard works.

**SUPERSEDED 2026-08-21.** This section said RISC-V-over-DFU and secure
boot were the same blocker and both needed `rom_chain_image()`. Neither half
holds any more. RISC-V now launches through the **block-loop annex**
(`rom_reboot(NORMAL | TO_RISCV)` after transplanting the app's IMAGE_DEF
into slot 0's last sector so the ROM's own scan finds it) -- no
`chain_image` involved. And secure boot never required it: the ROM
verifies the bootloader, which then ECDSA-verifies the app. What
`chain_image` would still add is an OTP-anchored root key and
ROM-enforced rollback -- hardening, on nobody's critical path. The
measurements below are kept because they are real, but the framing that
this gates anything is wrong.

**Open question, deliberately not asserted:** whether RP2350 secure boot
supports RISC-V at all. The evidence here cuts both ways --
`picobin.h` defines `PICOBIN_IMAGE_TYPE_EXE_CPU_RISCV`, so a signed
image can declare itself RISC-V; but OTP `BOOT_ARCH` is documented as
*"Ignored if ARM_DISABLE, RISCV_DISABLE or SECURE_BOOT_ENABLE is set"*,
which suggests the arch decision changes under secure boot. Settling it
needs the RP2350 datasheet bootrom chapter, not these headers. If it
turns out RISC-V and secure boot are mutually exclusive, that is an
accepted limitation for this project (Arm is the shipping
configuration) -- but it should be recorded as a finding, not assumed.

#### The ROM-anchored chain: what it actually returns

`rom_chain_image()` is the launch path both RISC-V-over-DFU and
secure boot need. It was recorded as "hangs" from 2026-07-20; that was
never a measurement of the chain path. Three separate layers stood in
the way of getting a real answer, and none was the ATRANS/credential-store
cause the code comment proposed:

1. **`PQF_BOOT_LAUNCH_CHAIN` was never a CMake option.** The `#if` in
   `main.c` existed, nothing passed the define, and
   `-DPQF_BOOT_LAUNCH_CHAIN=ON` therefore produced a **byte-identical
   in-place build** (122728 either way). The build never fails; only a
   size diff exposes it.
2. **pico-sdk's wrapper disguises errors as hangs.** Its epilogue is
   `bootrom_acquire_lock_blocking()` -- a hardware boot-lock spin with no
   timeout. If the ROM's failure path leaves that lock held it deadlocks
   *after* the ROM has answered, which is indistinguishable from the ROM
   hanging. Call the ROM entry directly to see the code.
3. **The call site discarded the return value**, so refusal and hang
   were the same event.

With all three fixed, measured on silicon 2026-08-20 -- **Arm and RISC-V
behave identically**, which is what proves the blocker is not
architectural:

| Lock handling | Result |
|---|---|
| none | `-19 LOCK_REQUIRED` |
| `release(BOOTROM_LOCK_ENABLE)` | `-4 NOT_PERMITTED` |
| hold SHA_256 + FLASH_OP + OTP | hangs -- the ROM wants those locks itself |
| `+ rom_load_partition_table()` first | hangs |
| sector-aligned window | hangs |

**Still unresolved.** `NOT_PERMITTED` is a policy refusal, not a crash.
The leading candidate is that we hand the ROM a bare flash window while
its own boot path always loads a **partition table** first, and nothing
declares the app slot bootable. Testing that means writing a partition
table (reversible -- it is only flash). Settling it properly needs the
RP2350 datasheet's bootrom chapter on what permission `chain_image`
checks; guessing has already cost several wrong hypotheses.

**Partition table: attempted, INCONCLUSIVE, and it bricked picotool.**
Embed one with

```bash
picotool partition create pt.json out.elf <bootloader.elf>   # note: writes ELF
```

(the embed mode ignores the output extension and always emits ELF).

> **Do not declare unpartitioned space as `absolute`-only.** The
> bootloader itself lives in unpartitioned space and its family is
> `rp2350-arm-s`; a table that only accepts `absolute` there locks it
> out, and picotool then refuses everything with
> `Family ID 'rp2350-arm-s' cannot be downloaded anywhere`. Worse,
> `picotool erase -a` also fails (`Cannot determine the flash size`) and
> `partition info` returns `data is invalid`, so the obvious recovery
> routes are all shut. **Recovery that works:**
>
> ```bash
> picotool erase -r 0x10000000 0x10200000   # explicit range
> picotool reboot -u                        # flush the ROM's cached table
> ```
>
> The reboot matters -- the ROM caches the partition table at boot, so
> erasing alone leaves it still refusing. Cost a live token several
> minutes on 2026-08-20.

The chain result WITH a valid table is still **unknown**. The first
attempt did put a table on the device, but it was flashed with
`load -x` (instant reboot) so its presence was never verified, and by
the time verification was attempted the malformed table was blocking
every query. Retry wants: unpartitioned space accepting `rp2350-arm-s`,
`load` without `-x`, `partition info` read back BEFORE measuring, and a
**spare board**.

**Tooling that came out of it:** the bootloader can now cycle chain
strategies across guard reboots -- index in watchdog scratch 5, results
accumulated a nibble per strategy in scratch 6, reported via the USB
serial once the walk completes. One BOOT+RESET tests four hypotheses
instead of one.

#### Mixed-ISA over DFU -- RESOLVED in BOTH ports, silicon 2026-08-20/21

Was blocked by a layout conflict, not a test failure: the C `.core1_blob`
landed at `0x1019c6b8`, outside the app slot, and the link failed with
`region FLASH overflowed by 587468 bytes`; Rust's `memory_core1riscv.x`
put `BLOB` at `0x10180000`, inside the **staging** slot.

Fixed by deriving the blob origin from a single CMake value that
generates both linker scripts and the C constant. A DFU build pins it at
`0x100A0000`, inside the slot, leaving 508 KiB for core 0 against the
~206 KiB it uses. Installed over DFU and signed `-52` at 3381 B.

**Rust port, 2026-08-21.** Same class of fix, three places instead of
one: `memory_core1riscv.x` (`BLOB` region), `fw-core1-riscv/blob.x`
(`BFLASH`, because the payload links absolute and must move in lockstep)
and `signer-core`'s `BLOB_FLASH_ORIGIN`. All follow `PQF_APP_OFFSET`;
`signer-core` gained a `build.rs` solely to emit
`rerun-if-env-changed`, without which the constant would silently
disagree with the linker scripts. A DFU build puts `BLOB` at
`0x100A0000/128K` and caps core 0 at 508K so it ends there. Installed
over DFU and signed `-52` at 3381 B.

Confirming mixed mode is *easier* on the Rust side: `main.rs` does
`spawn_core1_signer_riscv_blob(...).expect(...)` under `panic_halt`, so a
failed blob launch **halts the device**. It cannot fall back to Arm the
way the C port does. A Rust mixed image that enumerates and signs has
necessarily launched the blob.

**Verify it is really in mixed mode, not the Arm fallback.** If the blob
does not launch, signing silently falls back to core 0 and still returns
correct signatures, so a round trip cannot tell the two apart. The CDC
heartbeat now carries the state: `core1=RISCV-BLOB` or
`core1=FALLBACK-ARM`. Read that, not the signature.

### Anti-rollback and the Rust port over DFU -- silicon, 2026-08-19

**Anti-rollback (`-DPQF_BOOT_ANTI_ROLLBACK=ON`) -- validated.**

| Step | Expected | Result |
|---|---|---|
| install `fw_version` 5 into an empty slot | accept | accepted, ran |
| downgrade to `fw_version` 2 | reject | **`dfuERROR status(2)`** (errFILE -- `PQF_IMG_ROLLBACK` maps to `DFU_STATUS_ERR_FILE`), installed app untouched |
| reinstall the same `fw_version` 5 | accept | accepted -- the check is strictly `<`, so equal versions reinstall |
| upgrade to `fw_version` 9 | accept | accepted, token healthy |

Worth knowing: DFU 1.1 has no rollback-specific status, so a refused
downgrade is indistinguishable on the wire from other format errors.

**Rust port over DFU -- installed and chain-loaded.** The Rust firmware
gained `PQF_APP_OFFSET` (build.rs rewrites memory.x to the app slot) and
a launch-guard check-in matching `pqf_boot_checkin()`; without the
latter a healthy Rust image is reset back into DFU seconds after
booting, because the guard reads silence as a failed launch. Installed
over DFU onto a Feitian, it chain-loads and enumerates as
FIDO_2_0/FIDO_2_1 advertising `-53 -52 -51 -7` with aaguid
`664d9f67...`, distinct from the C port's `7071632d...`, and stays up well
past the 10 s guard window.

**Rust PQC round trip over DFU -- done.** `fw_version` 11, board
`feitian_rp2350`, installed over DFU onto the anti-rollback bootloader:
MakeCredential negotiates `-52` (MLDSA65-ES256) and GetAssertion returns
a **3380-byte** signature -- the same size as the C port's row in the
matrix above. Both ports are now silicon-validated end to end over DFU.

A trap that cost a round of confusion: the first Rust image installed
was a `--release` build with DEFAULT features, i.e. `board_tiny2350`.
It worked perfectly over CTAPHID -- PING, getInfo, the lot -- but the
token's **LED stayed dark**, because the Tiny 2350 drives a WS2812 RGB
while the Feitian has a plain GP25 LED. A board mismatch presents as
dead hardware while the device is entirely healthy. Check the USB
product string: `Tiny 2350 PQC` vs `Feitian RP2350 PQC` names the board
the image was built for. Always pass
`--no-default-features --features mldsa65,board_feitian_rp2350`.

Note also that a `test_no_user_button` image AUTO-CONFIRMS user presence
and is dev-only -- fine for unattended tests, not something to carry.
Without it, `CMD_REBOOT` and MakeCredential both correctly demand a
touch, which is the gate working rather than a fault.

### Power loss during the staging->app copy -- validated, 2026-08-19

The install journal does what it claims. Cable pulled mid-copy on a real
Feitian, then replugged:

```
APP SLOT   magic PQFW   image_len 512000   fw_version 16   <- the NEW image
JOURNAL    0xFFFFFFFF                                      <- cleared, install retired
```

The app slot was left half-overwritten by the cut. On the next boot the
bootloader found the journal `PENDING`, re-verified staging, redid the
whole copy and retired the journal. The token came back with a working
new image -- not the wreck, and not the old one.

**Timing this by hand is the hard part, and the first attempt missed.**
After `Download done` the device spends **~1.8 s verifying** (SHA-256 +
ECDSA over 512 KB) BEFORE the journal is written, and only then copies
for ~6.2 s. Pulling at 2-3 s lands in the verify phase: no journal
exists yet, the app slot is untouched, and the token comes back on the
OLD image looking like a pass when nothing was tested. Measure the
window first -- total manifest time was 8.0 s here -- and pull at roughly
60-85% of it. The pattern for a scripted attempt: pad the image to
widen the copy (the host's own manifest timeout scales as
`sectors * 50 + 500` ms, so a larger image does not risk a spurious
dfu-util timeout), and drive the cue from a script rather than
eyeballing the progress bar. `tools/dfu-powerloss-test.sh` has since
taken the other route: it writes the flash state a power loss leaves
behind -- a staged image plus a pending journal -- directly over BOOTSEL
and exercises what the next boot does with it, so the replay runs for
real with no cable pull.

That first attempt did prove something worth keeping, just not what was
aimed at: **an interrupted transfer leaves the installed app perfectly
intact.**

Not covered: a cut *during* a single sector erase or program. Replay
rewrites every sector so it should be handled, but it cannot be aimed at.

Also
note the Rust `memory.x` still declares `LENGTH = 4096K` for a 2 MiB
die -- benign today because nothing links past ~1 MiB, but the same
latent overstatement that was corrected on the C side.

Still unrun at the time of that sweep: anti-rollback, power-loss during
the staging->app copy, and the Rust port over DFU. Two of the three are
covered in the section directly below.

**Two lessons worth keeping.** A wrap is self-consistent: the credential
store at `0x3FC000` wraps to `0x1FC000` and reads wrap with it, so
credentials persist and read back perfectly while living 2 MiB from
where the constants say they are -- which was repeatedly taken as proof
of a 4 MiB die. And validate the instrument before trusting it: "nothing
hung" and "my detector is broken" look identical, and a `picotool info`
that exits non-zero on a *present* device silently blinded an automated
BOOTSEL detector.

Answer this class of question by measurement, not inference:

```bash
picotool load -o 0x10200000 pattern.bin -t bin && picotool save -r 0x10000000 0x10001000 low.bin -t bin
```

### Real-browser WebAuthn

Confirmed working by the author on 2026-08-17. Not independently
measured here, so no algorithm or timing figures are recorded -- but it
exercises the one path nothing else in this document does: the browser's
own pre-flight intersection of the RP's `pubKeyCredParams` against the
getInfo algorithm list. That intersection is why getInfo advertises all
three composite ids rather than only the compiled-in one (see the 0x0a
block in `ctap2.c`); an empty intersection is a silent
`kNoCommonAlgorithms` failure before any CTAP frame is sent.

If you want it reproducible from a script rather than by hand: a
scripted browser can reach the WebAuthn API (`navigator.credentials.create`
present, secure context, UVPA true), but a ceremony needs transient user
activation and a physical touch, so it is not automatable unattended.

## Previously listed as "future tests" -- all three already exist

This section used to propose three tests as unwritten. They are all
implemented and run as part of `make test`; the list was stale, and
acting on it would have produced duplicates. Recorded here so the next
person does not rewrite them:

| Proposed test | Where it actually lives |
|---|---|
| Cross-RP replay defence | `test_ctap2.c` -- "credential rejected at a different RP" (`CTAP2_ERR_NO_CREDENTIALS` for a credential replayed at `evil.example`) |
| Tampered credentialID | `test_domain.c` -- and stronger than proposed: **every** single-byte flip of the sealed blob is rejected, not merely one |
| hmac-secret salt stability | `test_extensions.c` -- same salt across two GetAssertions yields identical output, a different salt yields a different one |

The lesson generalises: check the suite before trusting a to-do list in
a document. Test inventories drift out of date faster than the tests
they describe.

### Genuinely still unwritten

Reviewed 2026-08-26. Two of the four items this list used to carry were
already done when it was written; they are struck below rather than
quietly deleted, because a list that has been wrong once is worth
showing the shape of.

- ~~**TrustZone** -- resident credentials, the conformance suite, a physical press~~
  **All three done.** Resident credentials are validated by the
  compaction churn test (240 writes of 8 users, nothing refused);
  the conformance suite run for `-52` gives 64 passed / 0 failed / 4 skipped
  against the TZ image (re-measured 2026-09-02; the 65 recorded earlier predates
  a rework of the suite itself, not a regression); and the presence gate was
  confirmed with a real finger (the `tz_test` example with `--press`), no
  injection and no
  auto-present. See
  [`TRUSTZONE.md`](TRUSTZONE.md).
- ~~**A GDB stub for the Rust port**~~ **Done and silicon-validated** --
  monitor-mode debug on ARMv8-M, breakpoints in both `copy_to_ram` and
  XIP, halting inside `tud_task()` while CDC keeps answering. See
  [`GDB_DEBUG.md`](GDB_DEBUG.md).

Still genuinely outstanding:

- ~~**USB network gadget**~~ -- **dropped 2026-08-31.** The FIDO path
  never needed it (ceremonies go over the phone OS's own CTAP stack),
  "internet through the phone" was never justified for a security key,
  and management-over-IP did not survive the question that killed the
  rest: this firmware already ships vendor CTAPHID commands over the
  interface the phone already speaks. See
  [`NETWORK-GADGET.md`](NETWORK-GADGET.md) for the reasoning and for the
  last measurement, which found the device side healthy and the fault
  looking like macOS Internet Sharing rather than firmware -- reversing
  the old "macOS is a dead end" conclusion. The offline harness
  (`make -C c/gadget/test`, 38 checks) stays: it found four real bugs
  and still passes.


- **The Rust firmware is mostly untested on the host.** 10,665 lines
  across `crates/firmware/src` against twelve host binaries on the C
  side. `credential_id.rs` is now covered (see below); the rest is not.
  Six modules need **no seam at all** -- no HAL, no `rom_data`, no fixed
  XIP address -- so `crates/firmware-hosttest` reaches them by adding a
  `#[path]` line each:

  | module | lines | state |
  |---|---|---|
  | `ctap2.rs` | 2956 | **86 checks** (dispatch, getInfo, Selection, Reset, both ceremonies) |
  | `client_pin.rs` | 1187 | **46 checks** |
  | `flash_store.rs` | 716 | **17 checks** |
  | `credential_management.rs` | 627 | **23 checks** |
  | `ctaphid.rs` | 556 | **23 checks** |
  | `credential_id.rs` | 536 | **14 checks** |
  | `large_blobs.rs` | 412 | **23 checks** |
  | `authenticator_config.rs` | 299 | **19 checks** |

  All eight are now covered. Reaching them cost four small
  stubs -- `core1_signer` (the cross-core mailbox), `arch::nop`,
  `ramfunc`, and `RngCore` on the test TRNG -- because `ctap2.rs` is not
  hardware-free despite importing no HAL. The signing enters at exactly
  one function, `opensk_hybrid_sign`, 97 lines of 2956.

  **What the stub costs, stated once:** these tests cover what the token
  *says* -- dispatch, CBOR shaping, request parsing, policy -- and never
  what it signs. Signature validity stays a silicon claim, covered by
  `pqc_roundtrip` on all six port x ISA configurations and by the conformance
  suite verifying attestation against the credential's own key. Anything here
  that touches a signature asserts its *shape* only.

- **Secure boot / OTP** -- provisioning now exists and is
  partly done. `tools/secureboot-provision.sh` seals the bootloader and
  splits the OTP rows, and on 2026-09-01 the boot key was really burned
  into a Tiny 2350 (chipid `0x764d62245aa0b134`): `BOOTKEY0` at row
  `0x0080`, `BOOT_FLAGS1.KEY_VALID` set, both read back byte-for-byte.
  `CRIT1.SECURE_BOOT_ENABLE` is **not** set and secure boot itself is
  therefore still unvalidated -- that fuse is irreversible, permanently
  disables the RISC-V cores, and must be proven before the BOOTSEL
  fuses rather than after. See [SECUREBOOT.md](SECUREBOOT.md).
- **Four boards** -- `tiny2350`, `xiao_rp2350`,
  `waveshare_rp2350_lcd_1_47`, `spotpear_rp2350_lcd_1_28` build but have
  never run, for want of the hardware. "It builds" is the only claim
  anyone can make about them, so `tools/host-tests.sh` now actually makes it
  rather than leaving it asserted here: all five boards build in both
  ports, verified 2026-08-26. (Since then the Tiny 2350 has run every
  image in the 2026-09-15 to 09-17 sections above.)
