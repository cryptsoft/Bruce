# Contributing

This page is for anyone sending a change to Bruce. It assumes the
tools from [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md); the
build reference is [docs/BUILD.md](docs/BUILD.md) and the test
procedures are in [docs/TESTING.md](docs/TESTING.md).

## Licence

The project is Apache-2.0 ([LICENSE](LICENSE)). By submitting a change
you agree that it is contributed under that licence, as section 5 of
the Apache License provides; there is no separate contributor
agreement. New first-party files carry the same two-line header the
existing ones do:

```
// Copyright <year> <you or your organisation>
// SPDX-License-Identifier: Apache-2.0
```

Third-party code keeps the licence it came with and gets an entry in
[THIRD_PARTY.md](THIRD_PARTY.md); nothing copyleft goes into a firmware
image.

## Before the first commit: install the hooks

Two hooks keep the tree in the state the tools expect. Install them
once per clone:

```bash
ln -sf ../../tools/pre-commit.sh .git/hooks/pre-commit
```

```bash
ln -sf ../../tools/commit-msg.sh .git/hooks/commit-msg
```

- `pre-commit` runs `tools/pre-commit-key-guard.sh`, which refuses a
  commit whose staged content contains a private key (the two published
  development keys under `keys/` are allow-listed by hash), and
  `tools/ascii-check.sh --staged`.
- `commit-msg` refuses a non-ASCII commit message.

## ASCII only

Every text file in this repository is plain ASCII: source, docs,
scripts, build files and commit messages. Write `--` for a dash, `->`
for an arrow, straight quotes, `x` for a multiplication sign, and
`us`, `ohm`, `deg` for units. [docs/BUILD.md, "ASCII only"](docs/BUILD.md#ascii-only)
has the full substitution list and the reason: every byte reads the
same on a serial console, in a hex dump and under any locale.

## Commit messages

Sentence case, a subject of about 70 characters that says what changed,
a blank line, then a body that says why. No trailers that name tools or
collaborators. Match the tone of `git log`.

## What to run before a pull request

Everything that needs no board, in one command:

```bash
tools/host-tests.sh
```

It runs every Rust host suite with its feature variants, builds the
firmware for both instruction sets and every board profile, runs the C
firmware, bootloader and gadget host suites, the signing-tool key
guards and the ASCII sweep. `tools/host-tests.sh rust` or `c` runs
half. The C half needs a pico-sdk checkout with its `tinyusb` and
`lwip` submodules (`PICO_SDK_PATH`, default `~/pico-sdk`).

The formatter and the licence audit; CI fails a change that is not
`rustfmt`-clean:

```bash
cargo fmt --all && (cd crates/fw-secure && cargo fmt) && (cd crates/fw-nonsecure && cargo fmt)
```

```bash
cargo deny check
```

A change that touches user presence, the reboot path, flashing, or the
USB-C token procedure also needs a run on silicon, recorded as a dated
entry in [docs/TESTING.md](docs/TESTING.md), the way every existing
entry is. CI runs the host checks on every pull request; it cannot
stand in for the board.

## Conventions that are easy to miss

- Both ports must stay wire-compatible: the credential id layout, the
  HMAC domain labels ([docs/HMAC-DOMAINS.md](docs/HMAC-DOMAINS.md)), the
  CTAP command surface and the error codes. A change to one port is a
  change to both.
- The vendored trees (`crates/bc-rust-mini/`, `c/firmware/openssl-mini/`)
  are refreshed by their documented procedures, not edited by hand;
  `c/firmware/openssl-mini/README.md` says where the one deliberate
  exception lives.
- Never put a production key in this repository, on any branch. The
  guards are backstops; the control is an offline machine
  ([docs/SECUREBOOT.md](docs/SECUREBOOT.md), "Production key ceremony").
- Security problems go through [SECURITY.md](SECURITY.md), not a public
  issue.
