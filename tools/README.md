# tools/

Everything here is a script or a small program with its own header
comment; this is the index. "Board" means an RP2350 running `bruce`
or sitting in BOOTSEL; "C toolchain" means `PICO_SDK_PATH`, `cmake` and
`arm-none-eabi-gcc` as set up in [GETTING-STARTED.md](../docs/GETTING-STARTED.md);
the Rust client examples need the host triple, as described in
[crates/ctaphid-client](../crates/ctaphid-client/README.md).
Anything that erases or reflashes a board says so in bold. Several
scripts need `c/hid/reboot`, the host-driven reboot CLI
(`make -C c/hid reboot`, [c/hid](../c/hid/README.md#reboot));
`c/hid/reboot --list` shows the tokens it can see and sends nothing.

## Build and flash helpers

The everyday ones live at the repository root:

- `../build.sh [board]` -- the Rust firmware -> `bruce.uf2`. Needs rustup
  and `picotool`. Knobs: `MLDSA=44|87`, `ED25519=1`, `SINGLE_CORE=1`,
  `REBOOT_NO_UP=1`.
- `../build-c.sh [board]` -- the C firmware -> `bruce-c.uf2`. Needs the C
  toolchain and a `picotool` matching the SDK. Same knobs, plus `RISCV=1` and
  `CMAKE_EXTRA="-D..."`.
- `../flash.sh [-y] [--board <id>] [file.uf2]` -- `picotool load -x` after naming
  the board the image was built for and asking; refuses a USB-C token image, a
  blank board until `--board` names it, and on a board carrying a USB-C image
  any image not marked `pqf-reboot=no-touch`. Board in BOOTSEL.
- `../client.sh <example> [args]` -- runs a `pqf-ctaphid` example for the host
  without spelling out the target triple; `../client.sh list` names them.
  **Overwrites the firmware**; a reflash of the same firmware keeps
  credentials and the PIN. Warns about an image whose reboot needs a button
  press (`pqf-reboot=touch`) and points a USB-C image at `flash-usbc.sh`;
  never use it on the Feitian RP2350 USB-C token.
- `../wipe.sh [-y] <board>` -- board in BOOTSEL; names the device it sees and asks. **Erases the whole flash**: credentials,
  master keys, PIN and firmware.
- `../build-tz.sh` -- the TrustZone-M Secure + Non-secure image pair; flashing
  them **overwrites the FIDO firmware**.
- `flash-fw.sh <elf> [required-symbol ...]` -- **flashes** a Rust ELF only if
  it contains the named symbols, so the wrong feature set is refused rather
  than flashed. Needs `arm-none-eabi-nm` (or `nm`), `picotool`; board in BOOTSEL.
- `flash-usbc.sh [--check] <file.uf2>` -- the only way to put an image on the
  Feitian RP2350 USB-C token, which has no way into boot mode but its own firmware.
  Refuses any UF2 not marked `pqf-board=feitian_rp2350_usbc` and
  `pqf-reboot=no-touch`, or not a plain Arm image at `0x10000000`; there is no
  override. Then **erases the first 2 MiB -- firmware, credentials and PIN**,
  **flashes** and verifies, and proves the way back into boot mode with no
  touch before it prints `PASS`. `--check` only inspects the file. Needs
  `picotool` >= 2.0, `perl`, `c/hid/reboot` (built if missing); the token, or
  a Feitian RP2350 for the rehearsal. The procedure is
  [the USB-C token section of FLASHING.md](../docs/FLASHING.md#the-feitian-usb-c-token).
- `tz/flash-tz.sh <fw-secure.elf> <fw-nonsecure.elf>` -- **flashes** a
  TrustZone pair with every step checked. Needs `picotool`, `c/hid/reboot`; board.
- `browser/flash.sh before|after` -- **flashes** the C firmware from before or
  after the largeBlobs parameter fix, for the browser check; refuses a board
  whose `picotool info` name is not this project's. Needs the C toolchain,
  `picotool`; board. `before` needs the development history, which this
  single-commit repository does not carry: here only `after` runs.

## Host test runners (no board)

- `host-tests.sh [rust|c]` -- every test that needs no token: the Rust crates
  on the host triple, the C firmware, bootloader and crypto suites, then the
  three checks below and `ascii-check.sh --all`. The C USB-descriptor tests
  need `PICO_SDK_PATH`.
- `mutate.sh rust|c <src-file> <suite> [pattern]` -- mutation testing: one
  small edit per site, rebuild, run the suite, list the survivors. Needs
  `python3` plus the toolchains `host-tests.sh` uses. Env: `PQF_MUT_OUT`,
  `PQF_MUT_MAX`.
- `test-key-guards.sh` -- the dev-key guards checked against the real keys in
  the tree. Needs `python3` with `cryptography`, `openssl`.
- `test-ascii-check.sh` -- the two ASCII hooks exercised in a scratch git repo.
- `test-flash-guards.sh` -- `../flash.sh`'s refusals and the flashes it must
  still allow, against a mock `picotool` on `PATH`. Needs nothing but bash.
- `annex_check.py --bootloader <bin> --app <bin>` -- replays the RP2350 boot
  ROM's block scan over a composed bootloader + RISC-V app image before it is
  flashed. `python3` standard library only.

## Silicon test drivers (need a board)

- `silicon-sweep.sh` -- both ports at ML-DSA 44, 65 and 87, each rebuilt,
  **flashed** and driven with `alg_roundtrip` and `pqc_roundtrip`; about half
  an hour. Needs both toolchains, `picotool`, `c/hid/reboot`; optional
  `PQF_CONFORMANCE_CMD` runs an external suite per configuration. Built with
  `PQF_TEST_NO_USER_BUTTON`, so it says nothing about the presence gate.
- `silicon-remaining.sh [gdb|gadget|trustzone|all]` -- the GDB stub, the
  TrustZone images and the USB network gadget. Needs the C toolchain,
  `picotool`, `gdb`; start in BOOTSEL. **Erases the flash between stages**,
  and the gadget firmware has no software way back: it **strands the token
  until BOOT + RESET**, which is why it runs last.
- `validate-wire-format.sh c|rust` -- **flashes** a `REBOOT_NO_UP` image of
  one port and runs the ceremonies behind the CTAP 2.1 wire-format
  corrections. Needs that port's toolchain, `picotool`, `c/hid/reboot`.
- `dfu-powerloss-test.sh <good.dfu> <other.dfu>` -- writes a staged image plus
  a pending install journal over BOOTSEL and checks what the next boot does
  with it. Needs a provisioned board (bootloader + app), images signed with
  `pqf_sign.py`, `picotool`, `python3`, `c/hid/reboot`. **Leaves the app slot
  holding whichever image the replay installed.**
- `tz/tz_counter_stress.sh [cycles]` -- reboots a TrustZone board repeatedly
  and checks the signature counter never rewinds (`tz_test --count`, one
  MakeCredential per cycle). Needs `c/hid/reboot`, `picotool`, cargo.
- `tz/Makefile`, `tz/tz_transport.c` -- `make -C tools/tz` builds
  `tz_transport`, a CTAPHID multi-frame check against the `TZ-NS` image on
  `c/hid`'s `libpqhid`; `make -C tools/tz tz_test ARGS=...` / `tz_cm ARGS=...`
  wrap the two Rust examples.
- `gadget-linux-check.sh` -- Linux only, as root: watches the USB network
  gadget enumerate and captures its DHCP exchange with `tcpdump`. Read-only.

## Signing and provisioning

- `pqf_sign.py keygen|export-pubkey|sign|verify|info|fingerprint` -- signs
  images for the DFU bootloader (`app.bin` -> `app.dfu`) and identifies keys.
  Needs `python3` with `cryptography`; no board. The published dev keys are
  not secret; `--production` turns the warning about them into a refusal.
- `secureboot-provision.sh seal|key|flash|enable|verify` -- RP2350 secure boot
  in stages. `seal` needs no device; the rest need a board, `picotool`,
  `python3` with `cryptography`, `openssl`, `c/hid/reboot`. `flash`
  **replaces the bootloader**; `key` **burns OTP** (one-way); **`enable` is
  terminal** and refuses without `I_MEAN_IT=1`. Read
  [SECUREBOOT.md](../docs/SECUREBOOT.md) first.

## Vendoring

- `vendor-bc-rust.sh [path-to-bc-rust-checkout]` -- refreshes
  `crates/bc-rust-mini` from a Bouncy Castle Rust checkout, records the
  upstream commit and transliterates the copied comments to ASCII with a
  fixed map, refusing anything it cannot map. Needs `python3`; no board. The
  only way that directory is meant to change.

## Repository hooks

- `pre-commit.sh` -- the pre-commit hook: runs the two guards below on the index.
- `pre-commit-key-guard.sh` -- refuses staged content carrying a PEM
  private-key header (checked by content, not filename); the two published
  dev keys are allow-listed by blob hash.
- `ascii-check.sh --staged | --all | FILE...` -- refuses non-ASCII bytes in
  text files, naming each as `file:line:column` with its code point. The
  tree is ASCII only ([BUILD.md](../docs/BUILD.md#ascii-only)).
- `commit-msg.sh` -- the commit message is ASCII only too.

Install once per clone; `git commit --no-verify` is the deliberate override:

```bash
ln -sf ../../tools/pre-commit.sh .git/hooks/pre-commit    # key guard + ASCII check on staged files
ln -sf ../../tools/commit-msg.sh .git/hooks/commit-msg    # ASCII check on the message
```

## udev rules (Linux)

- `udev/99-bruce.rules` -- lets an ordinary user open the token's HID
  interface (the client examples, `c/hid`, browsers) and lets `picotool` see
  the RP2350 in BOOTSEL:

```bash
sudo cp tools/udev/99-bruce.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger   # then replug the board
```

## Browser checks

- `browser/largeblob-check.html` -- drives `authenticatorLargeBlobs` through a
  real browser, the one client never written from this firmware. Needs
  `localhost` (a secure context) and a human for Chrome's security-key
  dialog; registers a credential on the token.
- `browser/serve.py <dir> <port> <result.json>` -- serves the page and
  collects the result it POSTs back with `?auto=1`. `python3` standard
  library only.
- `browser/flash.sh` -- see the flash helpers above;
  [`browser/README.md`](browser/README.md) has the method.

Nothing under "Host test runners", "Vendoring", "Repository hooks" or
`pqf_sign.py` touches a board. The client examples that change a token
(`reset`, `pin_set`, `tz_cm --wipe`, and every registration) are listed
in [crates/ctaphid-client](../crates/ctaphid-client/README.md#the-examples).
