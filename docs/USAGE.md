# Usage

The user's reference for a built and flashed `bruce` token, either
firmware: what the device shows on first boot, every `getInfo` field,
every LED state, the PIN rules, the host-side commands from the in-tree
client examples, and the browser WebAuthn flows. It assumes the token
is already running -- [GETTING-STARTED.md](GETTING-STARTED.md) is the
path from an empty machine to that point, [BUILD.md](BUILD.md) the
build options and [FLASHING.md](FLASHING.md) the per-board flashing
detail.

Contents:

- [First boot](#first-boot)
- [Inspecting the device](#inspecting-the-device)
- [Checking which entropy source is live](#checking-which-entropy-source-is-live)
- [LED state reference](#led-state-reference)
- [Confirming user presence (the button)](#confirming-user-presence-the-button)
- [Setting a PIN](#setting-a-pin)
- [Factory reset](#factory-reset)
- [Wink](#wink)
- [Rebooting into BOOTSEL from the host](#rebooting-into-bootsel-from-the-host)
- [Browser WebAuthn](#browser-webauthn)
- [Troubleshooting](#troubleshooting)

## First boot

After `./flash.sh` (`picotool load -x bruce.uf2`) the device should:

1. Re-enumerate on USB within ~1 s. The manufacturer string is
   `bruce` on every image; the Rust firmware's product string names
   the board (`Tiny 2350 PQC`, `XIAO RP2350 PQC`, `Feitian RP2350 PQC`,
   `Feitian USB-C PQC`, `RP2350-LCD-1.47 PQC`, `RP2350-LCD-1.28 PQC`),
   the C firmware's is `Bruce (C port)` on every board. (The
   Feitian RP2350 USB-C token is not flashed with `./flash.sh`; see
   [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token).)
2. Show the board's idle heartbeat -- on the Tiny 2350 a **blue LED
   blinking about once a second**, on the XIAO an orange blink, on both Feitians a
   green blink -- indicating the main loop is alive. (On the two LCD
   boards -- Waveshare 1.47", Spotpear 1.28" -- there's no discrete LED;
   the stats panel lights up instead, and its uptime counter ticking
   once a second is the heartbeat. The C port does not drive the LCDs,
   so on those boards a C image shows nothing until you probe it.)

If the heartbeat LED is steady on or off after enumeration (or an LCD board's panel stays dark / frozen), the firmware has panicked or hung. Power-cycle and reflash; a dark device right after a flash is usually the intermittent post-flash failure described in [FLASHING.md](FLASHING.md#intermittent-dark-device-after-flashing-erase-first), not a bug in the build.

The `probe` example of the in-tree client (`crates/ctaphid-client`, crate `pqf-ctaphid`) is the most direct way to talk to the device. It is read-only: it never writes device state. [GETTING-STARTED.md, section 8](GETTING-STARTED.md#8-check-that-it-works) walks through it and the register / sign examples; the short form is:

```bash
$ ./client.sh probe
Found 1 FIDO HID device(s):
  <path> cafe:f1d0 Some("Bruce (C port)")
INIT ok: cid=0x00000001 caps=0x0d ver=0.1.0
  caps:  cbor=true wink=true nmsg=true
PING echo verified (27 bytes)
authenticatorGetInfo:
  versions:                  ["FIDO_2_0", "FIDO_2_1"]
  ...
```

The path on the left is platform-specific; a Rust image shows `cafe:f1d0 Some("Tiny 2350 PQC")` (or the other board names above). The examples take no device argument, so detach any other FIDO token when more than one is attached.

> **This project uses no third-party FIDO client.** The firmware is developed
> and tested against the in-tree client (`crates/ctaphid-client`, crate
> `pqf-ctaphid`, and its examples), the in-tree `c/hid` transport, and an
> external CTAP 2.1 conformance suite. If something you need is missing from
> the examples, the fix is to add it there.

## Inspecting the device

The `probe` example performs the CTAPHID INIT handshake, round-trips a PING, and pretty-prints the whole `authenticatorGetInfo` map. A healthy build reports:

| Field | Healthy value | What it means |
| --- | --- | --- |
| INIT capability flags | `WINK`, `CBOR`, `NMSG` (`0x0d`) | Wink supported, CTAP2 supported, CTAP1/U2F deliberately off at the transport |
| `0x01 versions` | `FIDO_2_0`, `FIDO_2_1` | Both advertised |
| `0x02 extensions` | `credBlob`, `credProtect`, `hmac-secret`, `largeBlobKey`, `minPinLength` | All five advertised by name |
| `0x03 aaguid` | `ef80634d...6a0b` | This project's own id (default). Different if you built with `BRUCE_AAGUID=...` |
| `0x04 options` | `rk`, `up`, `credMgmt`, `authnrCfg`, `largeBlobs`, `pinUvAuthToken`, `setMinPINLength`, plus `clientPin` / `alwaysUv` | `clientPin` is false until you set a PIN. `ep` is deliberately absent |
| `0x05 maxMsgSize` | `7609` | The CTAP HID structural ceiling (`57 + 128 x 59`), needed for ML-DSA-87 hybrid responses |
| `0x06 pinUvAuthProtocols` | `1, 2` | Both protocols advertised |
| `0x08 maxCredentialIdLength` | `161` | The compact encrypted credentialID (carries the credProtect policy) |
| `0x0a algorithms` | `-56`, `-55`, `-54`, then `-7` | All three composite PQ/T hybrid ids are advertised whichever ML-DSA variant you built, so this list does **not** tell you which one is compiled in. `-8` appears only in an `ed25519` build |
| `0x0d minPINLength` | `4` | The floor `setPIN` enforces |
| `0x0f maxCredBlobLength` | `32` | Max `credBlob` per credential |
| `0x14 remainingDiscoverableCredentials` | counts down from `6` (Rust) / `7` (C) in a default build; from `6 + 7N` / `7 + 7N` in one built with `N` extra credential sectors (`RK_SECTORS=N`, see [BUILD.md](BUILD.md#axis-7-optional-discoverable-credential-capacity)) | Free resident-credential slots |

If anything looks wrong, double-check the build (see [BUILD.md](BUILD.md)).

## Checking which entropy source is live

A token with a quantum RNG on its I2C bus draws every random byte from it; without one it uses the RP2350's on-die TRNG. The bytes look the same either way, so ask the token:

```bash
make -C c/hid rng && ./c/hid/rng
```

It prints `source: QRNG` while the chip is live; `source: TRNG -- ... LOST` if a chip answered at boot and has since been unplugged or failed (reconnect it and reboot the token -- the probe runs at power-up); or `source: TRNG -- no QRNG answered at boot`. The `served:` line splits the bytes drawn since boot between the two sources and carries the QRNG's error counters, and the timing line corroborates the answer: a KiB takes about 330 ms over the QRNG's 100 kHz bus and a few milliseconds from the TRNG. The C firmware prints the same on its serial port as the `[rng]` heartbeat line (`screen /dev/cu.usbmodem*1 115200`).

## LED state reference

On the Tiny 2350, the three on-board LEDs (red GP18, green GP19, blue GP20, all active-low) encode device state (the XIAO and both Feitians OR-merge all three onto their single GP25 LED; the LCD boards show the same states as text on their stats panel):

| LEDs                                     | Meaning                                                                             |
| ---                                      | ---                                                                                 |
| Blue blinks about once a second          | Idle, ready, USB enumerated                                                         |
| Red on                                   | CTAP2 CBOR command in flight. The heartbeat pauses while a command runs, so blue holds whatever state it was in: purple if it was on |
| Green blinks fast (~5 Hz), red and blue off | **Waiting for you to touch the button** (boards with a presence input only -- see below) |
| Green on (1 s) then off                  | Wink -- a host sent CTAPHID `CMD_WINK` asking the device to identify itself         |
| All LEDs off                             | Device hung / panicked -- power-cycle                                                |

If you want a richer signal, the panic handler can be replaced with one that strobes the red LED at a distinct frequency -- see the comment near `panic-halt` in `Cargo.toml`.

## Confirming user presence (the button)

On the three boards with a presence input, every register
(MakeCredential) and login (GetAssertion) waits for a **physical
touch** before signing -- the browser shows "touch your security key"
and the LED blinks fast:

  - **Tiny 2350**: press the **BOOT button** -- or, if your unit has one
    wired, touch the GP0 pad / press the GP0 switch. One caveat: keep your
    finger OFF the pad while plugging the device in -- the firmware
    learns the pad's untouched level during the first second of boot
    (see [HARDWARE.md](HARDWARE.md#user-presence-buttons)).
  - **Feitian RP2350**: tap the board's one button (yes, the BOOTSEL
    button -- at runtime it's just a button; it only enters the
    bootloader when held while plugging in).
  - **Feitian RP2350 USB-C token**: touch the pad. (The pad is read
    the same way as the Feitian RP2350's button, confirmed on one
    production token -- if a touch never registers, see
    [FLASHING.md, what is not yet known about the token](FLASHING.md#what-is-not-yet-known-about-this-token).)

The gesture must be a fresh press -- holding the button down from
before the request does not count; release and press again. If you
don't touch within 10 seconds the operation fails with
`CTAP2_ERR_OPERATION_DENIED` (0x27) and the browser reports the
ceremony as cancelled/failed -- just retry.

The other boards (XIAO, both LCD boards) have no readable button and
confirm presence automatically after a short LED-blink window.

## Setting a PIN

```bash
$ ./client.sh pin_set
```

Browsers set a PIN through their own WebAuthn UI; the `pin_set` example (which
sets the PIN `1234` on a device with no PIN) is the command-line route. The constraints the firmware enforces:

- **Minimum length 4 bytes (UTF-8)** -- `minPINLength = 4` in `getInfo`. Shorter PINs return `CTAP2_ERR_PIN_POLICY_VIOLATION`.
- **Maximum length 63 bytes** -- the CTAP wire encoding pads to 64 bytes with trailing zeros, so 63 bytes max payload.
- **Initial setup only when no PIN is set** -- once one exists, only `changePIN` (with the current PIN) can replace it.

After setting a PIN, `getInfo` flips `noclientPin` to `clientPin`, and MakeCredential / GetAssertion now require a `pinUvAuthParam` (otherwise we respond `ERR_PUAT_REQUIRED = 0x36`).

### Changing the PIN

Browsers drive `changePIN` from their security-key settings. On the command
line, the conformance suite (an external CTAP 2.1 conformance suite, not part
of this repository), run in its extended mode with the current PIN, exercises
a full `changePIN` round trip and restores the original PIN afterwards. The
in-tree examples have no `changePIN` command.

### PIN retry counter

Eight attempts (`PIN_MAX_RETRIES = 8`). Each wrong guess decrements; a correct guess resets to 8. At 0 the device refuses every PIN-authenticated request until `authenticatorReset`.

The retry counter is enforced *before* checking the supplied PIN, so a guessing attacker has to count their own attempts (we don't give them a budget).

On top of that persistent counter there is a **volatile** one: three wrong
PINs in a single power cycle return `CTAP2_ERR_PIN_AUTH_BLOCKED` (0x34) and
the device refuses further PIN traffic until it is replugged. `getPinRetries`
reports that state as the `powerCycleState` Boolean.

## Factory reset

```bash
$ ./client.sh reset
```

Wipes every credential slot AND rotates the two credentialID master keys, so any credentialID an RP has cached becomes un-decryptable (HMAC fails). The device returns to a fresh state -- no PIN, no credentials, `clientPin` false.

Reset requires a **test of user presence**: touch the button when the LED
starts blinking. Without a confirmed gesture the device refuses with
`CTAP2_ERR_OPERATION_DENIED` (0x27) and leaves the PIN and credentials
intact. The CTAP 2.1 spec additionally wants Reset gated on "power-on within
10 seconds" -- we relax that one (no real-time clock), so possession plus a
deliberate touch is the gate.

## Wink

A CTAP HID `CMD_WINK` (`0x08`) flashes the green LED for 1 second. Useful
when you have several CTAP devices plugged in and need to identify which is
which. It requires no PIN and no credential.

The in-tree client ships no dedicated wink example. The firmware advertises the
`WINK` capability bit in its INIT reply, which the `probe` example shows, and
any host that
sends the command drives it.

## Rebooting into BOOTSEL from the host

You can put the token into the RP2350 bootloader (for reflashing) or warm-reboot it **without touching a BOOTSEL button**, using the in-tree reboot CLI:

```bash
$ make -C c/hid reboot          # one-time build
$ c/hid/reboot bootsel          # -> BOOTSEL (USB mass storage / DFU)
$ c/hid/reboot warm             # -> warm reboot back into the firmware
$ c/hid/reboot bootsel Bruce # disambiguate when several tokens are attached
```

(Rust equivalent: `cargo run -p pqf-ctaphid --example reboot -- bootsel`.)

Whether the reboot waits for a touch is a **per-board policy**. On the Tiny 2350 and the Feitian RP2350 -- the two boards with both a button and a power-on BOOTSEL -- it is gated like a WebAuthn touch: after you run it, the status LED blinks and you have ~10 s to press the **BOOT / BOOTSEL button** (the Tiny's GP0 pad also counts on the Rust firmware), unless the image was built `PQF_REBOOT_NO_UP` / `reboot_no_up` (flash-station use). Every other board reboots at once: the XIAO and the LCD boards have nothing to press, and the Feitian RP2350 USB-C token, whose only way into BOOTSEL is this command, is never gated, by design. `c/hid/reboot --list` shows which tokens are attached without sending anything. Full details -- including the warning that a token with no power-on BOOTSEL can be locked out of it by the wrong image -- are in [`docs/REBOOT.md`](REBOOT.md), and the USB-C token's flashing procedure is [the USB-C token section of `docs/FLASHING.md`](FLASHING.md#the-feitian-usb-c-token).

## Browser WebAuthn

Once a PIN is set, the device should work as a regular FIDO2 / WebAuthn authenticator on any HTTPS site that uses WebAuthn.

### Firefox

`about:preferences#privacy` -> scroll to *Logins and Passwords* -> *Security Keys*. Firefox accepted hybrid PQC credentials byte-for-byte against our default ML-DSA-65 build while it was labelled `-52` -- it was the first browser the firmware passed end-to-end against. Firefox releases that follow RFC 9864 then read `-52` as ESP512 and refused the key. Under `-55` Firefox registers and signs in with the hybrid credential again, but only when the relying party offers the build's id on its own: offered `-56, -55, -54, -7` together, Firefox drops the hybrid ids and the token makes an ES256 credential. See [TESTING.md](TESTING.md#2026-09-30-composite-cose-ids-relabelled-to-draft--04).

### Chrome on macOS

`chrome://settings/securityKeys` or directly in any `navigator.credentials.create(...)` flow. Chrome's WebAuthn UI prompts for the PIN; the device returns the assertion under the PIN protocol Chrome picks (v2 if you advertised both in `getInfo`, which we do).

### Local testing

A relying party that accepts the composite COSE algorithms `-54 / -55 / -56` and does not filter on AAGUID can register the default build (mldsa65 + default AAGUID) out of the box. One that only trusts the OpenSK PQC reference list needs a build with `BRUCE_AAGUID` set to the OpenSK sample id ([BUILD.md](BUILD.md#aaguid-override)).

For local testing without such an RP, [webauthn.io](https://webauthn.io) supports basic ECDSA but rejects the hybrid PQC alg as unsupported -- useful for confirming the ES256 fallback works (rebuild with no hybrid feature isn't currently supported; the device always advertises hybrid alongside ES256).

## Troubleshooting

### "Identity could not be verified" in Chrome after entering a PIN

Make sure you're running the latest build -- older builds (before commit `c1d4037`) didn't accept v2 `pinUvAuthParam` in MakeCredential / GetAssertion, and Chrome picks v2 when offered.

### Chrome WebAuthn flow hangs / times out during MakeCredential

Pre-Phase-1 firmware (before commit `85c4a6a`) had the hybrid sign on core 0 -- it held the CPU for ~2 s and Chrome's CTAP HID watchdog dropped the transaction. Confirm the INIT capability flags read `WINK`, `CBOR`, `NMSG` (`0x0d`) in the `probe` example's output, and that the LED goes red+purple during signing.

### Device doesn't enter BOOTSEL when I press the button

The Tiny 2350 only enters BOOTSEL when BOOT is held **during reset**:

- For a virgin board: hold BOOT, plug in.
- For a flashed board: hold BOOT, tap RESET (or unplug + replug while holding BOOT).

Pressing BOOT while the firmware is running does not enter BOOTSEL: the firmware samples it through the QSPI chip-select line as the user-presence button (see [HARDWARE.md](HARDWARE.md#user-presence-buttons)), and a runtime press has no reset side effect.

On firmware that has `CTAPHID_CMD_REBOOT`, you don't need the button at all: `c/hid/reboot bootsel` reboots it into BOOTSEL from the host (on the Tiny 2350 and the Feitian RP2350, confirm with a button press / pad tap within ~10 s unless it's a `reboot_no_up` build; the other boards need no touch). See ["Rebooting into BOOTSEL from the host"](#rebooting-into-bootsel-from-the-host) above and [`docs/REBOOT.md`](REBOOT.md). Note a token with no power-on BOOTSEL -- the Feitian RP2350 USB-C token -- whose firmware lacks this command or cannot answer it has **no** BOOTSEL path -- see the warning in that doc.

### `picotool reboot -u -f` says "No accessible RP-series devices in BOOTSEL mode were found"

Expected after the first auto-reboot succeeds in a power cycle (see [FLASHING.md](FLASHING.md#picotool-reboot--u--f-reports-no-accessible-rp-series-devices-in-bootsel-mode-were-found)). A manual BOOT+RESET cycle (or `c/hid/reboot bootsel`) and `picotool load -x` will work.

### "PIN blocked" message

Eight wrong guesses exhausted the retry counter. The only recovery is `authenticatorReset` (the `reset` example), which also rotates the credentialID master keys, so all your stored credentials become unusable. Re-register with each RP from scratch.

### Credentials I made before flashing a new build don't work anymore

The flash schema is versioned (see the [flash schema table](ARCHITECTURE.md#flash-schema-evolution)). Bumping the version invalidates the sector, which regenerates the credentialID master keys and wipes the resident-credential index -- old credentialIDs become un-decryptable. Re-register.

### The `probe` example shows `pinUvAuthProtocols: 1` only (no 2)

You're running a build from before PIN/UV auth protocol 2 was added (phase 5 in the Rust firmware's history; see the phase table in [TESTING.md](TESTING.md#phase-smoke-tests)). Rebuild from the current source and reflash.

### The `probe` example shows `maxCredentialIdLength: 32`

You're running a build from before the stateless 161-byte credentialID (phase 2: earlier builds used random 32-byte credentialIDs with the keys stored in flash). Rebuild from the current source and reflash. Re-register all credentials.

### Device disappears from the `probe` example after a few seconds

The host's USB stack is dropping the device. On macOS this can happen when *another* CTAP HID device is plugged in (system handoff). Unplug the other CTAPHID device or reboot the host.

### Wink doesn't flash anything

Confirm the INIT capability flags include `WINK` in the `probe` example's output -- that bit means the firmware advertises it. If the bit is set but the LED doesn't flash, the panic handler may have fired during the request -- power-cycle and check for a stuck LED.
