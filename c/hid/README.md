# `libpqhid`: CTAP over USB HID in C, and the tools built on it

`libpqhid` is the C transport for talking to a FIDO authenticator over
USB HID, written from the CTAP specification's HID protocol section
(sec. 8.1 in CTAP 2.0 numbering, sec. 11.2 in CTAP 2.1). It is
self-contained: a platform-independent core (`pqhid.c`: framing,
reassembly, the INIT handshake, KEEPALIVE skipping) plus exactly one
per-OS backend behind the internal `pqhid_os.h` contract. No
dependencies beyond the operating system; every function returns
`PQFIDO_OK` or a negative `PQFIDO_ERR_*` code, and every buffer is
caller-owned.

The public header is `pqhid.h`:

- `pqhid_enumerate`, `pqhid_open` / `pqhid_close`, `pqhid_get_info`;
- the standard commands `pqhid_ping`, `pqhid_wink`, `pqhid_cbor`
  (CTAP2) and `pqhid_msg` (CTAP1 / U2F APDU passthrough);
- the `bruce` extensions: `pqhid_rng` (vendor 0x50), `pqhid_rng_status`
  (0x52), `pqhid_reboot` (0x51), and `pqhid_vendor` for any other
  command in the vendor range 0x40 to 0x7f (it rejects anything
  outside it, so it cannot forge a standard command).

The Rust counterpart is [`crates/ctaphid-client`](../../crates/ctaphid-client/README.md);
the two clients match the token the same way and behave the same.

## Platforms

The backend is chosen from `uname -s`; override with
`OS_BACKEND=linux|macos|windows`.

| OS | Backend | Consumers must link |
| --- | --- | --- |
| Linux | `pqhid_linux.c`: `/dev/hidraw` + `poll()` | nothing extra |
| macOS | `pqhid_macos.c`: IOKit `IOHIDManager` / `IOHIDDevice` | `-framework IOKit -framework CoreFoundation` |
| Windows (MINGW / MSYS) | `pqhid_windows.c`: SetupAPI + `hid.dll`, overlapped I/O, `bcrypt` | `-lhid -lsetupapi -lbcrypt` |

The Makefile adds those libraries to the tools it builds here; a
program of your own that links `libpqhid.a` adds them itself. On
Windows 10 1903 and later, opening a FIDO device needs an elevated
(Administrator) process; enumeration works unelevated. That is
Windows policy, not a library limitation. On Linux, ordinary users
need the udev rules in `tools/udev/`.

## Building

```bash
make -C c/hid            # libpqhid.a
make -C c/hid test       # builds and runs smoke: version + NULL-argument checks, no device needed
make -C c/hid reboot     # the reboot CLI
make -C c/hid rng        # the RNG CLI
```

`CFLAGS` defaults to `-O2 -Wall -Wextra -pedantic -std=c11` (plus
`-fPIC`); the library builds clean under it.

## `reboot`

Sends the vendor `CTAPHID_CMD_REBOOT` so a running token can be
reflashed without touching a button:

```bash
c/hid/reboot --list              # list the Bruce tokens it can see; sends nothing
c/hid/reboot                     # into BOOTSEL (USB mass storage / DFU)
c/hid/reboot bootsel
c/hid/reboot warm                # warm reboot back into the firmware
c/hid/reboot bootsel Bruce    # pick a token by product-string substring
c/hid/reboot warm Tiny           #   (needed when several tokens are attached)
```

`--list` (or `-l`) only enumerates. It prints one line per candidate,

```
found: Feitian USB-C PQC (vid=cafe pid=f1d0) path=<platform path, or n/a>
```

and exits 0, or prints `no Bruce token found` and exits 1. It never
opens a device, so it cannot reboot anything: it is the way to see
which token, and which firmware by its product string, is attached
before planning a reboot, and what scripts poll to see a token come
back (`tools/flash-usbc.sh` does, around every reboot it asks for).
It takes no other argument.

A candidate is a device with the FIDO product id `0xF1D0` (or
`0xF1DC`, the TrustZone Non-secure image) and either the manufacturer
string `bruce` or the placeholder vendor id `0xcafe` both firmware
ports use, so one binary drives both ports. The optional second argument narrows that by product-string
substring. With no match, or more than one, it refuses and exits 2
rather than guess; it never reboots a device that is not a `bruce`
token.

The reboot is gated behind a test of user presence on boards that have
one: press or touch the token within ~10 s or it is declined. Images
built with `REBOOT_NO_UP` and buttonless boards reboot immediately.
The token drops off the bus on success, so the tool is fire-and-forget:
exit 0 means the request reached the wire, and `picotool info` (or a
new `probe` after a warm reboot) confirms the rest. The full story,
including the warning about buttonless tokens that cannot be put into
BOOTSEL at all, is in [REBOOT.md](../../docs/REBOOT.md#host-clis).

## `rng`

Pulls bytes from the vendor RNG command, times the transfer, then asks
the token which entropy source served them:

```bash
c/hid/rng                # 1024 bytes from the only attached token
c/hid/rng 256            # a different count (1..1024)
c/hid/rng 1024 Tiny      # pick a token by product-string substring
```

QRNG output and on-die TRNG output are indistinguishable by
inspection, so `rng` uses `CTAPHID_CMD_RNG_STATUS` (0x52) to report
the source (QRNG live, QRNG lost since boot, TRNG, or a build without
QRNG support), the bytes served by each since boot and the QRNG's
error counters; the timing corroborates it (about 330 ms per KiB over
the QRNG's 100 kHz I2C bus, milliseconds from the TRNG). On firmware
without the status command it falls back to the timing alone. It
matches any FIDO device whose product string contains the substring
and refuses if more than one does. No presence gesture is involved.
See [USAGE.md](../../docs/USAGE.md#checking-which-entropy-source-is-live).

## The matching CBOR decoder

[`c/cbor`](../cbor/pqcbor.h) (`libpqcbor`, `make -C c/cbor`) is the
minimal RFC 8949 decoder for the responses `pqhid_cbor` returns:
attestation objects, authenticator data, COSE keys. It shares the
`PQFIDO_OK` / `PQFIDO_ERR_*` values with this header so codes pass
between the two unchanged. `tools/tz/tz_transport.c` is a third
program built on `libpqhid`, a multi-frame reassembly check against
the TrustZone image.
