# Secure boot

RP2350 secure boot makes the mask ROM verify the **bootloader** against
a key fingerprint burned into OTP. This document is both the record of
enabling it on a token and the procedure for doing it again: the two
keys and what each protects, the production key ceremony, the staged
provisioning script, the ordering rule that keeps a mistake
recoverable, and what the fuses cost permanently. It is for whoever
provisions tokens, and assumes the DFU bootloader of [DFU.md](DFU.md)
is built and working; [GETTING-STARTED.md](GETTING-STARTED.md) and
[BUILD.md](BUILD.md) cover everything before that. It is the layer
underneath DFU: DFU decides what the *bootloader* will install, secure
boot decides what the *ROM* will run.

Contents:

- [Two keys, and why](#two-keys-and-why)
- [Production key ceremony](#production-key-ceremony)
- [What `picotool seal` gives you](#what-picotool-seal-gives-you)
- [The lower half of the chain is already enforcing](#the-lower-half-of-the-chain-is-already-enforcing)
- [Provisioning, in stages](#provisioning-in-stages)
- [Ordering: secure boot before the BOOTSEL fuses, never after](#ordering-secure-boot-before-the-bootsel-fuses-never-after)
- [The BOOTSEL fuses, and the trap in testing them](#the-bootsel-fuses-and-the-trap-in-testing-them)
- [What it costs, permanently](#what-it-costs-permanently)
- [What it does and does not protect](#what-it-does-and-does-not-protect)
- [Recovery](#recovery)
- [See also](#see-also)

> **Status: enabled and enforcing.** Burned on a Tiny 2350 (chipid
> `0x764d62245aa0b134`) on 2026-09-01 and verified: `CRIT1 = 0x000001`,
> `SECURE_BOOT_ENABLE = 1`, `available cpus: ARM` -- the RISC-V cores are
> permanently gone on that part, which is the unambiguous sign it took.
> The sealed bootloader passes ROM verification, the token boots, the
> conformance suite (an external CTAP 2.1 suite, not part of this
> repository) run for `-52` gives 76/0 with a real ML-DSA-65 signature,
> and the DFU runtime interface still works. `BOOTKEY0` sits at OTP row
> `0x0080` with `KEY_VALID = 1`.
>
> The `BOOT_FLAGS0` `DISABLE_BOOTSEL_*` fuses are deliberately still
> clear, so BOOTSEL remains as a recovery path.

> WARNING: **After burning, `picotool info` lies until a hard reset.** It will
> report `secure boot: 0` and `available cpus: ARM, RISC-V` even though
> the fuse is set, because the CRIT flags are latched at boot and the
> running chip still reflects pre-burn state. Read the OTP row itself --
> `picotool otp get CRIT1` -- and `picotool reboot -a` before believing
> the info line. Checking only `picotool info` would lead you to
> conclude the burn failed and try again.

**Programming the key is idempotent.** OTP bits only go 0->1, so
re-running `key` against a board that already has the same hash is a
no-op; it re-verifies rather than failing. That matters because the
verification is worth repeating and should never be something you avoid
running twice.

## Two keys, and why

This is the part that most often gets confused, because the token
carries two ECDSA keys on two different curves doing two different
jobs.

| | curve | file | who verifies with it | what it protects |
|---|---|---|---|---|
| Boot key | **secp256k1** | `keys/pqf-dev-bootkey.pem` | the RP2350 mask ROM, against a hash in OTP | the **bootloader** |
| Firmware key | **P-256** | `keys/pqf-dev-fw.pem` | the bootloader, against `pqf_boot_pubkey.h` | the **app** |

The chain is: ROM -> bootloader -> app. The ROM authenticates the
bootloader against OTP; the bootloader authenticates the app against a
public key compiled into an image the ROM has already authenticated.
Unbroken, but note where the app's root of trust actually lives -- in
that embedded key, not in OTP. See
[DFU.md](DFU.md#how-this-composes-with-secure-boot-otp) for why
`rom_chain_image()` is not in the path.

Signing order per release is therefore: `picotool seal --sign`
(secp256k1, ROM layer) **then** `tools/pqf_sign.py sign` (P-256, DFU
envelope).

> **The checked-in keys are development keys**, and their private
> halves are in the repository on purpose so that dev builds reproduce
> without a ceremony. A board provisioned with either one has no secure
> boot at all -- it has a signature check that anybody can satisfy. The
> next section is how to get a real one, and what the tooling now
> refuses in the meantime.

## Production key ceremony

This is a process, not a build flag. The code changes below exist only
to make the process hard to skip; none of them can generate a key
safely for you, and none of them should be trusted to.

### Why the two keys are not equally recoverable

The asymmetry is the whole reason this section is long.

The **firmware key** (P-256) lives in `pqf_boot_pubkey.h`, compiled
into the bootloader. Replacing it means shipping a new bootloader, which
is inconvenient and entirely possible. If it leaks, you rotate.

The **boot key** (secp256k1) is different in kind. Its hash goes into
OTP, which is one-way, and there is one usable slot. There is no
rotation and no recovery:

- **Lose the private half** and no further bootloader can ever be
  installed on those parts. Every board provisioned with it is frozen at
  whatever bootloader it has, permanently.
- **Leak the private half** and every board provisioned with it will
  boot an attacker's bootloader forever. You cannot revoke it, because
  the thing that would have to accept the revocation is the thing the
  attacker now controls.

A boot key is therefore closer to a factory master than to a signing
key. Treat losing it and leaking it as equally terminal, because they
are.

### The ceremony

Do this on a machine that **does not have this repository checked out**.
That is not ritual: the guards in this repo are content-based and
best-effort, and the reliable way not to commit a key is for the key
never to be on a machine that can commit.

**1. Generate, offline.** Two keys, two curves, two different jobs -- do
not reuse one for both.

```bash
umask 077
openssl ecparam -name secp256k1 -genkey -noout -out pqf-prod-bootkey.pem
openssl ecparam -name prime256v1 -genkey -noout -out pqf-prod-fw.pem
```

**2. Record the fingerprints before anything else.** These are what you
check against later, and they are the only way to tell two 256-bit keys
apart by eye.

```bash
for k in pqf-prod-bootkey.pem pqf-prod-fw.pem; do
  printf '%s  ' "$k"
  openssl ec -in "$k" -pubout -outform DER 2>/dev/null | tail -c 65 | shasum -a 256
done
```

Write them down somewhere that is not the same machine.

**3. Back the boot key up before it is used for anything.** Not after.
The failure this prevents is provisioning a production run against a key
whose only copy is on a laptop that then dies, and every one of those
boards is scrap. Two copies, two locations, offline, and **restore one
of them and check the fingerprint matches step 2** -- an untested backup
is not a backup.

**4. Export the firmware public key into the bootloader.** `--production`
makes this refuse a dev key rather than warn:

```bash
python3 tools/pqf_sign.py export-pubkey --production \
    --key /path/to/pqf-prod-fw.pem \
    --out c/bootloader/src/pqf_boot_pubkey.h --name prod-2026-09
```

The generated header records the fingerprint and sets
`PQF_BOOT_PUBKEY_IS_DEV 0`. The *public* half is meant to be committed --
that is the point of it.

**5. Build the bootloader with `-DPQF_PRODUCTION=1`.** With that
defined, `c/bootloader/src/main.c` fails to compile against a dev key:

```
#error "PQF_PRODUCTION build against the published dev signing key: ..."
```

A dev-keyed and a production-keyed bootloader are otherwise
indistinguishable -- same source, same size, same behaviour, right up
until someone else's image installs. That is why the check is a build
failure and not a warning in a log nobody reads.

**6. Provision.** `tools/secureboot-provision.sh` refuses to burn the
published dev boot key into OTP, because that burn is one-way:

```bash
PQF_SB_KEY=/path/to/pqf-prod-bootkey.pem \
PQF_SB_CHIPID=0x...  tools/secureboot-provision.sh seal
# ... then key, flash, enable -- see 'Provisioning, in stages' below
```

`PQF_SB_ALLOW_DEV_KEY=1` overrides that refusal, and exists for
deliberately spending a bench board -- which is how the staging in this
document was validated. It should never appear in a production runbook.

**7. Sign firmware with `--production`.**

```bash
python3 tools/pqf_sign.py sign --production \
    --key /path/to/pqf-prod-fw.pem --in build/bruce_c.bin \
    --out bruce_c.dfu --fw-version 3 --board feitian_rp2350
```

### Before a production run, check all four

Each of these has a command, so none of them is a matter of opinion:

| | check | expected |
|---|---|---|
| 1 | `pqf_sign.py fingerprint --key <fw key> --strict` | exits 0, "not a published dev key" |
| 2 | `grep IS_DEV c/bootloader/src/pqf_boot_pubkey.h` | `PQF_BOOT_PUBKEY_IS_DEV 0` |
| 3 | bootloader built with `-DPQF_PRODUCTION=1` | compiles; with a dev key it would not |
| 4 | `pqf_sign.py verify --key <fw key> --in <image>.dfu` | signature OK, no "published dev key" line |

Checks 1 and 4 are the ones that catch a key swapped in by a build
script; 2 and 3 catch a stale generated header, which is the more likely
mistake because nothing about it looks wrong.

### What is committed, and what never is

Committed: `c/bootloader/src/pqf_boot_pubkey.h` (public), the recorded
fingerprints, and the `bootkey0` hash from `picotool seal`. All public
by construction.

Never committed: either private half. Enforced two ways, both backstops
rather than controls --

- `.gitignore` drops `*.pem`, `*.key`, `*.p8` and all of `keys/` except
  the two dev keys named explicitly, so `git add -A` cannot pick one up;
- `tools/pre-commit-key-guard.sh` scans staged **content** for a PEM
  private-key header, which also catches `git add -f`, a key under an
  unmatched name, and a key pasted into a source file or test fixture.
  The two dev keys are allow-listed by exact blob hash. It runs from the
  repository's pre-commit hook together with the ASCII check
  ([BUILD.md, "ASCII only"](BUILD.md#ascii-only)); install both with:

  ```bash
  ln -sf ../../tools/pre-commit.sh .git/hooks/pre-commit
  ln -sf ../../tools/commit-msg.sh .git/hooks/commit-msg
  ```

Neither protects a key that is already on the machine. They convert one
class of accident into an error message; the control is step 3's offline
machine.

### If a production key is exposed

Assume disclosure the moment a key touches a networked machine, a shared
drive, a CI secret store, or a commit -- including a commit that was
amended away, because it was on disk in a working tree and may survive in
a reflog, a stash, or an editor's undo history.

- **Firmware key:** rotate. New key, `export-pubkey --production`, new
  bootloader, ship it as a normal update. Bump `fw_version` so
  anti-rollback refuses images signed by the old one.
- **Boot key:** there is no rotation. Boards already provisioned against
  it cannot be fixed by any update, because the ROM's trust anchor is in
  OTP. The only honest responses are recall or disclosure. This is the
  reason step 3 exists.

## What `picotool seal` gives you

One command produces both halves of the job -- the signed image and the
OTP rows that image requires:

```bash
picotool seal --sign <bootloader.uf2> <signed.uf2> <bootkey.pem> <otp.json>
```

The JSON comes out as three things:

```json
{
  "bootkey0":   [ ...32 bytes... ],
  "boot_flags1": { "key_valid": 1 },
  "crit1":       { "secure_boot_enable": 1 }
}
```

`bootkey0` is **SHA-256 of the raw 64-byte public point (x||y)** -- no
`0x04` prefix. That is worth knowing because it means you can verify
the hash yourself before burning it, which is the last moment a wrong
key is free to fix:

```bash
openssl ec -in keys/pqf-dev-bootkey.pem -pubout -outform DER \
  | tail -c 64 | shasum -a 256
```

`tools/secureboot-provision.sh seal` does this check automatically and
refuses to continue on a mismatch.

After programming, the `key` stage verifies again from the other side --
it dumps OTP and pulls `BOOTKEY0` back out of row `0x0080` to compare
against the key. Note that `picotool otp get BOOTKEY0` does **not**
print the stored bytes in a form worth diffing; the dump is 4 bytes per
row with ECC rows carrying two data bytes in the low half, which is what
the script reassembles. A hash that programmed with one bit wrong is
indistinguishable from a good one until secure boot is already on -- at
which point the board no longer boots -- so this readback is the last
honest check there is.

## The lower half of the chain is already enforcing

Secure boot adds the ROM->bootloader link. The bootloader->app link does
not need it and is testable today, with secure boot off -- which is
worth doing first, because a chain is only as good as the link nobody
checked. On the Tiny 2350, 2026-09-01:

| pushed over DFU | result |
|---|---|
| app signed with a **different P-256 key** | refused, `errVERIFY` (7) |
| app pinned to **another board** (`--board feitian_rp2350`) | refused, `errTARGET` (1) |
| app with a **byte flipped in the body**, signature untouched | refused, `errVERIFY` (7) |
| app with a **lower `fw_version`** (anti-rollback build) | refused, `errFILE` (2) |
| correctly signed app | installs, conformance suite 76/0 |

After all of those the app slot was untouched -- same `fw_version`, same
sha -- so the bootloader really is verifying before it commits, not
after.

So the embedded P-256 key in `pqf_boot_pubkey.h` is doing its job. What
secure boot adds on top is authentication of the image that *contains*
that key: without it, an attacker who can write flash can replace the
bootloader and its embedded key together, and the app chain verifies
perfectly against the attacker's own key. That is the gap
`CRIT1.SECURE_BOOT_ENABLE` closes, and it is the whole argument for
blowing it.

## Provisioning, in stages

Run these in order. Only the last one is terminal; the rest exist so
that a mistake is discovered while it is still free.

```bash
tools/secureboot-provision.sh seal      # no device -- sign, split rows, verify hash
tools/secureboot-provision.sh key       # one-way, but changes nothing about booting
tools/secureboot-provision.sh flash     # install the sealed bootloader; reversible
#   ... confirm by hand that the token boots and DFU still works ...
I_MEAN_IT=1 tools/secureboot-provision.sh enable   # TERMINAL
tools/secureboot-provision.sh verify
```

**Why `key` and `enable` are separate.** `picotool seal` emits all
three rows together, and loading that JSON in one shot programs the key
*and* turns secure boot on in the same operation -- so the first time
you learn whether the key is right is also the moment it stops
mattering. Splitting them means a board can carry a boot key
indefinitely while still booting anything; only `crit1` changes
behaviour. The script does the split.

**The chipid guard.** Set `PQF_SB_CHIPID` to the board you mean and
every writing stage refuses a different one. With several RP2350
boards plugged into the same host that guard is what keeps the burn
off the wrong one: `picotool info -a` reports a hardware-unique
`chipid:` -- use it, not the USB serial, which **randomises per boot**
on this firmware and identifies nothing.

```bash
export PQF_SB_CHIPID=0x764d62245aa0b134
```

## Ordering: secure boot before the BOOTSEL fuses, never after

DFU.md says the BOOTSEL fuses are blown "alongside secure boot", and
DFU does survive them -- the bootloader is ordinary flash-resident
firmware and its USB device has nothing to do with the ROM's NSBOOT
interfaces. But that survival is conditional, and the condition is
easy to miss:

> **DFU survives the BOOTSEL fuses only while the bootloader boots.
> Secure boot is precisely the thing that can stop the bootloader
> booting.**

Wrong key hash, unsealed image, wrong key slot, `KEY_VALID` on the
wrong bit -- any of those and the ROM refuses the bootloader once
secure boot is on. No bootloader means no DFU. If the BOOTSEL
interfaces are already fused off at that point there is no route into
the part at all, by any tool, permanently.

| order | after a secure-boot mistake |
|---|---|
| secure boot -> verify -> BOOTSEL fuses | BOOTSEL is alive; write a correctly sealed bootloader. **Recoverable.** |
| BOOTSEL fuses -> secure boot | nothing left to talk to. **Dead.** |

Same end state, and only one of them has a window where a single
mistake is unrecoverable. Do secure boot first, prove it boots, then
blow `BOOT_FLAGS0` bits 17/18/19 (`0x0E0000`).

> **`DISABLE_WATCHDOG_SCRATCH` is bit 16**, immediately below
> `DISABLE_BOOTSEL_USB_MSD_IFC` at 17. The app->bootloader "stay in DFU"
> handshake writes magic `"PQDF"` to watchdog scratch 2/3
> (`c/bootloader/src/main.c:95`), so bit 16 would take out the very
> path you are keeping. `0x0F0000` and `0x030000` both catch it.

## The BOOTSEL fuses, and the trap in testing them

Blown on the Tiny 2350 on 2026-09-02, after secure boot was proven:

```bash
picotool otp set BOOT_FLAGS0 0x0E0000
```

Bits 17/18/19 -- `DISABLE_BOOTSEL_USB_MSD_IFC`,
`DISABLE_BOOTSEL_USB_PICOBOOT_IFC`, `DISABLE_BOOTSEL_UART_BOOT`. Bit 16
(`DISABLE_WATCHDOG_SCRATCH`) stays clear; the read-back confirms it,
because that bit carries the app-to-bootloader DFU handshake.

**The central claim is now silicon-proven: DFU works with BOOTSEL fused
off.** A full `dfu-util -D` cycle -- detach, bootloader, install, app
back, conformance suite 76/0 -- with no mass-storage volume, no PICOBOOT and no
UART boot. `picotool` can no longer reach the board at all, which also
means the OTP can never be read from it again: take any record you want
*before* this write.

> WARNING: **Do not test this with `reboot bootsel`.** That was the obvious
> check and it takes the board off the bus. The ROM still *enters*
> BOOTSEL; the mode simply exposes nothing, so the device sits awake and
> invisible with nothing on the host able to reach it, and only a
> physical power cycle brings it back. Nothing is lost -- flash is
> intact and the app boots on replug -- but it is an avoidable trip to
> the board. Test it by observing that the volume and `picotool` are
> gone, not by asking the device to go there.

Both ports now refuse a BOOTSEL reboot on a fused part rather than
obeying it (`pqf_board_bootsel_available()` in the C port,
`bootsel_available()` in the Rust one). They read `BOOT_FLAGS0` bits
17/18 from OTP row `0x48` through the raw window at `0x4013_4000`. The
check belongs in the firmware because the host cannot know and any host
can send `CMD_REBOOT`. Verified on the fused board: the command is
refused, the token stays on the bus, and a warm reboot still works.
The opposite direction was closed on 2026-09-02 on a second, entirely
unfused RP2350 (chipid `0xc792ce67556a32e3`, `BOOT_FLAGS0 = 0x000000`,
secure boot off): both ports still **allow** a BOOTSEL reboot there --
the FIDO device goes away, the `RP2350` volume mounts, `picotool`
reaches it. So the guard is now proven in both directions rather than
only in the one the fused board could show.

## What it costs, permanently

- **The RISC-V cores die.** `CRIT1.SECURE_BOOT_ENABLE` disables
  Hazard3. A secured part is Arm-only, so the RISC-V and mixed-ISA
  builds become impossible on it -- those stay dev-bench configurations
  on unsecured boards.
- **Only images signed by that key will ever boot**, and the key hash
  cannot be changed. Losing the private key ends the part's life at its
  current bootloader.
- **OTP is one-way.** Nothing here can be undone, cleared, or reset.
  `picotool` cannot help; there is no erase.

## What it does and does not protect

**Does:** an attacker with physical access can put the token in BOOTSEL
(if left enabled) and write whatever they like -- and it will not boot.
That is the actual answer to firmware replacement, and it is why
disabling BOOTSEL is hardening rather than the mechanism.

**Does not:** it says nothing about credential confidentiality. The
flash-store master keys still live in plain flash, not in OTP key
slots. Secure boot stops someone *replacing* the firmware; it does not
stop someone *reading* the part if debug is still enabled. Consider
`DEBUGEN` and OTP page locks separately.

## Recovery

| symptom | fix |
|---|---|
| Sealed bootloader will not boot, secure boot **off** | BOOTSEL, reflash. Nothing lost. |
| Sealed bootloader will not boot, secure boot **on**, BOOTSEL alive | BOOTSEL, write a correctly sealed bootloader with the same key. |
| Same, BOOTSEL fused off | None. The part is finished. |
| Wrong key programmed, secure boot off | `bootkey1..3` remain; seal against a different slot and set the matching `KEY_VALID` bit. Mark the bad slot `KEY_INVALID`. |
| App fails verification | Not a secure-boot problem -- the bootloader stays in DFU mode. Push a valid image. |

The fourth row is the reason to leave the other three boot key slots
unprogrammed until you need them, and the reason `KEY_INVALID` exists.

## See also

- [DFU.md](DFU.md) -- the update path secure boot sits underneath
- [TESTING.md](TESTING.md) -- silicon validation status
- `tools/secureboot-provision.sh` -- the staged script this documents
