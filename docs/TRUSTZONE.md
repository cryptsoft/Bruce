# TrustZone-M Secure / Non-secure split -- design & migration plan

The design, the migration plan and the record of carrying it out: the
Rust firmware split across the Cortex-M33's TrustZone-M boundary so that
the USB stack, CTAPHID framing and CBOR parsing run Non-secure with no
access to key material, while the keys, the TRNG, the flash store and
all crypto sit behind a small audited gateway. **State at the time of
writing: the split is implemented and validated on silicon.** The
milestones below -- M1 (boundary bring-up), M2 (NS owns USB, in the
steps M2a, M2b-1 and M2b-2), M3 (CBOR dispatch in NS), M4 (secrets fully
Secure, in the steps M4a to M4h) and M5 (gateway hardening) -- are all
done, and the sections after the milestone list are the record of what
was built and how it was proved. The two split images are separate
binaries (`crates/fw-secure`, `crates/fw-nonsecure`) built by
`./build-tz.sh`, excluded from the workspace and sharing no build with
`crates/firmware`, so the shipping FIDO firmware is unaffected. The test
tools are the `tz_test` and `tz_cm` examples of the in-tree client
(`pqf-ctaphid`, `crates/ctaphid-client`). The reader is assumed to know
the firmware's shape from [ARCHITECTURE.md](ARCHITECTURE.md) and to
have a working build from [GETTING-STARTED.md](GETTING-STARTED.md) and
[BUILD.md](BUILD.md); the silicon results are also summarised in
[TESTING.md](TESTING.md).

Build both images with `./build-tz.sh`; that script's header carries
the flashing order, which is load-NS-then-Secure and is not
interchangeable.

Contents:

- [Goal](#goal)
- [Why this is a project, not a patch](#why-this-is-a-project-not-a-patch)
- [Toolchain mechanism (the parts we assemble by hand)](#toolchain-mechanism-the-parts-we-assemble-by-hand)
- [Memory map (proposed -- refined during Milestone 1)](#memory-map-proposed----refined-during-milestone-1)
- [Gateway API (the audited S surface -- Milestone 4+)](#gateway-api-the-audited-s-surface----milestone-4)
- [Milestones (each flashed & verified before the next)](#milestones-each-flashed--verified-before-the-next)
- [Open decision (M2b): how NS drives the USB controller](#open-decision-m2b-how-ns-drives-the-usb-controller)
- [M4 as built](#m4-as-built)
- [References](#references)
- [M5 as built (silicon 2026-08-24)](#m5-as-built-silicon-2026-08-24)
- [M4 design note -- what still has to happen](#m4-design-note----what-still-has-to-happen)

## Goal

Split the firmware across the RP2350 Cortex-M33's ARM TrustZone-M
boundary so the large attacker-facing surface -- the USB stack, CTAPHID
framing, and CBOR parsing -- runs in the **Non-secure (NS)** world with
no access to key material, while the **Secure (S)** world holds the
master keys, the TRNG, the flash store, and all crypto, reachable only
through a small, audited set of gateway functions.

The security win: a memory-safety bug in the CBOR parser or USB path --
historically the highest-risk code in any authenticator (see
[notes/audit/AUDIT_FINDINGS.md](notes/audit/AUDIT_FINDINGS.md), where the C port's parser had exploitable stack
overflows) -- can no longer read or forge with the device keys. It can
only call the gateway, which validates every argument. This is defence
in depth on top of the ACCESSCTRL lockdown (originally a `security.rs`
module in the FIDO firmware; in the split the Secure image programs
ACCESSCTRL itself, `crates/fw-secure/src/main.rs`): that restricts
*masters*; this restricts *code*.

## Why this is a project, not a patch

Confirmed by research (2026-07, see "References"):

- **No Rust RP2350 TrustZone example exists anywhere.** pico-examples
  issue #708 confirms even the C SDK ships none; a Raspberry Pi
  engineer's answer was "roll your own." Trusted Firmware-M has an
  RP2350 port but it is C-only. We are on untrodden ground for Rust.
- **The CMSE features are nightly-only** (`cmse_nonsecure_entry`,
  rust #75835; `abi_cmse_nonsecure_call`, #81391 -- both still open).
  We already require nightly, so this is not a new constraint, but the
  features can churn.
- **`cortex-m-rt` has no S/NS split support** (rust-embedded/cortex-m
  #400, open since 2018): custom linker scripts and the handoff code
  are ours to write.
- **The bootrom hands off nothing.** It boots a single Secure image
  (the one whose `IMAGE_DEF` is `secure_exe()`) and configures only SAU
  region 7 (covering the bootrom). Our Secure image must set up every
  other SAU region and launch the NS world itself.

Because a wrong handoff produces an image that neither boots nor prints
anything, each milestone below is **proven on hardware before the next
begins**. We never move a secret across a boundary that has not already
been demonstrated working with a trivial payload.

## Toolchain mechanism (the parts we assemble by hand)

The canonical Rust workflow (Sascha Wise's nRF5340 write-up ports
directly; there is no RP2350-specific reference):

**Two crates, both `thumbv8m.main-none-eabihf`** (the `+trustzone-m`
target feature is implied by that triple):

- **Secure crate** -- boots first. Gateway functions are
  `#[no_mangle] pub extern "cmse-nonsecure-entry" fn ...` under
  `#![feature(cmse_nonsecure_entry)]`; the compiler emits an SG veneer
  and an `__acle_se_<name>` symbol for each. `build.rs` passes
  `-C link-arg=--cmse-implib -C link-arg=--out-implib=libnsclib.a` so
  the linker writes an import library of veneer addresses. The linker
  script places `.gnu.sgstubs` in the NSC-attributed flash region.
- **Non-secure crate** -- links `libnsclib.a`
  (`#[link(name = "nsclib")]`, `cargo:rustc-link-search`) and declares
  the gateways `extern "C"`; calls resolve to the SG veneers. If the
  Secure side ever needs to call *back* into NS (e.g. a progress
  callback), that needs `#![feature(abi_cmse_nonsecure_call)]` and
  `extern "cmse-nonsecure-call"` fn pointers -- avoided in the initial
  design to keep the boundary one-directional.

**Secure launch sequence** (all in Secure code, via `cortex-m` 0.7.7):

1. Program SAU regions (`cortex_m::peripheral::SAU::set_region`) -- see
   the memory map below. RP2350 has 8 SAU regions; #7 is the bootrom's.
2. Mark the `.gnu.sgstubs` range Non-secure-Callable.
3. `SCB` AIRCR: set `PRIS` (bit 14) and `BFHFNMINS` (bit 13).
4. Route NS interrupts via `NVIC` `ITNS` (which IRQs the NS world owns).
5. Write the NS vector-table base to `VTOR_NS` (`0xE002ED08`).
6. `msp::write_ns(ns_vt[0])` -- the NS initial stack pointer.
7. `cortex_m::asm::bx_ns(ns_vt[1] & !1)` -- branch to the NS reset
   handler; this is the S->NS transition.

The RP2350 also filters bus masters/peripherals independently via
`ACCESSCTRL` (there is no Nordic-style SPU) -- the peripherals the NS
world drives (USB, its GPIO, DMA if used) must be granted NS access in
ACCESSCTRL *and* fall in an SAU NS region.

## Memory map (proposed -- refined during Milestone 1)

Flash is **2 MiB** (`0x10000000`); RAM is 512 KiB (`0x20000000`).

An earlier version of this section said 4 MiB "(the chip is really
>=4 MiB)". That is wrong, and it is the same assumption that wedged the
DFU bootloader: a 2 MiB die addressed as 4 MiB aliases, so the staging
area landed on the bootloader's own vector table. `FLASH_DEVINFO` being
unprogrammed is not picotool being conservative -- 2 MiB is the truth.
Everything here therefore stays below `0x10200000`, and the M4d key
store takes the last sector under that line rather than anything above
it.

picotool refuses to load an image at/after offset `0x200000`, which is
correct behaviour for this die rather than a limitation to work around.

| Region            | Range                        | World | Notes                                   |
|-------------------|------------------------------|-------|-----------------------------------------|
| Secure flash      | `0x10000000`-`0x100F0000`    | S     | boots here; keys, crypto, flash store   |
| NSC veneers       | `0x100F0000`-`0x10100000`    | NSC   | `.gnu.sgstubs`; only SG instructions    |
| Non-secure flash  | `0x10100000`-`0x101F0000`    | NS    | USB / CTAPHID / CBOR                     |
| (unused)          | `0x101F0000`-`0x101FF000`    | S     | outside every SAU region                |
| Secure key store  | `0x101FF000`-`0x10200000`    | S     | M4d master key; SAU region 0 stops below |
| Secure RAM        | `0x20000000`-`0x20040000`    | S     | 256 KiB -- holds the crypto heap         |
| Non-secure RAM    | `0x20040000`-`0x20080000`    | NS    | 256 KiB -- NS heap / stacks              |

The heap (currently 256 KiB, shared) splits: the ML-DSA working set
stays Secure; the NS side needs its own smaller allocator for CBOR.
Flash regions will be resized once both images' real sizes and the
flash-size question are settled.

## Gateway API (the audited S surface -- Milestone 4+)

The NS world will reach the Secure world through only these calls (exact
signatures settle as they are migrated; all validate lengths/pointers
against the NS RAM range before touching Secure state):

- `sg_make_credential(req_ptr, req_len, resp_ptr, resp_cap) -> len`
- `sg_get_assertion(req_ptr, req_len, resp_ptr, resp_cap) -> len`
- `sg_get_info(resp_ptr, resp_cap) -> len`
- `sg_client_pin(req_ptr, req_len, resp_ptr, resp_cap) -> len`
- ... one per CTAP2 command, plus `sg_reset`, `sg_wink`.

Argument buffers live in NS RAM; the Secure side copies them in, works
on Secure copies, and copies the response back -- never dereferencing an
NS pointer that hasn't been range-checked (a "TT" `cmse::TestTarget`
check confirms the buffer is entirely NS-owned, defeating a caller that
passes a Secure address to trick the gateway into leaking).

## Milestones (each flashed & verified before the next)

> The milestone exit criteria below were originally written against a
> third-party Python CTAP client. That dependency was removed in `58cca62`;
> every criterion here is now driven by the in-tree client
> (`crates/ctaphid-client`) -- the `tz_test` and `tz_cm` examples of
> `pqf-ctaphid` -- so the project uses no third-party FIDO library.


- [x] **M1 -- Boundary bring-up. DONE (hardware-verified 2026-07-07).**
      Two minimal images. Secure sets up SAU + hands off; NS's only job
      is to blink the LED **by calling a Secure gateway veneer**
      (`sg_led_set(bool)` -- the GPIO stays Secure-owned). The NS blink
      ran on the Feitian, proving SAU attribution, the S->NS handoff, the
      SG veneer call, and the return all work end to end -- no FIDO code
      involved. Bring-up notes now baked into the crates: the ABI is
      `C-cmse-nonsecure-entry`; veneers pin via `--section-start`; the
      split stays under 2 MiB for the picotool/DEVINFO flash-size quirk;
      flash NS first (no `-x`) then Secure (`-x`).
- [ ] **M2 -- NS owns USB.** Split into two hardware-verified steps so
      the risky new mechanism (peripheral attribution across the
      boundary) is proven before the bulky USB stack rides it:
    - [x] **M2a -- NS reaches the USB peripheral. DONE (hardware-verified
          2026-07-07).** Secure un-resets the USB controller (it owns
          RESETS), grants NS access in `ACCESSCTRL.usbctrl`, and adds
          SAU region 3 marking the USB window (`0x50100000`+) Non-secure.
          NS then wrote and read back the USB DPRAM across the boundary
          (slow double-blink on the Feitian). Three RP2350 gotchas
          surfaced during bring-up, all now baked into `fw-secure`:
          **(1)** every `ACCESSCTRL` write needs the `0xACCE` password
          in the top 16 bits or it is silently ignored -- this also
          means the earlier `security.rs`/C lockdown was a no-op and is
          fixed in the same batch; **(2)** the USB controller can't
          complete its reset without `clk_usb` running, so Secure must
          bring up the PLLs (`init_clocks_and_plls`) before touching
          USB; **(3)** peripheral attribution needs BOTH an SAU NS
          region AND the ACCESSCTRL grant.
    - [x] **M2b-1 -- NS enumerates a USB device. DONE (hardware-verified
          2026-07-07).** Path A: Secure grants NS the CLOCKS + RESETS
          windows (SAU regions 4/5 + ACCESSCTRL) alongside USB; NS mints
          a real `UsbClock` via `ClocksManager::new`, builds the stock
          `hal::usb::UsbBus`, and enumerates a bare `usb-device`. The
          host saw `Bruce TZ-NS (M2b-1)` (PID 0xF1DC under the Rust
          vendor id of the time; the image uses `0xcafe` now),
          and correctly NOT as a CTAPHID device (no HID class yet).
          First real functionality running Non-secure -- worked first
          try, no bisect. Keys/crypto stay Secure; NS's CLOCKS/RESETS
          reach is DoS-class only (tighten in M5).
    - [x] **M2b-2 -- CTAPHID + PING via Secure echo. DONE
          (hardware-verified 2026-07-07).** NS runs the FIDO HID class
          (ported from the firmware) + single-frame CTAPHID: it answers
          INIT and PING, routing the PING payload through the Secure
          `sg_echo` gateway (the first buffer-passing veneer). Verified
          with the in-tree client: the device is recognized as CTAPHID
          (caps 0x0d) and a 32-byte PING round-tripped NS->Secure->NS
          with an exact match -- first try, no bisect. **M2 (NS owns
          USB) is complete:** the whole USB/CTAPHID transport now runs
          Non-secure and calls into Secure for its service, keys never
          leaving Secure. Two design points settled during bring-up:
          - **Polling, not interrupts.** The FIDO firmware already
            services USB by polling (`usb_dev.poll()` in the main
            loop), so NS polls too -- no NVIC ITNS / IRQ-routing needed.
          - **Getting a working `UsbBus` in NS is the crux** (see
            "Open decision" below).

## Open decision (M2b): how NS drives the USB controller

`hal::usb::UsbBus::new` wants a `UsbClock` token and `&mut RESETS`. In
the split, clocks and RESETS are Secure-owned, so neither is trivially
available to NS. Investigation (2026-07-07) found two viable paths:

- **Path A -- expose CLOCKS + RESETS to NS, use the stock HAL.** Grant
  NS an SAU region + ACCESSCTRL for the CLOCKS and RESETS blocks. NS
  then does `ClocksManager::new(pac.CLOCKS).usb_clock` to get a *real*
  (non-fabricated, no-UB) `UsbClock` token -- `ClocksManager::new` only
  wraps the already-configured CLOCKS, it doesn't re-run the PLLs -- and
  calls the stock `UsbBus::new`. **Low code, fast to a working M2b.**
  Cost: NS can now touch CLOCKS/RESETS, i.e. reconfigure clocks or
  reset peripherals. That is a **DoS-class** widening only -- it does
  NOT let NS read keys or crypto state, so it stays within the split's
  threat model ("a parser bug can't reach secrets") -- but it is
  broader than ideal and would be tightened in M5.
- **Path B -- fork a minimal NS USB init.** NS reimplements just enough
  of the USB device-controller bring-up to enumerate, operating on the
  USB block Secure already reset + clocked (M2a). No CLOCKS/RESETS
  exposure -- NS needs only the USB window it already has. **Tighter
  security, more code** (partial fork of the HAL USB driver), and it
  diverges from the HAL so it carries maintenance cost.

Recommendation: **Path A for M2b bring-up** (prove the boundary end to
end first, consistent with M1/M2a discipline), then revisit in M5 --
either tighten to Path B or move USB reset/clock behind a Secure
gateway. Both keep secrets Secure; they differ only in how much
DoS-class peripheral access NS holds during bring-up.
- [x] **M3 -- CBOR + dispatch in NS. DONE (hardware-verified 2026-07-07).**
      NS demuxes the CTAP2 CBOR command byte and dispatches
      to a Secure command gateway -- the parser/demux (the risk surface)
      is Non-secure, the handler is Secure. `authenticatorGetInfo`
      (0x04) is wired end to end through a new `sg_get_info` gateway
      (returns a minimal valid getInfo -- Secure has no allocator, so the
      CBOR is hand-encoded + `cbor2`-verified); unknown commands return
      `CTAP2_ERR_INVALID_COMMAND`. Exit criterion: a client-driven
      `authenticatorGetInfo` succeeds. Single-frame only for now
      (getInfo fits one frame); multi-frame + the full CTAP2 surface
      arrive with M4.
- [x] **M4 -- Secrets fully Secure.** Done, silicon 2026-08-25.
      **M4a** multi-frame CTAPHID (NS reassembles, Secure keeps the
      semantics); **M4b** the TRNG, Secure-only; **M4c** a Secure master
      key with credential keys derived, used and zeroized inside;
      **M4d** that key persisted in a Secure-only flash sector; **M4e**
      real CTAP2 MakeCredential/GetAssertion driven by `tz_test`;
      **M4f** the hybrid ML-DSA + ECDSA signer on a **Secure-only
      core 1**, validated at all three ML-DSA levels with both halves
      verified on the host (the `tz_test` example).
      **M4g** the user-presence gate and a monotonic signature counter,
      both Secure-owned.
      **M4h** resident (discoverable) credentials in a Secure flash
      store -- validated on silicon.
      The conformance suite (an external CTAP 2.1 suite, not part of
      this repository) now runs against this image -- 25 passed, 20
      failed, 3 skipped, with the composite `-52` both advertised and
      verified.
      The presence gate is confirmed with a **real finger** on the
      button. See "M4 as built" below.
- [x] **M5 -- Harden the gateway.** Done, silicon 2026-08-24.
      `TestTarget` range-checks on every NS pointer, volatile
      zeroization of Secure scratch, and SecureFault -> wipe + reset.
      The C-port plan remains outstanding. See "M5 as built" below.


## M4 as built

What exists, what it proves, and what it does not.

### The gateway surface

| Veneer | Purpose |
|---|---|
| `sg_led_set` | M1 boundary proof |
| `sg_echo` | M2b transport round trip |
| `sg_get_info` | M3 command gateway |
| `sg_make_credential` | M4c: rp_id_hash, client_data_hash -> id \|\| pubkey \|\| sig |
| `sg_get_assertion` | M4c: + credential_id -> sig |
| `sg_ctap_make_credential` | M4e: CTAP2 attestation object |
| `sg_ctap_get_assertion` | M4e: CTAP2 assertion |
| `sg_up_begin` / `sg_up_poll` | M4g: user presence |
| `sg_healthy` / `sg_reboot_bootsel` | dev escape (default off) |

Both CTAP2 gateways serve hybrid credentials as of M4f; the algorithm
comes from the credential id. Both require user presence as of M4g.

The M4c raw veneers (`sg_make_credential` / `sg_get_assertion`) are now
behind `dev-escape`. They are a test protocol for the boundary and are
not presence-gated, and an image built for real use must not carry an
ungated signing entry point at all.

Veneers take at most four arguments: `"C-cmse-nonsecure-entry"` passes
everything in r0-r3 and will not compile with a fifth. Both M4c gateways
therefore have a fixed output length instead of a capacity argument.
Writing a fixed size into checked NS memory cannot harm Secure -- an NS
caller that supplied a shorter buffer only corrupts its own.

### Why the CBOR parser stayed Non-secure

Design point 2 warns that a message must be copied into Secure storage
before parsing or NS can mutate it underneath a Secure parser. Point 1
says veneers should carry operations, not data structures. Following
point 1 dissolves point 2: arguments cross as copied fixed-size values,
never as pointers into a buffer NS still owns, so no Secure code ever
parses NS-writable memory. The CBOR parser -- the historical CVE surface
in this class of device -- stays out of the Secure world entirely, and
the NS reassembly buffer is deliberately Non-secure.

### Credential construction

A credential id is `nonce || HMAC(master, "cred-tag" || nonce || rp)`,
and the signing scalar is a second derivation under `"cred-key"`. Two
labels so tag and key can never collide; the rp in both so an id is
useless under a different relying party; a TRNG nonce so two credentials
for one rp differ. The token stays stateless -- nothing per-credential
is written to flash. Tag comparison is constant-time, because a
byte-at-a-time compare leaks the tag one byte per query and that is
enough to forge an id.

### CTAP2 (M4e)

NS parses the request CBOR and passes a fixed-layout struct of copied
values; Secure hashes the rp id, derives the key, builds `authData` and
signs. `authData` is built Secure-side deliberately: it is the thing
being signed, so an NS-built one would let NS choose what a Secure key
attests to. Attestation format is `none` -- there is no attestation key
in this image, and a self-attestation would assert something untrue.

The M4c raw-binary veneers are kept alongside. They are a smaller
surface to test the boundary against, and the `tz_test` example exercises
edge cases the CTAP2 layer would hide.

### How the boundary is actually proved

Not by inspection. The `tz_test` example drives the token over CTAPHID with
the in-tree client (`crates/ctaphid-client` -- this project uses no
third-party FIDO library), so the result is interoperability
rather than self-consistency: a `none`-format attestation object with flags
0x41, an `rp_id_hash` equal to SHA-256 of the rp id, and a DER assertion
signature that verifies under the public key from registration. The same tool
verifies, on the host, a signature the token produced with a key it never
handed over; asserts a fresh challenge signs under the *same* public key, so
the key really is recoverable inside Secure from the id alone; checks that a
flipped bit in the id, and the id under a different rp, are both refused; and
re-asserts a credential across a reset. The `tz_cm` example covers the
CredentialManagement surface, including `--cp3`, which is the witness for
credProtect level 3 on a **non-resident** credential.

Two fail-closed checks back that up, both of which refuse to bring the
device up rather than log:

  - The NS self-test probes **every** veneer pointer argument with a
    Secure address, plus one wholly-NS call that must still succeed so
    the probes cannot pass by everything being broken. Design point 5 is
    right that this is not per-veneer boilerplate -- one veneer that
    forgets the range check reopens the whole hole -- so it grows with
    each new gateway.
  - `secrets_unreachable_from_ns()` asks `TestTarget` whether the key
    sector or the in-RAM key is NS-reachable, and refuses to launch NS
    if either is. An off-by-one in an SAU limit is otherwise invisible:
    nothing misbehaves, NS simply gains a read. Verified non-vacuous by
    rebuilding with the old over-broad limit and watching the board
    refuse to boot NS.

### M4f -- the signer on core 1

Design point 3 offered two options and only one is real. A Non-secure
signer taking blinded inputs does not work for ML-DSA: signing expands
the private key from the seed, so the signer must hold the seed, which
is the thing being protected. So core 1 became Secure-only.

Core 1 is launched by the Secure image before the SAU is programmed and
long before the NS world exists, so it never executes a Non-secure
instruction. Its own SAU stays disabled -- on Armv8-M that means every
address is Secure to it. The mailbox moved into Secure RAM because it
carries the ECDSA scalar and the ML-DSA seed as *inputs*; in shared NS
RAM it would have handed over every credential's private key and let NS
forge requests to a core running with Secure privilege.
`secrets_unreachable_from_ns()` asserts the mailbox is NS-unreachable
alongside the master key, and refuses to launch NS otherwise.

RAM is therefore split **448 KiB Secure / 64 KiB NS**, up from 256/256:
a 256 KiB heap (ML-DSA needs an allocator), core 1's 64 KiB stack and
the 7.4 KiB mailbox. Three files must agree -- `memory-secure.x`,
`memory-nonsecure.x`, SAU region 1 -- or NS faults on its own stack.

The worker is `pqf-signer-core`, linked verbatim, so a hybrid signature
is byte-identical to the FIDO firmware's.

**The ECDSA half signs a prehash**: `SHA-256(HYBRID_LABEL || message)`
fed to `sign_prehash`, not the message. Assuming otherwise is what made
a working signature look broken the first time it was checked.

Credential ids carry the algorithm -- `nonce(31) || alg(1) || tag(32)` --
and the tag covers the algorithm byte, so flipping it to coax a
different key schedule out of the same nonce fails the check. On
assertion the algorithm comes from that authenticated id, never from
the caller.

### M4g -- user presence, and a counter that cannot rewind

**User presence** is only worth having if the Secure side both samples
the button and holds the verdict. If NS could assert "the user
touched it", a compromised NS would sign anything it liked with keys it
can never read -- which removes most of the value of moving them.

The obvious shape does not work: blocking inside a veneer until the
button is pressed means seconds with no USB service, and the host gives
up. So the gate is **two-phase**. NS calls `sg_up_begin`, then polls
`sg_up_poll` while pumping USB and emitting CTAPHID KEEPALIVE; the CTAP2
veneers refuse to act until a confirmation exists, and **consume** it.
NS drives the timing, Secure owns the decision, and all NS can achieve
by lying is denying itself service.

The gesture requires **release then press** -- a button already held when
the window opens does not count, or a resting finger (or tape) would
authorise everything that followed. Confirmations are single-use and
expire, so one touch is one operation.

The button sampler is carried over from the FIDO firmware and has to
live Secure-side anyway: `IO_QSPI` is not in ACCESSCTRL's NS allow-list.
It floats the flash chip-select for ~15 us, so **XIP is unreadable
during the sample** -- the same blackout as a flash write.

**Core 1 must be parked for that window, and originally was not.** A
fetch from core 1 re-asserts the chip select through the QMI, so the
sampled line reads "released" regardless of the button. It fails
*silently*: presence simply never confirms, which is indistinguishable
from nobody pressing.

The same omission applied to every flash write from M4f onward.
`flash.rs` was written at M4d and said, correctly at the time, that this
image never starts core 1; launching core 1 for the ML-DSA signer did
not revisit it. Parking now lives inside `flash_op` rather than at each
call site, so a caller cannot forget it, and it is skipped while core 1
has not yet started -- the key store and counter both write flash during
bring-up, before the spawn, and waiting for an acknowledgement from a
core that does not exist would hang.

**The signature counter** was in RAM and restarted at 1 every boot,
which is exactly the "counter went backwards" signal WebAuthn sec. 6.1.1
tells a relying party to read as a cloned authenticator.

Design point 4 flags the counter commit as being on the latency path, so
it does not write per signature. It reserves a block of 64 in flash
and hands values out from RAM, writing again only when the block runs
out. Reservation is **lazy** -- taken by the first signature, not at
boot. Reserving eagerly meant a token power-cycled a few times handed a
relying party a counter that had leapt hundreds with no signatures
behind it: legal, but it looks exactly like the cloning the counter
exists to reveal, and it cost a flash write on every boot.

What lazy reservation actually buys, measured in the host harness:
**an idle reboot writes nothing and moves the counter not at all.** A
reboot that *is* followed by a signature forfeits the unused tail of the
current batch -- once per run of reboots, not once per reboot -- so three
reboots then one signature advance the counter by 65, where eager
reservation would have taken about 192.

**A correction.** The figure first recorded here was "+2 across three
reboots", from a silicon run. That is not what this code does: the
harness reproduces the exact scenario -- one signature, three reboots,
one signature -- and measures 1 then 66. Either that hardware run was
measuring something other than the raw counter, or its arithmetic was
wrong; the claim should not be relied on as stated. The improvement over
eager reservation is real and is the 192-to-65 figure, plus free idle
reboots.

After a reset the counter resumes from the reserved high-water, so it
may still *skip* the unused tail of a batch -- which WebAuthn permits, requiring the value to increase
rather than to be contiguous -- but it can never repeat. Cost is one
256-byte program per 64 signatures and one sector erase per 16 of those.

Records are appended, so a sector eventually fills and must be erased --
and a power cut during that erase would leave no record, so the next
boot would restart from zero. That is the single failure the whole
design exists to prevent, so **two sectors ping-pong**: when the active
one is full the *other* is erased (it holds only older values) and the
new record written there. At every instant, including mid-erase and
between erase and program, the untouched sector still holds the current
high-water.

**Measured**, since design point 4 asked: 200 ES256 assertions came in
at a median of 118.1 ms, max 119.3 ms, with zero outliers over twice the
median. The 1-in-64 reservation write is invisible against the USB round
trip. (That 118 ms is transport and the presence handshake, not crypto.)

**One bug worth recording.** The first version treated "slot holds no
valid record" as "slot is free". It is not: flash programming only
clears bits, so writing into a slot holding stale data yields neither
value, and the counter silently rewound 13 -> 1 across a reboot. These
sectors are not blank merely because this image never wrote them --
restoring a whole-flash backup, as this board had, leaves data there.
`free_slot` now requires all 256 bytes to read `0xff`.

### M4h -- resident credentials

Eight 4 KiB Secure sectors at `0x101F0000`, sixteen 256-byte records
each, so 128 discoverable credentials. One record per page because 256
bytes is the flash programming unit, so a record is written without
disturbing its neighbours.

CTAP2 requires a new credential for the same `(rpId, userId)` to replace
the old one. Replacing in place would mean erasing 4 KiB over fifteen
bystanders, so instead the old record's magic is **programmed to zero** --
flash can always clear bits, never set them -- and the new record
appended. Invalidation costs one page write and no erase; a sector is
erased only once every record in it is dead.

**Compaction.** Allocation prefers a partly-used sector and only opens a
fresh one while more than one blank sector remains. `compact` copies the
live records out of the emptiest sector into another and erases it, so
dead records are reclaimed. The copy completes before the erase begins,
so a power cut leaves every record present at least once; duplicates are
harmless (first match wins, stale copy retired on the next write) where
a lost credential is not.

Validated on silicon: **240 writes of 8 users, none refused** -- well past
the 64 raw slots, so dead records are demonstrably reclaimed -- with a
credential still asserting afterwards and `numberOfCredentials` still
exactly 8. A host harness (`crates/fw-secure-hosttest`) later ran the
same shape 40 rounds deep with the same result.

**A correction.** This section previously said one sector is "always kept
blank as a spare, so usable capacity is 56, not 64". That is wrong, and
the host harness is what caught it: storing distinct credentials fills
**all 64 slots** and the store refuses on the 65th. Compaction stays
reachable not because a sector is held in reserve but because dead
records free slots *within* sectors, which is where the reclaimable space
actually is. Nothing in the behaviour changed -- only the description of
it, which had been asserted rather than measured.

The first version of that test was wrong in an instructive way: it
registered *distinct* users and expected to exceed the slot count. No
amount of compaction lets more than 56 credentials be live at once, so
it measured capacity rather than reclamation. Re-registering a fixed set
is what separates the two.

getInfo now reports `rk:true`. It was briefly `false` and accurate;
before that it was `true` and a lie.

**Validated on silicon** (`cargo run -p pqf-ctaphid --example tz_test -- --count`,
the `tz_cm` example), and it passed
first run: `rk:true` advertised; a discoverable credential registered
and then found with **no allowList**, returning the right user handle
and a verifying signature; re-registering the same user replaced rather
than duplicated; a second user was additive; an unknown relying party
got `NO_CREDENTIALS`. The same run shows one surviving a reset and still
verifying under its pre-reboot public key.

It went in clean because the trap was already known: these sectors are
not blank just because this image never wrote them, so `store` falls
back to erasing a sector with nothing live in it rather than assuming
`0xff`. That is the same bug that rewound the counter, caught in
advance this time.

### The conformance suite against this image

(Recorded before the 2026-09-30 relabel, when this image's ML-DSA-65
composite was `-52`; it is now `-55`. See
[PROTOCOL.md](PROTOCOL.md#cose-algorithm-identifiers).)

The conformance suite run for `-52`, with presence latched on (a conformance suite
cannot press a button -- see the dev escape below):

**64 passed, 0 failed, 4 skipped** -- the whole suite, re-measured
2026-09-02. (An earlier run of this section recorded 65/0/4. That figure
predates a rework of the suite itself, which changed how many checks the
suite emits; it is not a regression in this image. Run the `tz_cm` example
with `--wipe` first -- the TrustZone image has no `authenticatorReset`, so a store left full
by an earlier run makes the credential-count checks fail.) The composite
`-52` is both advertised and *verified* by the suite's own checker: a
3380-byte assertion splitting into ECDSA-DER plus a 3309-byte ML-DSA
half. (It was 25 passed / 20 failed when the CTAP2 surface was first
measured; the 4 skips are LargeBlobs and BioEnrollment, which this
image does not claim to support.)

Everything the suite exercises is implemented Secure-side: ClientPIN
(protocol v1), CredentialManagement, authenticatorConfig,
authenticatorSelection, and the credBlob, credProtect, hmac-secret and
minPinLength extensions.

Passing: getInfo, PIN/UV protocol negotiation, the full ES256 and
MLDSA65-ES256 non-resident round trips (MakeCredential, attestation
verify, GetAssertion, signature verify), algorithm negotiation from a
full preference list, resident MakeCredential for both algorithms,
excludeList rejection, and non-matching-allowList rejection.

Four findings came out of getting there, each of which had a real cause
rather than a missing feature:

- **excludeList** was a conformance gap, not an option: CTAP2 requires
  MakeCredential to refuse with `CREDENTIAL_EXCLUDED`.
- **GetNextAssertion** was missing, so a token reporting
  `numberOfCredentials: 3` could only ever return one of them.
- **pinUvAuthProtocol and pinUvAuthParam were swapped** in the Config
  and CredentialManagement parsers. The parsers now dispatch on the
  CBOR major type -- a byte string is the auth param, an unsigned int
  the protocol -- which interoperates whichever order a client uses.
- **`authData`'s extension allowance was incidental**, sized for the
  COSE key alone. It overflowed the moment extensions landed on a
  hybrid credential, which presented as MakeCredential failing only for
  ML-DSA and only with extensions.

Two things the conformance suite earned its keep on:

- **excludeList was a genuine conformance gap**, not a missing optional
  feature: CTAP2 requires MakeCredential to refuse with
  `CREDENTIAL_EXCLUDED` when the list names a credential the token
  holds. Now implemented via `sg_cred_is_ours`, which needs the master
  key and so has to be decided Secure-side. The one bit it returns is
  not a new disclosure -- NS could already learn the same thing by
  asking for an assertion.
- **GetNextAssertion was missing**, which the resident test surfaced
  once the store held more than one credential for a relying party: the
  first reply said `numberOfCredentials: 3` and the other two were
  unreachable, which is worse than not reporting a count. Implemented
  Secure-side, since choosing the credential is a Secure decision and
  an NS-supplied index would let it walk the store. It deliberately
  does not re-consume user presence: CTAP2 treats the gesture that
  started the sequence as authorising all of it, and choosing between
  two accounts should not cost two touches.

### Known weaknesses

  - **ACCESSCTRL opens RESETS to NS** (needed since M2b so the NS USB
    stack can reset its block). NS can therefore reset Secure-owned
    peripherals, including the TRNG.
    **Not closable here, and the reason is worth writing down:**
    ACCESSCTRL is per-peripheral, so RESETS cannot be granted for the
    USB bit alone, and `UsbBus::new` in rp235x-hal *unconditionally*
    calls `reset_bring_down`/`reset_bring_up` -- verified in the crate
    source, there is no constructor that skips it. Closing it means a
    HAL change or a vendored fork, which is a decision rather than a
    patch.
    **The exposure is smaller than it first looks.** The concern was
    fault injection against entropy collection, but the TRNG driver
    reconfigures the peripheral completely on every collection --
    `trng_sw_reset`, sample count, config, source enable -- inside a
    16-attempt retry loop that also checks the on-die health bits. A
    reset landing mid-collection costs a retry, not weak output. What
    NS actually gains is denial of service, which it already has by
    virtue of owning the USB stack.

  - **The dev escape is a real hole** when enabled: NS can reach
    BOOTSEL and from there rewrite flash. Default off for that reason.

### Building

`build-tz.sh` builds Secure first, then Non-secure. Both the order and
the feature set matter: `target/nsc/libnsclib.a` is shared state listing
the veneers the Secure image exported, so building the two crates from
different feature sets fails the link on a missing veneer.

A production build (no `dev-escape`) carries no ungated signing path, no
injection veneer, no BOOTSEL escape, and no warnings.

### The dev escape

`--features dev-escape` on both crates (`TZ_DEV_ESCAPE=1 ./build-tz.sh`;
the default build leaves it out). Two mechanisms: a CTAPHID
reboot command (id 0xd1, matching the main firmware, so `c/hid/reboot
bootsel TZ` drives it), and a Secure dead-man's switch for when NS never
gets far enough to serve one. Secure keeps a counter in watchdog
SCRATCH7 across resets, arms the watchdog at the top of `main`, and
drops to BOOTSEL instead of launching NS after three boots with no
check-in; NS calls `sg_healthy` once USB reaches Configured. Recovery
needs nothing from NS, which is the point. Measured: 4.7/4.5/4.5 s
windows against 5 s configured, BOOTSEL at ~16 s; window later raised to
7 s for headroom, and the HAL's `Watchdog::start` panics above ~8.39 s.

M4g adds a third dev-only affordance: `sg_up_inject`, a one-shot
simulated touch, so the presence gate can be exercised from both sides
without a finger on the board. It is one-shot rather than a level
because a stuck-high level could never satisfy release-then-press and so
could never confirm -- and because one-shot is what a real touch is, so a
test that passes is testing the same state machine a finger drives. The
real sampler still runs on every poll, so it cannot paper over a broken
button path.

**Confirmed with a real finger** (`cargo run -p pqf-ctaphid --example tz_test -- --press`): with no
injection and no auto-present, a physical press was accepted --
`flags=0x41`, UP set -- and the attempt immediately before it, with no
press, was refused. The whole chain now has hardware behind it.

Getting there turned up two genuine defects and one bad experiment,
worth recording because the failure mode is so quiet:

  - The sampler's settle loop was `bl __nop` into flash, a thousand
    times, *inside* the floated-chip-select window the module comment
    forbids fetching in. It survived on the XIP cache.
  - Core 1 was never parked across that window, nor across any flash
    write since M4f.
  - A "control" run against the shipping firmware appeared to prove the
    board was fine and the port was broken. It proved nothing: that
    build auto-confirms user presence, so it never consulted the
    button. The tell was in plain sight -- every `reboot bootsel` in the
    session succeeded with no touch.

The honest attribution: the earlier non-detections are equally
explained by no press having occurred, so neither fix is *demonstrated*
to have been the cause. Both were real bugs against the documented
contract and are fixed regardless.

A register-level probe (`sg_up_probe`, dev-only) reports the CTRL
readback after the override and the raw `QSPI_CSN` bit, which is what
finally separated "nobody pressed" from "the sampler cannot see it".

## References

- Rust unstable book -- `cmse-nonsecure-entry`; tracking #75835, #81391
- Sascha Wise, "Highway to the TrustZone-M" (canonical Rust workflow)
- `cortex-m` `cmse` + `peripheral::sau` modules (v0.7.7)
- Trusted Firmware-M RP2350 port (C reference for SAU/handoff)
- pico-examples #708 (confirms no S/NS example); RP2350 datasheet sec. 3.7
  (SAU), sec. 10.6 (ACCESSCTRL), sec. 5 (bootrom / partition table)

## M5 as built (silicon 2026-08-24)

The M3 gateway trusted every pointer NS handed it. A veneer argument is
just an integer the NS world chose, so `sg_echo` was an arbitrary Secure
**read** (Secure source) *and* an arbitrary Secure **write** (Secure
destination), and `sg_get_info` an arbitrary Secure write -- each carried
out with Secure privilege on NS's behalf.

**What changed.** `ns_readable()` / `ns_writable()` validate every NS
buffer with `cortex_m::cmse::TestTarget::check_range` before Secure
touches it, and fail closed on null, on unconfirmable addresses, and on
anything the attribution unit does not report as NS-accessible. Secure
scratch is zeroized with volatile writes so the stores cannot be elided
-- the mistake that made `openssl-mini`'s `OPENSSL_cleanse` a no-op.
`SecureFault` wipes scratch and calls `sys_reset()` rather than spinning
under `panic_halt`, which would brick the token *and* hold Secure state
in RAM for anyone patient enough to glitch it.

**How it is proved.** The NS image runs a **fail-closed** self-test
before USB init: it hands the gateway Secure addresses (`0x2000_0000`
Secure RAM, `0x1000_0000` Secure flash -- NS space starts at
`0x2004_0000` / `0x1010_0000`) and refuses to enumerate unless all three
are rejected *and* a legitimate call still succeeds. So **the token
enumerating is the assertion**. A self-test that merely logged would be
useless on a device with no console.

Verified in the built images, not just asserted: `tt r0, r0` at
`0x10000ac6` in a shared `__tt` helper with **four** `bl` call sites
(start/end pairs for the two range checks in `sg_echo` -- `check_range`
emits two TTs when a span may cross a 32-byte line), and `SecureFault`
linked at `0x10000492`. M1-M3 still pass through the hardened gateway:
capabilities `0x0d`, a 19-byte PING round trip via `sg_echo`, and
getInfo (`FIDO_2_0`, aaguid `664d9f67...`) via `sg_get_info`.

## M4 design note -- what still has to happen

> Written before M4 was started and kept as the design rationale; the
> five points below are what "M4 as built" above answers.

M4 is not an increment on M3; it is a port. M3 answers **one**
single-frame command from a hand-encoded constant. M4 has to move the
master keys, TRNG, flash store, credential-ID crypto and the core-1
signer behind the gateway, and carry the full multi-frame CTAP2 surface
across it -- against roughly 10,800 lines of Rust firmware in the tree
at the time. Attempting it as a series of small edits is how it goes
wrong.

**1. Decide what crosses, and in which direction.** The boundary should
carry *operations*, not *data structures*. `sg_make_credential(challenge,
rp_id_hash, ...) -> credential_id + attestation` keeps every key inside
Secure; a `sg_get_master_key()` would defeat the entire exercise. Each
veneer should be the smallest complete operation the NS side can name.

**2. Buffer ownership is the hard part.** Every veneer already needs
`ns_readable`/`ns_writable` on entry (M5). Multi-frame CTAP adds
reassembly: NS owns the transport, Secure owns the semantics, and the
message has to be copied into Secure-owned storage **before** parsing,
or NS can mutate it underneath a Secure parser (a TOCTOU on every
field). Budget the Secure-side buffer for `maxMsgSize` up front -- the
Secure image has no allocator.

**3. The core-1 signer is the awkward one.** The mailbox is shared
memory plus a FIFO handshake, and core 1 currently runs NS-visible code.
Either core 1 becomes Secure-only (and the mailbox moves into Secure
RAM, so ACCESSCTRL must stop NS reaching it), or the signer stays NS and
only receives blinded inputs -- which for ML-DSA means the private key
must never leave Secure, so it cannot. The first option is correct and
implies core 1's ARCHSEL/PSM bring-up happens Secure-side.

**4. Flash store.** The reserved sectors must become Secure-only in
ACCESSCTRL, and every write must funnel through the Secure side --
including the sign-counter commit that precedes *every* signature. That
is on the latency path, so measure it: the C port's counter write is
already the reason XIP builds were slow.

**5. Then re-run everything.** The full port x level matrix, the button
UP gate, and the conformance suite. M5's checks apply to each new veneer as it is
added -- the range check is not optional per-veneer boilerplate, it is
the boundary's only defence, and one veneer that forgets it reopens the
whole hole.

**Prerequisite, not optional:** ~~the TZ image still has no
`CMD_REBOOT`~~ -- done, and it was the right call: every step above was
brought up without touching the board. See "The dev escape" under
"M4 as built".
