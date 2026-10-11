# Debugging a locked token over USB (`PQF_GDB_STUB`)

The on-token GDB stub of both firmwares -- the C port's
`-DPQF_GDB_STUB=ON` and the Rust firmware's `--features gdb_stub`:
building it, finding the port and attaching, what works and what
cannot, the monitor-mode mechanism underneath, the host-side harnesses,
and why the flag must never reach a production image. It is for a
developer debugging their own build on their own hardware, and assumes
a working build from [GETTING-STARTED.md](GETTING-STARTED.md) with the
build options of [BUILD.md](BUILD.md); flashing is
[FLASHING.md](FLASHING.md), and the reboot command the stub reuses is
[REBOOT.md](REBOOT.md).

`bruce` can serve the **GDB remote serial protocol from the token
itself**, over the USB cable. Build the firmware with one flag, plug the
device in, and:

```bash
arm-none-eabi-gdb c/firmware/build-gdbstub/bruce_c.elf \
    -ex 'target remote /dev/cu.usbmodemXXXXXXXX4'
```

...then set breakpoints in the FIDO command handler, inspect registers,
step, and continue. No SWD probe, no opened enclosure, no exposed debug
pads -- **nothing but the cable**.

That matters because these devices otherwise have *zero* debuggability
once cased and locked. A sealed USB token with its SWD lines unbonded is
a black box: the only diagnostic channel is whatever the firmware
volunteers over CDC. This stub turns the same USB link the FIDO traffic
rides on into a real debug channel, which is a genuine differentiator for
an open-source token -- a downstream developer can debug *their* build on
*their* hardware with a stock `arm-none-eabi-gdb`.

> WARNING: **Debug builds only. Never ship one.**
> The stub is an **unauthenticated read / write / execute primitive over
> USB**: anyone who can reach the port can read RAM, write RAM, and
> redirect the program counter. `PQF_GDB_STUB` defaults **OFF** and must
> be excluded from production-signed images. See
> [Security](#security-why-this-must-never-ship-enabled).

---

## Contents

- [Build it](#build-it)
- [Find the port](#find-the-port)
- [Attach](#attach)
- [The exit-criteria walkthrough](#the-exit-criteria-walkthrough)
- [How it works: monitor-mode debug](#how-it-works-monitor-mode-debug)
- [The Rust port](#the-rust-port)
- [Constraints](#constraints)
- [Supported RSP commands](#supported-rsp-commands)
- [`monitor` commands](#monitor-commands)
- [Testing without hardware](#testing-without-hardware)
- [Security: why this must never ship enabled](#security-why-this-must-never-ship-enabled)
- [Troubleshooting](#troubleshooting)

---

## Build it

```bash
cmake -S c/firmware -B c/firmware/build-gdbstub \
      -DPQF_BOARD=feitian_rp2350 \
      -DPQF_GDB_STUB=ON
cmake --build c/firmware/build-gdbstub -j
```

The flag does three things:

1. links `src/gdbstub.c`;
2. grows the USB device by a **second CDC interface** -- the GDB channel
   (interfaces 3+4; the banner CDC and FIDO HID keep their numbers, so
   nothing about the FIDO side changes on the wire);
3. doubles the stack reservation (`PICO_STACK_SIZE=0x1000`), because a
   halted session nests a USB pump and a packet loop on top of whatever
   call depth it stopped at.

Cost when **off**: exactly zero. No source compiled, no interface
added, no symbols linked -- verifiable with
`arm-none-eabi-nm build/bruce_c.elf | grep -i gdb`, which comes back
empty for a normal build.

Arm only. `-DPQF_PLATFORM=rp2350-riscv` is rejected at configure time:
the stub is built on the ARMv8-M DebugMonitor exception and the FPB, and
the Hazard3 (RISC-V) cores implement a different debug architecture. A
RISC-V equivalent would be a separate piece of work.

Combines freely with the other build axes -- `PQF_HYBRID_VARIANT=87`
(XIP image, no `copy_to_ram`), `PQF_TEST_NO_USER_BUTTON`,
`PQF_REBOOT_NO_UP`. To debug an XIP image at level 65, add
`-DPQF_COPY_TO_RAM=0`; breakpoints in flash work the same (see the
[SRAM-vs-XIP table](#validated-in-both-execution-modes)).

For a hands-free flash -> debug loop, add `-DPQF_REBOOT_NO_UP=ON` so
`c/hid/reboot bootsel` needs no touch ([`docs/REBOOT.md`](REBOOT.md)) --
or just use `monitor bootsel` from inside the debug session once the
stub is running.

## Find the port

A stub build enumerates **two** serial ports. On macOS:

```bash
ls /dev/cu.usbmodem*
```

```
/dev/cu.usbmodem1A2B3C4D1     <- banner / BOOTSEL magic (CDC 0)
/dev/cu.usbmodem1A2B3C4D4     <- GDB stub              (CDC 1)
```

The trailing digit is the CDC **data** interface number, so it is **`1`
for the banner port and `4` for GDB** (the GDB pair is interfaces 3+4;
macOS names the tty after the data half). On Linux they are
`/dev/ttyACM0` and `/dev/ttyACM1`; the GDB one is the higher number. If
you are unsure, `screen` it -- the banner port prints the boot banner
every second, and a stub build's banner includes the line:

```
  gdb stub:      ACTIVE (GDB stub debug build -- never ship). Attach: target remote <the OTHER usbmodem tty>
```

The GDB port prints nothing until GDB talks to it.

Note the serial number changes on every boot (the macOS HID-cache
workaround in `usb_descriptors.c`), so the tty *names* change across
reflashes. Don't hard-code them in scripts; glob instead.

## Attach

```bash
arm-none-eabi-gdb c/firmware/build-gdbstub/bruce_c.elf \
    -ex 'target remote /dev/cu.usbmodem1A2B3C4D4'
```

Pass the `.elf` -- that is what gives you symbols, source lines, and
argument names. The stub also serves a target description
(`qXfer:features:read:target.xml`, `armv8-m.main` / m-profile), so you
do **not** need `set architecture`; GDB learns the register file from
the device.

`gdb-multiarch` works identically (`target remote` then
`set architecture armv8-m.main` if it doesn't pick it up from the ELF).

On attach GDB sends `?`, the stub halts the target, and you land at
whatever core 0 was executing -- usually the main loop.

## The exit-criteria walkthrough

The acceptance test for the stub: *set a breakpoint in the FIDO
command handler from gdb on the host, hit it, inspect registers,
continue.* Below is the real transcript, **silicon-validated on the
Feitian RP2350 (2026-07-29)**.

```gdb
(gdb) break ctap2_dispatch
Breakpoint 1 at 0x20002df8: file src/ctap2.c, line 1457.

(gdb) continue
Continuing.
```

Now make the token do some FIDO work from another terminal -- anything
that sends a CBOR command:

```bash
cargo run -p pqf-ctaphid --example probe --target "$(rustc -vV | awk '/host/{print $2}')"
```

The `probe` example of the in-tree client (`crates/ctaphid-client`) is a
read-only probe that sends INIT, PING and `authenticatorGetInfo`, and
needs no device argument.

The `register` example goes further -- a full register + assertion +
RP-side verification -- but note it *mutates* the device: it registers
a credential, and if a PIN is set it needs it in `BRUCE_PIN` (it
stops rather than guess).

### Breakpointing the hybrid PQC sign

Two things make this less obvious than it looks, both silicon-confirmed:

**Break on `core1_hybrid_sign`, not `hybrid_sign`.** `hybrid_sign()` is
executed by **core 1**, and this stub is core-0 only -- a comparator
programmed here never matches there, so that breakpoint simply never
fires. `core1_hybrid_sign()` is the core-0 side that submits the job and
polls while pumping the long-op tick, and it *does* fire.

**You need a GetAssertion, not a MakeCredential.** Registration only
generates the ML-DSA keypair; the hybrid signature is produced when
signing authenticator data for an assertion
(`credential.c` -> `core1_hybrid_sign`). Compounding the confusion,
a hybrid MakeCredential returns an **ES256** attestation statement
(`alg=-7`, ~70-byte sig) because a full hybrid attStmt plus a 2592-byte
ML-DSA key in authData overruns the 7609-byte CTAPHID ceiling -- see
`test/test_hybrid_msgsize.c`. So `alg=-7` on a registration does **not**
mean you got an ES256 credential. Check the *assertion* signature
length: ~3380 bytes is a genuine ECDSA-DER || ML-DSA-65 pair.

With a breakpoint on `core1_hybrid_sign` during an assertion you get the
signing inputs and the whole chain:

```gdb
Breakpoint 1, core1_hybrid_sign (ecdsa_scalar=0x20081b40, mldsa_seed=0x20081b60,
    msg=0x2004950c <to_sign>, msg_len=69, sig=0x20047a58 <sig> "0D\002 @...",
    sig_len=0x20081720) at src/core1_signer.c:453

(gdb) bt 4
#0  core1_hybrid_sign (...) at src/core1_signer.c:453
#1  credential_sign (...) at src/credential.c:240
#2  emit_assertion (...) at src/ctap2.c:832
#3  handle_get_assertion (...) at src/ctap2.c:1245
```

The `sig` buffer already holds `30 44 02 20 ...` -- the ECDSA half, in DER,
mid-construction -- while the ML-DSA half is still to come from core 1.
A brief halt here is survivable: the host's assertion still completed
(`sigLen=3381`) after inspecting registers and stepping.

Note a PIN is not required to reach any of this. `getInfo` advertises
`makeCredUvNotRqd=true`, so a non-discoverable, non-UV MakeCredential and
its assertion go through with no `pinUvAuthParam` at all -- useful when the
device has a PIN nobody remembers, since guessing burns retries (8, then
the PIN is blocked until a reset).

```gdb
Breakpoint 1, ctap2_dispatch (payload=payload@entry=0x20045c9c <scratch> "\004",
    payload_len=payload_len@entry=1, resp=resp@entry=0x2003d208 <resp> "",
    resp_cap=resp_cap@entry=7609, resp_len=resp_len@entry=0x20081e84)
    at src/ctap2.c:1457
1457	    if (payload_len < 1 || resp_cap < 1) {

(gdb) info registers r0 r1 r2 sp lr pc
r0   0x20045c9c    537156764
r1   0x1           1
r2   0x2003d208    537121288
sp   0x20081e70    0x20081e70
lr   0x20000999    536873369
pc   0x20002df8    0x20002df8 <ctap2_dispatch>

(gdb) p/x payload[0]
$1 = 0x4            # authenticatorGetInfo

(gdb) bt
#0  ctap2_dispatch (...) at src/ctap2.c:1457
#1  0x20000998 in dispatch_complete (...) at src/ctaphid.c:344
#2  0x20000ce4 in ctaphid_recv_frame (...) at src/ctaphid.c:532
#3  0x20000740 in tud_hid_set_report_cb (...) at src/fido_hid.c:266
#4  0x2002a960 in hidd_xfer_cb (...) at tinyusb/src/class/hid/hid_device.c:400
#5  0x20029430 in tud_task_ext (...) at tinyusb/src/device/usbd.c:659
#6  0x200006e2 in tud_task () at tinyusb/src/device/usbd.h:69
#7  0x20000320 in main () at src/main.c:239

(gdb) continue
```

That backtrace is worth a second look: frames #4-#7 show the target is
halted **inside `tud_task()`**, and GDB is being served over USB from
there -- the monitor's polled pump keeping its own transport alive
through the stack it stopped in. This is the nesting described under
[Halting inside `tud_task()`](#halting-inside-tud_task), working.

`stepi`, `next`, `finish`, `x/16xb`, `info frame`, and watch-free
`display` all work. Full `step` over a line works too, though see the
breakpoint budget below.

`stepi` retires exactly one instruction, variable Thumb widths included
-- stepping into `ctap2_dispatch`'s prologue on silicon walks
`0x20002df8 -> 0x20002dfc -> 0x20002dfe -> 0x20002e00` (4, 2, 2 bytes),
matching the disassembly. Detaching resumes the token cleanly: a
`probe` run straight after a debug session returns the full CTAP
2.1 surface, unaffected.

### Validated in both execution modes

Breakpoints work whether `.text` runs from SRAM or flash, which is the
whole reason the stub uses FPB comparators instead of patched
instructions:

| Build | `ctap2_dispatch` | Result |
|---|---|---|
| default (`copy_to_ram`, level 65) | `0x20002df8` (SRAM) | breakpoint hit, `stepi` 4/2/2 bytes |
| `-DPQF_COPY_TO_RAM=0` (XIP) | `0x10002ec8` (flash) | breakpoint hit, `stepi` 4 bytes, `.text` disassembled through `m` |

The XIP row is the important one: a comparator matched an address in
flash, which no instruction-patching stub could have done without a
sector erase.

## How it works: monitor-mode debug

A hardware probe halts the core **from outside**, over the DAP. There is
no probe here, so the core has to debug itself: ARMv8-M **monitor-mode
debug**.

With `DEMCR.MON_EN` set, debug events -- an FPB address match, a `BKPT`
instruction, a completed single step -- raise the **DebugMonitor
exception** instead of halting the core. The stub's DebugMonitor handler
*is* the debugger: it captures the interrupted context off the exception
frame, then sits in a packet loop serving GDB until told to resume.

So "halted" here means **"spinning inside an exception handler"**, not
"the clock stopped". Consequences run through everything below.

Design points worth knowing:

**DebugMonitor runs at priority 0** (the highest configurable level), so
breakpoints work almost anywhere, including inside ordinary
(priority 0x80) interrupt handlers. The price: while halted, *no*
interrupt can preempt the monitor -- so the monitor services USB **by
polling** (`tud_int_handler(0)` then `tud_task()`). That is precisely
the interrupt-free USB pump the pure-RISC-V port already runs full-time
(see `pqf_usb_task()` in `src/fido_hid.c`), so it is a proven shape on
this firmware rather than a novel one.

**Breakpoints use the FPB, not patched instructions.** GDB's `Z0`
"software breakpoint" normally rewrites the target instruction with a
trap -- impossible here, because `.text` is in XIP flash (or a
`copy_to_ram` image) and patching flash means a sector erase. The
ARMv8-M FPB comparators match *any* instruction address, XIP included,
so the stub maps **both** `Z0` and `Z1` onto them. **The RP2350's M33
gives you 8 comparators, so 8 breakpoints.** The 9th is refused with
`E0E` and GDB says "cannot insert breakpoint" -- it does not silently
lose one.

**Single-step uses `DEMCR.MON_STEP`.** Returning from the monitor with it
set retires one instruction and re-enters. For the duration of the step
`BASEPRI` is raised to `0x20`, masking every default-priority interrupt,
so the step lands on the next *application* instruction rather than the
first instruction of whatever IRQ happened to be pending. (The monitor's
own re-entry at priority 0 is unaffected.)

**Ctrl-C uses `DEMCR.MON_PEND`,** set from `pqf_gdb_poll()`. Poll is
called only from controlled thread-level sites -- the main loop, the
core-1 long-op tick, the user-presence gate -- so an async halt can never
land halfway through a TinyUSB queue operation the monitor is about to
re-enter. The halt is also *deferred* to the end of the receive drain
rather than taken inline: entering the monitor while the drain still held
buffered bytes would strand them where the monitor's own drain (which
reads the CDC FIFO) could not see them, and a resume packet landing
there would wedge the session.

**The FPB is master-disabled while halted** (`FP_CTRL.ENABLE=0`), so the
stub cannot trip its own breakpoints while pumping USB through the very
stack you are debugging. Comparators are re-armed on resume.

### Halting inside `tud_task()`

The FIDO dispatch runs *inside* a TinyUSB callback
(`tud_hid_set_report_cb` -> `ctaphid_recv_frame` -> `ctap2_dispatch`), so
a breakpoint there halts under `tud_task()` -- and the monitor then calls
`tud_task()` again to talk to GDB.

That nesting is not new. This firmware already re-enters `tud_task()`
from inside dispatches routinely: `fido_hid_send_frame()`'s
endpoint-ready wait, the KEEPALIVE long-op tick, the user-presence gate.
The CTAPHID layer defends its state against exactly this with the
`s_dispatching` / `ERR_CHANNEL_BUSY` guard (`src/ctaphid.c`).

The one case that genuinely breaks is a **breakpoint inside TinyUSB or
the RP2350 device driver itself** -- the endpoint and queue bookkeeping
the monitor's own pump depends on. Don't do that; the transport can't
debug itself. Everything above the transport is fair game.

## The Rust port

The Rust firmware has an equivalent stub
(`crates/firmware/src/gdbstub.rs`), built behind `--features gdb_stub`
and off by default for the same reason as the C one.

It is the same mechanism, because the mechanism is the silicon's:
monitor-mode debug via `DEMCR.MON_EN`, FPB comparators for breakpoints,
and the DebugMonitor handler acting as the debugger. Three things differ
in how they are expressed:

- The **halted spin runs in the firmware's main loop**, not inside the
  exception handler. USB must keep being serviced while the target is
  stopped, and the `UsbDevice` lives in that scope; the monitor sets a
  flag and waits for the loop to pump it.
- The **entry trampoline is `#[unsafe(naked)]`**. A normal prologue
  moves SP before the stacked exception frame can be read, and that
  frame is the whole point -- r0-r3, r12, lr, pc and xpsr come out of
  it, and register writes have to go back into it before resuming.
- The **CDC transport is new**. The Rust port exposed FIDO HID alone, so
  `usbd-serial` is added under the same feature, allocated before the
  USB device is built so its endpoints reach the configuration
  descriptor.

Memory reads and writes are whitelisted to flash, SRAM, peripherals and
the PPB. A debugger is an arbitrary read/write primitive by design, but
reading a reserved window faults and takes the token down mid-session,
which is a worse failure than refusing the packet.

### Testing it without hardware

The engine has its own host suite -- 47 checks in
`crates/gdbstub-core/tests/engine.rs`, with the same section headings as
the C port's `test_gdbstub.c` so the two can be read side by side. What
differs is the split: the C stub is one file holding both the protocol
and the DEMCR/FPB pokes, so its suite fakes the hardware registers.
Here the hardware lives in the firmware crate behind `Target`, so the
sections about MON_STEP and FPB master-disable have no counterpart --
those can only be judged on silicon.

It found `vKill` leaving every FPB comparator armed. `D` and `k` cleared
them and resumed; `vKill` only resumed, though the table below has
always said all three release the comparators. A debugger that exits
that way leaves the token trapping into a monitor nobody is listening
to, which halts it for good and looks from outside like a dead token.
All three now share one `detach`.

**Both fixes confirmed on the Feitian, 2026-08-26.** For `vKill`: a
breakpoint on `handle_cbor+20` trapped (`pc 0x10007d44`, `sp
0x2007b890`), GDB's `kill` was acknowledged, and then five consecutive
`getInfo` calls -- every one of which re-enters `handle_cbor` at exactly
the address the comparator was armed on -- all answered normally. Before
the fix the first of those would have trapped into a monitor with no
debugger attached and taken the token down for good, which is precisely
the failure that reads as dead hardware.

It also found the engine had no `}`-unescaping, which the C port has
had all along. GDB escapes `#`, `$`, `}` and `*` in packet data by
XORing with 0x20; the Rust engine copied the escape byte through
verbatim and let an escaped `#` end the packet early. It never bit in
practice because the packets this stub supports are hex-encoded, so
those bytes do not occur -- but the two stubs disagreed, and only one of
them was tested.

That one needed hand-crafted packets to test on hardware, since GDB only
escapes a byte when a payload needs it and every packet this stub
supports is hex-encoded. Driven raw over the token's own CDC
(the RSP escaping rule): `q}attached` -- the `A` sent as `}` + 0x61 --
came back `$1#31`, and `p}\x03`, an escaped `#` mid-packet, came back
`$E01#a6` rather than being cut short at the escape. So the decoder
runs, and an escaped terminator no longer ends the packet.

The protocol layer lives in its own crate, `crates/gdbstub-core`, and
the firmware links it -- so the code a real GDB is pointed at is the code
that ships. What stays in the firmware is only what needs silicon: the
DebugMonitor trampoline, the FPB and DEMCR writes, and the USB
transport.

```bash
cargo run -p pqf-gdbstub-core --example pty --features std \
    --target "$(rustc -vV | awk '/^host:/{print $2}')"
# prints:  gdbstub pty ready: /dev/ttysNNN
arm-none-eabi-gdb -ex 'target remote /dev/ttysNNN'
```

Validated that way against `arm-none-eabi-gdb`: register read and write
(`set $r5 = 0x5a5a5a5a` round-trips), memory read and write
(`0x20001000` reads back `0xcafebabe`), breakpoint set and delete,
`stepi`, and a clean detach.

### Validated on the token

The Rust stub was then driven on a Feitian RP2350 over USB:

- `x/4xw 0x10000000` returned the real vector table -- `0x20080000`
  (initial MSP), `0x10000139` (reset vector) -- read through the stub's
  own `m` packets.
- A write took effect in hardware: `DEMCR` went `0x00110000` ->
  `0x00100000`, confirmed by reading it back.
- **A breakpoint trapped into DebugMonitor and GDB resolved it to
  source**: `Breakpoint 1, usb_device::device::UsbDevice<...>::poll
  (self=0x2007de64, classes=...) at device.rs:175`, with `pc` exactly at
  the comparator address, `sp` in SRAM and `lr` pointing into firmware --
  the trampoline capturing the stacked frame correctly.
- The token stayed enumerated while halted, which is the whole design:
  CDC kept answering while CTAPHID went quiet, because the application
  loop was stopped and the monitor was not.
- `z0` then `c` resumed it, and the conformance suite (an external CTAP
  2.1 conformance suite, not part of this repository) immediately went
  back to passing. So the stub is non-invasive when idle.

**Register writes reach the target, and that has teeth.** The stacked
frame was cross-checked independently: reading `$sp-32` as memory at a
breakpoint returned exactly the frame GDB reported -- `r0` matching the
`self` argument, `lr` and `pc` matching the register view, xPSR with the
Thumb bit -- confirming `sp = frame + 32` and every field offset that
write-back depends on.

Proving the write path then crashed the token, and correctly so: the
test wrote garbage into **r7, which is the frame pointer** on Thumb.
Resuming `UsbDevice::poll` with a corrupt frame pointer faults on the
epilogue. Before write-back existed the same test left the firmware
running happily, because the value never left GDB's copy -- so the crash
is the evidence.

#### Proving it without taking the token down

A crash is evidence but a poor regression test. The same thing can be
shown by letting the **target itself** report the value back, which
needs no corrupt state at all.

`handle_cbor` opens with three stores of registers that were just
loaded with constants:

```
10007cf0:  movs r0, #0
10007cf2:  movs r4, #1
10007cf4:  cmp  r2, #0          <- breakpoint A
10007cf6:  str  r0, [sp, #116]
10007cf8:  str  r4, [sp, #120]
10007cfa:  str  r0, [sp, #124]
10007cfc:  beq  ...             <- breakpoint B
```

Stop at A, overwrite `r0` and `r4` with sentinels, resume, and stop
again at B. The CPU has executed the three stores in between, so the
stack tells the truth:

```
A hit  sp=0x2007b890  r0=0x00000000  r4=0x00000001
A wrote sentinels r0=0xa5a5a5a5 r4=0x5a5a5a5a
B hit  r0=0xa5a5a5a5  r4=0x5a5a5a5a
B stack 0x2007b904: 0xa5a5a5a5  0x5a5a5a5a  0xa5a5a5a5
B restored          0x00000000  0x00000001  0x00000000
```

Nothing but a write that reached the exception frame and was reloaded on
exception return can put those words there -- a stub that only updated
its own copy would store `0` and `1`. Restoring the originals at B (both
the registers and the three stack words) leaves the in-flight command
untouched: the `getInfo` the whole run rode on returned its usual
351-byte response.

`r4` matters as much as `r0`: it is callee-saved, so it is *not* in the
hardware exception frame. It comes from the trampoline's `r4-r11` push,
which `pop {r4-r11, pc}` restores. Covering both proves both halves of
write-back, not just the easy one.

**A halted token looks like a broken one.** CTAPHID stops answering and
`CMD_REBOOT` does nothing, because the loop that serves both is
suspended. If a token has gone quiet after a debug session, send `c`
before concluding anything is wrong with it. If GDB has already exited
without resuming, the token is not lost: the monitor is still pumping
USB, so attaching a fresh GDB and detaching again resumes it.

**`?` must halt a running target, not answer from memory.** The Rust
engine originally replied to `?` out of the register file captured at
the *previous* stop. On a first attach that reads as `0x00000000 in ??
()`, which is merely odd; on a re-attach it is worse, because GDB
believes the target is sitting at whatever address it last trapped on.
If that address holds a breakpoint, GDB steps over it when it resumes
-- and the next real hit is silently swallowed. Two identical sessions
back-to-back, the first working and the second appearing to have no
breakpoints at all, is the signature.

Ctrl-C had the same root cause: the engine recorded
`StopReason::Interrupt` and nothing ever stopped the core. `request_halt`
existed, was documented, and was called from nowhere.

Both are fixed by giving the target two questions to answer --
`is_halted` and `request_halt` -- and asking them on `?`, on Ctrl-C, and
before serving any register command. It is what the C port already did;
the Rust port had simply not caught up.

The one subtlety is *when* to raise `DEMCR.MON_PEND`. It fires the
instant it is written, and the monitor reaches USB by calling straight
back into packet handling -- so raising it from inside `feed` re-enters
the engine while the outer call still holds it. The request is recorded
instead, and taken in `poll` once packet handling has returned. On
silicon the stop then lands on the instruction after the `dsb` in
`request_halt`, which is exactly where it should.

Validated on the token: `SIGINT` during a free-running `continue` gave
*"Program received signal SIGINT, Interrupt"* with a live PC, and two
back-to-back attach/breakpoint/detach sessions behaved identically --
where before the fix the second one skipped its first hit.

**`qXfer:features:read` is not optional.** Without a target description
GDB assumes the legacy 26-register ARM layout and rejects the
17-register `g` reply outright -- *"Truncated register 16 in remote 'g'
packet"* -- after which nothing else in the session works. The engine
serves an `org.gnu.gdb.arm.m-profile` description in the chunks GDB
asks for.

## Constraints

Monitor-mode debug is weaker than SWD in specific, knowable ways.

**No halt-the-world.** Timers keep running, USB stays enumerated, core 1
keeps executing. Sit on a breakpoint for 30 seconds and:

- the host's FIDO transaction times out (a browser WebAuthn ceremony
  will fail; a command-line client will report a timeout);
- any in-flight CTAPHID reassembly hits the 500 ms inactivity abort;
- `time_us_64()` deltas measured across the halt are meaningless.

This is inherent to monitor mode, not a bug and not fixable in software.
Debug logic, not timing.

**Core 0 only (v1).** Core 1 -- the hybrid-PQC signing worker -- is
untouched: its vector table is not modified and it keeps running free.
Halt core 0 during a signature and the sign completes into the mailbox
harmlessly; core 0 picks the result up when you continue. You cannot set
a breakpoint in core-1 code. Pinning debug to core 0 is a deliberate v1
scope decision: a second monitor on core 1 needs its own vector table,
its own transport arbitration, and a multi-thread `qfThreadInfo` story
in the RSP layer.

**Breakpoints do not fire in interrupt-masked regions.** A debug event
inside a `PRIMASK`-masked window escalates to HardFault instead of
raising DebugMonitor. In this firmware that means **do not breakpoint**:

- the flash-commit park window (`core1_run_flash_op` in
  `src/core1_signer.c`);
- `pqf_bootsel_pressed()` (`src/bootsel.c`) -- interrupts off *and* the
  XIP window unreadable;
- anything else at priority 0.

**Memory access is whitelisted.** `m` / `M` reach ROM (read-only), XIP
flash (read-only) and SRAM (read/write). Everything else -- peripherals
included -- is refused with `E01`. This is deliberate: a bus fault raised
*inside* the monitor escalates to HardFault and wedges the device, which
is the one thing a debug stub must never do to you. If you need a
peripheral register, read it from code and inspect the variable, or
extend the whitelist in `mem_ok()` for your own build. Flash writes are
refused too -- patching flash is the programmer's job, not a debugger
poke.

**A compiled-in `BKPT` now parks instead of wedging.** pico-sdk panics
(and the old `PICO_MALLOC_PANIC` path) execute `bkpt`, which with no
debugger attached used to wedge the device dark. With the stub linked
that vectors into the monitor: the token parks itself halted and waits
for you to attach and look around. `continue` from such a stop re-traps
in place -- by design, it's a panic, there is nowhere good to go.

**A real SWD probe wins.** If something holds `DHCSR.C_DEBUGEN`, halting
debug takes precedence architecturally and the monitor never fires.
`pqf_gdb_init()` detects this and warns on the banner port.

**Killing GDB leaves its breakpoints armed on the device.** `D`/`k`/
`quit` all release the FPB comparators, but a GDB killed outright
(Ctrl-C at the shell, a timeout, a crashed session) never sends them --
so the comparators stay armed with nobody listening. The next call that
matches then halts the target into a monitor loop waiting for a
debugger that isn't there, and the token looks bricked: USB still
enumerated, FIDO stops answering. It isn't. Reattach and `detach`
cleanly (which clears every comparator), or reflash -- a fresh boot
re-runs `fpb_init()`. Worth knowing before you conclude the firmware
hung: if the device went quiet right after you killed a debug session,
this is why.

## Supported RSP commands

| Packet | Meaning |
|---|---|
| `?` | halt reason (`S05` trap / `S02` interrupt); halts a running target first |
| `g` / `G` | read / write all 17 registers (r0-r12, sp, lr, pc, xpsr); `E01` while running |
| `p` / `P` | read / write one register; `E01` while running |
| `m` / `M` | read / write memory (whitelisted regions) |
| `c` | continue, optional resume address |
| `s` | single step (`MON_STEP`) |
| `Z0`/`z0`, `Z1`/`z1` | set / clear breakpoint (both onto FPB comparators) |
| `D`, `k`, `vKill` | detach -- all three share one path: release every comparator, clear `attached`, resume |
| `H`, `T` | thread select / alive (single-threaded: always OK) |
| `qSupported` | `PacketSize=800`, `qXfer:features:read+` |
| `qAttached` | `1` -- so `quit` detaches rather than offering to kill |
| `qXfer:features:read` | `target.xml` (armv8-m.main, m-profile) |
| `qRcmd` | `monitor` commands, below |
| Ctrl-C (`0x03`) | async halt via `DEMCR.MON_PEND`, taken outside packet handling |
| `}`-escaped bytes | decoded (`^0x20`) before the `#` terminator is looked for |

Anything else gets the empty reply, per the RSP spec, and GDB degrades
gracefully.

Deliberately **not** implemented in v1: watchpoints (`Z2`/`Z3`/`Z4` --
the DWT has the comparators, but a data-watchpoint story needs its own
design pass), `vCont` (plain `c`/`s` cover single-threaded stepping),
non-stop mode, and `X` binary memory writes (`M` is enough at these
sizes).

Writing `sp` via `G`/`P` is accepted but ignored -- the stack pointer is
derived from the exception frame's position and moving it would mean
relocating the frame. Everything else round-trips.

## `monitor` commands

```gdb
(gdb) monitor help
monitor reset   -- warm reboot
monitor bootsel -- reboot into BOOTSEL (reflash)
```

`monitor bootsel` is the useful one: it drops the token into the RP2350
bootloader straight from your debug session, so the
edit -> build -> flash -> debug loop never needs a physical BOOTSEL hold.
(GDB reports `Target disconnected` when you run it -- that is the device
vanishing to re-enumerate as the bootloader, not a failure.)
It reuses `pqf_board_reboot()`, the same path as
[`CTAPHID_CMD_REBOOT`](REBOOT.md) -- and note it is **not**
user-presence gated here. That is consistent with the rest of the stub
(a debugger that can already write RAM and set the PC gains nothing from
a touch prompt), and another reason the flag must not ship.

## Testing without hardware

The stub's protocol layer builds and runs on the host. `-DPQF_GDB_HOST`
swaps the ARMv8-M debug MMIO, the target memory, and the TinyUSB CDC
transport for simulated ones (`test/gdbstub_host.h`), so `src/gdbstub.c`
-- the same source the firmware links -- can be driven with no board
attached.

**Assertion suite** (73 checks: packet framing, checksums, `}`-escaping,
the `m`/`M` whitelist, register marshalling out of and back into a
synthesized exception frame, the FPB slot allocator and its exhaustion
behaviour, `qXfer` chunking, stop-reason classification, detach):

```bash
cd c/firmware/test && make build/test_gdbstub && ./build/test_gdbstub
```

It also runs as part of `make test`.

**Live session against a real GDB.** The harness can serve the stub on a
pty, optionally preloading a real firmware `.elf` into the simulated
SRAM so GDB resolves real symbols and disassembles real instructions
fetched through the stub's own `m` packets:

```bash
cd c/firmware/test
make build/test_gdbstub
./build/test_gdbstub --pty ../build-gdbstub/bruce_c.elf
# prints:  gdbstub pty ready: /dev/ttysNNN
```

then, in another terminal:

```bash
arm-none-eabi-gdb c/firmware/build-gdbstub/bruce_c.elf \
    -ex 'target remote /dev/ttysNNN' \
    -ex 'break ctap2_dispatch' -ex continue
```

`make gdbstub-live` is the shorthand (no ELF).

The harness models the three hardware behaviours it stands in for the
way the architecture specifies them -- `MON_PEND` takes the exception,
`MON_STEP` retires one instruction and re-enters, an armed comparator
stops execution at its address -- rather than the way the stub happens to
be written, so it tests the stub instead of agreeing with it.

**What this cannot cover** are the four behaviours that are hardware by
definition: that the DebugMonitor exception actually fires on the
RP2350; that the FPB comparators actually match in XIP and in a
`copy_to_ram` image; that `MON_STEP` retires exactly one instruction;
and that the monitor's polled USB pump really keeps the link up while
halted inside `tud_task()`.

**All four are silicon-validated** on the Feitian RP2350 (2026-07-29) --
see [the exit-criteria walkthrough](#the-exit-criteria-walkthrough) for
the transcript, including the backtrace proving the halt-inside-
`tud_task()` case and the SRAM-vs-XIP breakpoint table. Keep running the
host suite anyway: it is where the protocol-layer regressions get
caught, and it needs no board.

## Security: why this must never ship enabled

The stub is a complete bypass of every protection the firmware has. Over
a plain USB serial port, with no authentication whatsoever, it offers:

- **read all of SRAM** -- which includes the master key material
  `flash_store.c` loads at boot, any PIN token in flight, and every
  credential blob in use;
- **write all of SRAM** -- patch out the user-presence check, patch the
  PIN retry counter;
- **redirect execution** -- `P` the program counter anywhere, or `set
  $pc` from GDB;
- **reboot to the bootloader** -- `monitor bootsel`, no touch required.

There is no gate on any of it. That is the right design for a *developer
build* -- a gate you can bypass by writing to your own RAM is theatre --
and an unacceptable one for a production token.

The line the stub draws is therefore a **build-time** one:

- `PQF_GDB_STUB` defaults **OFF**;
- with it off, `gdbstub.c` is not compiled, the second CDC interface
  does not exist in the descriptors, and no stub symbol is linked
  (`nm | grep -i gdb` -> empty);
- so a production-signed image cannot carry the stub by accident -- the
  flag has to be passed explicitly, and the resulting device is visibly
  different (an extra tty, a banner line announcing it).

A future runtime story -- a debug capability unlocked by an
authenticated challenge/response against a vendor key, so a
production-signed image *can* carry a dormant stub -- is a reasonable
follow-on, and would need: an unlock command in the vendor CTAPHID
range, key provisioning at manufacture, monotonic anti-rollback, and a
decision about whether unlocking wipes credentials first (it probably
must). None of that is in v1. **v1's rule is simply: debug build or
production build, never both.**

Related: [`docs/FLASHING.md`](FLASHING.md) for how images get onto a
device, and the
[buttonless-lockout warning](REBOOT.md#warning-buttonless-tokens-can-be-locked-out-of-bootsel)
-- a sealed token you flash a *non*-stub, *non*-`CMD_REBOOT` image onto
can become unreflashable.

## Troubleshooting

**`target remote` hangs or times out.** Check you're on the GDB tty, not
the banner tty -- attaching to the banner port sends RSP packets into the
boot-banner stream and neither side ever agrees. The GDB port is the
higher-numbered one and is silent until spoken to.

**"Remote replies unexpected: ..." on attach.** Something else has the
port open. `screen` on the wrong tty is the usual culprit; so is a
second GDB. One client at a time.

**Breakpoint never hits.** Three common causes: (a) the address is in
core-1 code, which this stub doesn't cover; (b) the code sits in an
interrupt-masked region (see [Constraints](#constraints)),
so the event escalated to HardFault instead -- if the device went dead
rather than stopping, this is why; (c) you're out of comparators, in
which case GDB already told you `Cannot insert breakpoint`.

**`Cannot access memory at address 0x...`.** The address is outside the
whitelist -- peripheral space, most likely. Expected; see
[Constraints](#constraints).

**The device dies when I continue.** If you stepped or breakpointed
inside TinyUSB internals, the monitor's own USB pump re-entered a
half-updated queue. Reflash and avoid the transport layer.

**`WARNING: C_DEBUGEN set` on the banner.** An SWD probe is attached and
owns the core; halting debug wins over monitor debug architecturally.
Detach the probe.

**No second tty appears at all.** The build didn't get the flag. Confirm
with `arm-none-eabi-nm build-dir/bruce_c.elf | grep -i gdb` -- a stub
build lists `pqf_gdb_init`, `pqf_gdb_poll`, `pqf_gdb_monitor_entry`.
