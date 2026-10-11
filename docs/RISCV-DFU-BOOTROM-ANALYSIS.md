# RISC-V over DFU -- the bootrom, read properly

A technical analysis of the RP2350 boot ROM's launch rules, written to
explain why every attempt to launch a RISC-V application through the
DFU bootloader had failed, and to derive the route that works: the
block-loop annex, since implemented in `c/bootloader/` and documented
in [DFU.md](DFU.md#risc-v-apps-over-dfu-the-block-loop-annex). The
bootloader code cites this document. It is for someone changing the
bootloader's launch path or repeating the experiments, and assumes the
DFU flash layout of [DFU.md](DFU.md); the diagnostic trail that led
here is [notes/RISCV-DFU-HANDOFF.md](notes/RISCV-DFU-HANDOFF.md), and
the secure-boot interaction it settles is in
[SECUREBOOT.md](SECUREBOOT.md).

**Status: ROOT-CAUSED, 2026-08-21.** Every observation from the
2026-08-20 silicon campaign is now explained by the bootrom sources and
the datasheet, with nothing left over. Nothing tried in that campaign
could have worked; two routes that can work are at the end. No new
silicon was touched for this analysis.

Sources: RP2350 datasheet ch. 5 (sec. 5.1.19, sec. 5.1.20, sec. 5.2.2.2, sec. 5.2.4,
sec. 5.2.4.1, sec. 5.2.5, sec. 5.1.16-17) and the published bootrom sources
(`raspberrypi/pico-bootrom-rp2350` @ `c6cdb17`), which are the ground
truth the SDK headers paraphrase. File references below are into that
repo.

## The two ROM laws that doomed all nine configurations

**Law 1 -- the ROM only ever launches what its own scan finds.** There
is no "boot this window in the other architecture" primitive. When any
launch path meets an IMAGE_DEF for the other CPU, it calls
`s_varm_crit_redo_last_reboot(TO_RISCV/TO_ARM)`
(`varm_launch_image.c:382-397`), which re-issues the *enclosing boot's*
type and parameters from `bootram.always.zero_init.reboot_params`
(`varm_launch_image.c:59-64`). Boot types that live in watchdog scratch
(RAM_IMAGE, FLASH_UPDATE) are therefore retained across the switch --
sec. 5.1.20 says exactly this -- but a `chain_image()` window is an API
argument, not a boot type. It is forgotten. The post-switch boot re-runs
the *normal* scan, finds the Arm bootloader in slot 0, and switches
straight back.

**Law 2 -- a flash-window launch is always rolled to 0x10000000.**
`verify_and_launch_flash_image` computes
`roll = flash_start_offset + rolling_window_delta` and programs QMI
ATRANS with it (`varm_launch_image.c:224-252`; sec. 5.1.19). Identity
mapping requires `roll == 0`, and negative `ROLLING_WINDOW_DELTA` values
are only allowed at -4 MiB granularity (sec. 5.1.19; enforced at
`varm_launch_image.c:200-205`). An image stored at offset `0x21000` can
therefore *never* be chain- or partition-launched at its storage
address. Our apps are linked at `0x10021000` and read the credential
store at absolute `0x103FF000`; under a rolled window the first is wrong
by `0x21000` and the second bus-faults (sec. 5.1.19: accesses beyond the
mapped partition fault).

Both laws were invisible from the SDK headers.

## Each observed failure, explained

### `rom_chain_image()`: the "hang" was never a hang

The walk recorded nibble 0 ("never came back") for every strategy past
the lock gate. Two different mechanisms produce that same observable:

- **RISC-V app**: the window scan finds the image, verification
  passes, the launch sees the other-CPU IMAGE_DEF and performs the
  redo-reboot with `NO_RETURN_ON_SUCCESS` -- *the call cannot return on
  success*. Law 1 then loses the window: the RISC-V-side normal scan
  finds only the Arm bootloader, flips back, the bootloader advances the
  walk and tries the next strategy. Four strategies, four reboots,
  ending in DFU. Exactly what silicon did.
- **Arm app (the control)**: same-CPU, so the ROM launches it -- rolled
  (Law 2). Code linked at `0x10021000` executes in a window mapped to
  `0x10000000`; every absolute reference lands `0x21000` deep into the
  wrong storage. It dies before `pqf_boot_checkin()`, the launch guard
  fires, the walk advances. Same nibble, different corpse.

So "Arm and RISC-V fail identically" was true and misleading: two
unrelated failures with one signature. The other codes now read
cleanly too:

- `-19 LOCK_REQUIRED`: `chain_image` is a scan-workarea API; its entry
  gate is `inline_s_lock_check(BOOTROM_LOCK_SHA_256)`
  (`varm_apis.c:507-527`). Hold the SHA lock (or disable lock
  enforcement) and the gate passes. The lock was never the bug.
- `-4 NOT_PERMITTED`: `verify_and_launch_image`'s "can't launch
  unverified image" (`varm_launch_image.c:269-273`) -- an image whose
  verification failed in that (contaminated) ROM state, not a
  permission refusal. The BOOTRAM partition-table contamination finding
  from 2026-08-20 stands.

### `rom_reboot(PC_SP | TO_RISCV)`: dark by design

The watchdog boot vector is consumed *before* any flash bring-up: the
boot path calls the PC directly (`varm_boot_path.c:1207-1233`), and
sec. 5.2.3/sec. 5.2.4 describe PC_SP as vectoring into "code preloaded in RAM".
After the reboot QMI is at reset state, so the first fetch from
`0x10021036` bus-faults with no watchdog armed. Dark forever, and cold
boot re-runs the same launch -- which is why the token stayed dark
across power cycles. PC_SP is only usable for RAM-resident code.

### `rom_reboot(FLASH_UPDATE | TO_RISCV)` + partition table: three independent kills

1. **p0 is an XIP address, not an offset.** The vectored boot stores
   `params[0]` as `flash_update_boot_window_base` and the boot path
   subtracts `XIP_BASE` (`varm_boot_path.c:1190-1194`, `:857`). We
   passed `0x20000`; the ROM computed update offset `0xF0020000`.
   The "first thing to try" in
   [the handoff note](notes/RISCV-DFU-HANDOFF.md) was a real bug -- and
   fixing it would not have mattered, because:
2. **FLASH_UPDATE does not launch a window at all.** It is a version
   bias -- "allowing older versions to boot in preference to newer
   ones" for A/B pairs plus TBYB arming (sec. 5.2.4.1, sec. 5.1.16-17). The
   mode-2 design assumed it "biases the boot toward the slot in p0".
   It has no such semantic; the scan is the normal scan.
3. **A slot-0 IMAGE_DEF shadows the partition table.** If the slot-0
   block loop contains an executable IMAGE_DEF, the ROM boots *it* and
   the partition walk never runs -- it is the `else` branch
   (`varm_flash_boot.c:117-131`). While the bootloader occupies slot 0,
   no partition table can ever route a boot to the app slot. The
   partition-table experiment was structurally dead before p0 was even
   looked at.

The observed dark is the flip-flop: RISC-V-side scan -> only candidate
is the Arm bootloader (selection prefers the right CPU but will take
the wrong one when it is alone, `varm_flash_boot.c:662-679`) -> redo ->
Arm side boots the bootloader -> `PQF_BOOT_RISCV_LAUNCH` fires again ->
TO_RISCV -> forever. USB never comes up on either side. Power cycling
re-enters the same loop from cold. That is precisely the "no FIDO, no
DFU, no BOOTSEL" stranding, and why only the button broke it.

### Why the "come back into DFU" belt never held

The ROM owns watchdog scratch 2-7 for reboot vectoring (sec. 5.2.4,
sec. 5.2.4.1; `varm_apis.c:143-201`): every `rom_reboot()` writes
`scratch[2]=p0, scratch[3]=p1, scratch[4]=0` and the one-shot types
also write 5/6/7. Our DFU magic lives in scratch 2/3; it is destroyed
by the very reboot it was meant to survive. (SDK `watchdog_reboot()`
with pc=0 only zeroes scratch 4, which is why the launch guard works
everywhere else.) Any future design must keep re-entry flags out of
scratch 2-7 across ROM-driven reboots -- an SRAM sentinel survives
watchdog resets and the ROM does not scrub it.

### One more thing the datasheet settles: secure boot decouples

sec. 5.2.2.2: on RISC-V, **"Secure boot is not supported (from any image
source)"** -- also no anti-rollback, no RCP hardening. So OTP secure
boot ([SECUREBOOT.md](SECUREBOOT.md)) and RISC-V apps are mutually
exclusive at the chip level.
`chain-image` being parked no longer gates secure boot for the Arm ports: the
ROM re-verifying a *chained* window is unavailable to us either way
(Law 2 forbids our identity layout), and as recorded on 2026-08-20 the
bootloader's own ECDSA gate keeps the chain of trust intact under
secure boot without `chain_image`.

## Two routes that fit the ROM's actual rules

### Route A (recommended): stitch the app's IMAGE_DEF into the slot-0 block loop

Block loops are chains of *window-relative* signed links; only the
first block must sit in the first 4 KiB of the window -- subsequent
links may point anywhere in it (`varm_flash_boot.c:26`,
`varm_blocks.c:56-205`), and the slot-0 scan window is the whole
flash. Selection between multiple executable IMAGE_DEFs in one loop
prefers the current CPU (`varm_flash_boot.c:672-679`). That yields a
per-architecture dispatch with no partition table and no relinking:

- Reserve one bootloader-owned sector as a **block-loop annex** (e.g.
  the last bootloader sector, `0x1F000`), and point the bootloader's
  embedded block's next-link at it (picotool does loop edits of this
  kind when sealing; ours is a fixed offset known at build time). The
  annex closes the loop back to the bootloader's block. Empty annex =
  one IGNORED block.
- On DFU install of a RISC-V app, after ECDSA verification, copy the
  app's IMAGE_DEF block (IMAGE_TYPE + ENTRY_POINT items are absolute
  addresses; our unsealed images carry no window-relative hash items)
  into the annex. Arm installs clear it. The annex must only ever hold
  RISC-V IMAGE_DEFs -- an Arm one would out-rank the bootloader on Arm
  boots (later block wins between two right-CPU candidates).
- To launch: `rom_reboot(NORMAL | TO_RISCV | NO_RETURN, ...)`. The
  RISC-V-side scan now finds a right-CPU IMAGE_DEF in slot 0 and boots
  the app **identity-mapped**: the slot-0 window has
  `flash_start_offset == 0`, so `roll == 0` and no ATRANS is written --
  the same launch state as the silicon-validated standalone boots.
  Entry is the block's `0x10021036`. Law 2 is satisfied with delta 0;
  the link script does not change; `0x103FF000` stays valid.
- Failure containment for free: if the annex block is bad, the RISC-V
  scan falls back to the Arm bootloader, auto-switches back
  (sec. 5.1.20), and the bootloader -- seeing a launch-attempt sentinel in
  SRAM (not scratch 2/3!) -- stays in DFU. The only dark window is a
  RISC-V app that verifies, launches, and then crashes; that is the
  same exposure the Arm in-place jump has today.
- Reboots of a running RISC-V app stay RISC-V and re-launch it via the
  annex (ARCHSEL is sticky until changed); reaching DFU from RISC-V is
  a `rom_reboot(NORMAL | TO_ARM)` plus the SRAM sentinel, which slots
  into the existing sec. 4.x CMD_REBOOT plumbing.

Validation is mostly host-side: a loop-walker that replays
`s_varm_crit_next_block`/selection over a candidate flash image (we
have the ROM sources to mirror), plus `picotool info` on the stitched
file before anything touches a board.

### Route B (fallback): RAM_IMAGE reboot through a RISC-V second stage

`rom_reboot(RAM_IMAGE, ms, base, size)` makes the ROM search an SRAM
window for an IMAGE_DEF and launch it (sec. 5.2.5), and sec. 5.1.20 explicitly
retains RAM_IMAGE scratch info across the automatic architecture
switch -- the ROM re-runs the same RAM boot on the RISC-V side and
launches natively. The catch: XIP is down when the RAM image starts, so
the staged binary must be a small RISC-V RAM-linked stub that brings up
flash (ROM flash APIs run under varmulet on RISC-V) and jumps to
`0x10021036`. Works with zero flash-layout changes, costs a second
binary and an SRAM staging protocol. Keep in the drawer in case the
annex meets an undocumented edge.

## What changed in the tree

- **Route A is implemented AND silicon-validated** (same day, Feitian
  RP2350): a RISC-V C-port app installed over DFU launches through the
  annex and completes a full hybrid ML-DSA-65-ES256 register + sign
  over USB; flash read-back confirms the ROM launches the annex's
  RISC-V IMAGE_DEF (cpu=1, entry 0x10021036) identity-mapped while the
  slot-0 loop still resolves to the Arm bootloader on the Arm side. The
  earlier empirical dead ends stand; the annex was never one of them.
- The annex is the SDK's own
  embedded end block pinned at `PQF_ANNEX_OFF` by
  `c/bootloader/pqf_annex.ld`, the bootloader re-syncs it from the
  verified app image every boot and launches RISC-V apps with
  `rom_reboot(NORMAL | TO_RISCV)`, the bounce sentinel lives in
  watchdog scratch 7, and the firmware's RISC-V DFU return rides
  `rom_reboot(NORMAL | TO_ARM)` p0/p1. The Rust image def gained the
  ENTRY_POINT item a transplanted block requires.
  `tools/annex_check.py` replays the ROM scan host-side; operational
  detail lives in docs/DFU.md. The `PQF_BOOT_RISCV_LAUNCH` reboot
  experiments were removed with it (this document and git history are
  their record); the earlier p0 fix matters only to that history.
- This document. The earlier handoff note, [notes/RISCV-DFU-HANDOFF.md](notes/RISCV-DFU-HANDOFF.md), points here.

## Hazards carried forward

- Never park re-entry state in watchdog scratch 2-7 across a
  `rom_reboot()`; the ROM owns them (sec. 5.2.4.1). Scratch 0/1 and SRAM
  survive.
- The annex sector is executable-adjacent bootloader flash: the DFU
  write path must treat it like the app slot (erase+program+verify),
  and the stitched link must be validated host-side before first
  flash -- a malformed loop invalidates slot 0's *entire* block list
  (>256-block walk = invalid, `varm_blocks.c`), which would take the
  bootloader's own IMAGE_DEF out of the scan and drop the token to
  BOOTSEL on the next boot. Recoverable via picotool, but only at the
  bench.
- `PQF_CHAIN_ONLY` / the chain walk stay useful as instrumentation,
  but any future chain experiments should expect Law 1 and Law 2 --
  there is nothing left to learn from chaining our current layout.
