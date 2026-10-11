# RISC-V over DFU -- handoff

> Point-in-time record, kept for its findings. Dates and line numbers
> are as of the date in the text; the current tree has moved on. Start
> from [docs/GETTING-STARTED.md](../GETTING-STARTED.md) for the present
> state.

**Status: SOLVED and SILICON-VALIDATED 2026-08-21.** The block-loop
annex (see [DFU.md](../DFU.md) and
[RISCV-DFU-BOOTROM-ANALYSIS.md](../RISCV-DFU-BOOTROM-ANALYSIS.md)) launches
RISC-V apps over DFU on the Feitian RP2350: install -> annex launch ->
FIDO enumeration -> full hybrid ML-DSA-65-ES256 register + sign over the
wire, stable across repeated reboots and the Arm->RISC-V upgrade. This
file is kept for the diagnostic trail that got here; every "blocked"
statement below is historical. The whole thing that follows was true
until it wasn't.

RISC-V images install and verify over DFU perfectly,
then never run. Everything else about DFU works, including mixed-ISA.

## Why it is blocked

ARCHSEL -- switching the RP2350 between Cortex-M33 and Hazard3 -- is a
bootrom decision. The bootloader's handover is `msr MSP / cpsie i / bx`,
Arm instructions that cannot switch architecture. So the ROM has to
launch a RISC-V image, and every ROM route tried so far fails.

## Three ROM mechanisms tried, all fail

| Mechanism | Result |
|---|---|
| `rom_chain_image()` | `-4 NOT_PERMITTED` when `BOOTROM_LOCK_ENABLE` is released; **hangs** in every configuration that satisfies the SHA-256 lock gate |
| `rom_reboot(PC_SP \| TO_RISCV)` | reboot taken (call does not return), device **dark** |
| `rom_reboot(FLASH_UPDATE \| TO_RISCV)` + partition table | device **dark** |

Arm and RISC-V return *identically* from `chain_image`, so the blocker is
not architectural and not ATRANS.

**The most informative observation:** `FLASH_UPDATE` runs the ROM's FULL
boot path, which should fall back to BOOTSEL when it finds no bootable
image. It went dark instead. That suggests the architecture switch itself
leaves the chip in a state the ROM cannot recover from -- which is also
consistent with `chain_image` hanging once past its lock gate. Three
entry points, one shared symptom.

> **Superseded (2026-08-21):** the inference was wrong. The switch is
> fine; the ROM *did* find a bootable image on the RISC-V side -- this
> Arm bootloader -- and auto-switched back to run it, which re-fired the
> launch, forever. Dark = an architecture reboot-tennis loop in which
> USB never comes up on either side, not an unrecoverable chip state.
> The `chain_image` "hang" is unrelated (two mechanisms, one
> observable). See the analysis doc.

## FIRST THING TO TRY -- a likely argument bug, untested

> **Answered (2026-08-21), no silicon needed:** it IS an address -- the
> vectored boot stores p0 and the boot path subtracts `XIP_BASE`
> (`varm_boot_path.c:1193`, `:857`). The argument is fixed in main.c.
> Do NOT redo the mode-2 test though: the fix is insufficient, because
> FLASH_UPDATE is only an A/B version bias, and a slot-0 IMAGE_DEF
> (this bootloader) shadows the partition walk entirely. Mode 2 cannot
> launch this layout under any p0.

`c/bootloader/src/main.c` passes `PQF_APP_SLOT_OFF` (= `0x20000`, a flash
**offset**) as `p0` to the FLASH_UPDATE reboot. The SDK documents p0 as
*"the **address** of the start of the region of flash that was updated"*.
The partition table expresses partitions as offsets (`00020000->0010d000`),
so it is genuinely ambiguous -- but if the ROM wants an XIP address, it
should be `0x10020000` and the mode-2 test was invalid.

## Things already ruled out -- do not re-litigate

- **Entry point is correct.** The picobin `ENTRY_POINT pc=0x10021036` IS
  `_reset_handler`. The ELF header's `0x10021034` is a 2-byte
  `j reenter_bootrom` sitting immediately before it. Do not "fix" this.
- **Image parsing works.** `IMAGE_TYPE` item word `>> 24 & 7` gives the
  CPU field: 1 = RISC-V, 0 = Arm. Verified against real images
  (`0x11010142` riscv, `0x10210142` arm).
- **The RISC-V firmware is fine.** Standalone RISC-V builds are
  silicon-validated (18-config matrix, 2026-08-17). Flash one with
  picotool and it runs.
- Not the 2 MiB flash map, not `copy_to_ram`, not `PRIMASK` -- all fixed
  earlier and separately validated.

## Build flags

```bash
# RISC-V firmware -- PQF_PLATFORM, *not* PICO_PLATFORM
cmake -S c/firmware -B build -DPQF_BOARD=feitian_rp2350 \
  -DPQF_PLATFORM=rp2350-riscv -DPICO_TOOLCHAIN_PATH=/path/to/riscv-toolchain \
  -DPQF_BOOTLOADER=ON -DPQF_TEST_NO_USER_BUTTON=ON
readelf -h build/pqc_fido_c.elf | grep Machine    # MUST say RISC-V
```

(`PQF_RISCV_TOOLCHAIN_BIN` / `PICO_TOOLCHAIN_PATH` must point at a bare-metal riscv32 GCC; there is no default.)

`-DPICO_PLATFORM` is silently overridden by `set(PICO_PLATFORM ${PQF_PLATFORM})`
and yields an **Arm** build that configures, compiles and links fine.

```bash
# bootloader launch paths (both OFF by default)
-DPQF_BOOT_LAUNCH_CHAIN=ON      # rom_chain_image
-DPQF_CHAIN_ONLY=<0-3>          # pin ONE chain strategy to a clean boot
-DPQF_BOOT_RISCV_LAUNCH=1|2     # 1=PC_SP, 2=FLASH_UPDATE. CAN STRAND THE TOKEN.
```

## Instrumentation you inherit

- **Launch guard** -- bootloader arms the watchdog before the app jump;
  the app checks in via `pqf_boot_checkin()` once USB enumerates. A
  non-booting app resets back into DFU. **Does not cover `rom_reboot`
  paths** -- `rom_reboot` drives the watchdog itself, which is exactly why
  those failures go dark with no way back.
- **Trace breadcrumb** -- watchdog scratch 0/1 survive resets and are
  reported in the USB serial string as `PQF-DFU-Enn-Ssss`. Firmware init
  stages appear as `E64-S00NN`.
- **Chain strategy cycler** -- but note the strategies **contaminate each
  other**: `rom_load_partition_table()` caches in BOOTRAM across watchdog
  resets, so only the FIRST strategy of a walk is a clean measurement.
  That is what `PQF_CHAIN_ONLY` is for.

## Hazards that cost real time

- A partition table declaring unpartitioned space `absolute`-only **locks
  picotool out completely**: `Family ID 'rp2350-arm-s' cannot be
  downloaded anywhere`, `erase -a` fails with "cannot determine the flash
  size", `partition info` says "data is invalid". Recover with
  `picotool erase -r 0x10000000 0x10200000` **then** `picotool reboot -u`
  -- the ROM caches the table at boot, so erasing alone is not enough.
  Always list `rp2350-arm-s` in unpartitioned space.
- `picotool partition create` emits an **ELF** regardless of the output
  file extension.

## Staying hands-free

Keep a `PQF_TEST_NO_USER_BUTTON` build installed and you can reach
BOOTSEL in software: `./c/hid/reboot bootsel`. C builds with
`PQF_BOOTLOADER=ON` also expose a DFU runtime interface, so
`dfu-util -e` reaches DFU. **Never install a ship-safe build mid-session**
-- it is deliberately UP-gated and not software-recoverable.

`PQF_BOOT_RISCV_LAUNCH` cannot be made hands-free. Use a spare board.

## Recommended next step

~~Read the RP2350 datasheet's bootrom chapter~~ -- done, 2026-08-21
(datasheet ch. 5 + `raspberrypi/pico-bootrom-rp2350` @ `c6cdb17`).
Findings and the two viable designs are in
[RISCV-DFU-BOOTROM-ANALYSIS.md](../RISCV-DFU-BOOTROM-ANALYSIS.md).

**And the recommended route is BUILT** (same day): the block-loop
annex -- a bootloader-owned sector stitched into the slot-0 block loop
carrying the installed RISC-V app's IMAGE_DEF, so the ROM's own scan
finds a right-CPU image after `rom_reboot(NORMAL | TO_RISCV)` and
launches it identity-mapped at its existing link address. Host-side
validation (`tools/annex_check.py` replaying the ROM's scan, plus
picotool's independent parser) passes against real C and Rust build
artifacts. Operational details and the on-silicon checklist:
[DFU.md](../DFU.md). Silicon validation is the remaining step (and was
completed the same day, per the status at the top).
