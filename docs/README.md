# Documentation index

Where to start depends on what you want to do. Every document below
says at its top who it is for and what it assumes.

## I want a working token

| Read | For |
| --- | --- |
| [GETTING-STARTED.md](GETTING-STARTED.md) | **Start here.** Tools per OS, one clone, both firmwares, BOOTSEL, flashing, verification, troubleshooting. Every command tested. |
| [FLASHING.md](FLASHING.md) | Per-board detail: buttons, connectors, what each board shows after a flash, wipe and recovery -- **and, in [its own section](FLASHING.md#the-feitian-usb-c-token), the only procedure for the Feitian RP2350 USB-C token. Read that before touching one**: the token has no power-on BOOTSEL, so a wrong image is permanent. |
| [USAGE.md](USAGE.md) | Using the token: LED states, every `getInfo` field, PIN rules, browsers, reset, troubleshooting. |

## I want to build a variant

| Read | For |
| --- | --- |
| [BUILD.md](BUILD.md) | The build reference: every cargo feature and CMake option of both ports side by side, the toolchain pin, the vendored trees, host test suites, the ASCII rule. |
| [HARDWARE.md](HARDWARE.md) | The six boards: pinouts, presence buttons, LEDs and LCDs, USB descriptor, TRNG and QRNG, memory map, how to add a board. |
| [RISCV.md](RISCV.md) | Running either firmware on the RP2350's Hazard3 cores, and the mixed-ISA build. |
| [REBOOT.md](REBOOT.md) | Rebooting a running token into BOOTSEL from the host, the per-board touch policy, the `pqf-*` image markers, and the buttonless-token warning. |

## I want to understand or extend it

| Read | For |
| --- | --- |
| [OVERVIEW.md](OVERVIEW.md) | One page: what the device can do, cryptographically. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Module map, the two-core signing design, heap, flash schema, why things are the way they are. |
| [PROTOCOL.md](PROTOCOL.md) | The CTAP 2.1 and CTAP1 surface on the wire: `getInfo`, COSE algorithm ids, the hybrid signature format, PIN protocols, extensions. |
| [HMAC-DOMAINS.md](HMAC-DOMAINS.md) | The normative HMAC domain-separation labels both ports must match byte for byte. |
| [TESTING.md](TESTING.md) | The test procedures, and the dated record of every silicon validation run with its numbers. |
| [../crates/ctaphid-client/README.md](../crates/ctaphid-client/README.md) | The host-side client crate and its examples, which are the test tools. |
| [../c/firmware/README.md](../c/firmware/README.md) | The C firmware's own map, board table and development notes. |
| [../c/hid/README.md](../c/hid/README.md) | The C CTAP-over-HID transport library and the `reboot` / `rng` tools. |
| [../tools/README.md](../tools/README.md) | Every script under `tools/`, what it needs, and which ones erase a board. |

## Deeper features

| Read | For |
| --- | --- |
| [DFU.md](DFU.md) | The signed-image DFU bootloader: staging slot, anti-rollback, launch guard, power-loss journal, per-ISA launch. |
| [SECUREBOOT.md](SECUREBOOT.md) | OTP provisioning, the boot-key burn, the irreversible fuses and the order they must be blown in. |
| [TRUSTZONE.md](TRUSTZONE.md) | The TrustZone-M Secure / Non-secure split: gateway surface, what each milestone proved, known weaknesses. |
| [GDB_DEBUG.md](GDB_DEBUG.md) | Debugging a cased token over USB with no SWD probe, and why that build must never ship. |
| [NETWORK-GADGET.md](NETWORK-GADGET.md) | A design note on a USB network gadget mode, with the bring-up firmware under `c/gadget/`. |
| [RISCV-DFU-BOOTROM-ANALYSIS.md](RISCV-DFU-BOOTROM-ANALYSIS.md) | How the RP2350 boot ROM launches a RISC-V image, as the bootloader relies on it. |

## Records

[notes/](notes/README.md) holds point-in-time engineering records: the
two security audits and their backlogs, a withdrawn finding, and a
superseded handoff note. They are kept for what they found; the current
tree has moved on.

## Licensing and security

[../THIRD_PARTY.md](../THIRD_PARTY.md) lists every third-party
component, its licence and its provenance; the project itself is
Apache-2.0 ([../LICENSE](../LICENSE), with the attribution notices in
[../NOTICE](../NOTICE)). [../SECURITY.md](../SECURITY.md)
says what this release does and does not promise, why the committed
signing keys are public, and how to report a vulnerability privately.
