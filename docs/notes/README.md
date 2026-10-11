# Engineering notes

Point-in-time records kept for what they found, not for what the tree
looks like now. Each is dated; line numbers and file names inside them
are as of that date, and several of the problems they describe have
since been fixed. Nothing here is needed to build, flash or use the
token -- start at [GETTING-STARTED.md](../GETTING-STARTED.md) for that.

| Note | What it records |
| --- | --- |
| [audit/AUDIT_FINDINGS.md](audit/AUDIT_FINDINGS.md) | A static security and correctness audit of both firmware ports (2026-06-23): 52 bugs, 6 features, 17 miscellaneous items, each with a fix. The backlog the subsequent hardening worked through. |
| [audit/AUDIT2_FINDINGS.md](audit/AUDIT2_FINDINGS.md) | The second audit (2026-06-24), run after the first one's fixes: 36 findings, each confirmed against the code, cross-port. |
| [UP-GATE-RETRACTED.md](UP-GATE-RETRACTED.md) | A withdrawn finding: the user-presence gate was reported as not holding, and the report turned out to be a testing error. Kept because the analysis of how the wrong conclusion was reached is useful. |
| [RISCV-DFU-HANDOFF.md](RISCV-DFU-HANDOFF.md) | The state of RISC-V-over-DFU at a handover point, superseded by [RISCV-DFU-BOOTROM-ANALYSIS.md](../RISCV-DFU-BOOTROM-ANALYSIS.md), which the bootloader code cites. |

The validation log proper -- every silicon run, with dates and numbers
-- is [TESTING.md](../TESTING.md).
