# Withdrawn: "the user-presence gate does not reliably hold"

> Point-in-time record, kept for its findings. Dates and line numbers
> are as of the date in the text; the current tree has moved on. Start
> from [docs/GETTING-STARTED.md](../GETTING-STARTED.md) for the present
> state.

**This finding was wrong. There is no known defect in the user-presence
gate.** The file is kept, rather than deleted, so the claim is not left
lying around in git history without its retraction attached.

## What was claimed

On 2026-08-17 a security finding was filed stating that the C port's
user-presence gate could be satisfied without a human touch: five
MakeCredentials out of five completed on a no-test-flags build, each
asserting UP (`flags 0x01`), with `clientPin=false` so UV could not be
standing in for UP.

## Why it was wrong

**The token was being pressed during those runs.** The author confirmed
it afterwards. Every observation the finding rested on has a simpler
explanation:

| Observation | Real explanation |
|---|---|
| 5-of-5 MakeCredential succeeded "untouched" | the button was pressed |
| `high=909 rising=10` spurious presses | those were real presses |
| ~180 ms "spurious bursts" | human press duration |
| Episodic, not a constant rate | humans press episodically |
| CMD_REBOOT once entered BOOTSEL untouched | a press |
| Longer holds "reduced leakage" | fewer presses happened to be that long |

## The measurement that settles it

Same build, no test flags, 20 ms hold -- the configuration the finding said
was wide open -- with the author explicitly not touching the token:

```
8 untouched MakeCredential attempts: 8 CTAP2_ERR_OPERATION_DENIED, 0 completed
```

The gate holds.

## What actually went wrong, methodologically

The finding was built on an assumption that was never checked: that
nobody was touching the token. Everything downstream was rigorous --
counters, burst timing, a controlled CMD_REBOOT vs MakeCredential
comparison, three mitigations sized from measurement -- and all of it was
measuring a human finger. The instrumentation was good; the control was
missing.

The tell was there and was misread. `PQF_UP_DEBUG` reported episodic
~180 ms events at a low rate, which is exactly what a person pressing a
button looks like and nothing like electrical noise. That was written up
as evidence *for* a hardware fault instead of prompting the obvious
question.

## What survives

- `PQF_UP_DEBUG` (`-DPQF_UP_DEBUG=ON`) -- the sample/high/rising counters
  in `board.c` and `main.c`. Genuinely useful for observing the presence
  read, and cheap to leave in place behind the flag.
- `PQF_UP_HOLD_US` in `fido_hid.c` -- the hold threshold is now a named,
  overridable constant instead of a bare `20000`. Default is 20 ms, the
  original behaviour.
- The 8-sample unanimity in `pqf_bootsel_pressed()`. It measurably
  changed nothing, and is defensible on its own terms, but it was added
  to fix a non-existent bug -- worth reverting if anyone wants the
  simplest possible read.

Nothing else from the finding should be relied on.
