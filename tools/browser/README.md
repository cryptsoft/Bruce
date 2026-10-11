# Browser checks

A browser-driven check of `authenticatorLargeBlobs` against a live
token, plus the scripts that serve the page and flash the two firmware
revisions it compares. It is for a human tester with Chrome and a
token, and assumes a built and flashed token
([`docs/GETTING-STARTED.md`](../../docs/GETTING-STARTED.md)) and a
board with a physical BOOTSEL button. The browser is the one client
that was never written from this firmware, which is the point.

Everything in
[`docs/TESTING.md`](../../docs/TESTING.md#the-three-unreachable-commands----fixed)
about the three unreachable commands follows from the CTAP 2.1 spec
plus the parser code. That is a strong inference and it is not an
observation: nobody has watched a browser fail against the old
firmware, because the in-tree client agreed with the firmware -- it was
written from it.

`largeblob-check.html` closes that gap for `authenticatorLargeBlobs`
(CTAP 0x0C), which is the one of the three a web page can reach.

```bash
python3 tools/browser/serve.py tools/browser 8765 /tmp/pqf-browser-result.json
open 'http://localhost:8765/largeblob-check.html?auto=1'
```

With `?auto=1` the page starts by itself and POSTs its results back to
`serve.py`, so nobody has to read a screen and retype what it said.

**A human is still required, and this is where the boundary is.** Chrome
begins the ceremony unattended -- WebAuthn's `create()` needs no click --
and then blocks on its own security-key dialog. That dialog is browser
UI, not page content: CDP input does not apply to it, and macOS refuses
`osascript` assistive access to it. Measured, on 2026-08-31, by running
an isolated Chrome against a live token: the FIDO stack initialised, the
request went in flight, and it stopped there. The dialog existing is the
security property, so defeating it would invalidate the test anyway.

`localhost` is required -- WebAuthn needs a secure context, so `file://`
will not do.

**What this repository can run: the `after` half.** Flash the current
firmware and run the page; the blob should round trip:

```bash
tools/browser/flash.sh after    # the numbering as CTAP 2.1 specifies
```

**The before/after comparison is a historical procedure, not runnable
here.** Its design was to run the page twice: against a token built
*before* the parameter renumbering the write step should fail, after
it the blob should round trip, and a pass on the old firmware would
mean the finding is wrong. `tools/browser/flash.sh before` builds that
old firmware from the commit prior to the fix (`0782c7a` in the
development history) rather than from a hand-reverted tree. This
repository is published as a single commit and does not carry that
history, so `flash.sh before` stops and says so; nothing in this tree
reproduces the old firmware. No result of the comparison is recorded
either: [`docs/TESTING.md`](../../docs/TESTING.md) records what was
observed instead (the old firmware's failure signature on hardware, and
passkey management confirmed working by hand on 2026-09-01). The
procedure is kept for anyone who holds the development history.

**The flash script refuses to flash the wrong board.** A device being
in BOOTSEL is not evidence it is the one you meant -- a board from an
unrelated project plugged into the same host sits in BOOTSEL just the
same, and flashing it would erase that project's firmware. `picotool
info` reports the program name, so the name is checked before anything
is written. That guard is not theoretical: it was added after a run
that would otherwise have overwritten such a board, and it is verified
against that same board.

## What a page cannot reach

- **credentialManagement (0x0A)** is a platform operation, not a web
  API. Chrome drives it from `chrome://settings/passkeys`: the
  credential this page creates should be listed there, and deletable.
  On the old firmware that list is empty for this token.
- **authenticatorConfig (0x0D)** has no browser surface at all. Its
  correction rides on the same one-line change as credentialManagement
  and is covered on the host
  (`crates/firmware-hosttest/tests/authenticator_config.rs`) and on
  silicon.
