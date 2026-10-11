# pqf-gadget -- USB network gadget bring-up target

A standalone firmware image, separate from the authenticator, that
proves the mobile-interfacing path for the Bruce device: the RP2350
enumerates as a **CDC-NCM USB ethernet gadget**, so an unmodified
iPhone or Android handset (or any desktop) gets a private IP link to
the device with no drivers, no entitlements, no MFi. This page is for
someone continuing that work; it assumes the C toolchain and pico-sdk
from [`docs/GETTING-STARTED.md`](../../docs/GETTING-STARTED.md) and a
board with a physical BOOT button (see
[Getting the token back](#getting-the-token-back)). Plan of record:
[`docs/NETWORK-GADGET.md`](../../docs/NETWORK-GADGET.md).

What runs on the link (all lwIP, `NO_SYS`, single loop):

- **DHCP server** offering an address + subnet mask **only** -- no router, no
  DNS -- so the handset never routes internet traffic at us (`src/dhcp_server.c`).
- **mDNS responder** -- `pqf-gadget.local`, service `_pqf-mgmt._tcp` (the app
  browses; nothing is hardcoded).
- **HTTP status endpoint** on :80 -- placeholder for the TLS management
  channel of the plan's phase 4. `curl http://192.168.7.1/` -> JSON.
- Optional **CDC-ACM debug console** (`PQF_GADGET_CONSOLE`, default ON).

Identity is stable across reconnects: MAC and USB serial both derive from
the RP2350 flash unique ID (deliberately unlike the CTAP token's per-boot
random serial). Device address: `192.168.7.1/24`; leases `192.168.7.2-.5`.

## Build

```sh
export PICO_SDK_PATH=~/pico-sdk          # 2.x + tinyusb/lwip submodules
cmake -S c/gadget -B c/gadget/build      # -DPICO_BOARD=pico2 (default)
cmake --build c/gadget/build -j
```

Images:

- default -- NCM + CDC-ACM console
- `-DPQF_GADGET_CONSOLE=OFF` -- **NCM-only descriptor set**, the image for
  iOS descriptor validation (the plan's "start NCM-only" rule)
- `-DPQF_GADGET_CDC_BOOTSEL=ON` -- **test only, never ship**: a reflash
  escape on the console (`<STX>BOOTSEL<ETX>` written to the CDC port drops
  the device into BOOTSEL). Needs the console, so an NCM-only image cannot
  carry it; it is an unauthenticated "erase yourself" command. Off by
  default.
- any RP2350 board pico-sdk knows via `-DPICO_BOARD=...`
  (`pico2`, `pimoroni_tiny2350`, `seeed_xiao_rp2350`, ...)

The network stack is also host-testable without a board:
`make -C c/gadget/test` builds and runs `test_net` (lwIP + the DHCP
server, TinyUSB stubbed); `tools/host-tests.sh c` includes it.

## Flash + first test

```sh
picotool load -f c/gadget/build/pqf_gadget.uf2   # or BOOTSEL drag-and-drop
```

Then, on the host (Linux first, per the plan's validation order):

```sh
ping 192.168.7.1                    # link + lwIP up
dns-sd -G v4 pqf-gadget.local       # mDNS (macOS; avahi-resolve on Linux)
curl http://192.168.7.1/            # status JSON
tcpdump -i <usb-if> port 67         # verify the DHCP offer carries NO router/DNS
```

This is the standalone bring-up target for plan phases 0-3. Once the
descriptors are proven against iOS, the NCM function folds into the main
`c/firmware` composite alongside CTAP HID.

## Silicon status (2026-08-17, Feitian RP2350): works

First run on a Feitian RP2350. All three services are up:

```
en20: inet 192.168.7.2 netmask 0xffffff00   <- DHCP lease from the device
      media: autoselect (10baseT/UTP <full-duplex>)   status: active
ping 192.168.7.1 -> 3/3 packets, 0.0% loss, 0.775 ms avg
curl http://192.168.7.1/ ->
  {"device":"bruce-gadget","fw":"0.1.0","board_id":"3A005A89B69CA292",
   "uptime_ms":68069,"transport":"usb-ncm","tls":false}
```

**An earlier revision of this section claimed the gadget enumerated but
carried no traffic, and called it a bug. That was wrong** -- the
measurement was taken before the NCM link had come up and DHCP had
completed. The interface reports `status: inactive` with no lease for the
first several seconds after flashing, and pinging in that window fails.
Give it ~15 s, or watch the console (below) until the link is reported
UP, before concluding anything.

### Reading the console

`PQF_GADGET_CONSOLE` is ON by default and the CDC-ACM interface shows up
as a second `/dev/cu.usbmodem*`. It now announces each init step and
reports NCM link transitions, so a hang reads as "last line printed":

```
[pqf-gadget] usb up / net_init / dhcp_server / mdns / http / init complete
[pqf-gadget] NCM link UP (host selected alt-1)
```

Two caveats. The boot markers go into a 256-byte TX FIFO before any host
opens the port, so attach the reader fast or you will only catch the link
lines. And the link indicator is `tud_network_can_xmit()`, which is
really "can transmit *right now*" -- it reads DOWN while a transmit is in
flight, so expect it to flap under load. It is a liveness signal, not a
link-state authority.

### Validation record (same day)

Validated end to end against the success criteria above:

| Check | Result |
|---|---|
| DHCP lease on the host | `192.168.7.2/24` |
| `ping 192.168.7.1` | 3/3, 0% loss, 0.8 ms round trip |
| HTTP status endpoint | returns the JSON status document |
| Offer carries no router/DNS | subnet mask only, as specified |

Device-side counters (`-DPQF_GADGET_CONSOLE=ON`) for the same run:

```
frames rx_cb=133 rx_in=133 tx_try=6 tx=6 | dhcp pkts=2 disc=1 req=1 sent=2
```

A complete DHCP handshake -- one DISCOVER, one REQUEST, two replies
(OFFER and ACK) -- with every transmit attempt succeeding.

### How this was nearly mis-reported, and the traps that remain

Four "findings" were written up before this and each was retracted by the
next measurement. The traps are still here:

1. **"Enumerates but carries zero traffic."** The host was checked about
   ten seconds after flashing, before DHCP had completed. **Allow 20-30
   seconds.** Every symptom in that report -- no lease, `status:
   inactive`, 100% ping loss -- was a premature read of a working device.
2. **"The host never selects alt-1"**, then **"the link is flapping"**.
   Both came from a console line printing `NCM link UP/DOWN` off a
   `tud_network_can_xmit()` check. That flag is false whenever a transfer
   is queued, so it toggles on ordinary traffic and says nothing about
   the interface setting. Renamed to `tx IDLE` / `tx BUSY`.
3. **"tx=0, the transmit path is dead."** The counter existed but was
   never incremented. Check the instrument before believing the reading.

The counters added along the way are kept behind `PQF_GADGET_CONSOLE` --
they are what finally showed the handshake completing.

### Getting the token back

This firmware has **no BOOTSEL path** in its default build -- it is not
a FIDO device, so `CTAPHID_CMD_REBOOT` cannot reach it, and `picotool`
cannot see it. Once flashed, recovering the token needs a physical
BOOT + RESET (the only software alternative is the test-only
`-DPQF_GADGET_CDC_BOOTSEL=ON` escape described under Build, which must
never ship). Test it last; `tools/silicon-remaining.sh` runs this stage
last for that reason.
