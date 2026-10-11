# USB Security Device -- Mobile Interfacing Plan

A design note for a USB network gadget personality (CDC-NCM) that would
let an unmodified phone manage the token over TCP/IP. **Status:
exploratory, and dropped as a product direction** -- the blockquote
below records why. What exists in the tree: the bring-up firmware under
[`c/gadget/`](../c/gadget/README.md) (NCM composite, DHCP server, mDNS
responder, HTTP status endpoint, optional CDC-ACM console), its host
harness `c/gadget/test/` (38 checks, no board needed), and
`tools/gadget-linux-check.sh` for the one hardware experiment still
open. What is only a plan and was never built: the TLS management
channel and everything after it (sections 3.3, 4, 5 from phase 3 on,
6, 7 and 8). It is for anyone reviving the idea or reusing the harness,
assumes the C toolchain of [GETTING-STARTED.md](GETTING-STARTED.md), and
is independent of the FIDO firmware -- the gadget image is not a FIDO
device (see "Recovering the token afterwards" below).

Contents:

- [1. Objective](#1-objective)
- [2. Design summary](#2-design-summary)
- [3. Firmware architecture (RP2350)](#3-firmware-architecture-rp2350)
- [4. Mobile platform integration](#4-mobile-platform-integration)
- [5. Phased plan and milestones](#5-phased-plan-and-milestones)
- [6. Risks and mitigations](#6-risks-and-mitigations)
- [7. Test and validation matrix](#7-test-and-validation-matrix)
- [8. Open decisions](#8-open-decisions)

> **Dropped, 2026-08-31.** Kept for the record and for the offline test
> harness, which found four real bugs and is still worth reading. The
> plan below is not being pursued. The reasoning, because a decision
> without one gets reversed by the next person who reads the plan:
>
> **The FIDO path never needed this.** Authentication ceremonies go over
> the phone OS's built-in CTAP stack -- USB, NFC or BLE, handled natively
> by iOS and Android. The gadget contributes nothing there and never
> claimed to.
>
> **"Internet through the phone" was never justified.** sec. 2 calls it
> optional and punts the implementation to an on-handset proxy. No use
> case is given for why a security key wants outbound internet, and it
> materially widens the attack surface of a device whose entire value is
> that keys never leave it.
>
> **Management-over-IP was the only real claim, and it did not survive
> the same question.** This firmware already ships vendor CTAPHID
> commands (`0x50` RNG, `0x51` reboot) over the interface the phone OS
> already speaks. A management protocol can ride there: no second USB
> personality, no lwIP, no DHCP server, no TLS stack, no mDNS. On a
> device where the ML-DSA-87 build already fights for SRAM, that is a
> great deal of firmware to carry for a transport we have.
>
> The last thing measured, in case anyone does revive it: the device
> side is **healthy**. The DHCP exchange completes and macOS records the
> lease as `State: BOUND`, `192.168.7.2`, `IsPublished: TRUE`,
> `RouterARPVerified: TRUE` -- it simply never plumbs the address onto
> the interface. `en20` was in Internet Sharing's `SharingDevices` list
> at the time, which is the obvious suspect and was never eliminated.
> So the long-standing "macOS is a dead end" conclusion was **wrong**:
> the fault looks like host configuration, not firmware. Start there.

*RP2350 USB network gadget for iOS and Android connectivity -- 23 July 2026.
Implementation lives in [`c/gadget/`](../c/gadget/); this document is the
plan of record it was built against.*

## 1. Objective

Enable a custom security device, built on the Raspberry Pi RP2350 (Pico 2),
to be managed from unmodified iPhones and Android handsets over a direct
USB-C connection, with an optional path for the device to reach the internet
through the phone. The device firmware is fully under our control, so the
design selects the one USB device class that both mobile platforms support
without privileges, drivers, or MFi arrangements: a **USB network gadget**.
The management channel then rides on ordinary TCP/IP with TLS, keeping the
protocol layer (REST, gRPC, or KMIP) standard and portable to desktop hosts
as a side effect.

## 2. Design summary

The device enumerates as a composite USB device whose primary function is
**CDC-NCM** networking, with CDC-ECM available as a fallback configuration
for older host stacks and a CDC-ACM serial function for a debug console.
RNDIS is deliberately excluded: Android is deprecating it and iOS has never
supported it. On top of the USB link the device runs a small TCP/IP stack
(lwIP) with three services: a minimal DHCP server, an mDNS/Bonjour
responder, and a TLS-protected management endpoint.

Two DHCP decisions carry most of the interoperability weight. First, the
**device must run the DHCP server**, because iOS provides no way to
configure a static address on an ethernet interface. Second, the DHCP offer
must contain **only an IP address and subnet mask -- no default gateway and
no DNS servers** -- so the handset never mistakes the device for an internet
connection and continues to route normal traffic over cellular or Wi-Fi. The
management app on the phone talks to the device directly on the private USB
subnet (for example 192.168.7.0/24), discovering it via Bonjour rather than
a hardcoded address.

If the device itself needs internet access through the phone, that remains a
phone-side arrangement: an on-handset HTTP/SOCKS proxy (readily available on
Android; a foreground-app exercise on iOS) with the device firmware pointing
its outbound client at the phone's address on the shared subnet. Nothing in
the gadget design changes for this option.

## 3. Firmware architecture (RP2350)

### 3.1 USB device layer

TinyUSB, bundled with the pico-sdk, provides the device-side NCM, ECM, and
CDC-ACM class drivers. NCM (`CFG_TUD_NCM`) is preferred over the older ECM
driver, matching what modern USB ethernet adapters present and what iOS
enumerates natively. Interface association descriptors must be exactly
right -- iOS is intolerant of malformed composite descriptors -- so descriptor
work starts NCM-only and adds the ECM fallback configuration and ACM
function once the primary path is proven. The device presents a fixed,
locally administered MAC address derived from the RP2350 unique ID so the
handset sees a stable interface across reconnects, and it declares honest
`bMaxPower` given how conservative phones are as USB hosts.

### 3.2 Network and services layer

lwIP (`pico_lwip`) attaches to the TinyUSB network function using the
existing `tud_network` glue demonstrated in the TinyUSB webserver example,
which also ships a compact DHCP server that is trimmed to offer address and
mask only. The lwIP mDNS responder advertises a stable service name (for
example `pqf-gadget.local`) plus a service type the mobile app can browse
for. TLS is provided by mbedTLS via lwIP's `altcp_tls` integration, with
maximum fragment length negotiated down to 4 KB to bound memory. The 520 KB
of SRAM comfortably accommodates lwIP, mbedTLS, and the application provided
pbuf pools and TLS buffers are sized deliberately and verified under soak
testing.

### 3.3 Security posture

Each device carries a unique key pair and certificate, provisioned at
manufacture and anchored in RP2350 OTP; the mobile apps pin the device CA or
certificate. RP2350 platform features -- TrustZone-M isolation, secure boot,
and the SHA-256 hardware -- are used to protect key material and firmware
integrity, which is table stakes given the product is itself a security
device. USB full speed (12 Mbps, roughly 5-8 Mbps effective through NCM) is
accepted as a management-channel constraint and documented as such.

## 4. Mobile platform integration

### 4.1 iOS

The iPhone treats the gadget as an ethernet interface, DHCPs against the
device, and will typically report a network without internet -- harmless by
design. The app uses Network.framework to browse Bonjour on, and scope
connections to, the USB ethernet interface rather than relying on default
routing, then speaks the TLS management protocol directly. No driver,
entitlement, or MFi participation is required for the network-gadget path.
Raw USB access is not available on iPhone, which is precisely why the
network-gadget architecture was chosen.

### 4.2 Android

Android brings the interface up and takes the DHCP lease in the same way.
The app resolves the device via mDNS (`NsdManager`) or the known subnet and,
where the platform prefers another network, uses `ConnectivityManager`
network binding to pin sockets to the USB ethernet network. Android
additionally offers escape hatches unavailable on iOS -- the USB Host API for
a raw-USB side channel and mature proxy apps for the internet-sharing
option -- but the primary management path is kept identical to iOS for a
single protocol surface.

### 4.3 Desktop hosts

The same NCM/ECM composite enumerates on macOS, Linux, and Windows 11
without additional drivers, giving engineering and support a free desktop
management path and a convenient debugging platform. Validation order for
each firmware drop is Linux (most forgiving, easy packet capture), then
macOS (the same NCM stack family as iOS), then iPhone and Android hardware.

## 5. Phased plan and milestones

| Phase | Deliverable / exit criteria | Indicative effort |
|-------|------------------------------|-------------------|
| 0 | Toolchain and board bring-up: pico-sdk build, TinyUSB device enumeration as CDC-ACM console on Linux host. | 1-2 days |
| 1 | NCM gadget enumerates on Linux; lwIP netif up; device answers ping over the USB link. | 2-3 days |
| 2 | On-device DHCP server (IP + mask only) and mDNS responder; device discoverable as a stable `.local` name from macOS. | 2 days |
| 3 | iPhone and Android validation: interface comes up, app-side socket scoped to the USB interface reaches the device; ECM fallback config if required. | 2-4 days |
| 4 | TLS management channel (mbedTLS server, pinned device certificate); skeleton REST or KMIP endpoint. | 1-2 weeks |
| 5 | Mobile app integration (Network.framework on iOS; ConnectivityManager network binding on Android), optional internet-via-phone proxy path. | 1-2 weeks |
| 6 | Hardening: provisioning of per-device keys via RP2350 OTP, secure boot, descriptor robustness testing, power/compliance checks. | 2+ weeks |

**Status (26 August 2026): first hardware run.** Phases 0-2 are
code-complete in `c/gadget/` -- NCM (+ optional CDC-ACM console)
composite, stable unique-ID-derived MAC, lwIP netif, trimmed DHCP
server, mDNS responder (`pqf-gadget.local`, `_pqf-mgmt._tcp`), and a
placeholder HTTP status endpoint standing in for the Phase-4 TLS
channel.

### What the Feitian actually did

Flashed to the Feitian RP2350 and attached to macOS. Everything on the
device side worked:

- **It enumerates as a network interface.** macOS created `en20`,
  `status: active`, MTU 1500, MAC `02:b7:90:52:ca:84`.
- **The NCM datapath opened.** Console: `NCM link UP (host selected
  alt-1)` -- the top suspect in the README, and it is not the problem.
- **The receive path is healthy.** `rx_cb=2470 rx_in=2470` -- every frame
  the class driver handed up was accepted by `ethernet_input`, nothing
  dropped, over thousands of frames.
- **DHCP completed.** `dhcp pkts=2 disc=1 req=1 sent=2`: one DISCOVER,
  one REQUEST, an OFFER and an ACK. macOS reports `State : BOUND` with
  `192.168.7.2`, lease a full day.
- **The sec. 2 interoperability decision holds on real hardware.** The ACK
  carries exactly five options -- `dhcp_message_type`,
  `server_identifier`, `lease_time`, `subnet_mask`, `end`. No `router`,
  no `domain_name_server`, as designed. And the host's own default route
  was untouched throughout: still the LAN's own gateway via `en0`, so
  the gadget never became the machine's route to the internet.

### Where it stops

**No IPv4 address is ever bound to the interface.** `ipconfig
getsummary en20` says `BOUND` with `192.168.7.2`, but `ifconfig en20`
shows only an IPv6 link-local address. With no IPv4 on the link the host
cannot reach `192.168.7.1` at all: ping times out, the HTTP status
endpoint is unreachable, and `_pqf-mgmt._tcp` never appears in a
`dns-sd` browse. So the **Phase 1 exit criterion -- "device answers ping
over the USB link" -- fails**, and Phases 2's discovery half and 3
onwards are untestable behind it.

**The device is not what is failing.** Its transmit count reconciles
exactly: `tx_try=3 tx=3` = the DHCP OFFER, the DHCP ACK, and one ARP
reply. That ARP reply is corroborated from the host side, which reports
`RouterARPVerified : TRUE` for `192.168.7.1`. So the device answered
every question it was asked and then was asked nothing further, because
the host had no address to ask from. The thousands of received frames
are host IPv6 multicast and mDNS chatter, correctly ignored.

**The open question is the missing `router` option.** macOS synthesises
`Router : 192.168.7.1` from `server_identifier` and ARP-verifies it, yet
never completes the IPv4 configuration. That points at the sec. 2 decision --
address and mask only -- being the thing macOS will not finish a lease
on, which would be an awkward finding: that decision exists precisely so
a handset does not route its traffic at the device. Whether a `router`
option can be offered without the handset adopting a default route is a
design question and needs a deliberate answer, not a quick patch.

Untried, and worth trying before anything else: the NCM-only image
(`-DPQF_GADGET_CONSOLE=OFF`), in case the composite descriptor is
implicated; and a Linux host, whose DHCP client is less opinionated and
would separate "our ACK is deficient" from "macOS is strict".

### A host harness, and the four bugs it found

`c/gadget/test/` runs the real `net_glue.c`, `dhcp_server.c`,
`http_status.c` and lwIP on a development machine with TinyUSB stubbed,
driven by hand-built Ethernet frames. Every frame the device sends back
is captured and decoded, so the DHCP payload and the ARP, ICMP, mDNS and
TCP replies can be asserted on byte by byte.

```bash
make -C c/gadget/test        # 38 checks, no board
```

It should have existed before any of this was flashed. Nothing in the
tree could exercise this stack without a token, which is most of why the
code sat compile-verified for five weeks -- and it found four real bugs in
its first afternoon.

**mDNS could never have worked.** `netif_init_cb` set
`NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP |
NETIF_FLAG_UP` and no `NETIF_FLAG_IGMP`. lwIP's `igmp_joingroup_netif`
refuses without it -- *"attempt to join on non-IGMP netif"* -- and the
responder joins 224.0.0.251 the moment `mdns_resp_add_netif` runs. So
the responder came up, reported success, and was deaf: it never received
a query and its announcements reached nobody. On silicon this was
invisible, because with no IPv4 address bound the missing
`_pqf-mgmt._tcp` looked like a symptom of that instead of a bug of its
own. With the flag set, the responder announces itself and answers a
query for `pqf-gadget.local` with a real answer record.

**The DHCP reply was below the legal minimum.** RFC 1542 sec. 2.1 sets 300
octets as the floor for a BOOTP message and RFC 2131 inherits it; a
client or relay may drop anything shorter. The reply came to 262, and
the buffer was sized `BOOTP_OPTIONS + 32` -- 272 -- so a conformant
message was not even expressible. Now padded to 300 with the zero pad
option, and the harness asserts it: remove the padding and the check
fails at 262.

**A truncated option was read past the data that arrived.**
`find_option` looped on `i + 1 < len`, which puts an option's code and
length bytes in range and says nothing about its body -- while every
caller goes on to read `opt[2]`. An option at the very end of a message
therefore had its value read from uninitialised stack in the 400-byte
request buffer, or one byte past it when a request filled the buffer
exactly. The message type came out as whatever happened to be there, so
a packet could be acted on as a DISCOVER or REQUEST it never was, and
any USB host can send one. The harness demonstrates it: a request whose
options end `53 01` with nothing following drew a reply before the fix
and draws none after. `find_option` now requires the whole option to
fit, and the request buffer is zeroed.

**A host that stopped draining wedged the device outright.**
`linkoutput_fn` was `for (;;)` with `tud_ready()` as its only exit. A
host still enumerated but no longer collecting the IN endpoint -- a
handset that suspended, which is ordinary and exactly what Phase 3 walks
into -- leaves that condition true forever. The device then spins inside
lwIP's output path and the main loop never runs again: no console, no
heartbeat, and no reflash escape. It reads as dead hardware and it is a
stalled endpoint. There is now a 50 ms deadline, after which the frame
is dropped and counted (`txdrop` on the console line), which is what any
Ethernet driver does when its ring is full. The harness blocks the
endpoint, checks the frame is dropped rather than queued forever, and
checks the link recovers on the next request.

Whether that second one is what macOS was objecting to is **not
established**. It is a real conformance gap and a plausible cause, and
it needs a hardware run to confirm.

What the harness does settle:

- **The device answers ping.** The Phase 1 exit criterion passes here,
  so the stack can do the thing that failed on silicon.
- **A duplicate-address probe for the client goes unanswered.** That was
  the leading hypothesis: something replying to the host's RFC 5227
  probe for the address it had just been offered would make the host
  declare a conflict and drop the lease, which is the exact shape of
  "BOUND but no address on the interface". It does not reply.
- **The HTTP endpoint works** -- a SYN to port 80 is answered with
  SYN-ACK and a `GET /` draws an `HTTP/1` response. That is what the
  Phase-4 TLS channel will stand on.
- **The section 2 decision is now a test**, not a one-off observation:
  the ACK carries `yiaddr`, mask, server-id and lease, and no `router`
  and no `domain_name_server`.

**Two cautions the harness taught the hard way**, both of which produced
a confident wrong answer before they were fixed. Its first version had a
hand-written `lwipopts.h` that omitted `LWIP_IP_ACCEPT_UDP_PORT` -- the
hook that lets a DHCP *server* receive packets whose source is still
0.0.0.0 -- so lwIP dropped every DISCOVER at `ip4_input: packet source is
not valid` and the harness reported a broken DHCP server. The host
options are now a two-line `#include` of the board's, with `pico/rand.h`
stubbed alongside, so that divergence has nowhere to hide. And the TCP
segments were built with a zero checksum on the assumption lwIP would
not be checking; it does, every segment was discarded at `tcp_input:
packet discarded due to failing checksum`, and it looked exactly like a
listener that had never been started.

### Second hardware run, 2026-08-28: the padding was not the cause

The 300-octet DHCP padding is **not** what macOS was objecting to.
Flashed with all four fixes and the exchange plays out exactly as
before: `yiaddr = 192.168.7.2`, five options, `State: BOUND` -- and no
IPv4 address on the interface. That hypothesis is dead, and it was the
plausible one.

What the run did establish:

- **`NETIF_FLAG_IGMP` works on silicon.** After a reflash where the host
  never brought the link up -- `rx_cb=0`, nothing received at all -- the
  device still shows `tx_try=8 tx=6`. Those are mDNS announcements going
  out unprompted. Before the fix it emitted nothing, because
  `igmp_joingroup_netif` had refused and the responder never joined
  224.0.0.251.
- **macOS is doing duplicate-address detection.** The new frame
  classification says `arp rx=12 probe=3 for_us=1 for_client=6`: three
  RFC 5227 probes (sender 0.0.0.0) and six requests targeting the
  client's *own* offered address. So DAD is happening, which is the
  right place to keep looking -- even though the host harness shows the
  device does not answer a probe for the client's address.
- **The reflash escape works.** Two full flash cycles with no button.
- `txdrop=0`, so the transmit deadline has not fired in normal use.

### The thing that now blocks it, and it is not the device

**macOS will not re-configure the interface after a soft reflash.** The
device comes back, enumerates, and reports `NCM link UP (host selected
alt-1)` -- so alt-1 *was* selected -- while `ifconfig` says `status:
inactive` and the device receives nothing at all. Repeated cycles do not
shake it loose, and there is only one `en20`, so it is not a stale
second service.

The first run, which did reach DHCP, followed a flash from a physical
BOOTSEL -- a full detach and re-attach. So investigating the address
binding needs a **replug** per attempt, not just a reflash, which makes
this expensive to iterate on and is worth knowing before anyone tries.

Packet capture on the host works without privileges (`tcpdump -i en20`,
with a harmless promiscuous-mode warning), so the next attempt should
capture the DAD exchange directly rather than inferring it from
counters. That is the measurement that will settle it.

### Why the Linux run has not happened yet

Checked properly on 2026-08-31 rather than left as "no Linux available",
because that turned out to be wrong: the author's development Mac did
have a Linux guest (UTM, *COSMIC atomic*). It is not usable for this
test, and the reason is worth recording so nobody spends an afternoon
on a similar setup:

- **`UsbSharing => false`** in its `config.plist`. The token cannot reach
  the guest without changing the VM's configuration.
- Attaching a *specific* device is a GUI action in UTM even once sharing
  is on, so it cannot be driven from the test tooling.
- **It is an emulated `x86_64` guest on Apple Silicon** (`Backend =>
  QEMU`, `Architecture => x86_64`). This investigation is about USB
  enumeration timing and a DHCP exchange; running it through an emulated
  USB controller would produce results that cannot be trusted either
  way. A misleading answer here is worse than no answer, because the
  whole point of moving to Linux is to get a capture macOS could not
  take.

So it wants **real** Linux hardware with the token in its own port, not
a VM on the macOS host.

What is ready: `c/gadget/build-escape/pqf_gadget.uf2`, built with
`-DPQF_GADGET_CDC_BOOTSEL=ON` so the image has a software way back out.
That matters more than usual here -- the stock gadget image is not a FIDO
device and carries no BOOTSEL path, so flashing the stock one strands
the token until someone holds BOOT and taps RESET.

### The Linux run, packaged

`tools/gadget-linux-check.sh` is the next step, ready to run. It starts
`tcpdump -i any` *before* the interface exists -- which is precisely what
macOS could not do, and why three replugs there caught nothing -- then
watches `ip monitor` for the link appearing, gives the host 45 seconds to
bind an address unaided, and saves the pcap plus the interface state.

It deliberately configures nothing. The question is what the host decides
to do on its own, and nudging it would answer a different one.

Either outcome is worth having, and the script says which is which:

- **Linux binds an address.** The device and its DHCP server are fine and
  the fault is on the macOS side; compare the two captures to find the
  field it objects to.
- **Linux does not bind either.** The fault moves to the device -- two
  independent stacks rejecting the same reply -- and the pcap has the
  whole exchange from the first frame, which is the thing that could
  never be captured on macOS.

Needs a Linux host with the token plugged into *it*, not into the Mac.

### Stop debugging this on macOS

Three replugs went into catching the DHCP exchange on the wire and none
of them caught it. The exchange lands about a second after the host
configures the interface, and the interface does not exist for `tcpdump`
to attach to until that configuration happens, so a capture is always
either too early or too late. Busy-retrying the attach with no sleep did
not close the gap either -- during the teardown the loop just spins on
`(No such device exists)`.

Two things were built trying to get around it, and both are worth
keeping even though neither solved this:

- **`<STX>USBCYCLE<ETX>`** on the debug console does
  `tud_disconnect()`, a 1.5 s wait, then `tud_connect()`. It works: the
  interface disappears and comes back, and a capture re-attaches. But
  **macOS treats it as less than a replug** -- the interface comes back
  `inactive`, the lease is dropped entirely, and no DHCP is attempted.
  So an electrical detach is not what the host is waiting for, and the
  one-replug-per-attempt cost cannot be engineered away from the device
  side.
- The frame classification on the console, which is what showed the DAD
  probes in the first place.

By the end the interface would not come up on a physical replug either,
which is host state rather than anything the device did.

**The next move is a Linux host, not another macOS attempt.** Its DHCP
client is far less opinionated, `tcpdump` runs without the BPF
attach race, and the question that matters -- is our ACK deficient, or
is macOS strict? -- is exactly the question a second host answers. The
risk table in section 6 already calls for a per-OS regression matrix;
this is the first thing that matrix is for.

What is *not* in doubt, and should not be re-litigated on the next
attempt: the device completes the exchange, sends a conformant ACK,
answers ARP for its own address, does not answer a probe for the
client's, and now announces itself over mDNS. Those are covered by 38
host checks and by the first hardware run.

### Recovering the token afterwards

This image is **not** a FIDO device and carries no BOOTSEL path --
`CFG_TUD_VENDOR` is 0 and there is no CTAPHID reboot command. Once it is
flashed there is no software route back: `picotool` cannot see it and
nothing answers CTAPHID. Recovery is holding BOOT and tapping RESET.
Flash it last in any session, which is what `tools/silicon-remaining.sh`
already says and is worth repeating here.

## 6. Risks and mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| iOS rejects composite descriptors | Device not usable on iPhone | NCM-only primary config (`-DPQF_GADGET_CONSOLE=OFF` image); validate descriptors early on macOS; keep CDC-ACM in a separate configuration if problems arise |
| Full-speed USB throughput ceiling (~5-8 Mbps effective) | Limits bulk data use cases | Scope the channel to management/control traffic; document the limit; different silicon if bulk transfer becomes a requirement |
| Phone declines to power the device | Field failures on some handsets | Honest `bMaxPower` in descriptors; measure real draw; self-power or USB-PD option in hardware revision |
| Phone routes internet traffic at the gadget | Broken connectivity on the handset, support burden | DHCP offers address and mask only -- no router, no DNS options |
| lwIP/mbedTLS memory pressure on 520 KB SRAM | Instability under load | Deliberate pbuf pool sizing; TLS max fragment length 4 KB; soak testing in Phase 6 |
| TinyUSB NCM maturity gaps | Enumeration or datapath bugs on specific hosts | Track TinyUSB releases; ECM fallback configuration; per-OS regression matrix (Linux, macOS, iOS, Android, Windows 11) |

## 7. Test and validation matrix

Every release candidate is exercised against a fixed host matrix: Linux
(kernel NCM/ECM, tcpdump verification of the DHCP offer contents), macOS
current and previous major versions, iOS current and previous major versions
on physical hardware, Android 11+ across at least two OEM builds, and
Windows 11. Functional checks cover enumeration, DHCP lease, mDNS discovery,
TLS handshake with pinning, management API round trips, reconnect stability
(stable MAC, no stale leases), and confirmation that the handset's own
internet connectivity is unaffected while the device is attached. Negative
testing includes malformed-descriptor regression, power-draw measurement
against the declared `bMaxPower`, and TLS memory soak under sustained
concurrent sessions.

## 8. Open decisions

Three items need a decision before Phase 4:

1. **Management protocol** -- a compact REST/JSON API versus KMIP, noting
   KMIP keeps the device in familiar standards territory and reuses existing
   client tooling.
2. **Internet-via-phone** -- supported product feature or an engineering
   convenience (robust on Android, awkward on iOS)?
3. **Provisioning workflow** -- per-device certificates at manufacture,
   including CA hierarchy and OTP layout on the RP2350.
