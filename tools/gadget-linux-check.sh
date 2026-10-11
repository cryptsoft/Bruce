#!/usr/bin/env bash
# gadget-linux-check.sh -- diagnose the USB network gadget on Linux.
#
# The device side is healthy and DHCP completes, but macOS never binds
# the IPv4 address. Three replugs went into catching the exchange there
# and none of them caught it: the interface does not exist for tcpdump
# to attach to until the host has already configured it, so the capture
# is always too early or too late (docs/NETWORK-GADGET.md, "Stop
# debugging this on macOS").
#
# Linux does not have that problem. `ip monitor` sees the link appear,
# and tcpdump can attach with `-i any` before it exists at all -- so the
# DHCP exchange is captured from the first frame whatever happens next.
# That is the whole reason the next step is a Linux box and not another
# macOS attempt.
#
# Run it, THEN plug the token in:
#
#   sudo tools/gadget-linux-check.sh
#
# Needs root for tcpdump. Everything else is read-only: it watches, it
# does not configure anything, because the question is what the host
# decides to do on its own.
#
# Expected, from the device side (docs/NETWORK-GADGET.md):
#   device 192.168.7.1, host offered 192.168.7.2, /24, no router, no DNS.
#
# SPDX-License-Identifier: Apache-2.0
set -u

OUT="${OUT:-/tmp/pqf-gadget-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"
echo "  writing to $OUT"

command -v tcpdump >/dev/null || { echo "  need tcpdump" >&2; exit 1; }
command -v ip      >/dev/null || { echo "  need iproute2" >&2; exit 1; }
[ "$(id -u)" = 0 ] || echo "  WARNING: not root -- tcpdump will probably fail"

# 1. Capture on every interface, from before the gadget's exists. This is
#    the step macOS could not do.
tcpdump -i any -s 0 -U -w "$OUT/all.pcap" \
        'udp port 67 or udp port 68 or arp or icmp' >/dev/null 2>&1 &
TCPDUMP=$!
trap 'kill $TCPDUMP 2>/dev/null' EXIT
sleep 1
echo "  capturing (pid $TCPDUMP)"

# 2. Watch the link and address events as the kernel emits them.
ip monitor link addr > "$OUT/ip-monitor.log" 2>&1 &
MONITOR=$!
trap 'kill $TCPDUMP $MONITOR 2>/dev/null' EXIT

before=$(ip -br link show | awk '{print $1}' | sort)
echo
echo "  >>> plug the token in now. Watching for 90 seconds. <<<"
echo

IFACE=""
for i in $(seq 1 90); do
    now=$(ip -br link show | awk '{print $1}' | sort)
    new=$(comm -13 <(echo "$before") <(echo "$now"))
    if [ -n "$new" ]; then
        IFACE=$(echo "$new" | head -1)
        echo "  [${i}s] interface appeared: $IFACE"
        break
    fi
    sleep 1
done

if [ -z "$IFACE" ]; then
    echo "  no new interface in 90s -- the gadget did not enumerate as a NIC."
    echo "  Check 'dmesg | tail -40' and lsusb; that is a different failure"
    echo "  from the one this script is for."
    dmesg 2>/dev/null | tail -40 > "$OUT/dmesg.log"
    exit 1
fi

# 3. Give the host its own time to bring the link up, run DHCP and bind.
#    Deliberately NOT nudged: what is being measured is what the host
#    chooses to do unaided, which is exactly where macOS stops.
for i in $(seq 1 45); do
    addr=$(ip -4 -br addr show dev "$IFACE" 2>/dev/null | awk '{print $3}')
    state=$(ip -br link show dev "$IFACE" 2>/dev/null | awk '{print $2}')
    [ -n "$addr" ] && { echo "  [${i}s] bound $addr (link $state)"; break; }
    sleep 1
done

{
    echo "=== interface ==="; ip -d link show dev "$IFACE"
    echo; echo "=== addresses ==="; ip -4 addr show dev "$IFACE"; ip -6 addr show dev "$IFACE"
    echo; echo "=== routes ==="; ip route show dev "$IFACE"
    echo; echo "=== neighbours ==="; ip neigh show dev "$IFACE"
    echo; echo "=== dmesg tail ==="; dmesg 2>/dev/null | tail -60
} > "$OUT/state.txt" 2>&1

addr=$(ip -4 -br addr show dev "$IFACE" 2>/dev/null | awk '{print $3}')
echo
if [ -n "$addr" ]; then
    echo "  RESULT: Linux bound $addr on $IFACE."
    echo "  That is the thing macOS never does. The device and the DHCP"
    echo "  server are therefore fine, and the macOS failure is on the host"
    echo "  side -- compare $OUT/all.pcap against a macOS capture of the"
    echo "  same exchange to see which field it objects to."
    ping -c 3 -W 2 192.168.7.1 2>&1 | tail -4 | sed 's/^/    /'
else
    echo "  RESULT: Linux did NOT bind an address on $IFACE either."
    echo "  That moves the fault to the device: the DHCP reply itself is"
    echo "  being rejected by two independent stacks. Read $OUT/all.pcap"
    echo "  -- it has the whole exchange from the first frame, which is"
    echo "  what could never be captured on macOS."
fi
echo
echo "  saved: $OUT/{all.pcap,ip-monitor.log,state.txt}"
