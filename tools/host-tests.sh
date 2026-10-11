#!/usr/bin/env bash
# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# host-tests.sh -- every test in this repository that needs no token.
#
# There are four Rust crates and twelve C binaries, and none of them run
# the same way. The Rust ones are not in the workspace default set (the
# default target is the firmware, which has no test harness), so each
# needs an explicit host triple; `pqf-signer-core` additionally needs a
# variant feature, and `pqf-pkcs11` has four tests that must run alone
# on one thread. Getting any of that wrong reports "ok" while running
# nothing, which is worse than failing.
#
#   ./tools/host-tests.sh            # everything
#   ./tools/host-tests.sh rust       # Rust crates only
#   ./tools/host-tests.sh c          # C firmware suite only
#
# What is NOT here: anything needing a token. See docs/TESTING.md.

set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

# The USB descriptor tests compile against the real TinyUSB macros, so
# they need the SDK. Default: a pico-sdk checkout at ~/pico-sdk.
: "${PICO_SDK_PATH:=$HOME/pico-sdk}"
export PICO_SDK_PATH

HOST=$(rustc -vV | awk '/^host:/{print $2}')
WHICH=${1:-all}
FAILED=0
declare -a SUMMARY=()

note() { printf '\n=== %s\n' "$*"; }

# run <label> <command...>
run() {
	local label="$1"; shift
	local out rc
	out=$("$@" 2>&1); rc=$?
	if [ $rc -ne 0 ]; then
		FAILED=1
		SUMMARY+=("FAIL  $label")
		printf '  FAIL  %s\n' "$label"
		printf '%s\n' "$out" | tail -25 | sed 's/^/        /'
		return
	fi
	# Sum the "N passed" across every test target the command ran.
	local passed ignored
	passed=$(printf '%s\n' "$out" | awk -F'ok. ' '/test result: ok/{split($2,a," ");s+=a[1]} END{print s+0}')
	ignored=$(printf '%s\n' "$out" | awk '/test result: ok/{for(i=1;i<=NF;i++) if($i=="ignored;") s+=$(i-1)} END{print s+0}')
	if [ "$ignored" != "0" ]; then
		SUMMARY+=("ok    $label -- $passed passed, $ignored ignored")
		printf '  ok    %-46s %s passed, %s ignored\n' "$label" "$passed" "$ignored"
	else
		SUMMARY+=("ok    $label -- $passed passed")
		printf '  ok    %-46s %s passed\n' "$label" "$passed"
	fi
}

if [ "$WHICH" = all ] || [ "$WHICH" = rust ]; then
	note "Rust host suites (target $HOST)"
	run "pqf-cbor" cargo test -q -p pqf-cbor --target "$HOST"
	run "pqf-gdbstub-core" cargo test -q -p pqf-gdbstub-core --target "$HOST"
	# One run per variant: the constants under test are what the feature
	# selects, so a single run proves only one third of the wiring.
	for f in mldsa44 mldsa65 mldsa87; do
		run "pqf-signer-core ($f)" \
			cargo test -q -p pqf-signer-core --features "$f" --target "$HOST"
	done
	run "pqf-pkcs11" cargo test -q -p pqf-pkcs11 --target "$HOST"
	# The Secure world cannot be compiled for the host (own linker script,
	# CMSE veneers), so its storage modules are pulled in by path and run
	# against a simulated NOR die. `static mut` globals: one thread.
	# The Rust firmware's hardware-free modules, pulled in by #[path].
	# The counterpart to the C port's twelve host binaries.
	run "Bruce logic (host)" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST"
	# ...and again with three overflow discoverable-credential sectors
	# (27 slots instead of 6), the whole crate, since every CTAP2 suite
	# walks the store. Must run AFTER the default run above: that one's
	# resident_capacity suite saves a default-layout die, which this
	# one's enlarge test boots.
	run "Bruce logic, 3 overflow credential sectors" \
		env PQF_RESIDENT_EXTRA_SECTORS=3 \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST"
	# u2f is off by default in the firmware, so its suite needs the
	# feature turned on -- without this the file compiles to nothing
	# and prints a cheerful "ok" having run zero tests.
	run "Bruce U2F (host, feature on)" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--features u2f --test u2f
	# ...and the transport suite too. ctaphid.rs branches on
	# cfg!(feature = "u2f") to check that CMD_MSG routes out rather than
	# being refused, and that arm had never executed in any configured
	# run: the default build takes the else, and the u2f build above only
	# ever ran --test u2f. A test whose interesting half never runs is a
	# test that passes for the wrong reason.
	run "Bruce CTAPHID with u2f built in" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--features u2f --test ctaphid
	# Ed25519 is likewise off by default in the firmware. It is the one
	# algorithm path verifiable on the host -- ed25519_dalek is the real
	# implementation, not a stub -- so these checks verify signatures
	# rather than measuring their length.
	# The size headroom the credProtect-output decision rests on. Was a
	# claim in a comment that nothing measured.
	run "Bruce hybrid message size headroom" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--test hybrid_msgsize
	run "Bruce Ed25519 (host, feature on)" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--features ed25519 --test ed25519_alg
	# The real TRNG driver against a scriptable noise source. Serial:
	# the simulated peripheral is process-global, like the flash die.
	run "Bruce TRNG driver (simulated source)" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--test real_trng -- --test-threads=1
	# The QRNG driver and the picker that puts it ahead of the
	# TRNG, against a scripted bus: bad headers, health flags, a bus that
	# dies mid-draw, a chip that never readies, and the fallback that
	# completes every one of those requests. No global state, so parallel.
	run "Bruce QRNG driver + entropy picker" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--test real_qrng
	# flash_op_locked: the core-1 park handshake and the QMI window
	# restore -- the guard that turned a 13-second ML-DSA-65 signature
	# back into 1.3 seconds. Serial for the same reason.
	run "Bruce flash-op guard (QMI + park)" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--test real_ramfunc -- --test-threads=1
	run "fw-secure storage (simulated die)" \
		cargo test -q -p pqf-fw-secure-hosttest --target "$HOST" \
		-- --test-threads=1
	# The Secure world's flash guard: the core-1 park handshake and the
	# QMI restore. The boot-time case needs its own process, because
	# CORE1_RUNNING is one-way and can only be observed unset once.
	run "fw-secure flash guard (core-1 park)" \
		cargo test -q -p pqf-fw-secure-hosttest --target "$HOST" \
		--test flash_guard -- --test-threads=1
	run "fw-secure flash guard at boot" \
		cargo test -q -p pqf-fw-secure-hosttest --target "$HOST" \
		--test flash_guard_boot
	# The BOOTSEL sampler floats the flash chip select. If it does not
	# put OEOVER back, XIP is dead and the device wedges silently.
	run "fw-secure BOOTSEL sampler" \
		cargo test -q -p pqf-fw-secure-hosttest --target "$HOST" \
		--test bootsel_sampler -- --test-threads=1
	# fw-secure/src/trng.rs and firmware/src/trng.rs are the same file,
	# copied. Both are their image's root of trust, so a fix applied to
	# one and not the other leaves the bug in the other world.
	run "fw-secure TRNG copy has not drifted" \
		cargo test -q -p pqf-fw-secure-hosttest --target "$HOST" \
		--test trng_no_drift
	# The NON-secure world's CBOR reader: the first thing an attacker's
	# bytes reach, and it had no tests at all. Lives in this crate
	# because it is entirely self-contained -- no shims needed.
	# credProtect: stored and echoed to the relying party since M4,
	# enforced only since the 2026-09 hunt found nothing consulted it.
	run "fw-secure credProtect enforcement" \
		cargo test -q -p pqf-fw-secure-hosttest --target "$HOST" \
		--test credprotect
	# getInfo's canonical CBOR ordering, checked on the emitted bytes.
	# Two maps here have gone out of order and each time the effect was
	# silent: a strict client stops at the first bad key.
	run "fw-secure getInfo canonical ordering" \
		cargo test -q -p pqf-fw-secure-hosttest --target "$HOST" \
		--test getinfo_order
	run "fw-nonsecure CBOR reader (untrusted input)" \
		cargo test -q -p pqf-fw-secure-hosttest --target "$HOST" \
		--test cborr
	# The layer above cborr: CTAP2 request parsing, still Non-secure.
	# This is what turns hostile CBOR into the fixed-layout arrays handed
	# across the boundary.
	run "fw-nonsecure CTAP2 request parsing" \
		cargo test -q -p pqf-fw-secure-hosttest --target "$HOST" \
		--test ctapreq
	# The routing above those parsers -- and the presence gate, which
	# lives there and nowhere else. Was unreachable while it sat inside
	# a 274-line match that needed USB and the Secure gateway present.
	run "fw-nonsecure CTAPHID routing and the presence gate" \
		cargo test -q -p pqf-fw-secure-hosttest --target "$HOST" \
		--test route
	# The two USB classes, through a mock bus. usb-device keeps its
	# control-transfer types pub(crate), so these drive UsbDevice::poll
	# rather than the class directly -- the path a real host takes.
	run "DFU runtime interface (descriptor + control)" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--test dfu_runtime
	run "FIDO HID (RX ring, L15 cancel, descriptors)" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--test fido_hid
	# The GDB stub TX queue. The protocol is gdbstub-core's; this is the
	# transport, and it is where the truncated-packet defect lived.
	run "GDB stub TX queue (truncation)" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--test gdb_session
	# The debug-unit registers behind gdbstub.rs's mmio seam: the FPB
	# comparators and DEMCR. Takes the crate device lock internally, so
	# it is safe under the crate-wide sweep too.
	run "GDB stub debug registers + whitelist" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--test gdbstub_mmio
	# The Non-secure HID class. Not a duplicate of the firmware suite:
	# that image polls USB for ten seconds without draining the ring.
	run "fw-nonsecure HID (overflow latch)" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--test ns_fido_hid
	# Fuzzing the CBOR decoders -- structure-aware generation plus a
	# differential oracle between pqf_cbor and the Non-secure reader.
	# Seeded, so a failure prints a number that reproduces it. Set
	# PQF_FUZZ_ITERS to soak harder than the CI default.
	run "CBOR fuzz (differential + round trip)" \
		cargo test -q -p pqf-firmware-hosttest --target "$HOST" \
		--test cbor_fuzz
	# Guards the crash that used to make the four bus-scanning pkcs11
	# tests unrunnable in parallel. A regression here aborts the binary
	# rather than failing, so watch for a run that ends early.
	run "pqf-ctaphid (hidapi thread safety)" \
		cargo test -q -p pqf-ctaphid --test thread_safety --target "$HOST"
	# The host client's own unit tests: the strict DER reader that the
	# signature checks rest on, and the session framing.
	run "pqf-ctaphid (unit tests)" \
		cargo test -q -p pqf-ctaphid --lib --target "$HOST"

	note "Bare-metal build check (no harness, but it must still compile)"
	for t in thumbv8m.main-none-eabihf riscv32imac-unknown-none-elf; do
		run "Bruce builds for $t" \
			cargo build -q -p bruce --release --target "$t" \
			--no-default-features --features mldsa65,board_feitian_rp2350
	done
	# The mixed-ISA build is the only code that touches OTP (ARCHSEL),
	# and no other target here selects the feature -- so without this
	# line it is not even type-checked, and a break would surface only
	# when someone next flashed a mixed image.
	run "Bruce builds with core1_riscv (the ARCHSEL path)" \
		cargo build -q -p bruce --release \
		--target thumbv8m.main-none-eabihf \
		--no-default-features --features mldsa65,board_feitian_rp2350,core1_riscv
	# The single-core build is the only code that arms a timer interrupt
	# and drives USB from it; both instruction sets have their own
	# handler plumbing, so both are checked.
	for t in thumbv8m.main-none-eabihf riscv32imac-unknown-none-elf; do
		run "Bruce builds single_core for $t" \
			cargo build -q -p bruce --release --target "$t" \
			--no-default-features --features mldsa65,board_tiny2350,single_core
	done

	# fw-nonsecure is outside the workspace, so a root `cargo build`
	# never reaches it. It is the untrusted half of the TrustZone split;
	# leaving it uncompiled by CI is how it rots.
	run "fw-nonsecure builds (TrustZone untrusted half)" \
		sh -c 'cd crates/fw-nonsecure && cargo check -q --target thumbv8m.main-none-eabihf'

	# The overflow-sector option changes the linker reservation and the
	# store; check it links on both instruction sets.
	for t in thumbv8m.main-none-eabihf riscv32imac-unknown-none-elf; do
		run "Bruce builds with 3 overflow sectors for $t" \
			env PQF_RESIDENT_EXTRA_SECTORS=3 \
			cargo build -q -p bruce --release --target "$t" \
			--no-default-features --features mldsa65,board_feitian_rp2350
	done

	# Most of the six boards have no hardware here, so "it builds" is the
	# only claim anyone can make about them -- which makes it worth
	# actually checking rather than asserting in a doc.
	for b in tiny2350 xiao_rp2350 waveshare_rp2350_lcd_1_47 \
	         spotpear_rp2350_lcd_1_28 feitian_rp2350 feitian_rp2350_usbc; do
		run "board $b" \
			cargo build -q -p bruce --release \
			--target thumbv8m.main-none-eabihf \
			--no-default-features --features "mldsa65,board_$b"
	done
fi

# Toolchain-independent: these check the signing tooling and the dev-key
# guards, so they run in every mode rather than under `c` or `rust`.
note "signing tooling and dev-key guards"
if out=$(./tools/test-key-guards.sh 2>&1); then
	line=$(printf '%s\n' "$out" | grep -E '[0-9]+ checks' | tail -1)
	printf '  ok    %-46s %s\n' "key guards" "${line# }"
	SUMMARY+=("ok    key guards")
else
	printf '  FAIL  %s\n' "key guards"
	printf '%s\n' "$out" | grep -E 'FAIL|checks' | sed 's/^/        /'
	FAILED=1
	SUMMARY+=("FAIL  key guards")
fi

# flash.sh's refusals (the blank board, the USB-C token's reboot
# policy), against a mock picotool: toolchain-independent too.
note "flash.sh guards"
if out=$(./tools/test-flash-guards.sh 2>&1); then
	line=$(printf '%s\n' "$out" | grep -E '[0-9]+ checks' | tail -1)
	printf '  ok    %-46s %s\n' "flash guards" "${line# }"
	SUMMARY+=("ok    flash guards")
else
	printf '  FAIL  %s\n' "flash guards"
	printf '%s\n' "$out" | grep -E 'FAIL|checks' | sed 's/^/        /'
	FAILED=1
	SUMMARY+=("FAIL  flash guards")
fi

# The tree is ASCII only (docs/BUILD.md, "ASCII only"): the hook's own
# self-test, then the same check over every tracked file.
note "ASCII only"
if out=$(./tools/test-ascii-check.sh 2>&1); then
	line=$(printf '%s\n' "$out" | grep -E '[0-9]+ checks' | tail -1)
	printf '  ok    %-46s %s\n' "ascii guard self-test" "${line# }"
	SUMMARY+=("ok    ascii guard self-test")
else
	printf '  FAIL  %s\n' "ascii guard self-test"
	printf '%s\n' "$out" | grep -E 'FAIL|checks' | sed 's/^/        /'
	FAILED=1
	SUMMARY+=("FAIL  ascii guard self-test")
fi
if out=$(./tools/ascii-check.sh --all 2>&1); then
	printf '  ok    %-46s\n' "tree is ASCII"
	SUMMARY+=("ok    tree is ASCII")
else
	printf '  FAIL  %s\n' "tree is ASCII"
	printf '%s\n' "$out" | head -20 | sed 's/^/        /'
	FAILED=1
	SUMMARY+=("FAIL  tree is ASCII")
fi

if [ "$WHICH" = all ] || [ "$WHICH" = c ]; then
	note "C gadget network stack (lwIP + DHCP server, TinyUSB stubbed)"
	if out=$(make -C c/gadget/test 2>&1); then
		line=$(printf '%s\n' "$out" | grep -E '[0-9]+ checks' | tail -1)
		printf '  ok    %-46s %s\n' "gadget test_net" "${line:-passed}"
		SUMMARY+=("ok    gadget test_net")
	else
		printf '  FAIL  %s\n' "gadget test_net"
		printf '%s\n' "$out" | tail -20 | sed 's/^/        /'
		FAILED=1
		SUMMARY+=("FAIL  gadget test_net")
	fi

	note "C firmware host suite"
	if ! make -C c/firmware/test test >/dev/null 2>&1; then
		printf '  FAIL  building the C suite\n'
		make -C c/firmware/test test 2>&1 | tail -20 | sed 's/^/        /'
		FAILED=1
	else
		for bin in c/firmware/test/build/*; do
			[ -x "$bin" ] || continue
			label=$(basename "$bin")
			if out=$("$bin" 2>&1); then
				line=$(printf '%s\n' "$out" | grep -iE '[0-9]+ (checks|failure)|all passed' | tail -1)
				printf '  ok    %-46s %s\n' "$label" "${line:-passed}"
				SUMMARY+=("ok    $label")
			else
				printf '  FAIL  %s\n' "$label"
				printf '%s\n' "$out" | tail -20 | sed 's/^/        /'
				FAILED=1
				SUMMARY+=("FAIL  $label")
			fi
		done
	fi
fi

note "Summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
if [ $FAILED -ne 0 ]; then
	printf '\nFAILED\n'
	exit 1
fi
printf '\nAll host tests passed.\n'
