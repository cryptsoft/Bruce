# Host-side test harness for the firmware's CTAP2 layer.
#
# Compiles the firmware's protocol modules (ctap2 / credential /
# client_pin / pin_protocol / hybrid + the CBOR codec) together with
# the full openssl-mini crypto stack ON THE HOST (not the RP2350) and
# drives ctap2_dispatch() / the hybrid signer through full ceremonies,
# verifying signatures. This catches CBOR wire-format, authData layout,
# COSE encoding, and signing bugs without flashing hardware.
#
# Platform seams for host builds:
#   - RAND_*           : openssl-mini/test/host_rand_stub.c (arc4random)
#                        -- the firmware uses pqf_rand.c (RP2350 TRNG).
#   - flash_store_*    : host_flash_stub.c (RAM)
#                        -- the firmware uses src/flash_store.c (QSPI).
#
# gnu11 (not c11): the vendored sha512/keccak use GNU `asm`; the
# firmware's arm-none-eabi-gcc build defaults to gnu mode, so this
# matches it. -Wno-deprecated-declarations silences the OpenSSL 3.x
# EC_KEY deprecated-but-internal API.
#
# Usage:  make test   (build + run every test_*)
#         make clean
#
# SPDX-License-Identifier: Apache-2.0

CC     ?= cc
OM      = ../openssl-mini
# -DPQF_RESIDENT_HOST builds resident_store.c against RAM instead of
# the pico-sdk QSPI flash routines (host has no flash). Only
# resident_store.c reads the macro, so it's harmless globally.
CFLAGS  = -O2 -Wall -Wno-deprecated-declarations -std=gnu11 \
          -DPQF_RESIDENT_HOST \
          -I ../src -I ../../cbor -I $(OM)/include \
          -I $(OM)/src -I $(OM)/src/bn -I $(OM)/src/ec -I $(OM)/src/ml_dsa

# Firmware protocol sources under test (platform-agnostic).
FW_SRC   = ../src/ctap2.c ../src/credential.c ../src/cbor_encode.c \
           ../src/client_pin.c ../src/pin_protocol.c \
           ../src/authenticator_config.c ../src/resident_store.c \
           ../src/credential_management.c ../src/large_blobs.c \
           ../src/hybrid.c ../../cbor/pqcbor.c

# Vendored crypto: BN + EC + ML-DSA trees + the SHA / SHAKE / AES /
# HMAC / HKDF / EVP / packet / buffer support the above pull in.
OM_SRC   = $(wildcard $(OM)/src/bn/*.c) $(wildcard $(OM)/src/ec/*.c) \
           $(wildcard $(OM)/src/ml_dsa/*.c) \
           $(OM)/src/sha256.c $(OM)/src/sha512.c $(OM)/src/sha3.c \
           $(OM)/src/keccak1600.c $(OM)/src/aes_core.c \
           $(OM)/src/pqf_sha256.c $(OM)/src/pqf_hmac_sha256.c \
           $(OM)/src/pqf_aes.c $(OM)/src/pqf_evp.c $(OM)/src/pqf_hkdf.c \
           $(OM)/src/packet.c $(OM)/src/buffer.c

RAND_STUB  = $(OM)/test/host_rand_stub.c
FLASH_STUB = host_flash_stub.c
CORE1_STUB = host_core1_stub.c
ALL_SRC    = $(FW_SRC) $(OM_SRC) $(RAND_STUB) $(FLASH_STUB) $(CORE1_STUB)

# Suites also built with three overflow credential sectors (the
# build/%-rk3 rule below). Defined before TESTS: the `test` rule's
# prerequisites are expanded as the file is read.
RK3_SUITES = test_resident test_credmgmt test_ctap2 test_config
TESTS = test_cbor_fuzz test_flash_store test_ctap2 test_pin test_hybrid test_hybrid_msgsize \
        test_extensions test_config \
        test_resident test_credmgmt test_largeblobs test_domain \
        test_ctaphid test_core1_arena test_fido_hid test_align_str \
        test_blob_alloc test_gdbstub test_qrng test_yield \
        test_resident_flash-rk0 test_resident_flash-rk3 \
        $(addsuffix -rk3,$(RK3_SUITES))

.PHONY: test clean
test: $(addprefix build/,$(TESTS)) descriptors core1 reboot_policy
	@for t in $(TESTS); do echo "--- $$t ---"; ./build/$$t || exit 1; done

# test_blob_alloc drives the blob's arena allocator (see the .c) with
# the crypto compiled so that malloc/free/calloc/realloc RESOLVE TO the
# arena -- same linkage the RISC-V blob gets by overriding newlib's.
ALLOC_DEFS = -Dmalloc=blob_malloc -Dfree=blob_free \
             -Dcalloc=blob_calloc -Drealloc=blob_realloc
ALLOC_SRC  = ../core1-riscv-blob/blob_alloc.c ../src/hybrid.c \
             $(OM_SRC) $(RAND_STUB)
build/test_blob_alloc: test_blob_alloc.c $(ALLOC_SRC) ../core1-riscv-blob/blob_alloc.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(ALLOC_DEFS) -I ../core1-riscv-blob -o $@ $< $(ALLOC_SRC)

# test_core1_signer drives the cross-core mailbox with core 1 as a
# thread. Built TWICE, and the difference matters: without
# PQF_SIGN_ARENA, core1_p256_keygen and core1_p256_sign run locally on
# core 0 and never reach the mailbox at all -- the #if in
# core1_signer.c sends them straight to pqf_p256_keygen. A first run of
# this suite missed that and reported passing checks for a code path
# that was not running. Both configurations ship, so both are built.
C1_SRC = ../src/core1_signer.c ../src/hybrid.c ../src/core1_arena.c \
         ../core1-riscv-blob/blob_alloc.c $(OM_SRC) $(RAND_STUB)
# -I . puts test/ on the include path, which is where the pico and
# hardware header shims live.
C1_INC = -I ../core1-riscv-blob -I .
build/test_core1_signer: test_core1_signer.c $(C1_SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) $(C1_INC) -DPQF_SIGN_ARENA=1 -o $@ $< $(C1_SRC)
	$(CC) $(CFLAGS) $(C1_INC) -o $@-noarena $< $(C1_SRC)

.PHONY: core1
core1: build/test_core1_signer
	@echo "--- core1_signer (arena: cross-core dispatch) ---"; ./build/test_core1_signer
	@echo "--- core1_signer (no arena: local dispatch) ---"; ./build/test_core1_signer-noarena

# test_align_str drives the alignment-safe memcmp/strcmp that replaced
# newlib's on RISC-V. That file exists because of real silicon freezes:
# newlib's optimised versions issue word loads with no alignment check,
# and Hazard3 traps on misaligned access, so whether a given CBOR string
# happened to be 4-aligned decided whether the token froze. Built with
# __riscv defined, since it is an empty translation unit otherwise, and
# checked against the host libc as the oracle at every alignment pair.
build/test_align_str: test_align_str.c ../src/pqf_align_str.c
	@mkdir -p build
	$(CC) -O2 -Wall -std=gnu11 -D__riscv=1 -I ../src -o $@ $<

# test_usb_descriptors walks the real emitted descriptor bytes -- the
# same TinyUSB macros the firmware compiles, via test/host_tusb_config.h
# which differs from ../tusb_config.h only in selecting OPT_OS_NONE (the
# Pico OSAL pulls in the whole SDK). Descriptors are the one part of the
# firmware where a mistake is silent: an inconsistent one does not crash,
# it makes the device enumerate wrongly, or on one host and not another.
#
# Built four times, because the risk is CONFIG_TOTAL_LEN drifting from
# what the macros emit when an optional interface is added.
TUSB      = $(PICO_SDK_PATH)/lib/tinyusb/src
DESC_CFG  = -DCFG_TUSB_CONFIG_FILE='"host_tusb_config.h"'
DESC_SRC  = ../src/usb_descriptors.c
DESC_INC  = -I ../src -I . -I $(TUSB)
DESC_VARIANTS = base gdb dfu both
build/test_usb_descriptors: test_usb_descriptors.c $(DESC_SRC) host_tusb_config.h
	@mkdir -p build
	$(CC) $(DESC_CFG) -O2 -Wall -std=gnu11 $(DESC_INC) -o $@ $< $(DESC_SRC)
	$(CC) $(DESC_CFG) -DPQF_GDB_STUB -O2 -Wall -std=gnu11 $(DESC_INC) \
	    -o $@-gdb $< $(DESC_SRC)
	$(CC) $(DESC_CFG) -DPQF_DFU_RUNTIME -O2 -Wall -std=gnu11 $(DESC_INC) \
	    -o $@-dfu $< $(DESC_SRC)
	$(CC) $(DESC_CFG) -DPQF_GDB_STUB -DPQF_DFU_RUNTIME -O2 -Wall -std=gnu11 \
	    $(DESC_INC) -o $@-both $< $(DESC_SRC)

.PHONY: descriptors
descriptors: build/test_usb_descriptors
	@for v in "" "-gdb" "-dfu" "-both"; do \
	    echo "--- usb_descriptors$$v ---"; \
	    ./build/test_usb_descriptors$$v || exit 1; \
	done

# test_fido_hid drives the user-presence gate -- the security boundary
# every registration and assertion passes through. The clock and the
# button are both under the test's control (test/pico/time.h), so a
# timeout takes microseconds instead of ten seconds and the debounce
# boundary can be probed exactly. Built for a board WITH a wired button,
# since that is the configuration where the gate does anything.
build/test_fido_hid: test_fido_hid.c ../src/fido_hid.c pico/time.h host_tusb_config.h
	@mkdir -p build
	$(CC) $(DESC_CFG) -DPQF_BOARD_FEITIAN_RP2350 -O2 -Wall -std=gnu11 \
	    $(DESC_INC) -o $@ $< ../src/fido_hid.c

# test_core1_arena drives the dispatcher above blob_alloc: core 1 gets
# the dedicated sign arena, core 0 gets newlib, and free/realloc route
# by POINTER so a block allocated on one core can be released on the
# other. hardware/structs/sio.h is a two-line shim giving the test a
# settable cpuid, which is the only hardware core1_arena.c reads.
# blob_alloc.c is linked as-is (test_blob_alloc covers it directly).
ARENA_SRC = ../src/core1_arena.c ../core1-riscv-blob/blob_alloc.c
build/test_core1_arena: test_core1_arena.c $(ARENA_SRC) hardware/structs/sio.h
	@mkdir -p build
	$(CC) $(CFLAGS) -I . -I ../core1-riscv-blob -o $@ $< $(ARENA_SRC)

# test_gdbstub drives the GDB stub's remote-serial-protocol layer
# (src/gdbstub.c) on the host: -DPQF_GDB_HOST swaps the ARMv8-M debug
# MMIO, the target memory, and the TinyUSB CDC transport for simulated
# ones (gdbstub_host.h), so packet framing, the m/M whitelist, register
# marshalling and the FPB slot allocator are tested with no board. It
# links NONE of the CTAP/crypto stack -- hence its own rule rather than
# the catch-all below.
GDBSTUB_SRC = ../src/gdbstub.c
build/test_gdbstub: test_gdbstub.c $(GDBSTUB_SRC) gdbstub_host.h ../src/gdbstub.h
	@mkdir -p build
	$(CC) $(CFLAGS) -DPQF_GDB_STUB=1 -DPQF_GDB_HOST=1 -I . \
	    -o $@ $< $(GDBSTUB_SRC)

# Serve the same stub on a pty so a REAL arm-none-eabi-gdb can attach
# and exercise the protocol end-to-end (breakpoint / step / continue /
# registers) without hardware. Prints the tty path and the gdb command;
# Ctrl-C to stop. Silicon validation is still a separate step -- see
# docs/GDB_DEBUG.md.
.PHONY: gdbstub-live
gdbstub-live: build/test_gdbstub
	./build/test_gdbstub --pty

# test_ctaphid drives the CTAP-HID transport (src/ctaphid.c) frame by
# frame. -DPQF_CTAPHID_HOST swaps the RP2350 timer for a clock the test
# advances, which is what makes the reassembly timeout reachable; the
# test also supplies pqf_board_reboot, so CMD_REBOOT is recorded rather
# than performed. Linked against the full CTAP2 stack so a CBOR command
# really does reach ctap2_dispatch -- the seam between transport and
# dispatch is the part nothing else covers without a board.
# The REAL flash_store.c, against a simulated NOR die -- the only target
# that does not link host_flash_stub.c. Kept separate deliberately: five
# other suites use ctap2_init() as a factory reset and rely on the stub
# forgetting everything, so replacing the stub globally would break them.
# Its own -I . picks up test/pico/{stdlib,bootrom}.h,
# test/hardware/flash.h and test/hardware/structs/qmi.h, which exist for
# this. 32 KiB of die keeps the array small; flash_store.c places its
# sectors relative to the end of flash, so it needs at least five.
FLASH_STORE_SRC = ../src/flash_store.c host_flash_die.c
# build/test_cbor_fuzz -- the CBOR decoder against generated and mutated
# input. pqcbor.c is compiled into its OWN object with calloc/free
# redirected to the harness's counting wrappers, the same trick
# test_blob_alloc uses above. That counter IS the leak oracle:
# LeakSanitizer does not exist on macOS arm64 ("detect_leaks is not
# supported on this platform"), so a leak across a million iterations
# would simply never be seen. Checked every iteration, it also names the
# input that caused one rather than reporting a total at exit.
#
# Links pqcbor.c ALONE and never $(ALL_SRC): the -Dcalloc redirect must
# not reach the crypto stack. Declaring the target explicitly is also
# what stops the build/% pattern rule at the bottom of this file
# claiming it and linking forty sources.
FUZZ_SAN   ?= -fsanitize=address,undefined -fno-sanitize-recover=all
FUZZ_ALLOC  = -Dcalloc=pqfuzz_calloc -Dfree=pqfuzz_free
build/test_cbor_fuzz: test_cbor_fuzz.c ../../cbor/pqcbor.c ../../cbor/pqcbor.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(FUZZ_SAN) $(FUZZ_ALLOC) -I ../../cbor \
	    -c ../../cbor/pqcbor.c -o build/pqcbor_fuzz.o
	$(CC) $(CFLAGS) $(FUZZ_SAN) -I ../../cbor -o $@ $< build/pqcbor_fuzz.o

build/test_flash_store: test_flash_store.c $(FLASH_STORE_SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) -I ../src -I . -DPICO_FLASH_SIZE_BYTES=32768 \
	    -o $@ $^

# test_resident_flash: the REAL resident_store.c on its QSPI branch
# (so NOT -DPQF_RESIDENT_HOST, which CFLAGS carries), over the same
# simulated die and the real flash_store.c for the keys and the guarded
# flash op. Built at the default and with three overflow sectors
# (PQF_RESIDENT_EXTRA_SECTORS); the rk0 binary saves its die as
# build/rk-default.die and the rk3 one boots it, so the loop in `test`
# (and tools/host-tests.sh, which runs build/* in name order) must run
# rk0 first -- both do. 64 KiB of die: the four fixed sectors plus
# three overflow sectors, with room below.
RES_FLASH_SRC = ../src/resident_store.c ../src/flash_store.c host_flash_die.c \
                $(OM)/src/pqf_hmac_sha256.c $(OM)/src/pqf_sha256.c \
                $(OM)/src/sha256.c
RES_FLASH_CFLAGS = $(filter-out -DPQF_RESIDENT_HOST,$(CFLAGS)) -I ../src -I . \
                   -DPICO_FLASH_SIZE_BYTES=65536
build/test_resident_flash-rk%: test_resident_flash.c $(RES_FLASH_SRC) \
                               ../src/resident_store.h
	@mkdir -p build
	$(CC) $(RES_FLASH_CFLAGS) -DPQF_RESIDENT_EXTRA_SECTORS=$* \
	    -o $@ $< $(RES_FLASH_SRC)

# The CTAP2-level suites that walk the resident store (RK3_SUITES,
# above), rebuilt with three overflow sectors (RAM-only store, as in
# their default build): the capacity they fill, enumerate and report in
# getInfo is then 28, not 7.
build/%-rk3: %.c $(ALL_SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) -DPQF_RESIDENT_EXTRA_SECTORS=3 -o $@ $< $(ALL_SRC)

# test_qrng drives the QRNG driver (src/pqf_qrng.c) and the
# RAND picker above it (src/pqf_rand.c) against a scripted bus: the test
# implements pqf_qrng_hw.h as a model it controls and defines the
# get_rand_64 fallback as a counter. Links the REAL pqf_rand.c -- so it
# must not pick up $(RAND_STUB), whose RAND_bytes would clash -- and only
# the SHA-256 it conditions with. -DPQF_QRNG_HOST turns the spin lock
# into a no-op (one thread here); -I . finds test/pico/rand.h.
QRNG_SRC = ../src/pqf_qrng.c ../src/pqf_rand.c $(OM)/src/pqf_sha256.c $(OM)/src/sha256.c
build/test_qrng: test_qrng.c $(QRNG_SRC) ../src/pqf_qrng.h ../src/pqf_qrng_hw.h ../src/pqf_rand.h
	@mkdir -p build
	$(CC) $(CFLAGS) -DPQF_QRNG=1 -DPQF_QRNG_HOST=1 -I . -o $@ $< $(QRNG_SRC)

# test_yield drives the single-core signer (src/core0_signer.c) and the
# yield hook the vendored crypto calls from its loops. The clock is the
# test's (-DPQF_YIELD_HOST: core0_signer.c asks pqf_yield_test_now()
# instead of the RP2350 timer), advanced 1 ms per yield, so the tick
# count and the worst gap are exact expectations. Links the REAL
# core0_signer.c, so NOT $(CORE1_STUB) -- the two define the same API.
YIELD_SRC = ../src/core0_signer.c $(FW_SRC) $(OM_SRC) $(RAND_STUB) $(FLASH_STUB)
build/test_yield: test_yield.c $(YIELD_SRC) ../src/core1_signer.h
	@mkdir -p build
	$(CC) $(CFLAGS) -DPQF_SINGLE_CORE=1 -DPQF_YIELD_HOST=1 -I . -o $@ $< $(YIELD_SRC)

build/test_ctaphid: test_ctaphid.c ../src/ctaphid.c $(ALL_SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) -DPQF_CTAPHID_HOST=1 -o $@ $< ../src/ctaphid.c $(ALL_SRC)

# test_reboot_policy pins the CTAPHID_CMD_REBOOT presence policy per
# board (src/board.h, PQF_REBOOT_NEEDS_UP). test_ctaphid above has no
# board macro, so board.h resolves it as buttonless and the gate is
# compiled out there. The policy is fixed at compile time, so one binary
# sees one answer; this one is built once per configuration that
# matters, as the descriptor suite is:
#   -feitian       PQF_BOARD_FEITIAN_RP2350: gated -- a declined touch
#                  answers ERR_OTHER and does not reboot
#   -feitian-noup  the same with PQF_REBOOT_NO_UP: the override still
#                  drops the gate on a button board
#   -usbc          PQF_BOARD_FEITIAN_RP2350_USBC: reboots WITHOUT asking.
#                  Its power-on BOOTSEL does not work, so this command is
#                  its only way back into the bootloader; a gate here is
#                  a token that can never be reflashed.
# Linked like test_ctaphid, against the full CTAP2 stack, because the
# check that FIDO presence is still asked for goes through
# ctap2_dispatch. board.h is a prerequisite: it is where the policy is.
REBOOT_SRC = ../src/ctaphid.c $(ALL_SRC)
REBOOT_DEFS_feitian      = -DPQF_BOARD_FEITIAN_RP2350
REBOOT_DEFS_feitian-noup = -DPQF_BOARD_FEITIAN_RP2350 -DPQF_REBOOT_NO_UP=1
REBOOT_DEFS_usbc         = -DPQF_BOARD_FEITIAN_RP2350_USBC
REBOOT_VARIANTS = feitian feitian-noup usbc
REBOOT_BINS     = $(addprefix build/test_reboot_policy-,$(REBOOT_VARIANTS))
$(REBOOT_BINS): build/test_reboot_policy-%: test_reboot_policy.c $(REBOOT_SRC) \
                ../src/board.h ../src/ctaphid.h
	@mkdir -p build
	$(CC) $(CFLAGS) -DPQF_CTAPHID_HOST=1 $(REBOOT_DEFS_$*) \
	    -o $@ $< $(REBOOT_SRC)

.PHONY: reboot_policy
reboot_policy: $(REBOOT_BINS)
	@for v in $(REBOOT_VARIANTS); do \
	    echo "--- reboot_policy-$$v ---"; \
	    ./build/test_reboot_policy-$$v || exit 1; \
	done

build/%: %.c $(ALL_SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $< $(ALL_SRC)

clean:
	rm -rf build
