# Bruce -- C port of the bare-metal Rust firmware, built on pico-sdk.
#
# Target: RP2350A, shipped on the Pimoroni Tiny 2350 / Seeed XIAO
# RP2350 / Waveshare RP2350-LCD-1.47 / Spotpear RP2350-LCD-1.28 dev
# boards. The SoC carries two Cortex-M33 (Arm) AND two Hazard3
# (RISC-V) cores; -DPQF_PLATFORM picks which pair the image boots
# (`rp2350` = Arm-Secure, the default; `rp2350-riscv` = Hazard3).
#
# The build sits inside the Cargo workspace's `c/firmware/` directory
# but is otherwise independent -- it doesn't share crates with the
# Rust path; the C side is a parallel implementation.
#
# Quick start
# -----------
#   $ export PICO_SDK_PATH=/path/to/pico-sdk        # already set if
#                                                   # you have one
#   $ cmake -S c/firmware -B c/firmware/build \
#         -DPQF_BOARD=waveshare_rp2350_lcd_1_47     # see the table below
#   $ cmake --build c/firmware/build -j
#   # -> c/firmware/build/bruce_c.uf2
#
# RISC-V build (same boards, Hazard3 cores):
#   $ cmake -S c/firmware -B c/firmware/build-riscv \
#         -DPQF_BOARD=tiny2350 -DPQF_PLATFORM=rp2350-riscv \
#         -DPICO_GCC_TRIPLE=riscv64-elf   # if your riscv gcc is not
#                                         # riscv32-unknown-elf-gcc /
#                                         # riscv32-corev-elf-gcc; the
#                                         # Homebrew riscv64-elf-gcc
#                                         # has the rv32 multilibs
#   $ cmake --build c/firmware/build-riscv -j
# Needs a bare-metal RISC-V GCC with rv32 multilib support (e.g.
# `brew install riscv64-elf-gcc` on macOS); pico-sdk probes the
# compiler and picks the best -march for Hazard3 automatically.
#
# Board selection (Phase C-11) -- mirrors the Rust firmware's
# `board_*` cargo features. One -DPQF_BOARD=<name> picks both the
# pico-sdk board header (clock/flash/pin defaults) and the firmware's
# own board profile in src/board.c (status LED + quirk pins):
#
#   PQF_BOARD                  | pico-sdk PICO_BOARD | LED / quirks
#   ---------------------------+---------------------+---------------------
#   tiny2350                   | pimoroni_tiny2350   | RGB GP18/19/20, wink
#                              |                     | on the green leg;
#                              |                     | BOOT = user button
#   xiao_rp2350                | seeed_xiao_rp2350   | LED GP25; GP23 WS2812
#                              |                     | power gate held LOW
#   feitian_rp2350             | pico2 (reference    | LED GP25 active-HIGH;
#                              | design)             | BOOTSEL = user button
#   feitian_rp2350_usbc        | pico2 (ditto)       | as feitian_rp2350, in
#                              |                     | a sealed USB-C shell:
#                              |                     | touch pad = user
#                              |                     | button; NO power-on
#                              |                     | BOOTSEL, so CMD_REBOOT
#                              |                     | is ungated by design
#   waveshare_rp2350_lcd_1_47  | pico2 (no SDK hdr   | no LED; GP23 WS2812
#       (default)              | for this module)    | data held LOW
#   spotpear_rp2350_lcd_1_28   | pico2 (ditto)       | no LED
#
# An external quantum RNG on I2C is preferred over the
# on-die TRNG whenever one answers at boot (PQF_QRNG, default ON -- see
# its option block below for wiring and how to compile it out).
#
# The default is the Waveshare module -- the board this port has been
# flashed and verified on so far. (The Rust firmware defaults to the
# Tiny 2350 instead; pass -DPQF_BOARD=tiny2350 to match it.) The two
# LCD modules have no pico-sdk board header, so they ride the `pico2`
# reference profile -- same RP2350A, same 4 MB-window flash layout, and
# crucially the same flash-store offsets as every UF2 shipped before
# C-11, so a reflash never strands persisted credentials.
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13)

set(PQF_BOARD "waveshare_rp2350_lcd_1_47" CACHE STRING
    "Target board: tiny2350 | xiao_rp2350 | feitian_rp2350 | feitian_rp2350_usbc | waveshare_rp2350_lcd_1_47 | spotpear_rp2350_lcd_1_28")

# Map PQF_BOARD -> pico-sdk board header + the src/board.c profile
# macro. PICO_BOARD must be set before pico_sdk_import below.
if (PQF_BOARD STREQUAL "tiny2350")
    set(PICO_BOARD pimoroni_tiny2350)
    set(PQF_BOARD_MACRO PQF_BOARD_TINY2350)
elseif (PQF_BOARD STREQUAL "xiao_rp2350")
    set(PICO_BOARD seeed_xiao_rp2350)
    set(PQF_BOARD_MACRO PQF_BOARD_XIAO_RP2350)
elseif (PQF_BOARD STREQUAL "feitian_rp2350")
    set(PICO_BOARD pico2)
    set(PQF_BOARD_MACRO PQF_BOARD_FEITIAN_RP2350)
    # The pico2 header declares 4 MiB. This board carries 2 MiB, MEASURED:
    # a pattern written at 0x200000 reads back at 0x000000 (2026-08-18),
    # and picotool erase -a reports "Erased 2097152 bytes".
    #
    # Overstating it does not overflow, it ALIASES, and that is exactly
    # how the DFU staging slot came to erase the bootloader's own vector
    # table (see c/common/pqf_image.h). The persisted sectors here are
    # currently only correct by luck: flash_store/resident_store/
    # large_blobs place themselves at PICO_FLASH_SIZE_BYTES - N*4096, so
    # at 4 MiB they land on 0x3FC000..0x400000 and wrap onto
    # 0x1FC000..0x200000 -- the right sectors, by accident. Declaring the
    # true size makes those offsets land there directly, with no wrap,
    # and bounds the linked FLASH region to the real device.
    #
    # Physically a no-op on this board (same four sectors), so existing
    # credentials stay readable.
    set(PICO_FLASH_SIZE_BYTES 2097152)
elseif (PQF_BOARD STREQUAL "feitian_rp2350_usbc")
    set(PICO_BOARD pico2)
    set(PQF_BOARD_MACRO PQF_BOARD_FEITIAN_RP2350_USBC)
    # The same reference design as feitian_rp2350, in a sealed USB-C
    # shell with a capacitive touch pad for the button. The die size of
    # the USB-C token is not yet measured; declaring 2 MiB is safe either
    # way -- a smaller declared size never aliases (the failure mode the
    # entry above documents), a larger die just leaves the top unused.
    set(PICO_FLASH_SIZE_BYTES 2097152)
elseif (PQF_BOARD STREQUAL "waveshare_rp2350_lcd_1_47")
    set(PICO_BOARD pico2)
    set(PQF_BOARD_MACRO PQF_BOARD_WAVESHARE_LCD_1_47)
elseif (PQF_BOARD STREQUAL "spotpear_rp2350_lcd_1_28")
    set(PICO_BOARD pico2)
    set(PQF_BOARD_MACRO PQF_BOARD_SPOTPEAR_LCD_1_28)
else()
    message(FATAL_ERROR "Unknown PQF_BOARD '${PQF_BOARD}' -- pick one of: "
        "tiny2350, xiao_rp2350, feitian_rp2350, feitian_rp2350_usbc, "
        "waveshare_rp2350_lcd_1_47, spotpear_rp2350_lcd_1_28")
endif()
message(STATUS "Bruce board: ${PQF_BOARD} (PICO_BOARD=${PICO_BOARD})")

# Configure-time mirror of the two capability flags src/board.h derives
# from the board macro, used ONLY to print the resolved CMD_REBOOT
# policy below (the PQF_REBOOT_NO_UP block). board.h is authoritative:
# ctaphid.c compiles the gate from its PQF_REBOOT_NEEDS_UP, and main.c
# records the result in the image as the pqf-reboot= picotool feature,
# so a drift here would show up as a STATUS line disagreeing with
# `picotool info -a`. Keep the two tables in step when adding a board.
# PQF_TEST_NO_USER_BUTTON forces board.h's button flag to 0, so it does
# the same here.
if (PQF_BOARD MATCHES "^(tiny2350|feitian_rp2350|feitian_rp2350_usbc)$"
    AND NOT PQF_TEST_NO_USER_BUTTON)
    set(_pqf_has_user_button ON)       # BOOT button / touch pad on QSPI_SS
else()
    set(_pqf_has_user_button OFF)
endif()
if (PQF_BOARD STREQUAL "feitian_rp2350_usbc")
    set(_pqf_has_power_on_bootsel OFF) # sealed; power-on sensing does not work
else()
    set(_pqf_has_power_on_bootsel ON)
endif()

# The RP2350 ships two Cortex-M33 (Arm) and two Hazard3 (RISC-V)
# cores; the boot ROM runs whichever pair the flashed image declares.
# PQF_PLATFORM selects the instruction set:
#   rp2350       -- Arm-Secure (the default state cortex-m-rt and
#                  rp235x-hal also target on the Rust side)
#   rp2350-riscv -- Hazard3 RISC-V (pico-sdk >= 2.0; needs a bare-metal
#                  RISC-V GCC with rv32 multilibs on the PATH, plus
#                  -DPICO_GCC_TRIPLE=<triple> if it isn't one of the
#                  SDK's default triples)
# The source is instruction-set-neutral: the __sev()/__wfe()/__dmb()
# pairing in core1_signer.c and the interrupt save/restore in
# bootsel.c go through pico-sdk's hardware/sync.h, which maps them to
# the Hazard3 h3.unblock/h3.block hints and mstatus.MIE on RISC-V; the
# vendored openssl-mini asm fast paths are all x86/Arm-guarded with C
# fallbacks.
set(PQF_PLATFORM "rp2350" CACHE STRING
    "Instruction set: rp2350 (Arm Cortex-M33) | rp2350-riscv (Hazard3 RISC-V)")
if (NOT PQF_PLATFORM STREQUAL "rp2350" AND NOT PQF_PLATFORM STREQUAL "rp2350-riscv")
    message(FATAL_ERROR "Unknown PQF_PLATFORM '${PQF_PLATFORM}' -- pick rp2350 or rp2350-riscv")
endif()
set(PICO_PLATFORM ${PQF_PLATFORM})
message(STATUS "Bruce platform: ${PICO_PLATFORM}")

# Hybrid ML-DSA security level: 44, 65 (default), or 87. Drives the COSE
# alg, the public-key / signature sizes, and (in mixed mode) the blob's
# heap budget. Defined globally so every translation unit -- and the
# cross-compiled core-1 blob -- agree on the mailbox/buffer sizes.
set(PQF_HYBRID_VARIANT "65" CACHE STRING "Hybrid ML-DSA level: 44 | 65 | 87")
if (NOT PQF_HYBRID_VARIANT STREQUAL "44" AND NOT PQF_HYBRID_VARIANT STREQUAL "65"
    AND NOT PQF_HYBRID_VARIANT STREQUAL "87")
    message(FATAL_ERROR "Unknown PQF_HYBRID_VARIANT '${PQF_HYBRID_VARIANT}' -- pick 44, 65, or 87")
endif()
message(STATUS "Bruce hybrid ML-DSA level: ${PQF_HYBRID_VARIANT}")

# ML-DSA matrix-A residency policy. ExpandA() samples every element of the
# k*l matrix independently, so A can either be materialised once or
# re-derived a row at a time as the matrix multiply walks it. Key
# generation and verification multiply by A exactly once and therefore
# always stream -- it costs them nothing and saves (k*l-1) polynomials
# (15/29/55 KiB at 44/65/87). Signing multiplies once per rejection
# iteration, so there streaming is a real trade: ~1.3x on the ML-DSA
# arithmetic against 55 KiB at level 87.
#   0 -- never stream in the signing loop (fastest signing)
#   1 -- always stream (smallest heap)
#   2 -- stream only where A dominates the heap, i.e. level 87 (default)
# The default streams at 87 because that is where A sets the size of the
# single contiguous signing allocation PQF_SIGN_ARENA exists to serve
# (76,800 -> 20,480 bytes); at 44/65 there is no arena, so no reason to pay.
set(PQF_MLDSA_LOWMEM "2" CACHE STRING
    "ML-DSA streaming-A policy: 0 off | 1 on | 2 auto (87 only)")
if (NOT PQF_MLDSA_LOWMEM STREQUAL "0" AND NOT PQF_MLDSA_LOWMEM STREQUAL "1"
    AND NOT PQF_MLDSA_LOWMEM STREQUAL "2")
    message(FATAL_ERROR "Unknown PQF_MLDSA_LOWMEM '${PQF_MLDSA_LOWMEM}' -- pick 0, 1, or 2")
endif()
message(STATUS "Bruce ML-DSA streaming-A policy: ${PQF_MLDSA_LOWMEM}")
if (PQF_PLATFORM STREQUAL "rp2350-riscv")
    message(STATUS
        "PQF_PLATFORM=rp2350-riscv (pure RISC-V, both cores Hazard3): the "
        "long-standing registration freeze was root-caused 2026-07-14 "
        "(newlib memcmp/strcmp misaligned-access trap on Hazard3) and fixed "
        "(src/pqf_align_str.c + -mstrict-align); a full browser register+PIN "
        "ceremony is silicon-validated on the Feitian RP2350. This build also "
        "runs interrupt-free (polled USB, no alarm-pool TIMER IRQ). See "
        "docs/RISCV.md ('Known limitations: C port RISC-V').")
endif()

# ---------------------------------------------------------------------
# Mixed architecture: Arm core 0 + RISC-V core 1 (-DPQF_CORE1_RISCV=ON).
#
# Core 0 stays Arm (PQF_PLATFORM=rp2350); at boot it flips core 1 to a
# Hazard3 (OTP ARCHSEL) and runs an embedded riscv32 signing blob
# (core1-riscv-blob/), driving it through a shared-SRAM mailbox. This is
# the C mirror of the Rust firmware's `core1_riscv` feature.
#   - core1_signer_riscv.c replaces core1_signer.c (mailbox + launch)
#   - core1_blob.S .incbin's the cross-compiled blob binary
#   - memmap_core1riscv.ld carves SRAM 320/192 and pins the blob at
#     0x1018_0000
# The blob is built by core1-riscv-blob/build_blob.sh with a SEPARATE
# bare-metal riscv32 GCC (the Arm cross-compiler pico-sdk configures
# can't target RISC-V), located via PQF_RISCV_TOOLCHAIN_BIN.
# ---------------------------------------------------------------------
option(PQF_CORE1_RISCV
    "Mixed mode: run the core-1 signer as a RISC-V blob (Arm core 0)" OFF)

# ---------------------------------------------------------------------
# Single core: -DPQF_SINGLE_CORE=ON leaves core 1 asleep and runs the
# signer inline on core 0 (src/core0_signer.c). The second core only
# ever existed to keep CTAPHID KEEPALIVE frames flowing during a ~1 s
# hybrid sign; here that job moves INSIDE the crypto: the vendored
# ML-DSA and EC loops call pqf_yield() (openssl-mini/include/pqf_yield.h)
# every few microseconds of work, and the single-core signer turns
# those calls into a USB service + KEEPALIVE tick once per PQF_YIELD_US.
# Nothing to park around flash writes, no core-1 stack, no ARCHSEL.
# Either instruction set; not combinable with the mixed build, which is
# defined by having a second core. The banner reports the worst
# yield-to-yield gap measured on the token, which is the number that
# says whether a host's watchdog can ever see a hole.
# ---------------------------------------------------------------------
option(PQF_SINGLE_CORE
    "Run the signer inline on core 0; the crypto's yield hook pumps USB + KEEPALIVE" OFF)
set(PQF_YIELD_US "25000" CACHE STRING
    "Single core: microseconds between USB + KEEPALIVE ticks from inside the crypto")

if (PQF_CORE1_RISCV)
    if (PQF_SINGLE_CORE)
        message(FATAL_ERROR
            "PQF_SINGLE_CORE and PQF_CORE1_RISCV are exclusive: the mixed build "
            "IS a second core. Drop one of them.")
    endif()
    if (NOT PQF_PLATFORM STREQUAL "rp2350")
        message(FATAL_ERROR
            "PQF_CORE1_RISCV needs an Arm core 0 (PQF_PLATFORM=rp2350). "
            "For both cores RISC-V, use PQF_PLATFORM=rp2350-riscv WITHOUT this option.")
    endif()
    # No default location: point this at the bin/ directory of a
    # bare-metal riscv32 GCC, or have riscv32-unknown-elf-gcc on PATH.
    set(PQF_RISCV_TOOLCHAIN_BIN ""
        CACHE STRING "bin/ dir of a bare-metal riscv32 GCC (builds the core-1 blob)")
    if (NOT PQF_RISCV_TOOLCHAIN_BIN)
        find_program(PQF_RISCV_GCC_ON_PATH riscv32-unknown-elf-gcc)
        if (PQF_RISCV_GCC_ON_PATH)
            get_filename_component(PQF_RISCV_TOOLCHAIN_BIN "${PQF_RISCV_GCC_ON_PATH}" DIRECTORY)
        else()
            message(FATAL_ERROR
                "PQF_CORE1_RISCV needs a bare-metal riscv32 GCC: pass "
                "-DPQF_RISCV_TOOLCHAIN_BIN=<dir containing riscv32-unknown-elf-gcc> "
                "or put it on PATH.")
        endif()
    endif()
    set(PQF_RISCV_GCC     "${PQF_RISCV_TOOLCHAIN_BIN}/riscv32-unknown-elf-gcc")
    set(PQF_RISCV_OBJCOPY "${PQF_RISCV_TOOLCHAIN_BIN}/riscv32-unknown-elf-objcopy")
    set(PQF_CORE1_SIGNER_SRCS src/core1_signer_riscv.c src/core1_blob.S)
    message(STATUS "Bruce core-1: RISC-V blob (mixed) via ${PQF_RISCV_GCC}")
    message(STATUS
        "PQF_CORE1_RISCV=ON (mixed mode: Arm core 0 + RISC-V core 1) is "
        "silicon-validated as of 2026-07-14 (Feitian RP2350: register + "
        "PIN-set + login, real hybrid sigs from the blob at ~10 s/sign). Two "
        "bugs were fixed to get there -- the newlib misaligned-memcmp trap "
        "(src/pqf_align_str.c + -mstrict-align) and the blob-heap OOM (RAM "
        "window 192->256 KiB) -- see docs/RISCV.md ('Known limitations: C "
        "port RISC-V'). Experimental (not a shipping target): ML-DSA-65 on "
        "the Hazard3 is ~10x slower than the Arm build; use Arm for speed.")
elseif (PQF_SINGLE_CORE)
    set(PQF_CORE1_SIGNER_SRCS src/core0_signer.c)
    message(STATUS "Bruce core-1: NOT USED (PQF_SINGLE_CORE) -- signer inline on core 0, "
                   "USB + KEEPALIVE tick from the crypto's yield hook every ${PQF_YIELD_US} us")
else()
    set(PQF_CORE1_SIGNER_SRCS src/core1_signer.c)
endif()

# Pull in pico-sdk. Honours $PICO_SDK_PATH from the environment or a
# `-DPICO_SDK_PATH=...` on the cmake command line.
# ---------------------------------------------------------------------
# DFU bootloader integration: -DPQF_BOOTLOADER=ON builds the app
# for the DFU-updated flash layout (c/common/pqf_image.h):
#   - linked at 0x10021000 (behind the 128 KiB bootloader + the 4 KiB
#     signed-image header sector) instead of 0x10000000;
#   - a USB DFU *runtime* interface is added to the composite device,
#     so `dfu-util -D <image>.dfu` can detach the running token into
#     the bootloader and flash it in one command.
# The resulting .bin must be signed with tools/pqf_sign.py before the
# bootloader will install OR boot it (see docs/DFU.md). OFF (default)
# keeps the classic standalone image at 0x10000000 for the
# BOOTSEL/picotool dev flow.
# ---------------------------------------------------------------------
option(PQF_BOOTLOADER
    "Link behind the DFU bootloader + expose a DFU runtime interface" OFF)

# The two effects are separable, which matters for hardware bring-up
# bisection (2026-07-20): PQF_APP_OFFSET is the offset link,
# PQF_DFU_RUNTIME_IF is the extra DFU-runtime USB interface.
option(PQF_APP_OFFSET "Link the app at the DFU app-slot offset (0x10021000)" OFF)
option(PQF_DFU_RUNTIME_IF "Expose the DFU runtime USB interface" OFF)
if (PQF_BOOTLOADER)
    set(PQF_APP_OFFSET ON)
    set(PQF_DFU_RUNTIME_IF ON)
endif()

# Discoverable-credential capacity: -DPQF_RESIDENT_EXTRA_SECTORS=N adds N
# flash sectors of 7 discoverable credentials each, below the master-key
# sector (src/resident_store.h). 0 (the default) is the 7-slot store,
# byte for byte, so an existing token keeps its passkeys and PIN either
# way. Every slot is mirrored in RAM (about 5 KiB of .bss per sector),
# hence the cap. Not with the DFU layout: c/common/pqf_image.h puts its
# boot-state journal and staging slot directly below the persisted
# sectors, where the overflow sectors would go.
set(PQF_RESIDENT_EXTRA_SECTORS 0 CACHE STRING
    "Extra flash sectors of discoverable credentials, 7 each (0..8)")
if (NOT PQF_RESIDENT_EXTRA_SECTORS MATCHES "^[0-8]$")
    message(FATAL_ERROR "PQF_RESIDENT_EXTRA_SECTORS must be 0..8 "
        "(got '${PQF_RESIDENT_EXTRA_SECTORS}')")
endif()
if (PQF_RESIDENT_EXTRA_SECTORS GREATER 0 AND PQF_APP_OFFSET)
    message(FATAL_ERROR "PQF_RESIDENT_EXTRA_SECTORS cannot be combined "
        "with PQF_BOOTLOADER / PQF_APP_OFFSET: the DFU map's boot-state "
        "and staging sectors sit where the overflow sectors would go")
endif()
math(EXPR PQF_RK_SLOTS "7 + 7 * ${PQF_RESIDENT_EXTRA_SECTORS}")
math(EXPR PQF_RESERVED_SECTORS "4 + ${PQF_RESIDENT_EXTRA_SECTORS}")
math(EXPR PQF_RESERVED_BYTES "4096 * ${PQF_RESERVED_SECTORS}")

include(pico_sdk_import.cmake)

project(bruce_c
    VERSION 0.1.0
    DESCRIPTION "Bare-metal C port of the Bruce Rust firmware"
    LANGUAGES C CXX ASM
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# `pico_sdk_init()` defines the toolchain, the RP2350 boot ROM image
# definition, and the linker scripts. Must come after `project()`.
pico_sdk_init()

# DFU layout: relocate the linked FLASH region into the app slot by
# rewriting the SDK's generated pico_flash_region.ld (both
# memmap_default.ld and memmap_copy_to_ram.ld INCLUDE it out of
# CMAKE_BINARY_DIR). pico_sdk_init() wrote the full-flash default
# earlier in this same configure pass; overwriting it here wins. The
# 0x10021000 origin / 0xEC000 length mirror PQF_APP_IMAGE_OFF /
# PQF_IMAGE_MAX_LEN in c/common/pqf_image.h -- keep in lockstep. The
# length shrank when the flash map was corrected to the real 2 MiB die:
# the old 0x1DF000 was sized for a 4 MiB part that is not fitted, and
# would let an app link straight through its own slot and into staging.
if (PQF_APP_OFFSET)
    file(WRITE ${CMAKE_BINARY_DIR}/pico_flash_region.ld
        "FLASH(rx) : ORIGIN = 0x10021000, LENGTH = 0xEC000 /* pqf app slot (pqf_image.h) */\n")
    message(STATUS "Bruce: PQF_APP_OFFSET -- app linked at 0x10021000")
endif()
if (PQF_DFU_RUNTIME_IF)
    message(STATUS "Bruce: PQF_DFU_RUNTIME_IF -- DFU runtime USB interface ON")
endif()

# Firmware source groups.
#
# The build accretes across phases (C-1 .. C-11); every source below
# is one translation unit compiled with the ARM cross-compiler against
# the RP2350 target. The vendored OpenSSL crypto under openssl-mini/ is
# pulled in by glob (BN / EC / ML-DSA trees) plus an explicit list of
# the SHA / SHAKE / AES / EVP / pqf adapters + packet/buffer support.
#
# Three crypto layers, in dependency order:
#   - BN          : bignum arithmetic (P-256 + ML-DSA rely on it)
#   - EC          : NIST P-256 group + ECDSA + ECDH
#   - ML-DSA      : FIPS 204 ML-DSA-44/65/87 (PQC signatures)
# plus SHA-256/512 (classical hashing + ECDSA hedged nonce), SHA3 +
# Keccak (SHAKE XOF for ML-DSA), AES-256 (credentialID + PIN crypto),
# and the pqf_* wrappers that give firmware code a clean API.
file(GLOB OPENSSL_MINI_BN    ${CMAKE_CURRENT_LIST_DIR}/openssl-mini/src/bn/*.c)
file(GLOB OPENSSL_MINI_EC    ${CMAKE_CURRENT_LIST_DIR}/openssl-mini/src/ec/*.c)
file(GLOB OPENSSL_MINI_MLDSA ${CMAKE_CURRENT_LIST_DIR}/openssl-mini/src/ml_dsa/*.c)

add_executable(bruce_c
    src/main.c
    src/board.c
    src/bootsel.c
    src/usb_descriptors.c
    src/fido_hid.c
    src/ctaphid.c
    src/ctap2.c
    src/cbor_encode.c
    src/credential.c
    src/pqf_rand.c
    src/pqf_align_str.c
    src/flash_store.c
    src/resident_store.c
    src/client_pin.c
    src/pin_protocol.c
    src/authenticator_config.c
    src/credential_management.c
    src/large_blobs.c
    src/hybrid.c
    ${PQF_CORE1_SIGNER_SRCS}
    src/riscv_trap.c              # RISC-V trap forensics (empty on Arm)

    # CBOR decoder -- same source the host-side libpqcbor.a ships,
    # compiled here with the ARM cross-compiler against the firmware
    # target instead of the host.
    ../cbor/pqcbor.c

    # Vendored crypto (openssl-mini). The glob pulls every BN + EC
    # source; the SHA / EVP / pqf adapters are listed explicitly.
    ${OPENSSL_MINI_BN}
    ${OPENSSL_MINI_EC}
    ${OPENSSL_MINI_MLDSA}
    openssl-mini/src/sha256.c
    openssl-mini/src/sha512.c
    openssl-mini/src/aes_core.c
    openssl-mini/src/pqf_sha256.c
    openssl-mini/src/pqf_hmac_sha256.c
    openssl-mini/src/pqf_aes.c
    openssl-mini/src/pqf_evp.c
    openssl-mini/src/pqf_hkdf.c
    openssl-mini/src/sha3.c
    openssl-mini/src/keccak1600.c
    openssl-mini/src/packet.c
    openssl-mini/src/buffer.c
)

target_include_directories(bruce_c PRIVATE
    src
    ${CMAKE_CURRENT_LIST_DIR}     # tusb_config.h lives here
    ../cbor                       # pqcbor.h
    openssl-mini/include          # pqf_crypto.h + the openssl/* shims
    openssl-mini/src              # sha_local.h, aes_local.h
    openssl-mini/src/bn           # bn_local.h
    openssl-mini/src/ec           # ec_local.h
    openssl-mini/src/ml_dsa       # ml_dsa_local.h
)

# Optional picotool program URL (bi_program_url). Empty by default so a
# build carries no URL unless the packager supplies one:
#   -DPQF_PROGRAM_URL=https://example.org/bruce
set(PQF_PROGRAM_URL "" CACHE STRING "URL recorded in the picotool binary-info block (empty = none)")
if (PQF_PROGRAM_URL)
    target_compile_definitions(bruce_c PRIVATE PQF_PROGRAM_URL="${PQF_PROGRAM_URL}")
endif()

# Select the src/board.c profile (LED + quirk pins) matching PQF_BOARD
# -- see the board table at the top of this file. PQF_BOARD_ID is the
# same name as a string, which main.c stamps into the image's binary
# info (pqf-board=<id>) so `picotool info -a` can tell the UF2s apart
# before one is flashed.
target_compile_definitions(bruce_c PRIVATE
    ${PQF_BOARD_MACRO}=1
    PQF_BOARD_ID="${PQF_BOARD}"
    PQF_HYBRID_VARIANT=${PQF_HYBRID_VARIANT}
    PQF_MLDSA_LOWMEM=${PQF_MLDSA_LOWMEM}
    PQF_RESIDENT_EXTRA_SECTORS=${PQF_RESIDENT_EXTRA_SECTORS}
)
message(STATUS "Bruce: PQF_RESIDENT_EXTRA_SECTORS=${PQF_RESIDENT_EXTRA_SECTORS} "
               "-- ${PQF_RK_SLOTS} discoverable credential slots")
if (PQF_DFU_RUNTIME_IF)
    # Adds the DFU runtime interface (tusb_config.h / usb_descriptors.c)
    # and the DETACH -> watchdog-scratch -> bootloader hook in main.c.
    target_compile_definitions(bruce_c PRIVATE PQF_DFU_RUNTIME=1)
endif()
if (PQF_SINGLE_CORE)
    target_compile_definitions(bruce_c PRIVATE
        PQF_SINGLE_CORE=1
        PQF_YIELD_US=${PQF_YIELD_US}u
    )
endif()


# TEST-ONLY: -DPQF_TEST_NO_USER_BUTTON=ON forces user-presence
# auto-confirm (buttonless) even on a board with a button, so automated
# on-silicon CTAP tests run without a physical press. Never ship.
if (PQF_TEST_NO_USER_BUTTON)
    target_compile_definitions(bruce_c PRIVATE PQF_TEST_NO_USER_BUTTON=1)
    message(STATUS "Bruce: PQF_TEST_NO_USER_BUTTON -- user presence auto-confirms (TEST build)")
endif()

# TEST-ONLY: the CDC <STX>BOOTSEL<ETX> reflash hook on its own.
# PQF_TEST_NO_USER_BUTTON implies it, but the two are separate concerns --
# this one only lets the host reboot the token into BOOTSEL over CDC, it
# does not touch the FIDO user-presence gate. Needed to exercise a REAL
# UP gate on silicon while still reflashing hands-free; without it, a
# UP-enabled build can only be re-flashed by a physical BOOTSEL hold.
# TEST-ONLY: count user-presence samples and rising edges, reported on
# the CDC banner each second. For docs/notes/UP-GATE-RETRACTED.md -- on a quiet
# board both must stay 0; a non-zero rising count is a spurious press and
# explains a gate that confirms with no human.
option(PQF_UP_DEBUG "Instrument the user-presence read (test only)" OFF)
if (PQF_UP_DEBUG)
    target_compile_definitions(bruce_c PRIVATE PQF_UP_DEBUG=1)
    message(STATUS "Bruce: PQF_UP_DEBUG -- user-presence sample counters on the CDC banner")
endif()

option(PQF_CDC_BOOTSEL_HOOK
    "CDC <STX>BOOTSEL<ETX> reflash hook (test only; independent of the UP gate)" OFF)
if (PQF_CDC_BOOTSEL_HOOK AND NOT PQF_TEST_NO_USER_BUTTON)
    target_compile_definitions(bruce_c PRIVATE PQF_CDC_BOOTSEL_HOOK=1)
    message(STATUS "Bruce: PQF_CDC_BOOTSEL_HOOK -- CDC reflash hook ON (FIDO UP gate unaffected)")
endif()

# -DPQF_REBOOT_NO_UP=ON drops the user-presence gate for the
# CTAPHID_CMD_REBOOT vendor command ONLY, so a flash station can reboot
# into BOOTSEL / warm-reboot with no touch. Unlike PQF_TEST_NO_USER_BUTTON
# this leaves FIDO user presence (MakeCredential / GetAssertion) fully
# enforced -- the device stays a real authenticator, it just trusts any
# host that can already talk to it to reboot it.
#
# The gate itself is a per-board policy (src/board.h, PQF_REBOOT_NEEDS_UP):
# it exists only on boards with a button AND a power-on BOOTSEL to fall
# back on -- tiny2350 and feitian_rp2350 -- and this option is the way
# to drop it there. The buttonless boards have nothing to press, and the
# sealed USB-C token (feitian_rp2350_usbc) is ungated by design: its
# power-on BOOTSEL sensing does not work, so CMD_REBOOT is its only way
# back into the bootloader, and an image that waited for a touch it
# cannot give could never be reflashed. On those boards the option
# changes nothing.
if (PQF_REBOOT_NO_UP)
    target_compile_definitions(bruce_c PRIVATE PQF_REBOOT_NO_UP=1)
    message(STATUS "Bruce: PQF_REBOOT_NO_UP -- CMD_REBOOT is NOT user-presence gated (FIDO UP unaffected)")
    set(_pqf_reboot_no_up ON)
else()
    set(_pqf_reboot_no_up OFF)
endif()
# The resolved policy, spelled out, so a build log answers "will this
# image need a touch to reboot?" without reading board.h. Same terms as
# PQF_REBOOT_NEEDS_UP there; PQF_TEST_NO_USER_BUTTON enters through the
# button flag above, exactly as it does in board.h. The image records
# the same answer as its pqf-reboot= feature (main.c).
if (_pqf_has_user_button AND _pqf_has_power_on_bootsel
    AND NOT _pqf_reboot_no_up)
    set(_pqf_reboot_needs_up YES)
else()
    set(_pqf_reboot_needs_up NO)
endif()
message(STATUS "Bruce: CMD_REBOOT needs a touch: ${_pqf_reboot_needs_up} "
               "(board ${PQF_BOARD}: user button ${_pqf_has_user_button}, "
               "power-on BOOTSEL ${_pqf_has_power_on_bootsel}, "
               "PQF_REBOOT_NO_UP ${_pqf_reboot_no_up})")

# DEBUG-ONLY: -DPQF_GDB_STUB=ON links an on-token GDB remote-
# serial-protocol stub (src/gdbstub.c) and grows the USB device by a
# second CDC interface for it -- debug firmware on a cased/locked token
# with nothing but the USB cable: `target remote <tty>`, breakpoints
# via the FPB, single-step, register/memory access. Monitor-mode debug
# (ARMv8-M DebugMonitor), Arm core 0 only. See docs/GDB_DEBUG.md.
#
# NEVER ship: the stub is an unauthenticated read/write/execute
# primitive over USB. Default OFF; production images must not carry it.
if (PQF_GDB_STUB)
    if (PQF_PLATFORM STREQUAL "rp2350-riscv")
        message(FATAL_ERROR
            "PQF_GDB_STUB needs the Arm (Cortex-M33) cores: the stub is "
            "built on the ARMv8-M DebugMonitor exception + FPB, which the "
            "Hazard3 (RISC-V) cores don't have. Drop the flag or build "
            "PQF_PLATFORM=rp2350.")
    endif()
    target_sources(bruce_c PRIVATE src/gdbstub.c)
    target_compile_definitions(bruce_c PRIVATE PQF_GDB_STUB=1)
    message(STATUS "Bruce: PQF_GDB_STUB -- on-token GDB stub on a 2nd CDC interface (DEBUG build, never ship)")
endif()

# Core-0 stack. Two builds nest the USB pump on top of an already deep
# call chain: the GDB monitor runs a USB pump + packet loop at whatever
# depth it halted, and the single-core signer runs the USB + KEEPALIVE
# tick from inside the crypto's deepest loops. Double the .stack
# reservation for both so the linker-time stack/heap overlap check keeps
# its meaning.
if (PQF_GDB_STUB OR PQF_SINGLE_CORE)
    target_compile_definitions(bruce_c PRIVATE PICO_STACK_SIZE=0x1000)
endif()

# ---------------------------------------------------------------------
# PQF_QRNG -- an external quantum RNG on I2C.
#
# ON by default: the firmware probes the bus once at boot -- an absent
# chip NAKs its address in microseconds and the pins are released again
# -- and, if a chip answers and reads ready, draws every random byte
# from it: SHA-256 conditioned, 64 raw in per 32 out (src/pqf_qrng.h
# explains why raw output is never handed on), with pico_rand / the
# on-die TRNG completing anything the chip leaves short. Nothing
# answering means the port behaves exactly as it did before this option
# existed. Instruction-set neutral: hardware_i2c is the same block under
# both core types, and the timeout I2C calls poll the timer rather than
# arming an alarm, so the interrupt-free pure-RISC-V build is fine. In
# the mixed build core 0 additionally ships 32 bytes of its own
# (QRNG-first) entropy to the RISC-V blob with every request, which the
# blob hashes together with its own TRNG output -- core1_mailbox.h
# `entropy` -- since the blob cannot reach the I2C controller.
#
# Default wiring is the Tiny 2350's QW/ST (Qwiic / STEMMA QT) connector:
# SDA GP12, SCL GP13 = I2C0, no PD (the 4-pin cable has no line for it;
# the breakout idles PD high itself). The breakout header works too --
# A0/A1 = GP26/GP27 = I2C1, PD on any free GPIO:
#   cmake ... -DPQF_QRNG_I2C=1 -DPQF_QRNG_SDA=26 -DPQF_QRNG_SCL=27 -DPQF_QRNG_PD=2
# and -DPQF_QRNG=OFF compiles the probe out entirely. The Spotpear
# profile defaults OFF: its LCD reset is GP12 and the probe would pulse
# it. Pass -DPQF_QRNG=ON with a re-wired bus to use a QRNG there.
# ---------------------------------------------------------------------
if (PQF_BOARD STREQUAL "spotpear_rp2350_lcd_1_28")
    set(_pqf_qrng_default OFF)
else()
    set(_pqf_qrng_default ON)
endif()
option(PQF_QRNG
    "Probe for a QRNG on I2C at boot and prefer it over the on-die TRNG"
    ${_pqf_qrng_default})
set(PQF_QRNG_I2C  "0"      CACHE STRING "QRNG: I2C controller, 0 or 1")
set(PQF_QRNG_SDA  "12"     CACHE STRING "QRNG: SDA GPIO")
set(PQF_QRNG_SCL  "13"     CACHE STRING "QRNG: SCL GPIO")
set(PQF_QRNG_PD   "-1"     CACHE STRING "QRNG: PD (power-down, active low) GPIO; -1 if not wired")
set(PQF_QRNG_BAUD "100000" CACHE STRING "QRNG: I2C clock in Hz (the part allows 50000..400000)")
if (PQF_QRNG)
    target_sources(bruce_c PRIVATE src/pqf_qrng.c src/pqf_qrng_hw.c)
    target_compile_definitions(bruce_c PRIVATE
        PQF_QRNG=1
        PQF_QRNG_I2C_INDEX=${PQF_QRNG_I2C}
        PQF_QRNG_SDA=${PQF_QRNG_SDA}
        PQF_QRNG_SCL=${PQF_QRNG_SCL}
        PQF_QRNG_PD=${PQF_QRNG_PD}
        PQF_QRNG_BAUD=${PQF_QRNG_BAUD}
    )
    target_link_libraries(bruce_c PRIVATE hardware_i2c)
    message(STATUS "Bruce: PQF_QRNG -- QRNG probe on i2c${PQF_QRNG_I2C} "
                   "GP${PQF_QRNG_SDA}/GP${PQF_QRNG_SCL} (pd ${PQF_QRNG_PD}); "
                   "on-die TRNG when absent")
else()
    message(STATUS "Bruce: PQF_QRNG=OFF -- entropy from the on-die TRNG only")
endif()

# Pure-RISC-V builds run interrupt-free (the freeze fix -- see
# pqf_usb_task in src/fido_hid.c): the USBCTRL IRQ is disabled at boot
# and polled instead, and the SDK's default alarm pool must not claim
# the TIMER0 IRQ either. Nothing in this firmware arms an alarm
# (sleep_* is unused; all timing is time_reached() polling), so with
# the pool disabled NO interrupt is ever enabled on either Hazard3
# core -- the same concurrency model as the silicon-validated Rust
# RISC-V port.
if (PQF_PLATFORM STREQUAL "rp2350-riscv")
    target_compile_definitions(bruce_c PRIVATE
        PICO_TIME_DEFAULT_ALARM_POOL_DISABLED=1
    )
    # Hazard3 has NO misaligned load/store support (mcause 4/6 traps),
    # but GCC's default model for this -march is __riscv_misaligned_slow
    # ("supported, just slow"), under which both GCC's own inline
    # expansions and the PREBUILT newlib emit unchecked word accesses.
    # -mstrict-align fixes everything compiled here (our sources AND
    # the pico-sdk sources, which build inside this target);
    # src/pqf_align_str.c replaces the two prebuilt newlib functions
    # that were disassembly-confirmed unsafe (memcmp, strcmp) -- the
    # silicon-confirmed cause of the "random" RISC-V freezes.
    target_compile_options(bruce_c PRIVATE -mstrict-align)
endif()

# ---------------------------------------------------------------------
# Single-ISA ML-DSA-87: dedicated sign arena (PQF_SIGN_ARENA).
#
# The hybrid sign at level 87 USED to peak at ~216 KiB of heap including
# one ~138 KiB CONTIGUOUS allocation (ml_dsa_sign.c's temp-vector blob) --
# more than the copy_to_ram image left free (~210 KiB), and beyond what
# newlib can keep unfragmented even when it fits (the exact wall the
# mixed build hit; silicon 2026-07-17/20).
#
# PQF_MLDSA_LOWMEM cut both figures hard: the ML-DSA-87 sign peak is now
# 48,392 bytes with a largest contiguous request of 23,552 (host, malloc
# interposer, against 177,768 / 138,240 before). Note what now sets that
# 23,552: signing re-derives the key from its seed, and the l + 2k
# polynomial block ossl_ml_dsa_generate_key_for_sign() allocates for the
# unpacked s1/s2/t0 is larger than the signing loop's own 20,480 byte
# blob. See openssl-mini/ML-DSA-LOWMEM.md. The hybrid adds the
# ECDSA half on top of that. It fits the ~227 KiB a copy_to_ram image
# leaves free with room to spare, and the far smaller contiguous request
# is much kinder to newlib's free list -- so -DPQF_COPY_TO_RAM=1 at 87 is
# suppresses the arena (see the copy_to_ram block below). Both paths are
# now silicon-validated at 87 on the Feitian (conformance suite 55/56,
# the one failure being the suite hardcoding ML-DSA-65):
#
#   87, XIP + arena (default)  MC 1.52 s / GA 1.38 s
#   87, copy_to_ram            MC 0.67 s / GA 0.84 s
#
# The XIP path was believed broken here ("OOM-wedged at login") until
# 2026-08-04. It was not a heap failure at all -- it was the QMI slow-mode
# bug fixed in flash_store.c. Level 87 was simply the only single-ISA
# config forced onto XIP, so it was the only one where the bug showed.
#
# The default therefore still holds for single-ISA builds at 87:
#   - the image runs from XIP (PQF_COPY_TO_RAM defaults OFF below),
#     freeing the ~204 KiB of SRAM the copied .text occupied;
#   - the core-1 sign runs on the mixed build's proven two-ended arena
#     (core1-riscv-blob/blob_alloc.c -- ISA-neutral, host-tested by
#     test/test_blob_alloc.c), reset before every sign;
#   - the openssl-mini TUs reach the allocator through one macro layer
#     (OPENSSL_malloc -> malloc, crypto.h), so compiling them with
#     -Dmalloc=pqf_sign_malloc (etc.) routes ALL crypto allocations
#     through src/core1_arena.c's dispatch: core 1 -> arena, core 0 ->
#     newlib (free/realloc route by pointer). The cores stop sharing an
#     allocator, which also removes the cross-core malloc race.
#   - PICO_MALLOC_PANIC=0: a genuine core-0 heap OOM must fail the op
#     cleanly (openssl-mini handles NULL) and report over CDC
#     (core1_arena.h diagnostics), not panic. The default panic was the
#     old failure mode: bkpt-with-no-debugger = the Arm login wedge;
#     ebreak-into-trap-handler = the RISC-V CTAP 0x7F.
# Levels 44/65 are untouched (copy_to_ram, plain newlib) -- both are
# silicon-validated and their sign peaks fit the newlib heap.
# ---------------------------------------------------------------------
if (NOT PQF_CORE1_RISCV AND PQF_HYBRID_VARIANT STREQUAL "87")
    # copy_to_ram used to disqualify the arena outright. That was correct
    # when the arena was 240 KiB -- a ~292 KiB copied image plus 240 KiB
    # left nothing for stacks in 520 KiB of SRAM. The arena is now 96 KiB
    # (measured high-water 42,712 B over four signs), so the pair fits
    # with roughly 132 KiB to spare and level 87 can have both the arena
    # and the ~2x SRAM speed path.
    set(PQF_SIGN_ARENA 1)
    if (PQF_COPY_TO_RAM)
        message(STATUS "Bruce: level-87 single-ISA -- sign arena ON, image runs from SRAM")
    else()
        message(STATUS "Bruce: level-87 single-ISA -- sign arena ON, image runs from XIP")
    endif()
    target_sources(bruce_c PRIVATE
        src/core1_arena.c
        core1-riscv-blob/blob_alloc.c
    )
    target_include_directories(bruce_c PRIVATE core1-riscv-blob)
    target_compile_definitions(bruce_c PRIVATE
        PQF_SIGN_ARENA=1
        PICO_MALLOC_PANIC=0
    )
    # Arena size. Empty means "use core1_arena.c's own default", which is
    # 240 KiB. That reservation is ~6x the measured high-water: a real
    # ML-DSA-87 hybrid GetAssertion peaks at 41,176 B on silicon (see the
    # header of core1_arena.c). Shrinking it frees SRAM and is likely
    # enough to let level 87 default to copy_to_ram, which measures about
    # twice as fast -- but getting an allocator reservation wrong presents
    # as a signature that never completes, so it wants a spare board.
    # This variable exists so that experiment needs no code edit:
    #   cmake -DPQF_SIGN_ARENA_BYTES=98304 ...      # 96 KiB, 2.3x headroom
    set(PQF_SIGN_ARENA_BYTES "" CACHE STRING
        "core-1 sign arena size in bytes (empty = core1_arena.c default, 240 KiB)")
    if (NOT PQF_SIGN_ARENA_BYTES STREQUAL "")
        target_compile_definitions(bruce_c PRIVATE
            PQF_SIGN_ARENA_BYTES=${PQF_SIGN_ARENA_BYTES})
        message(STATUS "Bruce: PQF_SIGN_ARENA_BYTES=${PQF_SIGN_ARENA_BYTES} "
                       "(default is 240 KiB; measured high-water 41,176 B)")
    endif()
    set_property(SOURCE
        ${OPENSSL_MINI_BN} ${OPENSSL_MINI_EC} ${OPENSSL_MINI_MLDSA}
        openssl-mini/src/sha256.c
        openssl-mini/src/sha512.c
        openssl-mini/src/aes_core.c
        openssl-mini/src/pqf_sha256.c
        openssl-mini/src/pqf_hmac_sha256.c
        openssl-mini/src/pqf_aes.c
        openssl-mini/src/pqf_evp.c
        openssl-mini/src/pqf_hkdf.c
        openssl-mini/src/sha3.c
        openssl-mini/src/keccak1600.c
        openssl-mini/src/packet.c
        openssl-mini/src/buffer.c
        APPEND PROPERTY COMPILE_OPTIONS
        "-Dmalloc=pqf_sign_malloc" "-Dfree=pqf_sign_free"
        "-Dcalloc=pqf_sign_calloc" "-Drealloc=pqf_sign_realloc"
    )
endif()

# The vendored OpenSSL EC sources use the deprecated-but-internal
# EC_KEY API and GNU asm rotates (sha512). Match the host test flags:
# silence deprecation, allow GNU extensions. Scope to this target.
target_compile_options(bruce_c PRIVATE
    -Wno-deprecated-declarations
)
set_source_files_properties(
    ${OPENSSL_MINI_BN} ${OPENSSL_MINI_EC}
    openssl-mini/src/sha256.c openssl-mini/src/sha512.c
    openssl-mini/src/sha3.c openssl-mini/src/keccak1600.c
    openssl-mini/src/packet.c openssl-mini/src/buffer.c
    ${OPENSSL_MINI_MLDSA}
    PROPERTIES COMPILE_FLAGS "-std=gnu11 -Wno-deprecated-declarations"
)

# pico_stdlib pulls clocks / GPIO / uart bring-up. tinyusb_device adds
# the USB device stack; tinyusb_board picks up `BOARD_TUD_RHPORT` (= 0
# on RP2350) and the IRQ wiring.
target_link_libraries(bruce_c PRIVATE
    pico_stdlib
    pico_rand        # get_rand_64() -- entropy for pqf_rand.c
    pico_multicore   # core-1 hybrid PQC signing worker
    hardware_flash   # flash_range_erase / flash_range_program (RAM-resident).
                     # NOT pico_flash: its flash_safe_execute / multicore_
                     # lockout hangs core 0 between the two Hazard3 (RISC-V)
                     # cores; we do our own M1 park in core1_signer.c
                     # (core1_run_flash_op). See core1_signer.h.
    tinyusb_device
    tinyusb_board
)

# Build-time guard (audit #24): the firmware reserves FOUR 4 KiB
# sectors at the very top of flash (store / resident / large-blob /
# key), plus PQF_RESIDENT_EXTRA_SECTORS overflow sectors below them.
# The pico-sdk default linker grows .text/.rodata upward with no
# check, so a large enough image could collide with those sectors and
# the first flash commit() would erase live code. Append a NON-replacing
# linker fragment (INSERT AFTER keeps the SDK's default script) that
# ASSERTs the linked image ends strictly below the first reserved
# sector. This mirrors the Rust port's memory.x reservation ASSERT, but
# reserves four sectors (the C port keeps them in four separate sectors;
# the Rust layout packs resident creds into the store sector and
# reserves three). The fragment is a template, filled in here with the
# sector count, so the guard grows with the store.
configure_file(${CMAKE_CURRENT_LIST_DIR}/flash_reserve_assert.ld
               ${CMAKE_CURRENT_BINARY_DIR}/flash_reserve_assert.ld @ONLY)
target_link_options(bruce_c PRIVATE
    "-Wl,-T,${CMAKE_CURRENT_BINARY_DIR}/flash_reserve_assert.ld"
)
# Re-link if the fragment changes.
set_target_properties(bruce_c PROPERTIES
    LINK_DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/flash_reserve_assert.ld"
)

# Mixed mode: cross-compile the RISC-V core-1 blob, embed it, and swap
# in the SRAM-carving linker script. (Guarded -- no effect on Arm-only
# or pure-RISC-V builds.)
if (PQF_CORE1_RISCV)
    set(PQF_BLOB_BIN "${CMAKE_CURRENT_BINARY_DIR}/core1_blob.bin")
    file(GLOB PQF_BLOB_DEPS
        ${CMAKE_CURRENT_LIST_DIR}/core1-riscv-blob/blob_main.c
        ${CMAKE_CURRENT_LIST_DIR}/core1-riscv-blob/blob_alloc.c
        ${CMAKE_CURRENT_LIST_DIR}/core1-riscv-blob/blob_alloc.h
        ${CMAKE_CURRENT_LIST_DIR}/core1-riscv-blob/blob_start.S
        ${CMAKE_CURRENT_LIST_DIR}/core1-riscv-blob/blob.ld
        # The blob cross-compiles the vendored crypto with its own GCC
        # invocation (build_blob.sh SRCS), so it must rebuild whenever
        # any of those sources or headers change.
        ${CMAKE_CURRENT_LIST_DIR}/openssl-mini/src/*.c
        ${CMAKE_CURRENT_LIST_DIR}/openssl-mini/src/bn/*.c
        ${CMAKE_CURRENT_LIST_DIR}/openssl-mini/src/ec/*.c
        ${CMAKE_CURRENT_LIST_DIR}/openssl-mini/src/ml_dsa/*.c
        ${CMAKE_CURRENT_LIST_DIR}/openssl-mini/src/ml_dsa/*.h
        ${CMAKE_CURRENT_LIST_DIR}/openssl-mini/include/*.h
        ${CMAKE_CURRENT_LIST_DIR}/src/pqf_align_str.c)
    # Blob placement. Standalone images pin the core-1 blob at 0x10180000,
    # which is 1.5 MiB up and therefore OUTSIDE the DFU app slot
    # (0x10021000..0x1010D000). A mixed-ISA image built with PQF_APP_OFFSET
    # used to fail to link outright ("section `.core1_blob' is not within
    # region `FLASH'", FLASH overflowed by 587468 bytes), which is why
    # mixed ISA could not be shipped over DFU at all.
    #
    # For a DFU build, move the blob INSIDE the slot. 0x100A0000 leaves
    # 508 KiB for core 0 (it uses ~206 KiB) and the 114 KiB blob then ends
    # at ~0x100BC700, comfortably below the slot end. The blob executes in
    # place, so its own blob.ld ORIGIN has to move in lockstep -- both
    # scripts are generated from the same value here.
    if (PQF_APP_OFFSET)
        set(PQF_BLOB_ORIGIN "0x100A0000")
    else()
        set(PQF_BLOB_ORIGIN "0x10180000")
    endif()
    message(STATUS "Bruce: core-1 blob pinned at ${PQF_BLOB_ORIGIN}")

    file(READ ${CMAKE_CURRENT_LIST_DIR}/memmap_core1riscv.ld _mm)
    string(REPLACE "0x10180000" "${PQF_BLOB_ORIGIN}" _mm "${_mm}")
    file(WRITE ${CMAKE_BINARY_DIR}/memmap_core1riscv_gen.ld "${_mm}")
    file(READ ${CMAKE_CURRENT_LIST_DIR}/core1-riscv-blob/blob.ld _bl)
    string(REPLACE "0x10180000" "${PQF_BLOB_ORIGIN}" _bl "${_bl}")
    file(WRITE ${CMAKE_BINARY_DIR}/blob_gen.ld "${_bl}")

    add_custom_command(
        OUTPUT ${PQF_BLOB_BIN}
        COMMAND ${CMAKE_COMMAND} -E env
                PQF_BLOB_LD=${CMAKE_BINARY_DIR}/blob_gen.ld
                ${CMAKE_CURRENT_LIST_DIR}/core1-riscv-blob/build_blob.sh
                ${PQF_RISCV_GCC} ${PQF_RISCV_OBJCOPY}
                ${CMAKE_CURRENT_LIST_DIR} ${PQF_BLOB_BIN}
                ${PQF_HYBRID_VARIANT} ${PQF_MLDSA_LOWMEM}
        DEPENDS ${PQF_BLOB_DEPS}
                ${CMAKE_BINARY_DIR}/blob_gen.ld
                ${CMAKE_CURRENT_LIST_DIR}/core1-riscv-blob/build_blob.sh
                ${CMAKE_CURRENT_LIST_DIR}/src/hybrid.c
                ${CMAKE_CURRENT_LIST_DIR}/src/hybrid.h
                ${CMAKE_CURRENT_LIST_DIR}/src/core1_mailbox.h
        COMMENT "Cross-compiling RISC-V core-1 signing blob (riscv32)"
        VERBATIM)
    add_custom_target(pqf_core1_blob DEPENDS ${PQF_BLOB_BIN})
    add_dependencies(bruce_c pqf_core1_blob)

    # core1_blob.S does `.incbin "core1_blob.bin"`: add the build dir to
    # the assembler include path, and re-assemble it when the blob changes.
    set_source_files_properties(src/core1_blob.S PROPERTIES
        COMPILE_OPTIONS "-I${CMAKE_CURRENT_BINARY_DIR}"
        OBJECT_DEPENDS "${PQF_BLOB_BIN}")

    target_compile_definitions(bruce_c PRIVATE PQF_CORE1_RISCV=1
        PQF_BLOB_FLASH_ORIGIN=${PQF_BLOB_ORIGIN}u)

    # Replace the SDK default linker script with the SRAM-carving,
    # blob-pinning variant. The flash_reserve_assert.ld fragment above is
    # `INSERT AFTER .text`, so it still composes on top of this script.
    pico_set_linker_script(bruce_c ${CMAKE_BINARY_DIR}/memmap_core1riscv_gen.ld)
    set_property(TARGET bruce_c APPEND PROPERTY
        LINK_DEPENDS "${CMAKE_BINARY_DIR}/memmap_core1riscv_gen.ld")
endif()

# We supply our own USB descriptors via TinyUSB, so pico-sdk's stdio
# USB CDC class can't coexist (it would clash on descriptors). Use the
# UART driver instead -- debug output during the bring-up window lands
# on UART0 if a serial cable is wired. Banner output for the user
# watching `screen /dev/cu.usbmodem*` flows through OUR CDC interface,
# managed directly in main.c (see `cdc_log()`).
pico_enable_stdio_usb(bruce_c 0)
pico_enable_stdio_uart(bruce_c 1)

# Run the whole image from SRAM. The crypto is instruction-light (~10 M
# instructions for a full hybrid MakeCredential) but on-silicon wall time
# from XIP flash is higher, because every instruction fetch that misses
# the RP2350's XIP cache (16 KiB, 8-byte lines, 2-way -- XIP_CTRL.SPLIT_WAYS
# is 0 at reset; setting it splits the cache into two 8 KiB direct-mapped
# halves instead) waits on QSPI.
#
# HISTORY, CORRECTED 2026-08-04. This comment used to claim XIP cost
# 15.2 s per MakeCredential versus ~1.0 s copied -- a ~17x gap -- and
# attributed it to the ~195 KiB image oversubscribing the cache 12x
# ("CPI ~200"). The 15.2 s was real but the explanation was not. The
# actual cause was flash_op_cb leaving QMI in slow single-bit 03h serial
# read mode after every flash write (and ctap2 writes the signature
# counter immediately before every sign), so the whole sign ran at
# ~0.9 MB/s. With that restored (see flash_store.c) the measured gap is:
#
#   level 65, XIP          MC 1.96 s / GA 1.36 s   (was ~13 s, host timed out)
#   level 65, copy_to_ram  MC 0.97 s / GA 0.70 s
#
# i.e. copy_to_ram is worth ~2x, not ~17x. Cache pressure is real but
# second-order -- measured hit rate on an XIP sign is ~98.4% either way
# (PQF_XIP_STATS). copy_to_ram is still the performance path; it just
# is not rescuing the image from a 12x thrash. Costs ~288 KiB of the
# 520 KiB SRAM.
#
# DEFAULT: ON for single-ISA builds at levels 44/65 (this is THE
# performance path), OFF for:
#   - the mixed Arm+RISC-V build -- the RISC-V blob owns the upper
#     256 KiB RAM window and the build needs its own custom linker
#     script, both incompatible with pico's copy_to_ram binary type;
#   - single-ISA builds at level 87 -- historically the ML-DSA-87 sign
#     needed a ~240 KiB arena (PQF_SIGN_ARENA above) that could not
#     coexist with the ~292 KiB copied image in 520 KiB of SRAM, so the
#     image ran from XIP instead. PQF_MLDSA_LOWMEM has since halved the
#     peak, so an EXPLICIT -DPQF_COPY_TO_RAM=1 at 87 is now accepted and
#     suppresses the arena; it is silicon-validated (0.67 s / 0.84 s) and
#     is the faster of the two, but the arena path remains the default
#     because it is the longer-standing configuration.
# Override with -DPQF_COPY_TO_RAM=0/1 (the impossible combinations are
# rejected below).
if (NOT DEFINED PQF_COPY_TO_RAM)
    if (PQF_CORE1_RISCV OR PQF_SIGN_ARENA)
        set(PQF_COPY_TO_RAM OFF)
    else()
        set(PQF_COPY_TO_RAM ON)
    endif()
endif()
if (PQF_COPY_TO_RAM AND PQF_CORE1_RISCV)
    message(FATAL_ERROR
        "PQF_COPY_TO_RAM is incompatible with the mixed build (PQF_CORE1_RISCV): "
        "the RISC-V blob owns the upper RAM window and the mixed linker script. "
        "The blob already runs its hot path from SRAM via memmap surgery instead.")
endif()
# copy_to_ram + PQF_APP_OFFSET: SUPPORTED (corrected 2026-08-20).
#
# This used to force copy_to_ram OFF, on the theory that the bootloader's
# in-place vector-table jump could not honour a picobin LOAD_MAP. That
# theory was wrong twice over. A pico-sdk copy_to_ram image carries NO
# LOAD_MAP -- inspect the block loop and it holds only IMAGE_TYPE -- and
# the flash->SRAM copy is done by crt0 itself from a table the linker
# emits (__ram_text_source__ / __ram_text_start__ / __ram_text_end__,
# see pico_crt0/crt0.S). The reset vector stays flash-resident, so an
# in-place jump enters that crt0 and the copy happens normally.
#
# The dark token that prompted the force-off was really the bootloader
# handing the app a core with PRIMASK still set, so the interrupt-driven
# USB never enumerated. That was fixed separately (msr MSP / cpsie i /
# bx) and this restriction was never revisited.
#
# Keeping copy_to_ram available over DFU matters: ML-DSA-87 runs about
# twice as fast from SRAM as from XIP.
if (PQF_COPY_TO_RAM AND PQF_SIGN_ARENA)
    # Size-aware rather than a blanket refusal. A ~292 KiB copied image
    # plus the arena plus stacks has to fit 520 KiB of SRAM; 160 KiB of
    # arena is the point where that stops being comfortable. The linker
    # is the real arbiter -- this just gives a readable error first.
    set(_pqf_arena_kib 96)
    if (NOT PQF_SIGN_ARENA_BYTES STREQUAL "")
        math(EXPR _pqf_arena_kib "${PQF_SIGN_ARENA_BYTES} / 1024")
    endif()
    if (_pqf_arena_kib GREATER 160)
        message(FATAL_ERROR
            "PQF_COPY_TO_RAM with a ${_pqf_arena_kib} KiB level-87 sign arena "
            "will not fit: the copied image (~292 KiB) + arena + stacks "
            "exceed the RP2350's 520 KiB SRAM. Shrink PQF_SIGN_ARENA_BYTES "
            "(96 KiB is validated, against a 42,712 B measured high-water) "
            "or drop -DPQF_COPY_TO_RAM=1.")
    else()
        message(STATUS "Bruce: level 87 copy_to_ram + ${_pqf_arena_kib} KiB "
                       "sign arena (~132 KiB SRAM spare)")
    endif()
endif()
if (PQF_COPY_TO_RAM)
    pico_set_binary_type(bruce_c copy_to_ram)
    message(STATUS "Bruce: copy_to_ram ON (image runs from SRAM -- the ~1s path)")
    if (PQF_HYBRID_VARIANT STREQUAL "87")
        message(STATUS
            "Bruce: level 87 + copy_to_ram -- the sign arena is enabled "
            "TOO (96 KiB). The older note here said this path falls back to "
            "plain newlib malloc; that was true while copy_to_ram "
            "disqualified the arena, which it no longer does. Standalone "
            "reference: MakeCredential 0.67 s, GetAssertion 0.84 s "
            "(Feitian, 2026-08-04).")
    endif()
endif()

# ---------------------------------------------------------------------
# PQF_HOT_IN_RAM -- hot ML-DSA code to SRAM on the builds that stay in XIP.
#
# copy_to_ram above is all-or-nothing and needs ~292 KiB of SRAM, which
# the level-87 arena build (and any -DPQF_COPY_TO_RAM=0) cannot spare.
# Those builds run from flash. The static argument for this option was
# that the ML-DSA/Keccak/SHA3 sign path is ~18 KiB of .text plus ~1.7
# KiB of .rodata -- small enough to fit the 16 KiB 2-way cache on its
# own -- so it must be losing to conflict evictions from the other ~175
# KiB of image, and moving just that set into SRAM for ~20 KiB of RAM
# would take the hot lines out of the contest.
#
# SILICON SAYS THAT ARGUMENT IS MOSTLY WRONG. Measured on the Feitian
# with PQF_XIP_STATS at level 65, XIP, one ML-DSA-65 sign:
#
#   PQF_HOT_IN_RAM=0   73.2 M accesses, 98.33% hit   MC 1.96 s / GA 1.36 s
#   PQF_HOT_IN_RAM=1   68.9 M accesses, 98.37% hit   MC 1.88 s / GA 1.32 s
#
# The hit rate was already ~98.4% without the option, so there was never
# much thrash to recover. Moving the hot set out of XIP removes ~30% of
# the ACCESSES, but those were overwhelmingly hits (cheap); the misses
# that cost the time are spread across the rest of the image. Net win is
# 3-4% of wall clock for ~20 KiB of SRAM.
#
# Kept ON by default anyway because on an XIP build that SRAM is idle
# and 4% is free -- but do not expect more, and do not reach for this
# when what you actually want is copy_to_ram (2x) or, if XIP is slow in
# the pathological way, the QMI fast-read restore in flash_store.c's
# flash_op_cb (10x -- see that comment).
#
# The mechanism is the mixed build's, generalised: memmap_hotram.ld is
# the SDK's memmap_default.ld with the hot objects EXCLUDE_FILE'd out of
# flash .text/.rodata so they fall through to the .data->RAM catch-all
# (crt0 copies them at boot with the rest of .data). Same surgery
# memmap_core1riscv.ld has been shipping since 2026-07-16, minus the
# RAM-window carve and the blob section; see that script's header for
# the silicon history and memmap_hotram.ld's for why its object list is
# one entry longer.
#
# DEFAULT: ON for single-ISA XIP builds -- level 87, and anything built
# -DPQF_COPY_TO_RAM=0. Forced OFF (and rejected if asked for
# explicitly) when there is nothing for it to do or another script owns
# the layout:
#   - PQF_COPY_TO_RAM -- every byte of .text is in SRAM already;
#   - PQF_CORE1_RISCV -- memmap_core1riscv.ld is already selected and
#     already carries the exclusion; only one linker script can win, so
#     this would silently drop the blob pinning and the RAM carve.
# Override with -DPQF_HOT_IN_RAM=0/1.
# ---------------------------------------------------------------------
if (NOT DEFINED PQF_HOT_IN_RAM)
    if (PQF_COPY_TO_RAM OR PQF_CORE1_RISCV)
        set(PQF_HOT_IN_RAM OFF)
    else()
        set(PQF_HOT_IN_RAM ON)
    endif()
endif()
if (PQF_HOT_IN_RAM AND PQF_COPY_TO_RAM)
    message(FATAL_ERROR
        "PQF_HOT_IN_RAM is redundant with PQF_COPY_TO_RAM: the copied image "
        "already executes entirely from SRAM. Drop -DPQF_HOT_IN_RAM=1.")
endif()
if (PQF_HOT_IN_RAM AND PQF_CORE1_RISCV)
    message(FATAL_ERROR
        "PQF_HOT_IN_RAM is incompatible with the mixed build (PQF_CORE1_RISCV): "
        "memmap_core1riscv.ld already applies the same exclusion, and it also "
        "carves the 128/384 KiB RAM split and pins the blob at 0x10180000 -- "
        "swapping in memmap_hotram.ld would lose both. Drop -DPQF_HOT_IN_RAM=1.")
endif()
if (PQF_HOT_IN_RAM)
    pico_set_linker_script(bruce_c ${CMAKE_CURRENT_LIST_DIR}/memmap_hotram.ld)
    set_property(TARGET bruce_c APPEND PROPERTY
        LINK_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/memmap_hotram.ld")
    message(STATUS "Bruce: PQF_HOT_IN_RAM -- ML-DSA/Keccak hot set linked into SRAM (XIP image)")
endif()

# ---------------------------------------------------------------------
# PQF_XIP_STATS -- XIP cache hit-rate readout around the hybrid sign.
#
# The RP2350 XIP block has two write-to-clear 32-bit saturating
# counters, XIP_CTR_HIT and XIP_CTR_ACC. -DPQF_XIP_STATS=ON clears them
# before each hybrid signature and reports hits/accesses/hit-rate over
# CDC afterwards (src/xip_stats.c, printed from main.c's loop like the
# level-87 arena high-water is). That is the instrument that says
# whether PQF_HOT_IN_RAM actually bought anything on silicon, rather
# than only on paper.
#
# OFF by default and zero-cost when off: xip_stats.c is not compiled and
# xip_stats.h's begin/end collapse to empty static inlines, so the sign
# path is byte-identical (verified by comparing the linked .text).
# ---------------------------------------------------------------------
option(PQF_XIP_STATS
    "Measure the XIP cache hit rate across each hybrid sign (CDC report)" OFF)
if (PQF_XIP_STATS)
    target_sources(bruce_c PRIVATE src/xip_stats.c)
    target_compile_definitions(bruce_c PRIVATE PQF_XIP_STATS=1)
    message(STATUS "Bruce: PQF_XIP_STATS -- XIP hit/access counters reported per hybrid sign")
endif()

# The firmware formats no floating point. Every snprintf() behind
# cdc_log() is %s/%u/%x/%02x/%lu; no format string in src/ or ../cbor/
# carries a %f, %e or %g. But pico_printf compiles its float and
# %e/%g conversions unconditionally, and those are the only reference
# left to the soft-float helpers. Turning both families off drops
# 3,166 B of .text: printf.c.o 5,864 -> 3,408, and pico_double's
# double_aeabi_dcp.S.o (710 B) falls out of the link entirely, since
# --gc-sections then has nothing pulling it in. (pico_float and the
# rest of pico_double were already contributing zero allocated bytes;
# only the aeabi doubles printf itself called were still linked.)
#
# These are pico_printf compile-time config macros, so a compile
# definition on this target is the right lever -- printf.c is an
# INTERFACE source of pico_printf_pico and so compiles inside
# bruce_c. pico_set_printf_implementation() is the wrong one: it
# swaps the whole implementation for the compiler's or for a stub.
# If a future banner ever needs %f, delete these two lines rather than
# working around them -- and note main.c's XIP hit-rate line does its
# percentage in integer basis points precisely because of this.
target_compile_definitions(bruce_c PRIVATE
    PICO_PRINTF_SUPPORT_FLOAT=0
    PICO_PRINTF_SUPPORT_EXPONENTIAL=0
)

# Produce a UF2 (and the .bin / .hex picotool helpers) alongside the
# default .elf. pico-sdk's hook also reports the final binary size
# from arm-none-eabi-size, which is what we want for tracking flash
# growth across phases.
pico_add_extra_outputs(bruce_c)
