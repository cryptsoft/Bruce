# Bruce -- USB DFU bootloader.
#
# A standalone pico-sdk project producing pqf_bootloader.uf2: the
# 128 KiB second-stage bootloader that owns the start of flash and
# updates the application slot over USB DFU 1.1 (stock dfu-util).
# See c/common/pqf_image.h for the flash map + signed-image format,
# and docs/DFU.md for the end-to-end flow.
#
# Quick start
# -----------
#   $ cmake -S c/bootloader -B c/bootloader/build \
#         -DPQF_BOARD=feitian_rp2350
#   $ cmake --build c/bootloader/build -j
#   # -> c/bootloader/build/pqf_bootloader.uf2  (flash via BOOTSEL once;
#   #   after that, apps update through the bootloader with dfu-util)
#
# The bootloader is Arm-Secure only (PQF_PLATFORM has no meaning
# here): rom_chain_image() launches Arm-S app images; pure-RISC-V app
# images stay on the BOOTSEL development flow for now -- and note that
# Secure boot's OTP SECURE_BOOT_ENABLE permanently disables the RISC-V cores
# anyway (RP2350 datasheet, OTP CRIT1).
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13)

set(PQF_BOARD "waveshare_rp2350_lcd_1_47" CACHE STRING
    "Target board: tiny2350 | xiao_rp2350 | feitian_rp2350 | waveshare_rp2350_lcd_1_47 | spotpear_rp2350_lcd_1_28")

# Board table -- mirrors c/firmware/CMakeLists.txt. PQF_BOARD_ID feeds
# the signed-image header's board check (pqf_image.h).
if (PQF_BOARD STREQUAL "tiny2350")
    set(PICO_BOARD pimoroni_tiny2350)
    set(PQF_BOARD_ID 1)
elseif (PQF_BOARD STREQUAL "xiao_rp2350")
    set(PICO_BOARD seeed_xiao_rp2350)
    set(PQF_BOARD_ID 2)
elseif (PQF_BOARD STREQUAL "feitian_rp2350")
    set(PICO_BOARD pico2)
    set(PQF_BOARD_ID 3)
elseif (PQF_BOARD STREQUAL "waveshare_rp2350_lcd_1_47")
    set(PICO_BOARD pico2)
    set(PQF_BOARD_ID 4)
elseif (PQF_BOARD STREQUAL "spotpear_rp2350_lcd_1_28")
    set(PICO_BOARD pico2)
    set(PQF_BOARD_ID 5)
else()
    message(FATAL_ERROR "Unknown PQF_BOARD '${PQF_BOARD}'")
endif()
message(STATUS "pqf-bootloader board: ${PQF_BOARD} (PICO_BOARD=${PICO_BOARD})")

# Refuse images whose fw_version is older than the installed app's.
# OFF by default: in production BOOTSEL is disabled (secure boot) and DFU is
# the ONLY update path, so this also blocks intentional downgrades.
option(PQF_BOOT_ANTI_ROLLBACK "Reject DFU images with a lower fw_version" OFF)

# Launch path. The default is the in-place vector-table jump for Arm
# apps and the block-loop annex + NORMAL|TO_RISCV reboot for RISC-V apps
# (built in, no option -- see try_boot_app and pqf_annex.ld). This option
# switches Arm launches to the bootrom's rom_chain_image() instead; it is
# instrumentation, not a shipping path: a chained window is always
# ATRANS-rolled to 0x10000000, which our identity-linked layout cannot
# satisfy (docs/RISCV-DFU-BOOTROM-ANALYSIS.md).
#
# The main.c #if for this existed long before the option did, so
# -DPQF_BOOT_LAUNCH_CHAIN=ON was silently a no-op and produced a
# byte-identical in-place build. Found 2026-08-20 by diffing the two
# binaries' sizes, not by the build failing -- it never fails.
option(PQF_BOOT_LAUNCH_CHAIN
    "Launch the app via the bootrom rom_chain_image() (instrumentation)" OFF)

# Pin the chain walk to ONE strategy so it always runs from a clean boot.
# Needed because rom_load_partition_table() caches in BOOTRAM across
# watchdog resets, so later strategies in a walk are contaminated.
set(PQF_CHAIN_ONLY "" CACHE STRING "Run only this chain strategy (0-3)")

include(${CMAKE_CURRENT_LIST_DIR}/../firmware/pico_sdk_import.cmake)

project(pqf_bootloader
    VERSION 0.1.0
    DESCRIPTION "USB DFU bootloader for the Bruce authenticator"
    LANGUAGES C CXX ASM
)

set(CMAKE_C_STANDARD 11)

pico_sdk_init()

# Cap the bootloader at its 128 KiB flash slot: rewrite the SDK's
# generated FLASH region (memmap_*.ld does `INCLUDE pico_flash_region.ld`
# out of CMAKE_BINARY_DIR -- see pico_standard_link/CMakeLists.txt) so
# the link ERRORS if the image outgrows the slot instead of silently
# overlapping the app. Must come after pico_sdk_init(), which writes
# the default (full-flash) version of this file earlier in the same
# configure pass.
file(WRITE ${CMAKE_BINARY_DIR}/pico_flash_region.ld
    "FLASH(rx) : ORIGIN = 0x10000000, LENGTH = 128k /* pqf bootloader slot (pqf_image.h) */\n")

# The block-loop annex: a supplement script pins the SDK's picobin end
# block at the slot's last sector (PQF_ANNEX_OFF), turning it into the
# sector the bootloader rewrites to launch RISC-V apps through the ROM.
# Also the effective code-size cap: content past ORIGIN+0x1F000 makes
# the link fail ("cannot move location counter backwards").
set(PQF_ANNEX_LD ${CMAKE_CURRENT_LIST_DIR}/pqf_annex.ld)

# Crypto: the same vendored openssl-mini the firmware uses, minus
# everything the verify path doesn't need (no ML-DSA, no AES, no
# SHA-3). BN + EC + SHA-256 gives pqf_ecdsa_p256_verify/pqf_sha256.
set(OPENSSL_MINI ${CMAKE_CURRENT_LIST_DIR}/../firmware/openssl-mini)
file(GLOB OPENSSL_MINI_BN ${OPENSSL_MINI}/src/bn/*.c)
file(GLOB OPENSSL_MINI_EC ${OPENSSL_MINI}/src/ec/*.c)

add_executable(pqf_bootloader
    src/main.c
    src/usb_descriptors.c

    # Signed-image verification -- the same TU the host tests compile.
    ../common/pqf_image_verify.c

    # Runtime BOOTSEL-button sampling (BSD-3-Clause, from pico-examples
    # via c/firmware -- see the header of the file / THIRD_PARTY.md).
    ../firmware/src/bootsel.c

    # RAND_* surface over pico_rand -- referenced by BN's rand/nonce
    # object code (only the never-called sign path actually draws
    # randomness, but the symbols must resolve).
    ../firmware/src/pqf_rand.c

    ${OPENSSL_MINI_BN}
    ${OPENSSL_MINI_EC}
    ${OPENSSL_MINI}/src/sha256.c
    ${OPENSSL_MINI}/src/pqf_sha256.c
    # BN's DSA-nonce helper (reached from the ECDSA object code even
    # though only verify runs) links against the EVP digest shims:
    ${OPENSSL_MINI}/src/pqf_evp.c
    ${OPENSSL_MINI}/src/sha512.c
    ${OPENSSL_MINI}/src/sha3.c
    ${OPENSSL_MINI}/src/keccak1600.c
)

target_include_directories(pqf_bootloader PRIVATE
    src
    ${CMAKE_CURRENT_LIST_DIR}          # tusb_config.h
    ../common                          # pqf_image.h
    ../firmware/src                    # bootsel.h
    ${OPENSSL_MINI}/include
    ${OPENSSL_MINI}/src
    ${OPENSSL_MINI}/src/bn
    ${OPENSSL_MINI}/src/ec
)

# DIAGNOSTIC (never ship): accept DFU blocks and discard them without
# touching flash. Splits a wedge in the flash path from one in the
# DFU/USB state machine. See docs/DFU.md.
option(PQF_DFU_WDSELFTEST "Self-test the flash watchdog + trace at boot (diagnostic)" OFF)
if (PQF_DFU_WDSELFTEST)
    target_compile_definitions(pqf_bootloader PRIVATE PQF_DFU_WDSELFTEST=1)
    message(STATUS "pqf-bootloader: PQF_DFU_WDSELFTEST -- boot self-test of the flash watchdog")
endif()
option(PQF_DFU_NOFLASH "DFU accepts and discards blocks (diagnostic)" OFF)
option(PQF_DFU_ERASEONLY "DFU erases sectors but never programs (diagnostic)" OFF)
if (PQF_DFU_ERASEONLY)
    target_compile_definitions(pqf_bootloader PRIVATE PQF_DFU_ERASEONLY=1)
    message(STATUS "pqf-bootloader: PQF_DFU_ERASEONLY -- erase only, no program")
endif()
if (PQF_DFU_NOFLASH)
    target_compile_definitions(pqf_bootloader PRIVATE PQF_DFU_NOFLASH=1)
    message(STATUS "pqf-bootloader: PQF_DFU_NOFLASH -- blocks discarded, NO flash writes")
endif()

# Production bootloader. src/main.c turns PQF_BOOT_PUBKEY_IS_DEV into a
# compile error under this define, so an image meant to ship cannot be
# built against the published development signing key by accident
# (docs/SECUREBOOT.md, "Production key ceremony", step 5).
option(PQF_PRODUCTION "Production bootloader: refuse the published dev signing key at compile time" OFF)
if (PQF_PRODUCTION)
    target_compile_definitions(pqf_bootloader PRIVATE PQF_PRODUCTION=1)
    message(STATUS "pqf-bootloader: PQF_PRODUCTION -- the dev signing key is refused at compile time")
endif()

# Optional picotool program URL (bi_program_url); empty = none.
set(PQF_PROGRAM_URL "" CACHE STRING "URL recorded in the picotool binary-info block (empty = none)")
if (PQF_PROGRAM_URL)
    target_compile_definitions(pqf_bootloader PRIVATE PQF_PROGRAM_URL="${PQF_PROGRAM_URL}")
endif()

target_compile_definitions(pqf_bootloader PRIVATE
    PQF_BOOT_BOARD_ID=${PQF_BOARD_ID}
)
target_link_options(pqf_bootloader PRIVATE "LINKER:-T${PQF_ANNEX_LD}")
set_property(TARGET pqf_bootloader APPEND PROPERTY LINK_DEPENDS ${PQF_ANNEX_LD})
if (PQF_BOOT_LAUNCH_CHAIN)
    target_compile_definitions(pqf_bootloader PRIVATE PQF_BOOT_LAUNCH_CHAIN=1)
    if (NOT PQF_CHAIN_ONLY STREQUAL "")
        target_compile_definitions(pqf_bootloader PRIVATE PQF_CHAIN_ONLY=${PQF_CHAIN_ONLY})
        message(STATUS "pqf-bootloader: PQF_CHAIN_ONLY=${PQF_CHAIN_ONLY} (single clean-boot strategy)")
    endif()
    message(STATUS "pqf-bootloader: PQF_BOOT_LAUNCH_CHAIN -- ROM-anchored chain launch")
endif()
if (PQF_BOOT_ANTI_ROLLBACK)
    target_compile_definitions(pqf_bootloader PRIVATE PQF_BOOT_ANTI_ROLLBACK=1)
    message(STATUS "pqf-bootloader: anti-rollback ON")
endif()

# DIAGNOSTIC (never ship): boot straight into DFU mode, skipping the
# boot-decision / rom_chain_image path -- see main.c PQF_BOOT_FORCE_DFU.
option(PQF_BOOT_FORCE_DFU "Diagnostic: always enter DFU mode at boot" OFF)
if (PQF_BOOT_FORCE_DFU)
    target_compile_definitions(pqf_bootloader PRIVATE PQF_BOOT_FORCE_DFU=1)
    message(WARNING "pqf-bootloader: PQF_BOOT_FORCE_DFU -- diagnostic build, always DFU")
endif()

target_compile_options(pqf_bootloader PRIVATE -Wno-deprecated-declarations)
set_source_files_properties(
    ${OPENSSL_MINI_BN} ${OPENSSL_MINI_EC}
    ${OPENSSL_MINI}/src/sha256.c
    PROPERTIES COMPILE_FLAGS "-std=gnu11 -Wno-deprecated-declarations"
)

target_link_libraries(pqf_bootloader PRIVATE
    pico_stdlib
    pico_bootrom       # rom_chain_image
    pico_rand          # get_rand_* behind pqf_rand.c
    hardware_flash     # flash_range_erase / flash_range_program
    tinyusb_device
    tinyusb_board
)

# No stdio at all -- the bootloader's UI is the LED and DFU status.
pico_enable_stdio_usb(pqf_bootloader 0)
pico_enable_stdio_uart(pqf_bootloader 0)

pico_add_extra_outputs(pqf_bootloader)
