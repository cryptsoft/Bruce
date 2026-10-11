# SPDX-License-Identifier: Apache-2.0
#
# pqf-gadget -- RP2350 USB *network* gadget (docs/NETWORK-GADGET.md).
#
# Enumerates as CDC-NCM ethernet so unmodified iPhones/Androids (and any
# desktop) get an IP link to the device with no drivers, no MFi: the phone
# DHCPs against us, discovers us over mDNS, and manages the device over
# ordinary TCP. This is the mobile-interfacing path for the Bruce token --
# iOS offers no raw-USB access, so CTAP HID alone can never reach an iPhone.
#
# Standalone bring-up target (plan phases 0-3). Once the descriptors are
# proven against iOS, the NCM function folds into the main c/firmware
# composite next to CTAP HID.
#
# Build:
#   $ export PICO_SDK_PATH=~/pico-sdk          # 2.x, with tinyusb + lwip submodules
#   $ cmake -S c/gadget -B c/gadget/build      # PICO_BOARD=pico2 default
#   $ cmake --build c/gadget/build -j
#   -> c/gadget/build/pqf_gadget.uf2
#
# Options:
#   -DPICO_BOARD=...              any RP2350 board pico-sdk knows
#                               (pico2, pimoroni_tiny2350, seeed_xiao_rp2350, ...)
#   -DPQF_GADGET_CONSOLE=OFF    drop the CDC-ACM debug console and ship the
#                               NCM-only descriptor set -- this is the image
#                               for iOS descriptor validation, per the plan's
#                               "start NCM-only" rule.

cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD "pico2" CACHE STRING "pico-sdk board (any RP2350 board)")
option(PQF_GADGET_CONSOLE "Include the CDC-ACM debug console function" ON)

# TEST-ONLY: <STX>BOOTSEL<ETX> on the debug console drops the device into
# BOOTSEL. This image has no CTAPHID and no picotool reset interface, so
# without it every reflash is a physical BOOT-hold + RESET -- which is
# most of why the network stack went five weeks compile-verified and
# never run. Requires the console, so an NCM-only image cannot carry it.
# Never ship it: it is an unauthenticated "erase yourself" command.
option(PQF_GADGET_CDC_BOOTSEL
       "CDC <STX>BOOTSEL<ETX> reflash escape (test only, never ship)" OFF)

include(pico_sdk_import.cmake)

project(pqf_gadget C CXX ASM)
set(CMAKE_C_STANDARD 11)

pico_sdk_init()

add_executable(pqf_gadget
    src/main.c
    src/usb_descriptors.c
    src/net_glue.c
    src/dhcp_server.c
    src/http_status.c
    # TinyUSB's NCM class driver is NOT part of pico-sdk's tinyusb_device
    # target -- compile it in explicitly. (net_device.h is the shared API;
    # this TinyUSB version has no net_device.c.)
    ${PICO_TINYUSB_PATH}/src/class/net/ncm_device.c
)

target_include_directories(pqf_gadget PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}          # tusb_config.h, lwipopts.h
    ${CMAKE_CURRENT_LIST_DIR}/src
)

target_compile_definitions(pqf_gadget PRIVATE
    PQF_GADGET_CONSOLE=$<BOOL:${PQF_GADGET_CONSOLE}>
    $<$<BOOL:${PQF_GADGET_CDC_BOOTSEL}>:PQF_GADGET_CDC_BOOTSEL=1>
)

target_link_libraries(pqf_gadget PRIVATE
    pico_stdlib
    pico_unique_id      # stable MAC + serial derived from the flash unique ID
    pico_rand           # LWIP_RAND for mDNS probe jitter
    tinyusb_device
    tinyusb_board
    pico_lwip           # core + ipv4
    pico_lwip_netif     # ethernet_input / etharp glue
    pico_lwip_nosys     # NO_SYS=1 single-loop integration
    pico_lwip_mdns      # Bonjour responder
)

pico_add_extra_outputs(pqf_gadget)   # .uf2 for BOOTSEL drag/picotool
