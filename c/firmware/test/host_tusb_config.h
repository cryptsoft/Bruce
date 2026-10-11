/* Host TinyUSB config for the descriptor test.
 *
 * A copy of ../tusb_config.h with one change: CFG_TUSB_OS is OPT_OS_NONE
 * instead of OPT_OS_PICO, because the Pico OSAL pulls in pico/sem.h and
 * the rest of the SDK. Nothing in the descriptor path uses the OSAL --
 * the descriptors are static data and three callbacks -- so this only
 * has to make the headers resolve.
 *
 * The values that DO matter are mirrored exactly, because the
 * descriptor macros compute lengths from them: change one here without
 * changing it there and the test would validate a descriptor the
 * firmware never emits.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQF_HOST_TUSB_CONFIG_H
#define PQF_HOST_TUSB_CONFIG_H

#define CFG_TUSB_MCU                OPT_MCU_NONE
#define CFG_TUSB_OS                 OPT_OS_NONE
#define CFG_TUD_ENABLED             1
#define CFG_TUD_ENDPOINT0_SIZE      64

#ifdef PQF_GDB_STUB
#define CFG_TUD_CDC                 2
#else
#define CFG_TUD_CDC                 1
#endif
#define CFG_TUD_HID                 1
#define CFG_TUD_MSC                 0
#define CFG_TUD_MIDI                0
#define CFG_TUD_VENDOR              0
#define CFG_TUD_CDC_RX_BUFSIZE      64
#define CFG_TUD_CDC_TX_BUFSIZE      64
#define CFG_TUD_HID_EP_BUFSIZE      64
#ifdef PQF_DFU_RUNTIME
#define CFG_TUD_DFU_RUNTIME         1
#endif

#endif
