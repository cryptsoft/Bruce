/* SPDX-License-Identifier: Apache-2.0
 *
 * TinyUSB configuration for the pqf-gadget USB network device.
 *
 * Primary function: CDC-NCM (CFG_TUD_NCM) -- what iOS and modern hosts
 * enumerate natively; RNDIS is deliberately absent (Android deprecating,
 * iOS never supported). CDC-ACM debug console rides alongside unless the
 * build sets PQF_GADGET_CONSOLE=0 (the NCM-only iOS-validation image).
 * ECM fallback is a planned second configuration once NCM is proven
 * (docs/NETWORK-GADGET.md sec. 2).
 */

#ifndef PQF_GADGET_TUSB_CONFIG_H
#define PQF_GADGET_TUSB_CONFIG_H

/* RP2350's USB controller uses the RP2040-family TinyUSB port. */
#define CFG_TUSB_MCU                OPT_MCU_RP2040
#define CFG_TUSB_OS                 OPT_OS_PICO
#define CFG_TUSB_RHPORT0_MODE       (OPT_MODE_DEVICE | OPT_MODE_DEFAULT_SPEED)

#define CFG_TUD_ENABLED             1
#define CFG_TUD_ENDPOINT0_SIZE      64

/* ---- Class functions ---- */

/* CDC-NCM network gadget (the whole point). */
#define CFG_TUD_NCM                 1
#define CFG_TUD_ECM_RNDIS           0

/* CDC-ACM debug console -- compiled out for the NCM-only descriptor image. */
#ifndef PQF_GADGET_CONSOLE
#define PQF_GADGET_CONSOLE          1
#endif
#define CFG_TUD_CDC                 PQF_GADGET_CONSOLE

#define CFG_TUD_HID                 0
#define CFG_TUD_MSC                 0
#define CFG_TUD_MIDI                0
#define CFG_TUD_VENDOR              0

/* ---- Buffers ---- */

/* Endpoint size comes from the driver header (64 at full speed -- the
 * ~5-8 Mbit/s effective ceiling is an accepted management-channel
 * constraint, plan sec. 3.3 / risks table). Do not define it here:
 * net_device.h defines it unconditionally. */

/* Standard ethernet MTU + header; lwIP's netif->mtu is set from this. */
#define CFG_TUD_NET_MTU             1514

#define CFG_TUD_CDC_RX_BUFSIZE      64
#define CFG_TUD_CDC_TX_BUFSIZE      256

#endif /* PQF_GADGET_TUSB_CONFIG_H */
