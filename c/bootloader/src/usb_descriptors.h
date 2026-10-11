/* usb_descriptors.h -- DFU bootloader descriptor externs.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_BOOT_USB_DESCRIPTORS_H
#define PQF_BOOT_USB_DESCRIPTORS_H

/* Single DFU interface, one alt setting. Interface numbering is
 * trivial here; this header exists to mirror the firmware layout. */
#define BOOT_ITF_NUM_DFU     0
#define BOOT_ITF_NUM_TOTAL   1

#endif /* PQF_BOOT_USB_DESCRIPTORS_H */
