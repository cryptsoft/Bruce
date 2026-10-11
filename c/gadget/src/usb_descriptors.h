/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PQF_GADGET_USB_DESCRIPTORS_H
#define PQF_GADGET_USB_DESCRIPTORS_H

/* Derive the stable device identity (MAC + serial string) from the flash
 * unique ID. Must run before tusb_init() -- the descriptors reference both. */
void pqf_gadget_identity_init(void);

#endif /* PQF_GADGET_USB_DESCRIPTORS_H */
