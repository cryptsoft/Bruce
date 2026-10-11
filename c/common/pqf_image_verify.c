/* pqf_image_verify.c -- signed-image verification.
 *
 * One translation unit shared verbatim between the DFU bootloader and
 * the host-side test harness, so the exact code that gates a firmware
 * install is the code the negative tests beat on. Crypto comes from
 * the vendored openssl-mini (pqf_crypto.h): SHA-256 for the image
 * digest, ECDSA-P256 (DER) for the header signature.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "pqf_crypto.h"
#include "pqf_image.h"

pqf_img_result_t pqf_image_check_format(const pqf_image_hdr_t *hdr)
{
    if (hdr->magic != PQF_IMAGE_MAGIC)
        return PQF_IMG_BAD_FORMAT;
    if (hdr->header_version != PQF_IMAGE_HDR_VERSION)
        return PQF_IMG_BAD_FORMAT;
    if (hdr->image_len == 0 || hdr->image_len > PQF_IMAGE_MAX_LEN)
        return PQF_IMG_BAD_FORMAT;
    if (!(hdr->alg_mask & PQF_IMAGE_ALG_ECDSA_P256))
        return PQF_IMG_BAD_FORMAT;
    if (hdr->sig_len == 0 || hdr->sig_len > sizeof(hdr->sig_der))
        return PQF_IMG_BAD_FORMAT;
    return PQF_IMG_OK;
}

pqf_img_result_t pqf_image_verify(const pqf_image_hdr_t *hdr,
                                  const uint8_t *image,
                                  uint32_t board_id,
                                  const uint8_t pub_x[32],
                                  const uint8_t pub_y[32])
{
    pqf_img_result_t rc = pqf_image_check_format(hdr);
    if (rc != PQF_IMG_OK)
        return rc;

    if (hdr->board_id != PQF_BOARD_ID_ANY && hdr->board_id != board_id)
        return PQF_IMG_WRONG_BOARD;

    /* Image digest must match the one pinned in the signed region. */
    uint8_t digest[32];
    pqf_sha256(image, hdr->image_len, digest);
    if (memcmp(digest, hdr->image_sha256, sizeof(digest)) != 0)
        return PQF_IMG_BAD_HASH;

    /* ECDSA-P256 over SHA-256 of the signed region (header[0:64]). */
    pqf_sha256((const uint8_t *)hdr, PQF_IMAGE_SIGNED_LEN, digest);
    if (pqf_ecdsa_p256_verify(pub_x, pub_y, digest,
                              hdr->sig_der, hdr->sig_len) != 1)
        return PQF_IMG_BAD_SIG;

    return PQF_IMG_OK;
}
