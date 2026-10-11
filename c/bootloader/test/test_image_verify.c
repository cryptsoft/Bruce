/* test_image_verify.c -- host-side tests for the bootloader's signed-
 * image verification (c/common/pqf_image_verify.c -- the exact TU the
 * bootloader links).
 *
 * Two modes:
 *   no arguments   self-contained unit test: generate a P-256 key,
 *                  build + sign a header in-process, then beat on
 *                  every rejection path (corrupt image, corrupt sig,
 *                  wrong key, wrong board, bad magic/length).
 *   3 arguments    interop check against the host signer:
 *                    test_image_verify <file.dfu> <pub_x_hex> <pub_y_hex>
 *                  verifies a tools/pqf_sign.py-produced image with
 *                  the C verifier (see the Makefile's `interop` rule).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqf_crypto.h"
#include "pqf_image.h"

static int failures;

#define CHECK(cond, name) do {                                        \
    if (cond) { printf("  ok: %s\n", name); }                         \
    else      { printf("  FAIL: %s\n", name); failures++; }           \
} while (0)

/* ---- helpers ------------------------------------------------------ */

static void build_header(pqf_image_hdr_t *hdr, const uint8_t *image,
                         uint32_t image_len, uint32_t fw_version,
                         uint32_t board_id, const uint8_t priv[32])
{
    memset(hdr, 0, sizeof *hdr);
    hdr->magic = PQF_IMAGE_MAGIC;
    hdr->header_version = PQF_IMAGE_HDR_VERSION;
    hdr->image_len = image_len;
    hdr->fw_version = fw_version;
    hdr->board_id = board_id;
    hdr->alg_mask = PQF_IMAGE_ALG_ECDSA_P256;
    pqf_sha256(image, image_len, hdr->image_sha256);

    uint8_t digest[32];
    pqf_sha256((const uint8_t *)hdr, PQF_IMAGE_SIGNED_LEN, digest);
    uint8_t sig[PQF_P256_MAX_SIG_DER];
    size_t sig_len = 0;
    if (pqf_ecdsa_p256_sign(priv, digest, sig, &sig_len) != 0) {
        fprintf(stderr, "sign failed\n");
        exit(1);
    }
    hdr->sig_len = (uint16_t)sig_len;
    memcpy(hdr->sig_der, sig, sig_len);
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t n)
{
    if (strlen(hex) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* ---- interop mode -------------------------------------------------- */

static int verify_file(const char *path, const char *xh, const char *yh)
{
    uint8_t pub_x[32], pub_y[32];
    if (hex_to_bytes(xh, pub_x, 32) || hex_to_bytes(yh, pub_y, 32)) {
        fprintf(stderr, "bad pubkey hex\n");
        return 1;
    }
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *blob = malloc((size_t)sz);
    if (fread(blob, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "short read\n");
        return 1;
    }
    fclose(f);

    if ((size_t)sz < PQF_IMAGE_HDR_SIZE + 1) {
        fprintf(stderr, "file too short\n");
        return 1;
    }
    const pqf_image_hdr_t *hdr = (const pqf_image_hdr_t *)blob;
    if (PQF_IMAGE_HDR_SIZE + (long)hdr->image_len > sz) {
        fprintf(stderr, "image_len exceeds the file\n");
        return 1;
    }
    pqf_img_result_t rc = pqf_image_verify(hdr, blob + PQF_IMAGE_HDR_SIZE,
                                           PQF_BOARD_ID_ANY, pub_x, pub_y);
    printf("%s: %s (rc=%d)\n", path,
           rc == PQF_IMG_OK ? "signature OK" : "REJECTED", rc);
    free(blob);
    return rc == PQF_IMG_OK ? 0 : 1;
}

/* ---- unit mode ------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc == 4)
        return verify_file(argv[1], argv[2], argv[3]);

    uint8_t priv[32], pub_x[32], pub_y[32];
    if (pqf_p256_keygen(priv, pub_x, pub_y) != 0) {
        fprintf(stderr, "keygen failed\n");
        return 1;
    }

    /* A deterministic pretend-firmware image. */
    static uint8_t image[8192 + 37];
    for (size_t i = 0; i < sizeof image; i++)
        image[i] = (uint8_t)(i * 7 + 13);

    pqf_image_hdr_t hdr;
    build_header(&hdr, image, sizeof image, 42,
                 PQF_BOARD_ID_FEITIAN_RP2350, priv);

    printf("--- positive ---\n");
    CHECK(pqf_image_verify(&hdr, image, PQF_BOARD_ID_FEITIAN_RP2350,
                           pub_x, pub_y) == PQF_IMG_OK,
          "valid image verifies (exact board)");
    pqf_image_hdr_t any = hdr;
    build_header(&any, image, sizeof image, 42, PQF_BOARD_ID_ANY, priv);
    CHECK(pqf_image_verify(&any, image, PQF_BOARD_ID_TINY2350,
                           pub_x, pub_y) == PQF_IMG_OK,
          "board_id ANY verifies on any board");

    printf("--- negative ---\n");
    uint8_t save = image[100];
    image[100] ^= 0x01;
    CHECK(pqf_image_verify(&hdr, image, PQF_BOARD_ID_FEITIAN_RP2350,
                           pub_x, pub_y) == PQF_IMG_BAD_HASH,
          "flipped image bit -> BAD_HASH");
    image[100] = save;

    pqf_image_hdr_t bad = hdr;
    bad.sig_der[10] ^= 0x01;
    CHECK(pqf_image_verify(&bad, image, PQF_BOARD_ID_FEITIAN_RP2350,
                           pub_x, pub_y) == PQF_IMG_BAD_SIG,
          "flipped signature bit -> BAD_SIG");

    bad = hdr;
    bad.fw_version++;   /* header content changed, signature stale */
    CHECK(pqf_image_verify(&bad, image, PQF_BOARD_ID_FEITIAN_RP2350,
                           pub_x, pub_y) == PQF_IMG_BAD_SIG,
          "tampered signed field -> BAD_SIG");

    uint8_t pub2_x[32], pub2_y[32], priv2[32];
    pqf_p256_keygen(priv2, pub2_x, pub2_y);
    CHECK(pqf_image_verify(&hdr, image, PQF_BOARD_ID_FEITIAN_RP2350,
                           pub2_x, pub2_y) == PQF_IMG_BAD_SIG,
          "image signed with a DIFFERENT key -> BAD_SIG");

    CHECK(pqf_image_verify(&hdr, image, PQF_BOARD_ID_XIAO_RP2350,
                           pub_x, pub_y) == PQF_IMG_WRONG_BOARD,
          "board_id mismatch -> WRONG_BOARD");

    bad = hdr;
    bad.magic ^= 1;
    CHECK(pqf_image_verify(&bad, image, PQF_BOARD_ID_FEITIAN_RP2350,
                           pub_x, pub_y) == PQF_IMG_BAD_FORMAT,
          "bad magic -> BAD_FORMAT");

    bad = hdr;
    bad.header_version = 99;
    CHECK(pqf_image_check_format(&bad) == PQF_IMG_BAD_FORMAT,
          "unknown header version -> BAD_FORMAT");

    bad = hdr;
    bad.image_len = PQF_IMAGE_MAX_LEN + 1;
    CHECK(pqf_image_check_format(&bad) == PQF_IMG_BAD_FORMAT,
          "oversize image_len -> BAD_FORMAT");

    bad = hdr;
    bad.sig_len = sizeof(bad.sig_der) + 1;
    CHECK(pqf_image_check_format(&bad) == PQF_IMG_BAD_FORMAT,
          "oversize sig_len -> BAD_FORMAT");

    bad = hdr;
    bad.alg_mask = 0;
    CHECK(pqf_image_check_format(&bad) == PQF_IMG_BAD_FORMAT,
          "no ECDSA alg bit -> BAD_FORMAT");

    printf(failures ? "\n%d FAILURE(S)\n" : "\nall passed\n", failures);
    return failures ? 1 : 0;
}
