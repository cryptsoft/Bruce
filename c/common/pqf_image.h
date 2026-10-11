/* pqf_image.h -- signed firmware image format + DFU flash map.
 *
 * Shared by three consumers, so keep it dependency-free:
 *   - the DFU bootloader   (c/bootloader/)  -- verifies + installs images
 *   - the application      (c/firmware/)    -- linked at PQF_APP_IMAGE_OFF
 *   - host-side tests      (c/bootloader/test/) -- verify logic on the host
 * The host signing tool (tools/pqf_sign.py) mirrors the header layout;
 * change either side only in lockstep.
 *
 * ## Flash map (offsets from flash base, 4 MiB baseline)
 *
 *   0x000000  128 KiB  DFU bootloader (this is what the bootrom boots)
 *   0x020000    4 KiB  app slot: signed-image header sector
 *   0x021000  1.87 MiB app slot: application image (XIP at 0x10021000)
 *   0x200000    4 KiB  staging slot: header sector   (DFU writes here)
 *   0x201000  1.87 MiB staging slot: image
 *   0x3E0000    4 KiB  boot-state sector (install journal, power-loss safe)
 *   0x3E1000  108 KiB  spare
 *   0x3FC000   16 KiB  persisted sectors (master keys / large blobs /
 *                      resident creds / store) -- same location as the
 *                      pre-bootloader layout, so credentials survive the
 *                      migration to DFU updates.
 *
 * The staging slot mirrors the app slot byte-for-byte: a DFU download
 * streams (header sector || image) into staging; after signature
 * verification the bootloader copies it over the app slot. The old app
 * keeps working if a download is interrupted or fails verification.
 *
 * ## Signed image header (one 4 KiB flash sector, 256 bytes used)
 *
 *   off len  field
 *     0   4  magic "PQFW" (LE 0x57464250? see PQF_IMAGE_MAGIC)
 *     4   4  header_version (1)
 *     8   4  image_len          -- bytes of image following this sector
 *    12   4  fw_version         -- monotonic build number (rollback gate)
 *    16   4  board_id           -- 0 = any board (see PQF_BOARD_ID_*)
 *    20   4  alg_mask           -- bit 0: ECDSA-P256/SHA-256 present
 *    24   8  reserved (0)
 *    32  32  SHA-256(image)
 *    ---- bytes [0, 64) are the SIGNED REGION ----
 *    64   2  sig_len (LE)       -- DER ECDSA signature length
 *    66  ..  DER signature (<= PQF_P256_MAX_SIG_DER), zero-padded
 *   256+     0xFF padding to the sector end
 *
 * The signature is ECDSA-P256 over SHA-256(header[0:64]); the header in
 * turn pins SHA-256 of the image, so the whole file is covered. alg_mask
 * leaves room to append a post-quantum signature section in a later
 * header_version without breaking v1 verifiers.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_IMAGE_H
#define PQF_IMAGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ---- Flash map -------------------------------------------------- *
 *
 * EVERY offset here is derived from PQF_FLASH_SIZE, and that value must
 * be the size of the flash die that is actually fitted. This is not
 * pedantry -- getting it wrong does not overflow, it ALIASES, silently.
 *
 * The Feitian RP2350 carries a 2 MiB device, but its pico-sdk board
 * header (pico2.h) declares PICO_FLASH_SIZE_BYTES = 4 MiB. The old map
 * here trusted that and put the DFU staging slot at 0x200000 -- exactly
 * 2 MiB -- so the first sector a DFU download wrote wrapped to 0x000000
 * and erased the bootloader's own vector table underneath itself. The
 * download died at block 0 with the token unable to answer EP0, and no
 * amount of watchdog could help, because the code doing the recovering
 * was the code being erased.
 *
 * It hid for a long time because a wrap is consistent: the firmware's
 * credential store at 0x3FC000 also wraps, to 0x1FC000, and reads wrap
 * with it. Credentials persist, survive reboots and read back correctly
 * -- while living 2 MiB from where every constant says they are. That
 * apparent success was used as evidence AGAINST a 2 MiB device more
 * than once. Proven by writing a pattern at 0x200000 and reading it
 * back at 0x000000 (2026-08-18).
 *
 * The layout is now computed, not hand-placed, so a different die size
 * moves everything consistently instead of aliasing:
 *
 *   0x000000  bootloader            PQF_BOOT_SIZE (annex = its last sector)
 *   0x01F000  block-loop annex      one sector, inside PQF_BOOT_SIZE
 *   0x020000  app slot              PQF_SLOT_SIZE
 *   0x10D000  staging slot          PQF_SLOT_SIZE
 *   0x1FA000  boot state            one sector
 *   0x1FC000  persisted credentials four sectors, never erased here
 */

/* Size of the flash die actually fitted. NOT PICO_FLASH_SIZE_BYTES,
 * which the board header overstates on this hardware. */
#ifndef PQF_FLASH_SIZE
#define PQF_FLASH_SIZE          0x200000u   /* 2 MiB (Feitian RP2350) */
#endif

#define PQF_BOOT_SIZE           0x020000u   /* 128 KiB bootloader     */
#define PQF_IMAGE_HDR_SIZE      0x001000u   /* one flash sector       */
#define PQF_BOOT_STATE_SIZE     0x001000u   /* install journal sector */

/* The four persisted top-of-flash sectors. The bootloader must never
 * erase at or above this offset. */
#define PQF_PERSIST_OFF         (PQF_FLASH_SIZE - 4u * 4096u)

/* Two equal slots in whatever is left, rounded down to a sector. */
#define PQF_SLOT_SIZE           (((PQF_PERSIST_OFF - PQF_BOOT_SIZE \
                                   - PQF_BOOT_STATE_SIZE) / 2u) & ~0xFFFu)

/* The block-loop annex: the last sector of the bootloader region. The
 * bootloader's slot-0 picobin block loop runs through it (its linker
 * script pins the SDK's embedded end block here -- pqf_annex.ld, which
 * hardcodes the same value), and the bootloader rewrites it at boot to
 * carry the installed RISC-V app's IMAGE_DEF so the bootrom's own scan
 * can launch that app after an architecture-switch reboot. */
#define PQF_ANNEX_OFF           (PQF_BOOT_SIZE - 0x1000u)

#define PQF_APP_SLOT_OFF        PQF_BOOT_SIZE
#define PQF_APP_IMAGE_OFF       (PQF_APP_SLOT_OFF + PQF_IMAGE_HDR_SIZE)
#define PQF_STAGE_SLOT_OFF      (PQF_APP_SLOT_OFF + PQF_SLOT_SIZE)
#define PQF_STAGE_IMAGE_OFF     (PQF_STAGE_SLOT_OFF + PQF_IMAGE_HDR_SIZE)
#define PQF_BOOT_STATE_OFF      (PQF_STAGE_SLOT_OFF + PQF_SLOT_SIZE)

#define PQF_IMAGE_MAX_LEN       (PQF_SLOT_SIZE - PQF_IMAGE_HDR_SIZE)

/* Compile-time layout sanity (evaluated wherever this header lands). */
_Static_assert(PQF_BOOT_STATE_OFF + PQF_BOOT_STATE_SIZE <= PQF_PERSIST_OFF,
               "DFU flash map collides with the persisted sectors");
_Static_assert((PQF_APP_SLOT_OFF % 4096u) == 0 && (PQF_STAGE_SLOT_OFF % 4096u) == 0
               && (PQF_BOOT_STATE_OFF % 4096u) == 0,
               "DFU flash map offsets must be sector-aligned");
/* The one that would have caught this bug at compile time: nothing the
 * bootloader addresses may sit at or past the end of the real die. */
_Static_assert(PQF_BOOT_STATE_OFF + PQF_BOOT_STATE_SIZE <= PQF_FLASH_SIZE
               && PQF_PERSIST_OFF < PQF_FLASH_SIZE,
               "DFU flash map runs past the end of the flash device -- "
               "offsets past PQF_FLASH_SIZE do not fail, they ALIAS");
_Static_assert(PQF_SLOT_SIZE >= 0x40000u,
               "slot too small to hold a firmware image");

/* ---- Signed image header ---------------------------------------- */

#define PQF_IMAGE_MAGIC         0x57465150u  /* "PQFW" little-endian   */
#define PQF_IMAGE_HDR_VERSION   1u
#define PQF_IMAGE_SIGNED_LEN    64u          /* bytes covered by sig   */
#define PQF_IMAGE_ALG_ECDSA_P256 (1u << 0)

/* board_id values. 0 accepts any board; per-board ids let a production
 * profile refuse an image built for different hardware. */
#define PQF_BOARD_ID_ANY            0u
#define PQF_BOARD_ID_TINY2350       1u
#define PQF_BOARD_ID_XIAO_RP2350    2u
#define PQF_BOARD_ID_FEITIAN_RP2350 3u
#define PQF_BOARD_ID_WAVESHARE_147  4u
#define PQF_BOARD_ID_SPOTPEAR_128   5u

typedef struct {
    uint32_t magic;
    uint32_t header_version;
    uint32_t image_len;
    uint32_t fw_version;
    uint32_t board_id;
    uint32_t alg_mask;
    uint8_t  reserved0[8];
    uint8_t  image_sha256[32];
    /* ---- end of signed region (PQF_IMAGE_SIGNED_LEN bytes) ---- */
    uint16_t sig_len;
    uint8_t  sig_der[190];       /* DER ECDSA <= 72; rest is headroom  */
} pqf_image_hdr_t;

_Static_assert(sizeof(pqf_image_hdr_t) == 256, "header must be 256 bytes");
_Static_assert(offsetof(pqf_image_hdr_t, sig_len) == PQF_IMAGE_SIGNED_LEN,
               "signed region must end exactly at sig_len");

/* ---- Verification ------------------------------------------------ */

/* Result codes map 1:1 onto the DFU status the bootloader reports. */
typedef enum {
    PQF_IMG_OK           = 0,
    PQF_IMG_BAD_FORMAT   = -1,  /* magic/version/length nonsense      */
    PQF_IMG_BAD_HASH     = -2,  /* image SHA-256 mismatch             */
    PQF_IMG_BAD_SIG      = -3,  /* ECDSA verification failed          */
    PQF_IMG_WRONG_BOARD  = -4,  /* board_id mismatch                  */
    PQF_IMG_ROLLBACK     = -5,  /* fw_version older than installed    */
} pqf_img_result_t;

/* Verify a signed image: `hdr` is the 256-byte header, `image` points
 * at `hdr->image_len` bytes of firmware (typically an XIP address on
 * device, a file buffer on the host). `board_id` is the verifier's own
 * id (headers with board_id 0 always match). Uses SHA-256 + ECDSA from
 * openssl-mini (pqf_crypto.h) with the public key given as affine X/Y.
 * Does NOT enforce rollback (callers compare fw_version themselves --
 * only the DFU accept path gates on it, never boot). */
pqf_img_result_t pqf_image_verify(const pqf_image_hdr_t *hdr,
                                  const uint8_t *image,
                                  uint32_t board_id,
                                  const uint8_t pub_x[32],
                                  const uint8_t pub_y[32]);

/* Format-only checks (magic / version / image_len bounds), no crypto.
 * Cheap enough for the DFU download path's first-block sanity gate. */
pqf_img_result_t pqf_image_check_format(const pqf_image_hdr_t *hdr);

#endif /* PQF_IMAGE_H */
