#!/usr/bin/env python3
# annex_check.py -- walk a composed flash image the way the RP2350 boot
# ROM does, and prove the block-loop annex resolves correctly for BOTH
# architectures BEFORE anything is flashed.
#
# The bootloader launches RISC-V apps by copying the app's picobin
# IMAGE_DEF block into the annex sector (the last bootloader sector,
# PQF_ANNEX_OFF) and rebooting NORMAL|TO_RISCV; the ROM's own slot-0
# scan then finds a right-CPU IMAGE_DEF and boots the app identity-
# mapped. A malformed loop would instead invalidate slot 0 entirely and
# drop the token to BOOTSEL -- which is exactly why this check exists:
# it replays the ROM's block scan (pico-bootrom-rp2350 varm_blocks.c
# s_varm_crit_next_block) and its image selection
# (varm_flash_boot.c s_varm_crit_prefer_new_image_def) over the same
# bytes picotool would flash, including the bootloader's annex rewrite,
# and fails loudly on anything the ROM would reject.
#
#   tools/annex_check.py --bootloader build-bl/pqf_bootloader.bin \
#       --app build-fw-riscv/bruce_c.bin
#
# Checks, in order:
#   1. fresh state (annex = IGNORED placeholder): loop closes, the Arm
#      side selects the bootloader, the RISC-V side finds no right-CPU
#      image (it would launch the bootloader and auto-switch back -- the
#      recoverable bounce, not a brick);
#   2. the annex rewrite the bootloader would perform: app block found,
#      transplantable, fits the ROM's block-size cap;
#   3. post-sync state: loop still closes, Arm still selects the
#      bootloader, RISC-V selects the app's IMAGE_DEF, whose entry point
#      lies inside the app image and whose launch rolls nothing.
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import struct
import sys

MARKER_START = 0xFFFFDED3
MARKER_END   = 0xAB123579

ITEM_IMAGE_TYPE   = 0x42
ITEM_VECTOR_TABLE = 0x03
ITEM_ENTRY_POINT  = 0x44
ITEM_ROLLING      = 0x05
ITEM_LOAD_MAP     = 0x06
ITEM_VERSION      = 0x48
ITEM_HASH_DEF     = 0x47
ITEM_IGNORED      = 0xFE
ITEM_LAST         = 0xFF

MAX_BLOCK_WORDS   = 0x280 // 4       # PICOBIN_MAX_BLOCK_SIZE
SEARCH_WORDS      = 0x1000 // 4      # BLOCK_LIST_SEARCH_MAX

XIP_BASE      = 0x10000000
BOOT_SIZE     = 0x20000
ANNEX_OFF     = BOOT_SIZE - 0x1000   # PQF_ANNEX_OFF
APP_SLOT_OFF  = BOOT_SIZE
APP_IMAGE_OFF = APP_SLOT_OFF + 0x1000

CPU_NAMES = {0: "arm", 1: "riscv"}


def w32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def item_size_words(item):
    # type bit 7 selects the 8-bit (1BS) vs 16-bit (2BS) word count
    return (item >> 8) & (0xFFFF if item & 0x80 else 0xFF)


class Block:
    def __init__(self, off):
        self.off = off           # flash offset of the start marker
        self.words = None        # marker..LAST inclusive
        self.link = None         # signed bytes to next block start
        self.items = []          # (type, [words])
        self.cpu = None
        self.exe = False
        self.entry = None        # (pc, sp)
        self.rolling = None
        self.bad = []            # transplant blockers


def parse_block(img, off):
    """ROM-faithful: items to a LAST whose size equals the preceding
    words, end marker two words on. Returns Block or None."""
    if w32(img, off) != MARKER_START:
        return None
    b = Block(off)
    pos = 1
    while pos + 2 < MAX_BLOCK_WORDS and off + 4 * (pos + 2) + 4 <= len(img):
        item = w32(img, off + 4 * pos)
        typ = item & 0xFF
        size = item_size_words(item)
        if size == 0:
            return None
        if typ == ITEM_LAST:
            if size != pos - 1:
                return None
            if w32(img, off + 4 * (pos + 2)) != MARKER_END:
                return None
            b.words = pos + 1
            b.link = struct.unpack_from("<i", img, off + 4 * (pos + 1))[0]
            return b
        payload = [w32(img, off + 4 * (pos + k)) for k in range(size)]
        b.items.append((typ, payload))
        if typ == ITEM_IMAGE_TYPE:
            b.cpu = (item >> 24) & 7
            b.exe = ((item >> 16) & 0xF) == 1
        elif typ == ITEM_ENTRY_POINT and size >= 3:
            b.entry = (payload[1], payload[2])
        elif typ == ITEM_ROLLING:
            b.rolling = struct.unpack_from("<i", img, off + 4 * (pos + 1))[0]
            b.bad.append("ROLLING_WINDOW_DELTA")
        elif typ == ITEM_LOAD_MAP:
            if (item & 0x80000000) == 0:
                b.bad.append("relative LOAD_MAP")
        elif typ in (ITEM_VECTOR_TABLE, ITEM_VERSION, ITEM_IGNORED):
            pass
        else:
            b.bad.append("item 0x%02x" % typ)
        pos += size
    return None


def walk_loop(img, window_off=0):
    """The ROM's scan: hunt the first valid block in the window's first
    4 KiB (walking past false markers), then follow links; the loop must
    return exactly to the first block. Returns the block list."""
    first = None
    for i in range(SEARCH_WORDS):
        off = window_off + 4 * i
        if w32(img, off) != MARKER_START:
            continue
        first = parse_block(img, off)
        if first:
            break
    if not first:
        raise SystemExit("FAIL: no valid block in the first 4 KiB "
                         "(the ROM would fall through to BOOTSEL)")
    blocks = [first]
    cur = first
    while True:
        if len(blocks) > 256:
            raise SystemExit("FAIL: block loop does not terminate")
        if cur.link == 0:
            if cur is first:
                break                      # single-block loop
            raise SystemExit("FAIL: non-first block loops to itself")
        nxt = cur.off + cur.link
        if nxt == first.off:
            break                          # loop closed
        if nxt < first.off:
            raise SystemExit("FAIL: link goes below the first block "
                             "(0x%x -> 0x%x)" % (cur.off, nxt))
        if nxt & 3 or nxt + 4 > len(img):
            raise SystemExit("FAIL: link leaves the image (0x%x -> 0x%x)"
                             % (cur.off, nxt))
        b = parse_block(img, nxt)
        if not b:
            raise SystemExit("FAIL: linked block at 0x%x is invalid -- "
                             "the WHOLE loop is dead, bootloader "
                             "unbootable" % nxt)
        blocks.append(b)
        cur = b
    return blocks


def select_image(blocks, boot_cpu):
    """varm_flash_boot.c s_varm_crit_prefer_new_image_def: keep the
    first executable IMAGE_DEF; a later one replaces it unless it has
    the wrong CPU while the incumbent has the right one."""
    best = None
    for b in blocks:
        if b.cpu is None or not b.exe:
            continue
        if best is not None and b.cpu != boot_cpu and best.cpu == boot_cpu:
            continue
        best = b
    return best


def sync_annex(img, app_block):
    """The bootloader's annex_sync(), replayed: app block verbatim
    through LAST, then our loop-closing link + end marker."""
    first = walk_loop(img)[0]
    words = [w32(img, app_block.off + 4 * i) for i in range(app_block.words)]
    words.append((first.off - ANNEX_OFF) & 0xFFFFFFFF)
    words.append(MARKER_END)
    if len(words) > MAX_BLOCK_WORDS + 2:
        raise SystemExit("FAIL: annex block exceeds the ROM's 0x280 cap")
    img[ANNEX_OFF:ANNEX_OFF + 0x1000] = (
        struct.pack("<%dI" % len(words), *words).ljust(0x1000, b"\xFF"))


def describe(tag, blocks, arm, rv):
    print("%s: loop %s" % (tag, " -> ".join("0x%x" % b.off for b in blocks)))
    for cpu, best in (("arm", arm), ("riscv", rv)):
        if best is None:
            print("  %-5s side: no executable IMAGE_DEF at all" % cpu)
        else:
            note = "RIGHT cpu" if CPU_NAMES.get(best.cpu) == cpu else \
                   "wrong cpu -> ROM auto-switches"
            print("  %-5s side: block @0x%x (%s, %s)%s"
                  % (cpu, best.off, CPU_NAMES.get(best.cpu, best.cpu), note,
                     " entry=0x%x sp=0x%x" % best.entry if best.entry else ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootloader", required=True,
                    help="pqf_bootloader.bin (annex build)")
    ap.add_argument("--app", required=True,
                    help="app image .bin as linked for the DFU slot")
    ap.add_argument("--compose", help="write the composed+synced flash image")
    args = ap.parse_args()

    bl = open(args.bootloader, "rb").read()
    app = open(args.app, "rb").read()
    if len(bl) != ANNEX_OFF + 0x14:
        raise SystemExit("FAIL: bootloader is 0x%x bytes; an annex build "
                         "ends exactly at 0x%x (annex sector + end block)"
                         % (len(bl), ANNEX_OFF + 0x14))

    img = bytearray(b"\xFF" * (APP_IMAGE_OFF + len(app)))
    img[0:len(bl)] = bl
    img[APP_IMAGE_OFF:APP_IMAGE_OFF + len(app)] = app

    # 1. fresh state
    blocks = walk_loop(img)
    arm, rv = select_image(blocks, 0), select_image(blocks, 1)
    describe("fresh (placeholder annex)", blocks, arm, rv)
    assert arm and arm.cpu == 0 and arm.off < 0x1000, \
        "FAIL: Arm side must select the bootloader"
    assert rv is not None and rv.cpu == 0, \
        "FAIL: fresh RISC-V side should fall back to the (Arm) bootloader"

    # 2. the app block the bootloader would transplant
    app_block = None
    for i in range(SEARCH_WORDS):
        off = APP_IMAGE_OFF + 4 * i
        if w32(img, off) != MARKER_START:
            continue
        app_block = parse_block(img, off)
        if app_block:
            break
    if not app_block:
        raise SystemExit("FAIL: no IMAGE_DEF in the app's first 4 KiB")
    if app_block.cpu != 1:
        raise SystemExit("FAIL: app IMAGE_DEF is not RISC-V (cpu=%s) -- "
                         "wrong build handed to --app?" % app_block.cpu)
    if app_block.bad:
        raise SystemExit("FAIL: app block not transplantable: %s"
                         % ", ".join(app_block.bad))
    if not app_block.entry:
        raise SystemExit("FAIL: app block has no ENTRY_POINT")

    # 3. post-sync state
    sync_annex(img, app_block)
    blocks = walk_loop(img)
    arm, rv = select_image(blocks, 0), select_image(blocks, 1)
    describe("synced (app IMAGE_DEF in annex)", blocks, arm, rv)
    assert arm and arm.cpu == 0 and arm.off < 0x1000, \
        "FAIL: Arm side no longer selects the bootloader"
    assert rv and rv.cpu == 1 and rv.off == ANNEX_OFF, \
        "FAIL: RISC-V side does not select the annex"
    pc, sp = rv.entry
    lo, hi = XIP_BASE + APP_IMAGE_OFF, XIP_BASE + APP_IMAGE_OFF + len(app)
    assert lo <= pc < hi, \
        "FAIL: entry 0x%x outside the app image [0x%x,0x%x)" % (pc, lo, hi)
    assert (pc & 1) == 0, "FAIL: RISC-V entry has the Thumb bit set"
    assert rv.rolling is None, "FAIL: annex block would roll the window"

    if args.compose:
        open(args.compose, "wb").write(img)
        print("composed image -> %s" % args.compose)

    print("OK: loop closes both ways; arm boots the bootloader, riscv "
          "boots the app at 0x%x, identity-mapped (roll 0)" % pc)


if __name__ == "__main__":
    main()
