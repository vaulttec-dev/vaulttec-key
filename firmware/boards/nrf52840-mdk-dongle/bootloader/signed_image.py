"""Signed UF2 images for this board's bootloader fork (src/signature.h has the format).

    signed_image.py message KIND VERSION IMAGE OUT
        writes what gets signed: the slot header, then the image (a bootloader padded to
        its fixed length). Sign it with  openssl pkeyutl -sign -rawin.
    signed_image.py uf2 KIND VERSION IMAGE SIGNATURE OUT
        writes the UF2 to copy to the drive: the image and its slot.

KIND is `app` (images/vaultkey.bin, flashed from 0x1000) or `bootloader` (the build's
bootloader.bin, from 0xF4000). Only the private key is outside this file: the signature
arrives as a file from whoever holds it.
"""

import struct
import sys
from pathlib import Path
from typing import NamedTuple

BLOCK = 256
MAGIC = 0x31534B56  # "VKS1"
HEADER = 0x40
SLOT = 0x100

UF2_MAGIC = (0x0A324655, 0x9E5D5157, 0x0AB16F30)
UF2_FAMILY_FLAG = 0x2000

# The two UICR words a bootloader update must carry: the factory bootloader and this
# fork compare them with their own and refuse anything else. Nothing writes them.
UICR = 0x10001000
UICR_WORDS = {0x14: 0xF4000, 0x18: 0xFE000}


class Kind(NamedTuple):
    number: int
    base: int  # where the image starts in flash
    slot: int  # where its slot is written
    family: int  # the UF2 family the bootloader routes it by
    exact: bool  # signed up to the slot, whatever the image's own size


# An app ends before the page that holds its slot. A bootloader fills its region up to
# its slot at the end of the CF2 page, so everything the MBR copies is signed, the
# signature, or erased.
KINDS = {
    "app": Kind(1, 0x1000, 0x96000, 0xADA52840, False),
    "bootloader": Kind(2, 0xF4000, 0xFDF00, 0xD663823C, True),
}


def kind_of(name: str) -> Kind:
    if name not in KINDS:
        raise SystemExit(f"kind is app or bootloader, not {name!r}")
    return KINDS[name]


def image_for(k: Kind, raw: bytes) -> bytes:
    room = k.slot - k.base
    if not raw or len(raw) > room:
        raise SystemExit(f"the image is {len(raw)} bytes; 1 to {room} fit before its slot")
    return raw.ljust(room, b"\xff") if k.exact else raw


def header(k: Kind, version: int, image: bytes) -> bytes:
    return struct.pack("<4I", MAGIC, k.number, version, len(image)).ljust(HEADER, b"\0")


def uf2(blocks: list[tuple[int, bytes]], family: int) -> bytes:
    out = bytearray()
    for n, (addr, data) in enumerate(blocks):
        assert len(data) == BLOCK and addr % BLOCK == 0
        head = struct.pack("<8I", UF2_MAGIC[0], UF2_MAGIC[1], UF2_FAMILY_FLAG, addr, BLOCK,
                           n, len(blocks), family)
        out += head + data.ljust(476, b"\0") + struct.pack("<I", UF2_MAGIC[2])
    return bytes(out)


def build_uf2(k: Kind, version: int, image: bytes, signature: bytes) -> bytes:
    if len(signature) != 64:
        raise SystemExit(f"an Ed25519 signature is 64 bytes, not {len(signature)}")
    slot = (header(k, version, image) + signature).ljust(SLOT, b"\xff")
    padded = image.ljust(-(-len(image) // BLOCK) * BLOCK, b"\xff")
    blocks = [(k.base + i, padded[i:i + BLOCK]) for i in range(0, len(padded), BLOCK)]
    blocks.append((k.slot, slot))
    if k.exact:
        uicr = bytearray(b"\xff" * BLOCK)
        for off, word in UICR_WORDS.items():
            uicr[off:off + 4] = struct.pack("<I", word)
        blocks.append((UICR, bytes(uicr)))
    return uf2(blocks, k.family)


def main() -> int:
    args = sys.argv[1:]
    if len(args) == 5 and args[0] == "message":
        k, version = kind_of(args[1]), int(args[2], 0)
        image = image_for(k, Path(args[3]).read_bytes())
        Path(args[4]).write_bytes(header(k, version, image) + image)
        return 0
    if len(args) == 6 and args[0] == "uf2":
        k, version = kind_of(args[1]), int(args[2], 0)
        image = image_for(k, Path(args[3]).read_bytes())
        Path(args[5]).write_bytes(build_uf2(k, version, image, Path(args[4]).read_bytes()))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
