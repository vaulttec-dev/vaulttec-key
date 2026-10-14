"""The UF2s of the on-board test (test/app_test.c), from what the real pipeline made:

    board.py AS_APP.bin APP.uf2 BOOTLOADER.uf2 OUTDIR

APP.uf2 and BOOTLOADER.uf2 come from sign.sh. Writes into OUTDIR:

    m4.uf2          for the factory bootloader's drive: the test build at 0x1000, and
                    APP.uf2's image and slot moved into the scratch window where
                    app_test.c looks, with a second copy of the slot that has one bit of
                    the signature's R flipped. The signature covers the slot header and
                    the image, never their addresses, so moving them keeps it valid.
    bl-altered.uf2  BOOTLOADER.uf2 with one bit flipped at 0xF4110, a vector-table word
                    no interrupt uses: the signature covers every byte, used or not. For
                    the test build's own drive; it must be staged and then refused.
"""

import struct
import sys
from pathlib import Path

BLOCK = 256
UF2_BLOCK = 512
FAMILY_APP = 0xADA52840
FAMILY_BOOT = 0xD663823C
UF2_MAGIC = (0x0A324655, 0x9E5D5157, 0x0AB16F30)
UF2_FAMILY_FLAG = 0x2000

APP_BASE = 0x1000
APP_SLOT = 0x96000  # signed_image.py, kind app
# app_test.c: TEST_APP_IMAGE, TEST_APP_SLOT, TEST_APP_ALTERED
TEST_IMAGE = 0x40000
TEST_SLOT = 0x60000
TEST_ALTERED = TEST_SLOT + BLOCK
SIGNATURE_R = 0x40


def blocks_of(uf2: bytes) -> list[tuple[int, int, bytes]]:
    out = []
    for i in range(0, len(uf2), UF2_BLOCK):
        m0, m1, _, addr, size, _, _, family = struct.unpack_from("<8I", uf2, i)
        assert (m0, m1) == UF2_MAGIC[:2] and size == BLOCK, f"not a UF2 block at {i}"
        out.append((family, addr, uf2[i + 32:i + 32 + BLOCK]))
    return out


def uf2(blocks: list[tuple[int, bytes]], family: int) -> bytes:
    out = bytearray()
    for n, (addr, data) in enumerate(blocks):
        assert len(data) == BLOCK and addr % BLOCK == 0
        head = struct.pack("<8I", UF2_MAGIC[0], UF2_MAGIC[1], UF2_FAMILY_FLAG, addr, BLOCK,
                           n, len(blocks), family)
        out += head + data.ljust(476, b"\0") + struct.pack("<I", UF2_MAGIC[2])
    return bytes(out)


def flip(data: bytes, at: int) -> bytes:
    return data[:at] + bytes([data[at] ^ 1]) + data[at + 1:]


def m4(as_app: bytes, app: list[tuple[int, int, bytes]]) -> bytes:
    if APP_BASE + len(as_app) > TEST_IMAGE:
        raise SystemExit("the test build reaches its scratch window")
    padded = as_app.ljust(-(-len(as_app) // BLOCK) * BLOCK, b"\xff")
    blocks = [(APP_BASE + i, padded[i:i + BLOCK]) for i in range(0, len(padded), BLOCK)]
    slot = None
    for family, addr, data in app:
        assert family == FAMILY_APP
        if addr == APP_SLOT:
            slot = data
        elif TEST_IMAGE + addr - APP_BASE + BLOCK <= TEST_SLOT:
            blocks.append((TEST_IMAGE + addr - APP_BASE, data))
        else:
            raise SystemExit(f"the app reaches past {TEST_SLOT:#x} once moved")
    if slot is None:
        raise SystemExit("the app UF2 has no slot")
    blocks += [(TEST_SLOT, slot), (TEST_ALTERED, flip(slot, SIGNATURE_R))]
    return uf2(blocks, FAMILY_APP)


def altered(bootloader: list[tuple[int, int, bytes]]) -> bytes:
    # 0xF4110: past the 48 interrupts the vector table serves, well before the CF2 page
    # and the slot.
    assert all(family == FAMILY_BOOT for family, _, _ in bootloader)
    blocks = [(addr, flip(data, 0x10) if n == 1 else data)
              for n, (_, addr, data) in enumerate(bootloader)]
    return uf2(blocks, FAMILY_BOOT)


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    as_app = Path(sys.argv[1]).read_bytes()
    app = blocks_of(Path(sys.argv[2]).read_bytes())
    bootloader = blocks_of(Path(sys.argv[3]).read_bytes())
    out = Path(sys.argv[4])
    (out / "m4.uf2").write_bytes(m4(as_app, app))
    (out / "bl-altered.uf2").write_bytes(altered(bootloader))
    return 0


if __name__ == "__main__":
    sys.exit(main())
