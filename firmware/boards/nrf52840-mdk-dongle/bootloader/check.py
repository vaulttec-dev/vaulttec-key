"""Fail closed on a bootloader that would be dangerous to install on a board with no
SWD probe. Takes bootloader.bin, the region from 0xF4000 (code, then the CF2 page at
0xFD800). Run by build.sh after every build.

- No UICR address anywhere in the code: the bootloader must never write UICR. A write
  there (PSELRESET, NFCPINS, APPROTECT) is permanent without a probe.
- The CF2 block is the factory one, word for word. Its board ID is what the factory
  bootloader checks before it accepts this one as a self-update, and what a later
  self-update of this one is checked against.
"""

import struct
import sys

BASE = 0xF4000
CF2_AT = 0xFD800
UICR = range(0x10001000, 0x10002000)

# What the factory 0.7.1 image holds at 0xFD800: magic, 5 of 100 entries used,
# flash 1 MiB, RAM 256 KiB, board ID 2886:F00F, UF2 family, 32 pins per port.
CF2 = [
    0x1E9E10F1, 0x20227A79, 5, 100,
    204, 0x100000,
    205, 0x40000,
    208, 0x2886F00F,
    209, 0xADA52840,
    210, 0x20,
    0, 0, 0, 0, 0, 0, 0, 0,
]


def main() -> int:
    data = open(sys.argv[1], "rb").read()
    code = data[: CF2_AT - BASE]
    # Halfword steps: Thumb literal pools are word-aligned, but a constant built from
    # two halves or packed in data need not be.
    hits = [
        BASE + i
        for i in range(0, len(code) - 3, 2)
        if struct.unpack_from("<I", code, i)[0] in UICR
    ]
    if hits:
        print("UICR addresses in the code at " + ", ".join(hex(h) for h in hits))
        return 1

    cf2 = list(struct.unpack_from(f"<{len(CF2)}I", data, CF2_AT - BASE))
    if cf2 != CF2:
        print("the CF2 block differs from the factory one: " + " ".join(hex(w) for w in cf2))
        return 1

    print(f"check: no UICR address in {len(code)} bytes of code; CF2 block is the factory one")
    return 0


if __name__ == "__main__":
    sys.exit(main())
