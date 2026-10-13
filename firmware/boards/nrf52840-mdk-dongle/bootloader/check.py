"""Fail closed on a bootloader that would be dangerous to install on a board with no
SWD probe. Takes bootloader.bin, the region from 0xF4000 (code, then the CF2 page at
0xFD800), and bootloader.dis, its disassembly. Run by build.sh after every build.

- No UICR address the code could write through: the bootloader must never write UICR.
  A write there (PSELRESET, NFCPINS, APPROTECT) is permanent without a probe. Searched
  three ways: as a word anywhere in the code, as an immediate in any instruction but a
  comparison, and as a movw/movt pair. Like the radio search in build-vaultkey.sh, it
  catches direct addressing, not an address computed from another base plus an offset.
- The CF2 block is the factory one, word for word. Its board ID is what the factory
  bootloader checks before it accepts this one as a self-update, and what a later
  self-update of this one is checked against.
"""

import re
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

# objdump --no-show-raw-insn: "   f5f2a:\tcmp.w\tr3, #268439552\t@ 0x10001000"
INSN = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$")
NUMBER = re.compile(r"(?<![\w])(?:#|@ )?(0x[0-9a-f]+|\d+)\b")
MOVW = re.compile(r"^movw\S*\s+(r\d+|ip|lr|sl|fp), #(\d+)")
MOVT = re.compile(r"^movt\S*\s+(r\d+|ip|lr|sl|fp), #(\d+)")


def words_in_code(code: bytes) -> list[str]:
    # Halfword steps: Thumb literal pools are word-aligned, but a constant packed in
    # data need not be.
    return [
        hex(BASE + i)
        for i in range(0, len(code) - 3, 2)
        if struct.unpack_from("<I", code, i)[0] in UICR
    ]


def immediates_and_pairs(dis: str) -> list[str]:
    hits = []
    last_movw: dict[str, int] = {}
    for line in dis.splitlines():
        m = INSN.match(line)
        if not m:
            continue
        addr, op, args = m.group(1), m.group(2), m.group(3)
        text = f"{op} {args}"
        if not op.startswith(("cmp", "cmn")):
            for n in NUMBER.findall(args):
                if int(n, 0) in UICR:
                    hits.append(f"{addr}: {text}")
                    break
        if w := MOVW.match(text):
            last_movw[w.group(1)] = int(w.group(2))
        elif t := MOVT.match(text):
            low = last_movw.get(t.group(1))
            if low is not None and (int(t.group(2)) << 16 | low) in UICR:
                hits.append(f"{addr}: {text} (with movw #{low:#x})")
    return hits


def main() -> int:
    data = open(sys.argv[1], "rb").read()
    dis = open(sys.argv[2]).read()
    code = data[: CF2_AT - BASE]

    hits = words_in_code(code) + immediates_and_pairs(dis)
    if hits:
        print("UICR addresses the code could write through:\n  " + "\n  ".join(hits))
        return 1

    cf2 = list(struct.unpack_from(f"<{len(CF2)}I", data, CF2_AT - BASE))
    if cf2 != CF2:
        print("the CF2 block differs from the factory one: " + " ".join(hex(w) for w in cf2))
        return 1

    print(f"check: no UICR address in {len(code)} bytes of code; CF2 block is the factory one")
    return 0


if __name__ == "__main__":
    sys.exit(main())
