"""Cases for test/verify.c: images signed by openssl the way signed_image.py and the
signing tool do it, each with the answer the bootloader must give. Writes cases.h and
signing_key.h into DIR, which holds key.pem and other.pem.

    cases.py DIR
"""

import os
import random
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import signed_image as si  # noqa: E402

L = 2**252 + 27742317777372353535851937790883648493  # the Ed25519 group order


def raw_public(pem: Path) -> bytes:
    der = subprocess.run(["openssl", "pkey", "-in", str(pem), "-pubout", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    return der[-32:]


def sign(pem: Path, message: bytes, work: Path) -> bytes:
    msg = work / "msg.bin"
    msg.write_bytes(message)
    return subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(pem), "-rawin",
                           "-in", str(msg)], check=True, capture_output=True).stdout


def slot(head: bytes, signature: bytes) -> bytes:
    return (head + signature).ljust(si.SLOT, b"\xff")


def flip(data: bytes, index: int) -> bytes:
    b = bytearray(data)
    b[index] ^= 1
    return bytes(b)


def c_array(name: str, data: bytes) -> str:
    return f"static const uint8_t {name}[{len(data)}] = {{{','.join(map(str, data))}}};\n"


def main() -> int:
    work = Path(sys.argv[1])
    key, other = work / "key.pem", work / "other.pem"
    rng = random.Random(1)
    app, boot = si.KINDS["app"], si.KINDS["bootloader"]
    app_max, boot_len = app.slot - app.base, boot.slot - boot.base

    image = bytes(rng.getrandbits(8) for _ in range(5000))
    head = si.header(app, 7, image)
    sig = sign(key, head + image, work)
    good = slot(head, sig)

    boot_image = si.image_for(boot, bytes(rng.getrandbits(8) for _ in range(0x9858)))
    boot_head = si.header(boot, 3, boot_image)
    boot_good = slot(boot_head, sign(key, boot_head + boot_image, work))

    s = int.from_bytes(sig[32:], "little")
    malleable = sig[:32] + (s + L).to_bytes(32, "little")
    as_boot = si.header(boot, 7, image)
    short_boot = boot_image[:boot_len - 256]
    short_head = si.header(boot, 3, short_boot)
    reserved = bytearray(head)
    reserved[0x20] = 1
    long_head = struct.pack("<4I", si.MAGIC, 1, 7, len(image) + 1).ljust(si.HEADER, b"\0")
    zero_head = struct.pack("<4I", si.MAGIC, 1, 7, 0).ljust(si.HEADER, b"\0")
    tail = bytearray(good)
    tail[0xF0] = 0

    # (name, image, slot, kind, max, exact, expected)
    cases: list[tuple[str, bytes, bytes, int, int, int, int]] = [
        ("valid app", image, good, 1, app_max, 0, 1),
        ("header bit", image, flip(good, 0x08), 1, app_max, 0, 0),
        ("image bit", flip(image, 2500), good, 1, app_max, 0, 0),
        ("R bit", image, flip(good, 0x40 + 5), 1, app_max, 0, 0),
        ("s bit", image, flip(good, 0x60 + 5), 1, app_max, 0, 0),
        ("wrong key", image, slot(head, sign(other, head + image, work)), 1, app_max, 0, 0),
        ("s + L", image, slot(head, malleable), 1, app_max, 0, 0),
        ("bootloader kind in the app slot", image,
         slot(as_boot, sign(key, as_boot + image, work)), 1, app_max, 0, 0),
        ("length one past the image, signed", image + b"\xff",
         slot(long_head, sign(key, long_head + image + b"\xff", work)), 1, app_max, 0, 1),
        ("length one past what was signed", image + b"\xff",
         slot(long_head, sig), 1, app_max, 0, 0),
        ("length over the window, signed", image, good, 1, len(image) - 1, 0, 0),
        ("zero length, signed", image, slot(zero_head, sign(key, zero_head, work)),
         1, app_max, 0, 0),
        ("reserved byte set, signed", image,
         slot(bytes(reserved), sign(key, bytes(reserved) + image, work)), 1, app_max, 0, 0),
        ("tail not erased", image, bytes(tail), 1, app_max, 0, 0),
        ("valid bootloader", boot_image, boot_good, 2, boot_len, 1, 1),
        ("bootloader short of its slot, signed", short_boot,
         slot(short_head, sign(key, short_head + short_boot, work)), 2, boot_len, 1, 0),
        ("app slot offered as bootloader", image, good, 2, boot_len, 1, 0),
    ]

    out = ["#include <stdint.h>\n"]
    rows = []
    for n, (name, img, sl, kind, mx, exact, expect) in enumerate(cases):
        out += [c_array(f"I{n}", img), c_array(f"S{n}", sl)]
        rows.append(f'  {{"{name}", I{n}, S{n}, {kind}, {mx}, {exact}, {expect}}},\n')
    out.append("struct test_case { const char *name; const uint8_t *image; const uint8_t *slot;"
               " uint32_t kind, max_length; uint8_t exact, expect; };\n")
    out.append("static const struct test_case CASES[] = {\n" + "".join(rows) + "};\n")
    # The two valid messages whole, for the one-shot crypto_ed25519_check to agree with.
    out += [c_array("APP_MESSAGE", head + image), c_array("BOOT_MESSAGE", boot_head + boot_image)]
    (work / "cases.h").write_text("".join(out))

    pub = raw_public(key)
    (work / "signing_key.h").write_text(
        "#define SIGNING_PUBLIC_KEY_BYTES {" + ",".join(map(str, pub)) + "}\n"
        '#define SIGNING_KEY_FINGERPRINT "test"\n')
    print(len(cases))
    os.remove(work / "msg.bin")
    return 0


if __name__ == "__main__":
    sys.exit(main())
