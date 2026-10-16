#!/bin/sh
#
# The signature check against images openssl signed, with a throwaway key: src/signature.c
# compiled for the board's core (-mcpu=cortex-m4) and run under qemu-arm. Run by build.sh
# before every build is accepted; a check that refuses a valid image is a board that can
# never be updated again.

set -eu

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

openssl genpkey -algorithm ed25519 -out "$work/key.pem" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$work/other.pem" 2>/dev/null
cases="$(python3 -I /work/in/test/cases.py "$work")"

arm-none-eabi-gcc -Os -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -std=gnu11 -Wall -Werror \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -nostartfiles -static \
    --specs=nano.specs -Wl,-e,_start -DSIGNATURE_QEMU_TEST \
    -I"$work" -I/work/in/src -I/src/lib/monocypher/src -I/src/lib/monocypher/src/optional \
    /work/in/test/verify.c /work/in/src/signature.c \
    /src/lib/monocypher/src/monocypher.c /src/lib/monocypher/src/optional/monocypher-ed25519.c \
    -o "$work/verify.elf"

qemu-arm -cpu max "$work/verify.elf"
echo "signature test: $cases cases decided right, streamed and one-shot checks agree"
