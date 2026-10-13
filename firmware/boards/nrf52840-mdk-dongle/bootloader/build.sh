#!/bin/sh
#
# Runs inside the image built from Dockerfile, started by tools/build-bootloader.sh:
# /work/in is this folder (read-only), /work/out receives
#
#   bootloader.hex          the bootloader, with Nordic's MBR (what a probe would write)
#   update-bootloader.uf2   the same as a self-update UF2 (family 0xD663823C)
#   bootloader.bin          the bootloader region alone, from 0xF4000, for check.py
#   bootloader.dis          its disassembly, for check.py
#   systeminit.txt          SystemInit disassembled, read before any install
#
# The tree is the image's pristine upstream checkout, so every run starts from the same
# sources. The version and the build date are fixed, so the same inputs give the same
# bytes.

set -eu

BOARD=nrf52840_mdk_usb_dongle
# Upstream's version, then the fork's revision, bumped with every change to this folder:
# with no probe, INFO_UF2.TXT on the drive is the only way to tell which build a board
# runs. The Makefile takes the bootloader version number from the part before "-".
VERSION=0.9.2-vkey.2
# What `git submodule status` reports for the pinned commits today, as the factory
# 0.7.1 bootloader reports it too. Fixed here because the uf2 part names an upstream
# branch, and a fresh clone after that branch moves would change the INFO text.
SUBMODULES="lib/nrfx (v2.0.0) lib/tinyusb (0.12.0-145-g9775e7691) lib/uf2 (remotes/origin/configupdate-9-gadbb8c7)"

cd /src
mkdir -p "src/boards/$BOARD"
cp /work/in/board/board.h /work/in/board/board.mk "src/boards/$BOARD/"
# The CF2 block (board ID = VID:PID, family, flash and RAM size) is generic; upstream's
# copy for this dongle is the one the factory build carries.
cp src/boards/mdk_nrf52840_dongle/pinconfig.c "src/boards/$BOARD/"
# GNU patch, not git apply: editors and hooks strip the lone space of a blank context
# line, which git apply rejects. --fuzz=0 still demands every context line match. Some
# upstream files have CRLF endings and the patches are LF, so a file is made LF before
# it is patched.
for p in /work/in/patches/*.patch; do
    sed -n 's|^+++ b/||p' "$p" | while read -r f; do
        sed -i 's/\r$//' "$f"
    done
    patch -s -p1 --fuzz=0 --no-backup-if-mismatch -i "$p"
done

SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export SOURCE_DATE_EPOCH
out="_build/build-$BOARD/${BOARD}_bootloader-$VERSION"
make -s BOARD="$BOARD" GIT_VERSION="$VERSION" GIT_SUBMODULE_VERSIONS="$SUBMODULES" \
    "${out}_nosd.hex" "_build/build-$BOARD/update-${BOARD}_bootloader-${VERSION}_nosd.uf2"

cp "${out}_nosd.hex" /work/out/bootloader.hex
cp "_build/build-$BOARD/update-${BOARD}_bootloader-${VERSION}_nosd.uf2" /work/out/update-bootloader.uf2
# The two UICR words (bootloader and MBR-params addresses, already on the chip) are
# programmer data, not code; left in, the binary would span up to 0x10001018.
arm-none-eabi-objcopy -O binary -R .uicrBootStartAddress -R .uicrMbrParamsPageAddress \
    "$out.out" /work/out/bootloader.bin
arm-none-eabi-objdump -d --disassemble=SystemInit "$out.out" > /work/out/systeminit.txt
arm-none-eabi-objdump -d --no-show-raw-insn "$out.out" > /work/out/bootloader.dis
arm-none-eabi-size "$out.out"
python3 /work/in/check.py /work/out/bootloader.bin /work/out/bootloader.dis
