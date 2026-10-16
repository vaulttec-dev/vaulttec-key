#!/bin/sh
#
# Runs inside the image built from Dockerfile, started by tools/build-bootloader.sh:
# /work/in is this folder (read-only), /work/key.pem the Ed25519 public key the
# bootloader will trust, KEY_KIND `real` or `test`. /work/out receives
#
#   bootloader.bin    the bootloader region from 0xF4000 (code, then the CF2 page): what
#                     the signing step signs and wraps into the self-update UF2
#   bootloader.dis    its disassembly, for check.py
#   systeminit.txt    SystemInit disassembled, read before any install
#   as-app.bin/.dis   with a test key only: the on-board test build (test/app_test.c)
#
# The tree is the image's pristine upstream checkout, so every run starts from the same
# sources. The version and the build date are fixed, so the same inputs give the same
# bytes.

set -eu

BOARD=nrf52840_mdk_usb_dongle
# Upstream's version, then the fork's revision, bumped with every change to this folder:
# with no probe, INFO_UF2.TXT on the drive is the only way to tell which build a board
# runs. The Makefile takes the bootloader version number from the part before "-".
VERSION=0.9.2-vkey.4
# What `git submodule status` reports for the pinned commits today, as the factory
# 0.7.1 bootloader reports it too. Fixed here because the uf2 part names an upstream
# branch, and a fresh clone after that branch moves would change the INFO text.
SUBMODULES="lib/nrfx (v2.0.0) lib/tinyusb (0.12.0-145-g9775e7691) lib/uf2 (remotes/origin/configupdate-9-gadbb8c7)"

# The signature check first, on its own: a check that refuses valid images makes a
# board that can never be updated again.
sh /work/in/test/run.sh

# The key, compiled in. Its fingerprint goes into INFO_UF2.TXT, and a test key says so
# there, so a test build cannot pass for a real one on a board with no probe.
openssl pkey -pubin -in /work/key.pem -noout -text 2>/dev/null | grep -q '^ED25519 Public-Key' \
    || { echo "/work/key.pem is not an Ed25519 public key" >&2; exit 1; }
raw="$(openssl pkey -pubin -in /work/key.pem -outform DER | tail -c 32 | od -An -v -tu1 | tr -s ' \n' ',' | sed 's/^,//; s/,$//')"
fingerprint="$(openssl pkey -pubin -in /work/key.pem -outform DER | tail -c 32 | sha256sum | cut -c1-16)"
case "$KEY_KIND" in
    real) ;;
    test) fingerprint="$fingerprint TEST KEY" ;;
    *) echo "KEY_KIND is real or test, not '$KEY_KIND'" >&2; exit 1 ;;
esac

cd /src
mkdir -p "src/boards/$BOARD"
cp /work/in/board/board.h /work/in/board/board.mk "src/boards/$BOARD/"
# The CF2 block (board ID = VID:PID, family, flash and RAM size) is generic; upstream's
# copy for this dongle is the one the factory build carries.
cp src/boards/mdk_nrf52840_dongle/pinconfig.c "src/boards/$BOARD/"
cp /work/in/src/signature.c /work/in/src/signature.h src/
printf '#define SIGNING_PUBLIC_KEY_BYTES {%s}\n#define SIGNING_KEY_FINGERPRINT "%s"\n' \
    "$raw" "$fingerprint" > src/signing_key.h

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
out="_build/build-$BOARD/${BOARD}_bootloader-$VERSION.out"
make -s BOARD="$BOARD" GIT_VERSION="$VERSION" GIT_SUBMODULE_VERSIONS="$SUBMODULES" "$out"

# The two UICR words (bootloader and MBR-params addresses, already on the chip) are
# programmer data, not code; left in, the binary would span up to 0x10001018.
arm-none-eabi-objcopy -O binary -R .uicrBootStartAddress -R .uicrMbrParamsPageAddress \
    "$out" /work/out/bootloader.bin
arm-none-eabi-objdump -d --disassemble=SystemInit "$out" > /work/out/systeminit.txt
arm-none-eabi-objdump -d --no-show-raw-insn "$out" > /work/out/bootloader.dis
arm-none-eabi-size "$out"
python3 /work/in/check.py /work/out/bootloader.bin /work/out/bootloader.dis
echo "key: $fingerprint"

# With a test key, also the on-board test build (test/app_test.c, patches/0007): the
# same sources as an application at 0x1000, run under the factory bootloader. It runs
# on the chip too, so it passes the same UICR search.
[ "$KEY_KIND" = test ] || exit 0
cp /work/in/test/app_test.c src/
cp /work/in/test/app.ld linker/
printf 'CFLAGS += -DVKEY_AS_APP\nC_SRC += src/app_test.c\n' > Makefile.user
app="_build/app/${BOARD}_bootloader-$VERSION.out"
make -s BOARD="$BOARD" BUILD=_build/app LD_FILE=linker/app.ld GIT_VERSION="$VERSION" \
    GIT_SUBMODULE_VERSIONS="$SUBMODULES" "$app"
arm-none-eabi-objcopy -O binary -R .uicrBootStartAddress -R .uicrMbrParamsPageAddress \
    "$app" /work/out/as-app.bin
arm-none-eabi-objdump -d --no-show-raw-insn "$app" > /work/out/as-app.dis
python3 /work/in/check.py --as-app /work/out/as-app.bin /work/out/as-app.dis
