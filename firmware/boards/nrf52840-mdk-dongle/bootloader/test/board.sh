#!/usr/bin/env bash
#
# The on-board test (test/app_test.c, docs2/roadmap.md phase 3, milestone 4):
#
#   board.sh make TEST.pem OUTDIR   sign with the test key and write the test's UF2s
#                                   into OUTDIR, the output of a test-key build:
#                                   app.uf2, bl.uf2, m4.uf2, bl-altered.uf2
#   board.sh copy FILE.uf2          copy one onto the drive it is meant for, or refuse
#
# bl.uf2 is a real self-update: signed for a bootloader that trusts the test key, with
# the board ID and UICR words the factory bootloader checks. On the factory drive it
# would be installed, and the board would then trust a key that lives in a file. So
# `copy` reads the target's INFO_UF2.TXT first: a bootloader-family UF2 goes only to the
# test build's drive (VKEYTEST, "Test: as app"), an app-family one only to the factory
# bootloader's (UF2BOOT, "UF2 Bootloader 0.7.1").

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
usage() { sed -n '3,15p' "$0" >&2; exit 2; }

make_uf2s() {
    local key="$1" out="$2" image
    image="$here/../../images/vaultkey.bin"
    [[ -f "$out/as-app.bin" && -f "$out/bootloader.bin" ]] \
        || { echo "$out has no as-app.bin: build with BOOTLOADER_TEST_KEY first" >&2; exit 1; }
    "$here/../sign.sh" app 1 "$image" "$key" "$out/app.uf2"
    ALLOW_TEST_KEY=1 "$here/../sign.sh" bootloader 1 "$out/bootloader.bin" "$key" "$out/bl.uf2"
    python3 -I "$here/board.py" "$out/as-app.bin" "$out/app.uf2" "$out/bl.uf2" "$out"
    ls -l "$out"/*.uf2
}

copy_uf2() {
    local file="$1" family mount marker
    family="$(od -An -tx4 -j28 -N4 "$file" | tr -d ' ')"
    case "$family" in
        d663823c) mount="/media/$USER/VKEYTEST" marker='^Test: as app' ;;
        ada52840) mount="/media/$USER/UF2BOOT" marker='^UF2 Bootloader 0\.7\.1 ' ;;
        *) echo "$file: UF2 family $family is not this test's" >&2; exit 1 ;;
    esac
    grep -q "$marker" "$mount/INFO_UF2.TXT" 2>/dev/null \
        || { echo "$file goes only to $mount, whose INFO_UF2.TXT matches '$marker'" >&2; exit 1; }
    cp "$file" "$mount/"
    timeout 20 sync || true
    echo "$(basename "$file") copied to $mount"
}

case "${1:-}" in
    make) [[ $# -eq 3 ]] || usage; make_uf2s "$2" "$3" ;;
    copy) [[ $# -eq 2 ]] || usage; copy_uf2 "$2" ;;
    *) usage ;;
esac
