#!/usr/bin/env bash
#
# Sign a board's firmware images for Secure Boot v2 with the key that lives on the vkey.
#
#   ./tools/sign-vaultkey.sh                 every board folder
#   BOARD=esp32c6-zero ./tools/sign-vaultkey.sh
#
# Reads images/vaultkey.bin and images/bootloader-sb.bin, writes vaultkey.signed.bin
# and bootloader-sb.signed.bin next to them: the same images with a signature block
# appended, which a chip with Secure Boot enabled (docs/hardware.md) will boot. The
# unsigned images stay what the git hooks rebuild and compare; the signed ones they
# verify against firmware/secure-boot/public.pem, which needs no secret. Signing
# itself needs the key: the PIN and one tap.
#
# The private key is fetched from the device into tmpfs for the seconds of signing
# and removed; see tools/signing-key.sh for where it lives.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOARDS="$ROOT/firmware/boards"
PUBLIC="$ROOT/firmware/secure-boot/public.pem"
NAME="vkey-signing"

for tool in espsecure openssl vkey base64; do
    command -v "$tool" >/dev/null || { echo "$tool is missing" >&2; exit 1; }
done
[[ -f "$PUBLIC" ]] || { echo "no $PUBLIC: run tools/signing-key.sh first" >&2; exit 1; }
[[ -d /dev/shm ]] || { echo "no /dev/shm: the key would have to touch the disk" >&2; exit 1; }

if [[ -n "${BOARD:-}" ]]; then
    dirs=("$BOARDS/$BOARD")
else
    dirs=("$BOARDS"/*/)
fi

tmp="$(mktemp -d /dev/shm/vkey-sign.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

echo "the signing key comes off the vkey: PIN if asked, then one tap"
vkey get "$NAME" | sed -n 's/^SIGNING_KEY=//p' | base64 -d \
    | openssl rsa -inform DER -outform PEM -out "$tmp/key.pem" 2>/dev/null
[[ -s "$tmp/key.pem" ]] || { echo "no key came back from '$NAME'" >&2; exit 1; }

for dir in "${dirs[@]}"; do
    dir="${dir%/}"
    name="$(basename "$dir")"
    for stem in vaultkey bootloader-sb; do
        image="$dir/images/$stem.bin"
        [[ -f "$image" ]] || { echo "$name: no images/$stem.bin - build first" >&2; exit 1; }
        signed="$dir/images/$stem.signed.bin"
        espsecure sign-data --version 2 --keyfile "$tmp/key.pem" --output "$signed" "$image" >/dev/null
        espsecure verify-signature --version 2 --keyfile "$PUBLIC" "$signed" >/dev/null
        echo "$name: images/$stem.signed.bin  $(stat -c %s "$signed") bytes, verified"
    done
done
echo "rebuild the CLI to embed them:  cargo build --release  in cli/, then  vkey install"
