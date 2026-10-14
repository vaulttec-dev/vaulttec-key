#!/usr/bin/env bash
#
# Sign an image for this board's bootloader fork and wrap it into the UF2 to copy onto
# the UF2BOOT drive:
#
#   sign.sh app        VERSION images/vaultkey.bin  PRIVATE.pem OUT.uf2
#   sign.sh bootloader VERSION bootloader.bin       PRIVATE.pem OUT.uf2
#
# PRIVATE.pem is an Ed25519 private key. tools/sign-vaultkey.sh fetches the real one
# from the vkey into tmpfs and calls this; a test key works the same way, and the
# bootloader built with its public half (BOOTLOADER_TEST_KEY) is the only one that
# accepts the result. The signature is checked against the key's public half before
# the UF2 is written, so a bad signature never reaches a file.

set -euo pipefail

[[ $# -eq 5 ]] || { sed -n '3,13p' "$0" >&2; exit 2; }
kind="$1" version="$2" image="$3" key="$4" out="$5"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# A bootloader built with a test key trusts a key that lives in a temporary directory.
# Installed, it would freeze the board for good, so it is signed only on purpose.
if [[ "$kind" == bootloader ]] && grep -qa 'TEST KEY' "$image" && [[ "${ALLOW_TEST_KEY:-}" != 1 ]]; then
    echo "$image trusts a test key; it is never installed (set ALLOW_TEST_KEY=1 for a test)" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

python3 -I "$here/signed_image.py" message "$kind" "$version" "$image" "$work/message"
openssl pkeyutl -sign -inkey "$key" -rawin -in "$work/message" -out "$work/signature"
openssl pkey -in "$key" -pubout -out "$work/public.pem"
openssl pkeyutl -verify -pubin -inkey "$work/public.pem" -rawin -in "$work/message" \
    -sigfile "$work/signature" >/dev/null
python3 -I "$here/signed_image.py" uf2 "$kind" "$version" "$image" "$work/signature" "$out"
echo "$kind: $(basename "$out"), signed by $(openssl pkey -pubin -in "$work/public.pem" -outform DER | tail -c 32 | sha256sum | cut -c1-16)"
