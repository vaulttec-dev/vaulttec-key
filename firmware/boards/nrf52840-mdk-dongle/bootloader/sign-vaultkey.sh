#!/usr/bin/env bash
#
# Sign this board's images for its bootloader fork with the key that lives on the board.
#
#   bootloader/sign-vaultkey.sh
#
# Writes next to each image in images/ its signed UF2: vaultkey.signed.uf2, the app to
# copy onto the drive, and bootloader.signed.uf2, the fork's self-update, once a build
# with the real key has left bootloader.bin there. The unsigned images stay what the git
# hooks compare the UF2s against; the signatures they verify under signing-key.pem,
# which needs no secret. Signing itself needs the key: the PIN and one tap.
#
# The private key comes off the board into tmpfs for the seconds of signing and is
# removed; see signing-key.sh for where it lives.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
board="$(basename "$(dirname "$here")")"
images="$(dirname "$here")/images"
PUBLIC="$here/signing-key.pem"
NAME="vkey-signing-nrf"
# The firmware's own USB identity (src/main.rs), as in signing-key.sh.
PORT="/dev/serial/by-id/usb-vaulttecdev_vkey-if00"
vk() { vkey --port "$PORT" "$@"; }

for tool in openssl vkey base64 python3; do
    command -v "$tool" >/dev/null || { echo "$tool is missing" >&2; exit 1; }
done
[[ -f "$PUBLIC" ]] || { echo "no $PUBLIC: run signing-key.sh first" >&2; exit 1; }
[[ -d /dev/shm ]] || { echo "no /dev/shm: the key would have to touch the disk" >&2; exit 1; }
[[ -f "$images/vaultkey.bin" ]] || { echo "no images/vaultkey.bin - build first" >&2; exit 1; }
grep -qE "^device:.* $board\$" <<<"$(vk info)" || { echo "$PORT is not $board" >&2; exit 1; }

tmp="$(mktemp -d /dev/shm/vkey-sign.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

echo "the signing key comes off $board: PIN if asked, then one tap"
vk get "$NAME" | sed -n 's/^SIGNING_KEY=//p' | base64 -d \
    | openssl pkey -inform DER -out "$tmp/key.pem" 2>/dev/null
# sign.sh signs with whatever key it is given and checks only against that key's own
# public half; a UF2 signed by any other key than the one the fork trusts is refused.
openssl pkey -in "$tmp/key.pem" -pubout | cmp -s - "$PUBLIC" \
    || { echo "'$NAME' on $board is not the key in signing-key.pem" >&2; exit 1; }

# The slot's version is carried and signed but not compared yet (src/signature.h).
"$here/sign.sh" app 1 "$images/vaultkey.bin" "$tmp/key.pem" "$images/vaultkey.signed.uf2"
if [[ -f "$images/bootloader.bin" ]]; then
    "$here/sign.sh" bootloader 1 "$images/bootloader.bin" "$tmp/key.pem" "$images/bootloader.signed.uf2"
fi
echo "commit the signed UF2s with the images they sign"
