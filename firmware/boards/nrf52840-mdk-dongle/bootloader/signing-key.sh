#!/usr/bin/env bash
#
# The signing key of this board's bootloader fork: made once, kept on the board itself.
#
#   bootloader/signing-key.sh     generate it, store it on the board, write its public half
#
# The private key never reaches the disk. It is an Ed25519 key generated on tmpfs,
# stored on the board as the .env `vkey-signing-nrf` (one line: SIGNING_KEY=<base64 of
# the DER key>), and the tmpfs copy is removed. Signing then takes the key and a tap
# (sign-vaultkey.sh). The second copy is the owner's `vkey backup` file.
#
# The public half lands in signing-key.pem and is committed: the bootloader build
# compiles it in, and the git hooks verify signed UF2s with it. Neither is secret. Its
# fingerprint, printed at the end and shown by the fork's INFO_UF2.TXT, goes into
# docs/roadmap.md.
#
# Once a bootloader that trusts this key is installed, losing the private key freezes
# the board - no firmware and no bootloader update ever again - so run `vkey backup`
# right after this and keep the backup passphrase somewhere other than the backup file.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
board="$(basename "$(dirname "$here")")"
PUBLIC="$here/signing-key.pem"
NAME="vkey-signing-nrf"
# The firmware's own USB identity (src/main.rs): with the C6 plugged in too, the CLI
# would refuse to guess, and the key must never land on the other board.
PORT="/dev/serial/by-id/usb-vaulttecdev_vkey-if00"
vk() { vkey --port "$PORT" "$@"; }

for tool in openssl vkey base64; do
    command -v "$tool" >/dev/null || { echo "$tool is missing" >&2; exit 1; }
done
[[ -d /dev/shm && "$(stat -f -c %T /dev/shm 2>/dev/null)" == tmpfs ]] \
    || { echo "/dev/shm is not tmpfs: the key would have to touch the disk" >&2; exit 1; }
if [[ -e "$PUBLIC" ]]; then
    echo "$PUBLIC exists: the signing key was made already." >&2
    echo "A second one would not be the key a built bootloader trusts." >&2
    exit 1
fi

# Captured first: grep -q on a pipe can close it under the CLI, which then fails.
info="$(vk info)"
grep -qE "^device:.* $board\$" <<<"$info" || { echo "$PORT is not $board" >&2; exit 1; }
grep -qE '^pin: +set,' <<<"$info" || { echo "$board has no PIN yet:  vkey --port $PORT pin set" >&2; exit 1; }

# The device must be open before the blob is piped in: with stdin taken by the blob,
# the CLI has nowhere to read a PIN from.
grep -q '^unlocked: true' <<<"$(vk pin status)" || vk pin unlock
if grep -qE "^$NAME\s" <<<"$(vk list)"; then
    echo "$board already holds '$NAME'" >&2
    exit 1
fi

tmp="$(mktemp -d /dev/shm/vkey-signing.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

echo "generating an Ed25519 key"
openssl genpkey -algorithm ed25519 -out "$tmp/key.pem"
der="$(openssl pkey -in "$tmp/key.pem" -outform DER | base64 -w0)"

echo "storing it on $board as '$NAME'"
printf 'SIGNING_KEY=%s\n' "$der" | vk env add "$NAME" >/dev/null
unset der

openssl pkey -in "$tmp/key.pem" -pubout -out "$PUBLIC"
echo "public key: bootloader/signing-key.pem, fingerprint" \
    "$(openssl pkey -pubin -in "$PUBLIC" -outform DER | tail -c 32 | sha256sum | cut -c1-16)"
echo
echo "next:  vkey --port $PORT backup <file>   - the backup is now the only other copy"
