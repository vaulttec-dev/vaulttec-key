#!/usr/bin/env bash
#
# The firmware signing key for Secure Boot v2: made once, kept on the vkey itself.
#
#   ./tools/signing-key.sh          generate it, store it on the key, commit the public half
#
# The private key never reaches the disk. It is generated on tmpfs, stored on the
# device as the .env `vkey-signing` (one line: SIGNING_KEY=<base64 of the DER key)
# and the tmpfs copy is removed. Signing a build then takes the key and a tap
# (tools/sign-vaultkey.sh). The second copy is the owner's `vkey backup` file.
#
# The public key and its digest land in firmware/secure-boot/ and are committed:
# the digest is what gets burned into a chip (docs/hardware.md), the public key is
# what the git hooks verify signatures with. Neither is secret.
#
# Losing the private key freezes every board that trusts it - no firmware update
# ever again - so run `vkey backup` right after this and keep the backup passphrase
# somewhere other than the backup file.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/firmware/secure-boot"
NAME="vkey-signing"

for tool in espsecure openssl vkey base64; do
    command -v "$tool" >/dev/null || { echo "$tool is missing" >&2; exit 1; }
done
[[ -d /dev/shm ]] || { echo "no /dev/shm: the key would have to touch the disk" >&2; exit 1; }
if [[ -e "$OUT/public.pem" ]]; then
    echo "$OUT/public.pem exists: a signing key was made already." >&2
    echo "A second one would not match the digest burned into a chip." >&2
    exit 1
fi

# The device must be open before the blob is piped in: with stdin taken by the
# blob, the CLI has nowhere to read a PIN from.
if ! vkey pin status | grep -q '^unlocked: true'; then
    vkey pin unlock
fi
if vkey list | grep -qE "^$NAME\s"; then
    echo "the key already holds '$NAME'" >&2
    exit 1
fi

tmp="$(mktemp -d /dev/shm/vkey-signing.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

echo "generating an RSA-3072 key (Secure Boot v2)"
espsecure generate-signing-key --version 2 --scheme rsa3072 "$tmp/key.pem" >/dev/null
der="$(openssl rsa -in "$tmp/key.pem" -outform DER 2>/dev/null | base64 -w0)"

echo "storing it on the key as '$NAME'"
printf 'SIGNING_KEY=%s\n' "$der" | vkey env add "$NAME" >/dev/null

mkdir -p "$OUT"
espsecure extract-public-key --version 2 --keyfile "$tmp/key.pem" "$OUT/public.pem" >/dev/null
espsecure digest-sbv2-public-key --keyfile "$tmp/key.pem" --output "$OUT/digest.bin" >/dev/null
echo "public key: firmware/secure-boot/public.pem"
echo "digest:     firmware/secure-boot/digest.bin  sha256 $(sha256sum "$OUT/digest.bin" | cut -c1-16)..."
echo
echo "next:  vkey backup <file>   - the backup is now the only other copy of this key"
