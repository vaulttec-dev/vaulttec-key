#!/bin/sh
#
# Install the vkey CLI:
#
#   curl -fsSL https://github.com/vaulttec-dev/vaulttec-key/releases/latest/download/install.sh | sh
#
# Downloads the release binary, checks it against the SHA256SUMS published beside it, and
# puts it in ~/.local/bin. Nothing runs as root and nothing outside that directory is
# touched. The checksum check is not optional: this is the tool that will hold your
# secrets, and a binary that does not match what was published does not get installed.
#
# To read before running, which you should for any piped installer:
#   curl -fsSL https://github.com/vaulttec-dev/vaulttec-key/releases/latest/download/install.sh

set -eu

REPO=vaulttec-dev/vaulttec-key
BASE="https://github.com/$REPO/releases/latest/download"
DEST="${VKEY_BIN_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"

os=$(uname -s)
arch=$(uname -m)
case "$os $arch" in
    "Linux x86_64") asset="vkey-x86_64-linux" ;;
    *)
        die "no published binary for $os $arch.
Build it instead - it needs only Rust (https://rustup.rs):
  git clone https://github.com/$REPO.git
  cd vaulttec-key/cli && cargo build --release && ./target/release/vkey install"
        ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $asset"
curl -fsSL "$BASE/$asset" -o "$tmp/$asset" || die "download failed: $BASE/$asset"
curl -fsSL "$BASE/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "download failed: $BASE/SHA256SUMS"

want=$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1) || true
[ -n "$want" ] || die "SHA256SUMS does not list $asset"
if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)
else
    die "neither sha256sum nor shasum found; cannot verify the download"
fi
[ "$want" = "$got" ] || die "checksum mismatch - not installing.
  published $want
  received  $got"
say "checksum ok"

mkdir -p "$DEST"
install -m 755 "$tmp/$asset" "$DEST/vkey"
say "installed $("$DEST/vkey" --version) -> $DEST/vkey"

case ":$PATH:" in
    *":$DEST:"*) ;;
    *) say "add it to your PATH:  export PATH=\"\$PATH:$DEST\"" ;;
esac

id -nG 2>/dev/null | tr ' ' '\n' | grep -qx dialout \
    || say "the serial port needs group membership, once:  sudo usermod -aG dialout \$USER   (then log out and back in)"

say "plug a board in and run:  vkey setup"
