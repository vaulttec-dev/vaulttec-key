#!/usr/bin/env bash
#
# Build the key firmware for every board folder (or one), refresh the images the CLI
# embeds, rebuild the CLI.
#
#   ./tools/build-vaultkey.sh                    all boards, then the CLI
#   ./tools/build-vaultkey.sh monitor            ...then stay attached to the board's log
#   SKIP_CLI=1 ./tools/build-vaultkey.sh         images only (what the git hooks need)
#
# Flashing is `vkey setup` (on a Secure Boot chip after tools/sign-vaultkey.sh).
#
# A board is a folder under firmware/boards with a board.toml (chip, target, images).
# Nothing here names a chip. Needs rustup with the board's target, and espflash
# (`cargo install espflash`). The port is found by espflash itself; override with
# PORT=/dev/ttyACM1.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOARDS="$ROOT/firmware/boards"

toml_value() { grep -E "^$2\s*=" "$1" | head -1 | cut -d'"' -f2; }

# The git hooks live in the repository; git only runs them once told where they are.
if [[ -d "$ROOT/.git" ]] && [[ "$(git -C "$ROOT" config --get core.hooksPath || true)" != ".githooks" ]]; then
    git -C "$ROOT" config core.hooksPath .githooks
    echo "git hooks enabled: .githooks (pre-commit, commit-msg, pre-push)"
fi

command -v espflash >/dev/null || { echo "espflash is missing:  cargo install espflash" >&2; exit 1; }

# A panic location carries the path of the file it came from, and for a dependency that is
# an absolute path into the builder's ~/.cargo. Left alone it would put the builder's home
# directory into a published image and make the image differ on every machine, so the
# check that rebuilds it and compares could pass on one machine only. Cargo's `trim-paths`
# would do this in the profile, but it is not stable yet (1.97), hence the flags.
# Everything the compiler could name is mapped to a fixed stand-in.
# The ESP-IDF application descriptor carries a build date and time, so without this the
# image would differ on every compile and "the committed binary is what these sources
# build" could never be checked. esp-bootloader-esp-idf honours SOURCE_DATE_EPOCH, the
# reproducible-builds convention; a fixed value rather than the commit date, because the
# commit that carries the rebuilt image would change its own timestamp. The descriptor's
# date is informational - the firmware reports its real version through `info`.
export SOURCE_DATE_EPOCH=0

remap() { printf -- '--remap-path-prefix=%s=%s ' "$1" "$2"; }
REMAP="$(remap "${CARGO_HOME:-$HOME/.cargo}" /cargo)"
REMAP+="$(remap "$(rustc --print sysroot)" /rust)"
REMAP+="$(remap "$ROOT" /vaultkey)"
export RUSTFLAGS="${RUSTFLAGS:-} $REMAP"

if [[ -n "${BOARD:-}" ]]; then
    dirs=("$BOARDS/$BOARD")
else
    dirs=("$BOARDS"/*/)
fi

# No-radio assertion, on which docs/hardware.md relies: in a bare-metal build radio
# code can only come from a radio crate, so its absence from the lock file is the whole
# proof. Checked before building so a stray dependency never even compiles.
if grep -qE 'name = "esp-(radio|wifi|phy)' "$ROOT/firmware/Cargo.lock" 2>/dev/null; then
    echo "*** a radio crate is in firmware/Cargo.lock - this build would transmit ***" >&2
    exit 1
fi

for dir in "${dirs[@]}"; do
    dir="${dir%/}"
    name="$(basename "$dir")"
    [[ -f "$dir/board.toml" ]] || { echo "$name: no board.toml" >&2; exit 1; }
    chip="$(toml_value "$dir/board.toml" chip)"
    target="$(toml_value "$dir/board.toml" target)"
    elf="$ROOT/firmware/target/$target/release/vaultkey-$name"

    echo "== $name ($chip, $target)"
    # --locked, like every check in tools/checks.sh: without it cargo may rewrite
    # Cargo.lock mid-build, and the no-radio assertion above would have been read
    # from the old file while a different tree gets compiled.
    (cd "$dir" && cargo build --release --locked)
    mkdir -p "$dir/images"
    espflash save-image --chip "$chip" "$elf" "$dir/images/vaultkey.bin" >/dev/null
    echo "   image: $(stat -c %s "$dir/images/vaultkey.bin") bytes -> firmware/boards/$name/images/vaultkey.bin"
done
echo "no-radio check: passed"

# The images are compiled into the CLI, so it is rebuilt right after - once every
# image board.toml names exists; the signed ones come from tools/sign-vaultkey.sh,
# which needs the key on the vkey, so a fresh vaultkey.bin means signing first.
missing=()
for dir in "${dirs[@]}"; do
    dir="${dir%/}"
    while read -r rel; do
        [[ -f "$dir/$rel" ]] || missing+=("firmware/boards/$(basename "$dir")/$rel")
    done < <(grep -E '^file\s*=' "$dir/board.toml" | cut -d'"' -f2)
done
if ((${#missing[@]} > 0)); then
    echo "not rebuilding the CLI - it embeds images that do not exist yet:"
    printf '   %s\n' "${missing[@]}"
    echo "   tools/sign-vaultkey.sh makes the signed ones (PIN and a tap), then  cargo build --release  in cli/"
elif [[ -z "${SKIP_CLI:-}" ]]; then
    (cd "$ROOT/cli" && cargo build --release --locked 2>&1 | tail -1)
    echo "cli rebuilt - run  cli/target/release/vkey install  to update the command"
fi

# Flashing is `vkey setup` and nothing else: `espflash flash` would write its own
# bootloader and a partition table at 0x8000, and a chip with Secure Boot stops
# booting until the next `vkey setup`. What is left here is only watching the log.
case "${1:-}" in
    monitor)
        ARGS=(monitor)
        [[ -n "${PORT:-}" ]] && ARGS+=(--port "$PORT")
        espflash "${ARGS[@]}"
        ;;
    flash)
        echo "flashing is  vkey setup  (after tools/sign-vaultkey.sh on a Secure Boot chip)" >&2
        exit 1
        ;;
esac
