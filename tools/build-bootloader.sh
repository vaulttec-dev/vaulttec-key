#!/usr/bin/env bash
#
# Build the bootloader of every board folder that has a bootloader/ directory, in
# Docker: no ESP-IDF and no Arm toolchain on the host. Run when bootloader/ changes.
#
#   ./tools/build-bootloader.sh                    every such board
#   BOARD=esp32c6-zero ./tools/build-bootloader.sh
#
# ESP32 boards: the ESP-IDF second-stage bootloaders and the partition table, in the
# espressif/idf image. The outputs are committed.
#
#   bootloader/partitions.csv      the partition table (the key only needs `factory`)
#   bootloader/sdkconfig.plain     a bootloader that verifies nothing: boards without
#                                  Secure Boot get this one
#   bootloader/sdkconfig.secure    a bootloader that boots only signed images. Built
#                                  unsigned here; tools/sign-vaultkey.sh signs it. It
#                                  would ALSO burn the Secure Boot eFuses by itself on
#                                  a chip where they are not burned yet - which is why
#                                  `vkey setup` flashes it only where they already are
#                                  (docs/hardware.md), and why it is never flashed by
#                                  hand onto a plain chip.
#
#   Outputs, in images/: bootloader.bin (plain), bootloader-sb.bin (Secure Boot,
#   unsigned), partition-table.bin. Both bootloaders read the table from the same
#   offset (CONFIG_PARTITION_TABLE_OFFSET in both sdkconfigs), so one table serves both.
#
# nRF52840 boards: the UF2 bootloader, upstream Adafruit_nRF52_Bootloader at a pinned
# commit with bootloader/'s board definition and patches, built and checked by
# bootloader/build.sh in bootloader/Dockerfile. It trusts one Ed25519 public key:
# bootloader/signing-key.pem, or with BOOTLOADER_TEST_KEY=<pem> a throwaway key, which
# INFO_UF2.TXT then names as a test key. Either must be a public key and nothing else.
# A build with the real key copies bootloader.bin into images/, for bootloader/
# sign-vaultkey.sh to sign and the git hooks to check; a test build leaves its outputs
# in a temporary directory. Nothing is ever installed (docs/roadmap.md, phase 3).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOARDS="$ROOT/firmware/boards"
IDF_IMAGE="espressif/idf:v5.5"

for tool in docker openssl; do
    command -v "$tool" >/dev/null || { echo "$tool is missing" >&2; exit 1; }
done
toml_value() { grep -E "^$2\s*=" "$1" | head -1 | cut -d'"' -f2; }

build_esp() {
    local dir="$1" name="$2" chip="$3" work table
    work="$(mktemp -d)"
    cp "$dir/bootloader/partitions.csv" "$dir/bootloader/sdkconfig.plain" "$dir/bootloader/sdkconfig.secure" "$work/"
    # The hello_world example is only a project skeleton the bootloader target needs;
    # nothing of it ends up in the outputs.
    docker run --rm -v "$work:/work" "$IDF_IMAGE" bash -c '
        set -e
        for v in plain secure; do
            rm -rf /work/p
            cp -r "$IDF_PATH/examples/get-started/hello_world" /work/p
            cp /work/partitions.csv /work/p/
            cp "/work/sdkconfig.$v" /work/p/sdkconfig.defaults
            cd /work/p
            idf.py set-target "'"$chip"'" >/dev/null
            idf.py bootloader partition-table 2>&1 | grep -E "Bootloader binary size|Error" || true
            cp build/bootloader/bootloader.bin "/work/bootloader-$v.bin"
            cp build/partition_table/partition-table.bin "/work/partition-table-$v.bin"
        done
        chmod -R a+rwX /work' 2>&1 | grep -vE "^(Checking|Python|Activating|Setting|\* |Done!|Go to|  idf.py|\"python3\")" || true
    cmp -s "$work/partition-table-plain.bin" "$work/partition-table-secure.bin" \
        || { echo "$name: the two sdkconfigs produce different partition tables" >&2; exit 1; }
    # Fail closed on what a wrong sdkconfig would do to the chip: the download mode
    # branch is visible in the binary's log strings, the plain bootloader must carry
    # no Secure Boot code at all, and the signed one (+4 KiB) must end before the
    # partition table - ESP-IDF's own size check measures the unsigned file.
    # (grep -a on the file itself: `strings | grep -q` under pipefail reports the
    # SIGPIPE of a satisfied grep as a failure.)
    grep -qa 'Download mode kept enabled' "$work/bootloader-secure.bin" \
        || { echo "$name: bootloader-sb.bin does not keep ROM download mode" >&2; exit 1; }
    if grep -qaE 'Security download mode|Disable ROM Download' "$work/bootloader-secure.bin"; then
        echo "$name: bootloader-sb.bin would change the download mode eFuses" >&2; exit 1
    fi
    if grep -qai 'secure boot' "$work/bootloader-plain.bin"; then
        echo "$name: bootloader.bin carries Secure Boot code" >&2; exit 1
    fi
    table="$(grep -E '^CONFIG_PARTITION_TABLE_OFFSET=' "$dir/bootloader/sdkconfig.secure" | cut -d= -f2)"
    (( $(stat -c %s "$work/bootloader-secure.bin") + 4096 <= table )) \
        || { echo "$name: the signed Secure Boot bootloader would overlap the partition table at $table" >&2; exit 1; }
    cp "$work/bootloader-plain.bin" "$dir/images/bootloader.bin"
    cp "$work/bootloader-secure.bin" "$dir/images/bootloader-sb.bin"
    cp "$work/partition-table-plain.bin" "$dir/images/partition-table.bin"
    rm -rf "$work"
    ls -l "$dir/images/bootloader.bin" "$dir/images/bootloader-sb.bin" "$dir/images/partition-table.bin"
    echo "sign the Secure Boot bootloader next:  tools/sign-vaultkey.sh"
}

build_uf2() {
    local dir="$1" name="$2" out log key kind
    if [[ -n "${BOOTLOADER_TEST_KEY:-}" ]]; then
        # Absolute: docker -v reads a bare relative name as a named volume.
        key="$(realpath -m -- "$BOOTLOADER_TEST_KEY")" kind=test
    else
        key="$dir/bootloader/signing-key.pem" kind=real
    fi
    [[ -f "$key" ]] || {
        echo "$name: no $key. The real key is not made yet (docs/roadmap.md, phase 3);" >&2
        echo "  a test build:  BOOTLOADER_TEST_KEY=<Ed25519 public key .pem> $0" >&2
        exit 1
    }
    # Checked before it is mounted into the build: a file equal to its own public
    # re-encoding holds no private key.
    if [[ "$(openssl pkey -pubin -in "$key" -noout -text 2>/dev/null)" != "ED25519 Public-Key:"* ]] \
        || ! openssl pkey -pubin -in "$key" 2>/dev/null | cmp -s - "$key"; then
        echo "$name: $key must be an Ed25519 public key and nothing else" >&2
        exit 1
    fi
    docker build -q -t "vkey-bootloader-$name" "$dir/bootloader" >/dev/null
    out="$(mktemp -d)"
    log="$out/build.log"
    # As the host user, so the outputs are the host user's. The log keeps newlib's
    # "is not implemented" linker warnings out of sight; build.sh fails on anything real.
    if ! docker run --rm -u "$(id -u):$(id -g)" -e KEY_KIND="$kind" -v "$key:/work/key.pem:ro" \
        -v "$dir/bootloader:/work/in:ro" -v "$out:/work/out" \
        "vkey-bootloader-$name" sh /work/in/build.sh >"$log" 2>&1; then
        cat "$log" >&2
        echo "$name: the bootloader build or its checks failed" >&2
        exit 1
    fi
    grep -E "^ *(FLASH|BOOTLOADER_CONFIG):|^check:|^signature test:|^key:" "$log" || true
    (cd "$out" && sha256sum bootloader.bin)
    if [[ "$kind" == real ]]; then
        cp "$out/bootloader.bin" "$dir/images/bootloader.bin"
        echo "$name: images/bootloader.bin (the rest in $out), not installed"
        echo "sign it next:  firmware/boards/$name/bootloader/sign-vaultkey.sh"
    else
        echo "$name: outputs in $out - a test build, not installed, not copied into images/"
    fi
}

if [[ -n "${BOARD:-}" ]]; then
    dirs=("$BOARDS/$BOARD")
else
    dirs=("$BOARDS"/*/)
fi

for dir in "${dirs[@]}"; do
    dir="${dir%/}"
    name="$(basename "$dir")"
    [[ -d "$dir/bootloader" ]] || continue
    chip="$(toml_value "$dir/board.toml" chip)"
    echo "== $name ($chip)"
    case "$chip" in
        esp32*) build_esp "$dir" "$name" "$chip" ;;
        nrf52840) build_uf2 "$dir" "$name" ;;
        *) echo "$name: no bootloader build for chip $chip" >&2; exit 1 ;;
    esac
done
