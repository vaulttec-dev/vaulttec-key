#!/usr/bin/env bash
#
# Build the ESP-IDF second-stage bootloaders and the partition table for every board
# folder that has a bootloader/ directory, in the espressif/idf Docker image: no
# ESP-IDF on the host. Run when bootloader/ changes; the outputs are committed.
#
#   ./tools/build-bootloader.sh                    every such board
#   BOARD=esp32c6-zero ./tools/build-bootloader.sh
#
# bootloader/partitions.csv      the partition table (the key only needs `factory`)
# bootloader/sdkconfig.plain     a bootloader that verifies nothing: boards without
#                                Secure Boot get this one
# bootloader/sdkconfig.secure    a bootloader that boots only signed images. Built
#                                unsigned here; tools/sign-vaultkey.sh signs it. It
#                                would ALSO burn the Secure Boot eFuses by itself on
#                                a chip where they are not burned yet - which is why
#                                `vkey setup` flashes it only where they already are
#                                (docs/hardware.md), and why it is never flashed by
#                                hand onto a plain chip.
#
# Outputs, in images/: bootloader.bin (plain), bootloader-sb.bin (Secure Boot,
# unsigned), partition-table.bin. Both bootloaders read the table from the same
# offset (CONFIG_PARTITION_TABLE_OFFSET in both sdkconfigs), so one table serves both.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOARDS="$ROOT/firmware/boards"
IMAGE="espressif/idf:v5.5"

command -v docker >/dev/null || { echo "docker is missing" >&2; exit 1; }
toml_value() { grep -E "^$2\s*=" "$1" | head -1 | cut -d'"' -f2; }

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
    work="$(mktemp -d)"
    cp "$dir/bootloader/partitions.csv" "$dir/bootloader/sdkconfig.plain" "$dir/bootloader/sdkconfig.secure" "$work/"
    # The hello_world example is only a project skeleton the bootloader target needs;
    # nothing of it ends up in the outputs.
    docker run --rm -v "$work:/work" "$IMAGE" bash -c '
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
done
echo "sign the Secure Boot bootloader next:  tools/sign-vaultkey.sh"
