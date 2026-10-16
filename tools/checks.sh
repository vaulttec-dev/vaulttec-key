#!/usr/bin/env bash
#
# The checks behind the git hooks in .githooks/. Sourced, not run: each function stops
# the hook at the first failure and says what to do.
#
#   pre-commit   fmt, clippy, rustdoc, tests, shellcheck, mypy, lint tables, no radio,
#                forbidden marketing claims, the firmware image must be the one these
#                sources build, and every signed image must be signed from it
#   pre-push     the same on a clean tree and only for HEAD, so what is pushed is what
#                was checked
#
# Every one of them can be run by hand:  . tools/checks.sh && check_all

ROOT="$(git rev-parse --show-toplevel)"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

boards() {
    local d
    for d in "$ROOT"/firmware/boards/*/; do
        [[ -f "$d/board.toml" ]] && echo "${d%/}"
    done
}

check_fmt() {
    step "rustfmt"
    (cd "$ROOT/firmware" && cargo fmt --all --check) || fail "run:  cargo fmt --all   in firmware/"
    (cd "$ROOT/cli" && cargo fmt --check) || fail "run:  cargo fmt   in cli/"
}

check_clippy() {
    step "clippy - every warning is an error (the [lints] tables in Cargo.toml)"
    (cd "$ROOT/firmware" && cargo clippy -p vaultkey-core --all-targets --locked -q -- -D warnings) \
        || fail "clippy: firmware/core"
    local d
    for d in $(boards); do
        (cd "$d" && cargo clippy --locked -q -- -D warnings) || fail "clippy: $(basename "$d")"
    done
    (cd "$ROOT/cli" && cargo clippy --all-targets --locked -q -- -D warnings) || fail "clippy: cli"
}

check_doc() {
    step "rustdoc - broken links and bad markup are errors"
    (cd "$ROOT/firmware" && RUSTDOCFLAGS="-D warnings" cargo doc -p vaultkey-core --no-deps --locked -q) \
        || fail "rustdoc: firmware/core"
    (cd "$ROOT/cli" && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked -q) || fail "rustdoc: cli"
}

check_tests() {
    step "tests - the key on a flash made of RAM, and the CLI's parsers"
    (cd "$ROOT/firmware" && cargo test -p vaultkey-core --locked -q) || fail "tests: firmware/core"
    (cd "$ROOT/cli" && cargo test --locked -q) || fail "tests: cli"
}

check_scripts() {
    step "shellcheck and mypy --strict"
    local -a sh py
    mapfile -t sh < <(git -C "$ROOT" ls-files -- '*.sh' '.githooks/*')
    command -v shellcheck >/dev/null || fail "shellcheck is missing:  sudo apt install shellcheck"
    (cd "$ROOT" && shellcheck -x -S style -- "${sh[@]}") || fail "shellcheck"
    mapfile -t py < <(git -C "$ROOT" ls-files -- '*.py')
    if ((${#py[@]})); then
        command -v mypy >/dev/null || fail "mypy is missing:  pipx install mypy"
        (cd "$ROOT" && mypy --strict --ignore-missing-imports -- "${py[@]}") || fail "mypy"
    fi
}

check_lint_tables() {
    step "the [lints] tables of firmware/, cli/ and every board with its own are identical"
    local a b d
    a=$(sed -n '/^\[workspace\.lints\.rust\]/,$p' "$ROOT/firmware/Cargo.toml" | sed 's/^\[workspace\.lints\./[lints./')
    b=$(sed -n '/^\[lints\.rust\]/,$p' "$ROOT/cli/Cargo.toml")
    diff <(echo "$a") <(echo "$b") || fail "the [lints] tables differ - one strictness for both crates"
    # A board whose flash driver needs memory-mapped flash as a slice carries its own
    # copy, identical but for `unsafe_code = "deny"`, so that one place can say why
    # with #[expect]. Nothing else may differ.
    for d in $(boards); do
        grep -q '^\[lints\.rust\]' "$d/Cargo.toml" || continue
        b=$(sed -n '/^\[lints\.rust\]/,$p' "$d/Cargo.toml")
        diff <(echo "${a//unsafe_code = \"forbid\"/unsafe_code = \"deny\"}") <(echo "$b") \
            || fail "$(basename "$d"): its [lints] table differs from the workspace's in more than unsafe_code"
    done
}

check_no_radio() {
    step "no radio crate in firmware/Cargo.lock"
    if grep -qE 'name = "esp-(radio|wifi|phy)' "$ROOT/firmware/Cargo.lock"; then
        fail "a radio crate is in firmware/Cargo.lock - this build would transmit"
    fi
}

# Builds are reproducible on one machine, so the image in git must equal a fresh build
# of the sources in git. Compares against the index: what is about to be committed.
#
# The one check here that writes: it leaves the freshly built image in the working tree
# on purpose. That is exactly the file the failure message tells you to `git add`, so
# restoring the old one would undo the fix before it could be staged.
check_images() {
    step "firmware images are what these sources build (rewrites images/vaultkey.bin)"
    SKIP_CLI=1 "$ROOT/tools/build-vaultkey.sh" >/dev/null || fail "tools/build-vaultkey.sh failed"
    git -C "$ROOT" diff --quiet -- 'firmware/boards/*/images/*' \
        || fail "images/vaultkey.bin differs from a fresh build:  git add firmware/boards/*/images"
}

# A signed image is its unsigned twin plus padding and a signature block, and the
# block must verify under the project's public key: both are checked without any
# secret, so a stale or foreign signature never reaches a board.
check_signed_images() {
    step "signed images match their unsigned twins and firmware/secure-boot/public.pem"
    local public="$ROOT/firmware/secure-boot/public.pem" digest="$ROOT/firmware/secure-boot/digest.bin"
    local signed plain tmp
    [[ -f "$public" ]] || return 0
    command -v espsecure >/dev/null || fail "espsecure is missing:  pipx install esptool"
    # The digest in the repository is what gets burned into a chip: it must be the
    # digest of the public key the images are verified with.
    tmp="$(mktemp)"
    espsecure digest-sbv2-public-key --keyfile "$public" --output "$tmp" >/dev/null 2>&1 || true
    if ! cmp -s "$tmp" "$digest"; then
        rm -f "$tmp"
        fail "firmware/secure-boot/digest.bin is not the digest of public.pem"
    fi
    rm -f "$tmp"
    for signed in "$ROOT"/firmware/boards/*/images/*.signed.bin; do
        [[ -f "$signed" ]] || continue
        plain="${signed%.signed.bin}.bin"
        [[ -f "$plain" ]] || fail "$signed has no unsigned twin"
        cmp -s -n "$(stat -c %s "$plain")" "$plain" "$signed" \
            || fail "$(basename "$signed") is stale - it was signed from another build:  tools/sign-vaultkey.sh"
        espsecure verify-signature --version 2 --keyfile "$public" "$signed" >/dev/null 2>&1 \
            || fail "$(basename "$signed") does not verify under firmware/secure-boot/public.pem"
    done
    # A signed Secure Boot bootloader that reaches the partition table at 0xC000 is
    # a board that boots nothing; ESP-IDF's size check never sees the signature.
    for signed in "$ROOT"/firmware/boards/*/images/bootloader-sb.signed.bin; do
        [[ -f "$signed" ]] || continue
        (( $(stat -c %s "$signed") <= 0xC000 )) || fail "$(basename "$signed") overlaps the partition table"
    done
}

# A board's UF2 bootloader fork runs only images signed with one Ed25519 key, whose
# public half the board commits as bootloader/signing-key.pem. Checked without the
# secret: that file is a public key and nothing more, every signed UF2 is its unsigned
# twin plus a slot whose signature verifies under it, and a bootloader.bin trusts that
# key and not a test one - installed, a bootloader trusting the wrong key freezes the board.
check_signed_uf2() {
    step "signed UF2s match their unsigned twins and bootloader/signing-key.pem"
    local pem dir name signed plain kind tmp fp ok
    # Driven by the UF2s too: a key taken away must not silently end their check.
    for signed in "$ROOT"/firmware/boards/*/images/*.signed.uf2; do
        [[ -f "$signed" ]] || continue
        dir="$(dirname "$(dirname "$signed")")"
        [[ -f "$dir/bootloader/signing-key.pem" ]] \
            || fail "$(basename "$dir"): $(basename "$signed") has no bootloader/signing-key.pem to verify it under"
    done
    for pem in "$ROOT"/firmware/boards/*/bootloader/signing-key.pem; do
        [[ -f "$pem" ]] || continue
        dir="$(dirname "$(dirname "$pem")")"
        name="$(basename "$dir")"
        # A file equal to its own public re-encoding holds no private key.
        if [[ "$(openssl pkey -pubin -in "$pem" -noout -text 2>/dev/null)" != "ED25519 Public-Key:"* ]] \
            || ! openssl pkey -pubin -in "$pem" 2>/dev/null | cmp -s - "$pem"; then
            fail "$name: bootloader/signing-key.pem must be an Ed25519 public key and nothing else"
        fi
        [[ -f "$dir/images/vaultkey.signed.uf2" ]] \
            || fail "$name: no images/vaultkey.signed.uf2:  bootloader/sign-vaultkey.sh"
        for signed in "$dir"/images/*.signed.uf2; do
            plain="${signed%.signed.uf2}.bin"
            case "$(basename "$plain")" in
                vaultkey.bin) kind=app ;;
                bootloader.bin) kind=bootloader ;;
                *) fail "$name: $(basename "$signed") is neither the app nor the bootloader" ;;
            esac
            [[ -f "$plain" ]] || fail "$name: $(basename "$signed") has no unsigned twin"
            tmp="$(mktemp -d)"
            ok=0
            if python3 -I "$dir/bootloader/signed_image.py" verify "$kind" "$plain" "$signed" "$tmp" >/dev/null 2>&1 \
                && openssl pkeyutl -verify -pubin -inkey "$pem" -rawin -in "$tmp/message" \
                    -sigfile "$tmp/signature" >/dev/null 2>&1; then
                ok=1
            fi
            rm -rf "$tmp"
            ((ok)) || fail "$name: $(basename "$signed") is stale or not signed by bootloader/signing-key.pem:  bootloader/sign-vaultkey.sh"
        done
        [[ -f "$dir/images/bootloader.bin" ]] || continue
        # INFO_UF2.TXT names the key the build compiled in; a test key's line goes on
        # with " TEST KEY" before it ends.
        fp="$(openssl pkey -pubin -in "$pem" -outform DER | tail -c 32 | sha256sum | cut -c1-16)"
        grep -qa "^Key: $fp"$'\r$' "$dir/images/bootloader.bin" \
            || fail "$name: images/bootloader.bin does not trust bootloader/signing-key.pem ($fp)"
    done
}

# docs/threat-model.md calls breaking its wording rules a failure of the project, by the
# definition the project gave itself. Only claims that can never be true here are matched:
# phishing, certification and FIDO appear throughout the docs as denials ("does not
# protect against phishing"), so grepping for those words would flag the very honesty the
# rules exist to enforce. The file holding the list is skipped - it quotes every phrase.
check_wording() {
    step "no marketing claim that docs/threat-model.md forbids"
    local banned='military[ -]?grade|unbreakable|hardware-grade security'
    banned+='|bank[ -]?level security|(more|safer) secure than[^.]{0,20}yubikey'
    local -a files hits
    mapfile -t files < <(git -C "$ROOT" ls-files -- '*.md' '*.rs' | grep -v '^docs/threat-model\.md$')
    # `|| true`: grep exits 1 when it finds nothing, which is the good case here.
    mapfile -t hits < <(cd "$ROOT" || exit; grep -HniE "$banned" -- "${files[@]}" || true)
    ((${#hits[@]} == 0)) || fail "claims forbidden by docs/threat-model.md, section
'Marketing wording rules':
$(printf '%s\n' "${hits[@]}")"
}

# Known vulnerabilities in the dependency trees. Needs the network for the advisory
# database, so pre-push only.
check_audit() {
    step "cargo audit - advisories against firmware/Cargo.lock and cli/Cargo.lock"
    command -v cargo-audit >/dev/null || fail "cargo-audit is missing:  cargo install cargo-audit"
    (cd "$ROOT/firmware" && cargo audit -q) || fail "cargo audit: firmware"
    (cd "$ROOT/cli" && cargo audit -q) || fail "cargo audit: cli"
}

check_all() {
    check_fmt
    check_clippy
    check_doc
    check_tests
    check_scripts
    check_lint_tables
    check_no_radio
    check_wording
    check_images
    check_signed_images
    check_signed_uf2
}
