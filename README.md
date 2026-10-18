# vkey — a hardware key for TOTP codes, passwords, `.env` files and passkeys

An open USB key with bare-metal Rust firmware and a single-binary CLI. Every secret that
comes out needs a press of the board's button.

> **A personal key, not a product.** Read [docs/threat-model.md](docs/threat-model.md)
> before relying on it: neither board is a secure element. Keep your services' recovery
> codes.

| Board | Role |
|---|---|
| Makerdiary nRF52840 MDK USB Dongle | the key: vault, passkeys, `sudo`, signed commits, the login password |
| Waveshare ESP32-C6-Zero | test board: vault only, no passkeys |

## Install

```bash
curl -fsSL https://github.com/vaulttec-dev/vaulttec-key/releases/latest/download/install.sh | sh
```

x86_64 Linux; checks `SHA256SUMS`, writes only `~/.local/bin/vkey`. [Read it first](install.sh).
From source: `cd cli && cargo build --release && ./target/release/vkey install`. Then add
yourself to `dialout` and log in again.

## Use

`vkey` alone opens the shell: an item's name plus Enter gives it, empty Enter opens the
menu, `/settings` turns `auth`, `commits` and `login` on and off; `login` also changes
the password the key types.

```bash
vkey totp add GitHub:me               # otpauth URI or base32
vkey pass add mail --login me@example.com
vkey env add myapp .env
vkey get GitHub:me                    # a code after a tap
env $(vkey get myapp) npm start       # a .env with no file on disk
vkey list · rm · info · lock · pin set/change · totp selftest · wipe
vkey op [query]                       # mirror 1Password; deletes what it no longer offers
vkey import passwords.csv             # Google Password Manager or 1Password CSV
vkey export NAME                      # back into 1Password, seed in the clear (double tap)
vkey backup vault.vkb                 # everything, passkeys included, sealed on the key
vkey restore [file] · restore --only NAME file.vkb
vkey passkey list · rm · pin          # discoverable passkeys, under the FIDO PIN
sudo vkey auth enable | disable       # sudo and the lock screen with a tap (pam_u2f)
sudo vkey auth greeter typed | tap    # the login screen: the typed password, or a tap
vkey login set | clear                # nRF: the login password, typed on two idle taps
vkey commits enable | disable | github  # every git commit signed with a tap
vkey check --wipe-everything          # lifecycle test; ERASES EVERYTHING
```

`vkey auth` needs `libpam-u2f` and a root-owned copy:
`sudo install -m 0755 "$(command -v vkey)" /usr/local/sbin/vkey`. Keep a root shell open
until `sudo` and the lock screen work. On COSMIC a tap at the login screen leaves the
keyring locked. The `login` switch in `/settings` (or `vkey login set` and `sudo vkey
auth greeter typed`) has the key type the password there instead; the lock screen keeps
its tap. The key types as a US keyboard, so switch the login screen to the US layout.
A random part made of digits only types the same in any layout whose digits need no
Shift. Off, the login screen takes a tap again. The costs:
[sudo](docs/threat-model.md#vkey-auth--sudo-and-the-lock-screen-with-a-tap-through-pam_u2f),
[login](docs/threat-model.md#the-login-password-typed-by-the-key),
[commits](docs/threat-model.md#git-commits-signed-with-a-tap).

## Gestures and limits

| Gesture | LED | Releases |
|---|---|---|
| Tap | amber | a code, a password, a `.env`, a passkey, a login, a signature |
| Hold 5 s | red | wipe, restore, erasing every passkey |
| Double tap | blue | backup, export |
| Double tap, nothing asked | green | the login password typed, then Enter (nRF, `vkey login set`) |

| | |
|---|---|
| Items | 256; 32 fields each; a field 8056 B, an item 8192 B |
| Vault | 96 KiB per copy on the nRF, 212 KiB on the C6 |
| Name | 32 bytes, one namespace |
| PIN | exactly 8 digits, 8 attempts, auto-lock after 2 min |
| Backup passphrase | 12–128 bytes; five or six random words |

## Build

```bash
./tools/build-vaultkey.sh     # every board, images embedded into the CLI
./tools/sign-vaultkey.sh      # C6 Secure Boot images (PIN and a tap)
firmware/boards/nrf52840-mdk-dongle/bootloader/sign-vaultkey.sh   # nRF UF2s
(cd cli && cargo build --release) && cli/target/release/vkey install
```

After any firmware change `vkey totp selftest` must be green. Git hooks in `.githooks/`
run fmt, clippy, tests and the image checks; CI rebuilds the firmware and fails if a
committed image differs by a byte.

## Layout

| Path | What |
|---|---|
| `firmware/core/` | protocol, PIN, crypto, storage, TOTP; no chip name |
| `firmware/boards/<board>/` | pins, chip crates, `board.toml`, bootloader, images |
| `cli/` | the `vkey` command |
| `tools/` | build, signing and check scripts |
| [docs/threat-model.md](docs/threat-model.md) | what it does and does not protect. **Read first** |
| [docs/makerdiary.md](docs/makerdiary.md) · [docs/hardware.md](docs/hardware.md) | the nRF52840 and C6 boards |
| [docs/roadmap.md](docs/roadmap.md) · [docs/items-v2.md](docs/items-v2.md) | plan and status; the item model |

Vulnerabilities: [SECURITY.md](SECURITY.md). Licence: [Apache-2.0](LICENSE).
