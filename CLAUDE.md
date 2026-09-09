# Project rules

**vaulttecdev** — a hardware key on ESP32-C6: TOTP codes, passwords and project `.env`
files. One board, own code.

| Part | What it is |
|---|---|
| `firmware/core` | Firmware as a chip-free library: `proto` (frames), `device` (PIN, entries), `vault` (KDF/AEAD), `store` (flash, A/B image), `oath` (entry kinds, HOTP/TOTP), `ui` (button rules), `hal` (four traits — port, clock, button+LED, chip key; flash and RNG arrive via `embedded-storage` and `rand_core`). Bare-metal Rust, `no_std`, no RTOS; crypto from RustCrypto. |
| `firmware/boards/<board>/` | One board = one folder: `Cargo.toml` with the chip crates, `.cargo/config.toml` with the target, `src/main.rs` with pins and trait impls, `board.toml`, `bootloader/`, `images/`. The chip name appears **nowhere** outside such a folder. |
| `cli/` | The `vkey` command: one static binary. Subcommands for scripts (`clap`), an interactive shell (`crossterm`, draws itself), flashing through `espflash` as a library with images embedded via `include_bytes!`. All user work goes through this CLI. |

## Scope: personal use only

Decision of 2026-09-07. The key is built for the maintainer's own accounts. Sales,
production runs, enclosures, provisioning, certifications and marketing are **not built and
not proposed** unless the maintainer says otherwise. Passkey/WebAuthn is closed permanently.

Consequence for code: "convenience for a buyer" is not an argument; security of the
maintainer's own secrets and minimal code are.

## Language

**Everything a product user sees is English only**: CLI and script output, error text,
README. Code comments and `docs/` are English too.

Commit messages are English too. The `commit-msg` hook checks the subject length, not the
language.

---

## Priority order

These principles conflict. When they do, the higher one wins. Without an order, a set of
principles can justify anything.

1. **Correctness and security**
2. **Simplicity** — less code, fewer states, fewer execution paths
3. **Readability** — code is read more often than written
4. **DRY** — removing real duplication
5. **Flexibility and extensibility** — last, and almost always premature

If removing duplication makes the code more confusing, keep the duplication. If an
abstraction adds flexibility not needed today, do not add it.

## Principles

| Principle | The rule | Warning sign |
|---|---|---|
| **YAGNI** (first among these) | Write nothing that is not needed *now* | An abstraction layer with one implementation; configurability with no second consumer; a hook "just in case"; a generalisation for a hypothetical second case; a branch for a board not in hand |
| **KISS** | Of two working solutions, take the one simpler to explain out loud | One execution path needs three files open; a boolean parameter that switches behaviour; `Manager`, `Helper`, `Util`, `Handler` without specifics |
| **DRY, for knowledge only** | Rule of three: write it, tolerate it, then generalise | Two identical fragments that change for *different* reasons — that is coincidence, not duplication |
| **SRP** | One reason to change per module | A function whose description contains "and"; a name that needs a conjunction or a generic word |
| **Minimal surface** | `pub` only where a second consuming module exists | — |
| **Orthogonality** | A change in one place must not force one elsewhere | Every feature touches five files |
| **Explicit errors, early exit** | Validate at the entry, `return` early, keep the happy path unnested | An error swallowed, logged-and-continued, or replaced by a "safe" default. A silent failure in a PIN check is a vulnerability |
| **Locality of reasoning** | A fragment is understandable without the whole project in mind | Global state, implicit side effects, action at a distance |

**Dead code is a security issue**, not clutter: functionality that is not the product is
deleted, not kept "as an example". Record what was removed in `docs/` with the commit hash
it can be restored from.

**Irreversible actions are a separate class.** Anything that cannot be rolled back needs
confirmation and separate attention: here that is eFuse and publishing a release.

## SOLID, honestly

SOLID was formulated for OOP; dragging it mechanically into Rust is cargo cult.

| | Applicability |
|---|---|
| **S** — Single Responsibility | **Fully.** The most useful of the five |
| **I** — Interface Segregation | **Yes**, as small traits and narrow signatures |
| **D** — Dependency Inversion | **Partly.** Through traits — but only when there really are two implementations |
| **O** — Open/Closed | **Almost never.** Extension without modification costs more than it gives here |
| **L** — Liskov Substitution | **No.** No inheritance, no subject |

Do not invent traits for D, do not build dispatch tables for O. With one implementation, a
direct call beats any indirection.

## No overhead

Useless wrappers (a function that only calls another with the same arguments); premature
configurability (a constant becomes a parameter at the second call site with a different
value, not before); comments that restate the code (a comment explains *why*); defensive
programming with no scenario (checking for the impossible hides real bugs); logging "just
in case" (in a release every log is flash, time and a potential leak); abstractions built
for tests; default branches that swallow the unknown (`_ =>` must be an error, not silence).

---

## Secure code

This is a security device. The rules below are not recommendations.

- **Compare secrets in constant time only:** `subtle::ConstantTimeEq`. Plain `==` on a PIN,
  HMAC or verifier is a vulnerability.
- **Wipe secrets after use** with `zeroize`, not a manual `fill(0)` (the compiler may drop
  that as dead code).
- **Never log** keys, PINs or secrets. Not even in a debug build: a debug build eventually
  ships.
- **Randomness comes only from `Trng` with `TrngSource` enabled.** Without it the RNG
  register is not random. The handle lives for the whole runtime.
- **Validate every input** that arrives over USB. The host is assumed hostile.
- **Fail closed.** If anything goes wrong, the operation does not happen.
- **Spend the PIN attempt before checking, not after.** Otherwise cutting power mid-check
  yields free attempts. In flash this is one word write without an erase.
- **A claim in the protocol must hold in the code.** Advertising a guarantee only half the
  paths enforce is worse than not advertising it.
- **Irreversible actions get their own gesture.** Code and password — a tap (amber); wipe —
  hold 5 s (red); backup — double tap (blue). A tap never wipes and never exports; a hold
  never exports; a double tap never wipes. Password on a tap is the maintainer's decision of
  2026-09-08 — do not reintroduce a separate hold. A new command with consequences gets a
  new gesture, not an existing one.
- **`unsafe`** only with a comment on why it is unavoidable; in the frame parser, never.
- **No `alloc`.** Everything on the stack and in statics; every buffer size is known ahead.

---

## Project specifics

### A board is a folder

A new board is `firmware/boards/<name>/` and nothing else: copy an existing folder,
**measure the pins with a probe** (never copy from the datasheet — silent breakage), fix
`main.rs`, the chip crates, the target and `board.toml`. `./tools/build-vaultkey.sh` builds
it and embeds its images into the CLI. Acceptance is the same as for any board.

Core requires flash with a 4 KiB sector and word-aligned 4-byte reads and writes (checked in
`Store::new`; the fake flash in tests rejects unaligned access too, because `esp-storage`
without `bytewise-read` behaves that way). Everything else is the board folder's business.

The one board today is the Waveshare ESP32-C6-Zero: USB is a fixed Serial/JTAG
(`303a:1001`), HID is impossible, so passkey will never exist here; one port carries both
the protocol and logs — hence the `VTC2` magic word in frames. Pins and pitfalls:
`docs/hardware.md`.

### Firmware design

- Crates: `esp-hal` (features `esp32c6`, `rt`, `unstable`), `esp-storage`,
  `esp-hal-smartled`, `esp-println` (`jtag-serial`), `esp-backtrace`; RustCrypto:
  `aes-gcm`, `hmac`, `sha1`, `sha2`, `pbkdf2`, `subtle`, `zeroize`; `crc`. Not
  `esp-idf-hal`, not own crypto, not `esp-radio`. Toolchain: stable rustup with target
  `riscv32imac-unknown-none-elf`; no espup, no compiler fork. Read exact API signatures in
  `~/.cargo/registry/src/*/esp-hal-*/src/` rather than recalling them.
- Keys: pre = Argon2id(PIN, salt; 128 KiB, `t` measured for ~1 s on the board); KEK =
  `DeviceKey::mac`(pre) — HMAC with the eFuse key when burned (2026-09-08), otherwise
  `Unbound`; DEK = HMAC(KEK, "vaultkey/dek/v1"); verifier = HMAC(KEK, "vaultkey/verify/v1");
  AEAD with the entry name in the AAD. The header remembers the cost and whether the key is
  chip-bound: firmware answering differently refuses (`Incompatible`) instead of burning
  attempts. PIN is 6–8 digits.
- The entry kind (`oath::Kind`) decides what may leave the device. `Totp` — codes only,
  after a tap. `Password` — the login with no gesture, the password and note after the same
  tap (blob `login_len | login | password_len | password | note`, assembled only by
  `Entry::password`). `Env` — a project `.env` whole, up to `ENV_MAX` = 8000 bytes,
  `KEY=value` lines only (checked by the CLI, not the firmware), after the same tap. The
  single `match` on kind lives in `device.rs`; a TOTP secret has no path to `respond`. The
  kind is in the AAD with the name: a kind byte rewritten in flash breaks the tag instead of
  turning a seed into a password.
- `Env` is never an `Entry` (the constructor returns `None`): the blob lives in 16 slots of
  its own region (`env_*` in `store.rs`), encrypted under a random env key kept in the image
  header sealed under the DEK — a PIN change reseals 60 bytes in the same atomic write and
  leaves blobs untouched. Entry and blob names share one namespace. Everything, `list`
  included, requires the PIN; auto-lock is 2 minutes.
- The only way a TOTP secret leaves the device is the backup (`ExportBegin`/`ExportNext`,
  after a double tap; 2026-09-09): the device reseals every entry and blob under a key
  derived from a passphrase (Argon2id, `Passphrase` 12–128 bytes, without the chip key, so
  the file opens on another board) and returns them one at a time; the host sees only
  ciphertext and assembles a `.vkb`. `ImportBegin`/`ImportItem`/`ImportEnd` is the reverse,
  under the PIN, with no gesture, like `add`: entries are collected in RAM and written as one
  image in `ImportEnd`, blobs immediately after the table is written if it is dirty. A backup
  session is killed by any `load()`, by `lock`, and by the first error. An item's AAD is
  `BACKUP_AAD` plus its index in the file: a reordered or altered item does not open
  (`BadBackup`).
- Secrets and PINs never come from command arguments or environment variables: the CLI asks
  hidden or reads a line from stdin, and holds them in `Zeroizing`.
- Flash: `store.rs` knows *how*, the board says *where* (`Layout` in its `main.rs`; on
  C6-Zero 0x110000..0x17B000, raw flash past the `factory` partition, which the stock
  partition table does not describe). The PIN header and the entry table (256 slots of
  `SECRET_MAX` = 256 bytes) are **one** image, two A/B copies with a serial and a CRC; a PIN
  change is atomic. Every `add` rewrites the whole image, and the cost is erasing its sectors
  (~45 ms each): 512-byte slots gave 1.7 s per write, hence 256. The ~80 KiB image lives in
  RAM in a single instance — `State` in the board's static, filled in place by `Device`.
  `Store` remembers only which copy is newer, never the content; `pin_status` answers from
  the 12-byte head of each copy without a CRC — it is the shell's status tick once a second.
  Never pass or return `State` by value: the stack is 308 KiB and three copies overflowed it.
- The `.env` region is 16 slots, two copies over 2 sectors, each with its own serial and CRC;
  a damaged copy reads as empty, not `Corrupt`, because an interrupted write of a new blob
  has no older copy to roll back to. One blob in RAM — a static buffer, sealed and opened in
  place. A host request is read into a stack buffer of `MAX_PAYLOAD` bytes: a blob travels in
  one frame, no chunking. The attempt counter is a separate sector; an attempt is one word
  write with no erase, only via `NorFlash::write`.
- Entropy: `TrngSource::new(RNG, ADC1)` before `Trng::try_new()`; do not drop the handle.
- Acceptance happens on the board, in two tiers, because the full test wipes the device and
  a working key cannot be wiped after every change:
  - After **any** firmware change: `vkey totp selftest` green — one tap, destroys nothing,
    proves the live code against an independent HMAC. This one is not optional.
  - Before a **release**, and on every new board: `vkey check --wipe-everything` green too
    (it says when to tap, when to double tap and when to hold). It leaves the device with
    no PIN and no entries, so run it on an empty board — never on a key holding secrets.
    Without a spare board, say plainly in the release that the full lifecycle test was not
    re-run, rather than pretending it was.

  Gesture rules are proven on the host (`firmware/core/tests/key.rs`); the board verifies
  the hardware honours them.

### Points of no return

**eFuses are irreversible.** Secure Boot, Flash Encryption and HMAC keys burn the chip
forever. Never burn an eFuse without a direct instruction from the maintainer — and even
then the maintainer runs `espefuse.py` personally, following `docs/hardware.md`, after
`summary`. No wrappers around burning in the CLI or scripts: once per board, irreversibly,
and not one line away from an everyday `setup`. The firmware detects a burned key itself
(`ChipKey::detect`). The HMAC key was burned 2026-09-08, Secure Boot v2 on 2026-09-09.

### Build after firmware changes

After any change under `firmware/`, run `./tools/build-vaultkey.sh`: it builds each board
folder (from that folder, so its `.cargo/config.toml` applies), fails if a radio crate
appeared in `firmware/Cargo.lock`, writes `images/vaultkey.bin` and rebuilds the CLI, since
images are embedded in the binary; then `cli/target/release/vkey install`. Commit images
with the firmware change. After a change under `cli/`, `cargo build --release` and `vkey
install`.

Bootloaders and the partition table are built from the board's `bootloader/` folder in an
ESP-IDF 5.5 Docker image by `./tools/build-bootloader.sh`, only when `bootloader/` changes.
There are two: a plain bootloader, and a Secure Boot v2 one for a chip where
`SECURE_BOOT_EN` is already burned. `vkey setup` asks the ROM (`GET_SECURITY_INFO`) which to
flash, because a Secure Boot bootloader on a plain chip **burns the eFuse itself** on first
boot. Signed images (`*.signed.bin`) come from `./tools/sign-vaultkey.sh` with the signing
key held in vkey itself (PIN and a tap) after every firmware change; a hook verifies a
signed image is the unsigned one plus a signature under `firmware/secure-boot/public.pem`.
The partition table sits at 0xC000, because the Secure Boot bootloader does not fit below
0x8000.

Compilation is the **only** exception to the check rule. Linters, formatters, tests and
static analysers are not run without a direct request: git hooks in `.githooks/`
(`tools/checks.sh`) run them on pre-commit and pre-push. When the maintainer sends the
output of a failed `git commit`, fix what broke the hook and repeat the commit.

### Types and lints

Both `Cargo.toml` files carry the same `[lints]` table: `unsafe_code = "forbid"`,
`clippy::all` and `clippy::pedantic` as errors, `unwrap_used` denied. Any relaxation is a
targeted `#[expect(lint, reason = "...")]` (`#[allow]` is denied by `allow_attributes`):
when the reason disappears, the compiler says the `expect` is no longer needed.

Invalid state does not exist as a value: `Pin`, `Name`, `Params`, `Entry`, `Record` are
built only by constructors returning `Option`; in the CLI likewise `EnvBlob`. Parsing from
the wire and from flash happens once, at the edge (`proto.rs`, `store.rs`), and nothing
revalidates afterwards. The protocol is `firmware/core/src/wire.rs` and the CLI compiles the
same file: a command, error code or flag that is not there exists on neither end of the
cable. Add a new validity condition to the type's constructor, not to the call site.

### Working with the board

- Do not hardcode the port: after flashing or a reset `ttyACM0` may become `ttyACM1`. Find
  it by VID `0x303A`.
- `pkill -f <pattern>` matches the shell that contains the pattern and kills the session.
  Kill by PID.
- After a `cd` in a command, relative paths do not lead where they seem to. Use absolute.
- A session without the `dialout` group cannot open the port; espflash says "busy or doesn't
  exist" and `vkey` says "no permission". Fix: re-login after `usermod`; in scripts,
  `sg dialout -c '...'`.
- Firmware logs go to the same USB port as the protocol. Watch with `espflash monitor`;
  `cat /dev/ttyACM0` stays silent.
- Before a physical test, confirm the board runs the intended firmware: `info` returns the
  version and the board name.
- Do not guess the device PIN: every wrong attempt costs one of eight. Only the maintainer
  knows it. `check --wipe-everything` wipes the device and leaves it **without a PIN**; test
  PINs live only inside `check`. After each such run, tell the maintainer their PIN and
  entries were wiped.

### Shell rendering

`cli/src/shell.rs` draws the frame itself through `crossterm` in raw mode: a captioned rule,
the input line, menu lines, a rule, the status line — exactly as many lines as needed, the
cursor always on the input line. The transcript is printed above the frame (`out()`: erase
the frame, print, draw again; in raw mode use `\r\n`). The status line is never wider than
one line; the frame is never taller than the terminal. On resize: draw nothing during the
event storm, then after 120 ms of quiet move up by as many physical lines as the old top rule
now occupies (`ceil((old_width-1)/new_width)`), erase downward and draw. No TUI frameworks —
their hidden decisions are exactly what produced artifacts.

Check the look in a real VTE, not by eye: `tools/tui_snap.py` drives the shell with keys and
resizes and prints the screen with the scrollback. Every rendering change gets a resize storm
run (40 ms and 150 ms), a scenario with the menu open, and a prompt flow.

### Documentation is part of the product

`docs/threat-model.md` is not a formality. Project failure is defined as "shipping an unsafe
product", so any change that affects the threat model updates that file in the same change
set. The list of forbidden marketing claims lives there — honour it in the README, in
descriptions and in commits.

What was investigated and rejected is recorded with its reason so it is not re-argued:
security decisions in `docs/threat-model.md`, hardware and build decisions in
`docs/hardware.md`, permanently closed directions in the README.
