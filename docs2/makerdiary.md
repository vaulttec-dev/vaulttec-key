# Next board: Makerdiary nRF52840 MDK USB Dongle

Research notes of 2026-10-03. The board was ordered on 2026-10-03. Decided: passkey is back,
on Trussed. Since 2026-10-04 the board folder builds vkey for the chip (no Trussed yet); it
has not run on a board.

## Goal

One key that does both: what vkey does today (TOTP, passwords, `.env`, `vkey auth`) and
passkey/FIDO2 over USB HID. NFC is optional, nice to have later.

The C6-Zero cannot do passkey: its USB is a fixed Serial/JTAG, so HID is impossible. That
is the hardware reason passkey was closed. A board with native USB removes that reason.

**Passkey reopened 2026-10-03, maintainer's decision.** README, `docs/hardware.md` and
`docs/threat-model.md` still describe the C6 truthfully and change in the same change set as
the passkey code.

## Passkey stack: Trussed (decided 2026-10-03)

**Maintainer's decision 2026-10-03: passkey is built on Trussed + `fido-authenticator`.** No
own CTAP2 implementation; project rules change where Trussed requires it.

| Option | Fit | Verdict |
|---|---|---|
| **Trussed + `fido-authenticator`** (Nitrokey 3, Solo 2) | Rust, `no_std`, `heapless`; CTAP2.1 in production on Nitrokey 3A Mini, which is an nRF52840 | **chosen** |
| Google OpenSK | Rust, complete | rejected: built around Tock OS and `alloc`; development has slowed |
| Own authenticator on `ctap-types` | least code on the device | rejected: see below |

Why not our own, so it is not re-argued:

| | Own CTAP2 | Trussed |
|---|---|---|
| Code we write | ~3–5k lines (more than the whole current firmware) | ~1–2k lines of glue |
| First browser login | ~1–1.5 months | ~2–4 weeks |
| Production-hardened | months to years of platform quirks (Windows, macOS, iOS, Android) | already, on Nitrokey 3 and Solo 2 |
| Hardest part | PIN protocol 2 (ECDH, HKDF, AES-CBC, permission tokens): a bug is a silent UV bypass | dependency versions: Nitrokey pins git revisions |
| Reviewed by | nobody | Nitrokey, SoloKeys and their users |

Correctness and security rank above simplicity: a vetted stack beats fresh code of our own,
even a bigger one. The price is accepted: a large dependency tree, littlefs in C, two
storages, two PINs, no passkey backup.

Plan:

1. Run the plain Nitrokey nRF52 firmware (NK3 Mini runner) on the Makerdiary board: pins,
   button, LED, flash layout. Prove a passkey login in a browser.
2. Only then embed vkey next to it: its own USB interface, its own flash region.
3. Rewrite CLAUDE.md rules that change (storage, C dependency, crypto backends) in the same
   change set as the first Trussed code.

What Trussed brings, and the rules it changes:

- **Its own storage:** littlefs (a C library behind `littlefs2`) in a flash region of its
  own. The board layout splits flash into the vkey region and the Trussed region. Changes the
  rules "core requires … / `store.rs` knows how" (two storage engines) and the implicit
  pure-Rust firmware.
- **Its own crypto service and key store** for FIDO keys. "Crypto from RustCrypto" holds
  only if the RustCrypto backends are chosen in Trussed features; check before building.
- **Its own architecture:** apps (FIDO, maybe later vkey itself) talk to the Trussed
  service; USB goes through `usbd-ctaphid` + `ctaphid-dispatch`. The vkey protocol keeps its
  own USB interface next to CTAPHID.
- **Its own user presence hook:** Trussed's `UserInterface` asks for a touch; map it to the
  tap (amber). `reset` must be the 5 s hold.
- Start from the Nitrokey nRF52 runner (`nitrokey-3-firmware`, NK3 Mini), not from scratch.

Open questions before code:

- **No `DeviceKey` on nRF52840.** There is no eFuse HMAC key, so the KEK is `Unbound` and
  `Auth` items are refused. Candidate: a secret in a flash page that boot code reads and then
  locks with the ACL peripheral until reset, plus APPROTECT. CryptoCell-310 KDR needs
  Nordic's closed binary library — rejected unless nothing else works.
  Trussed needs a device secret too, so one mechanism serves both.
- **CTAP PIN vs vault PIN.** With Trussed they are separate by default: the FIDO PIN lives
  in Trussed's store, the vault PIN in `store.rs`. Merging them means changing Trussed.
- **Backup.** Passkeys in Trussed's store are not in the `.vkb` backup. Losing the key means
  re-enrolling passkeys on every site; keep a second factor registered everywhere.

## Memory map (decided 2026-10-03)

The Makerdiary dongle has no external flash: 1 MiB flash and 256 KiB RAM, all inside the
nRF52840. Sizes are taken from Nitrokey's own nRF52840 devices (`memory-regions` in
`nitrokey-3-firmware`): NK3 Mini splits 0x1000..0xEC000 into firmware and an 80 KiB
filesystem and claims up to 100 passkeys; the FIDO-only Nitrokey Passkey firmware is
≈230 KiB (v1.1.0 release, from its Intel HEX size).

| Range | Size | What |
|---|---|---|
| 0x00000..0x01000 | 4 KiB | MBR |
| 0x01000..0x97000 | 600 KiB | firmware: vkey + Trussed + FIDO, ≈420 KiB by the fit check below |
| 0x97000..0x98000 | 4 KiB | vkey attempt counter |
| 0x98000..0xB8000 | 128 KiB | vkey image copy A (32 sectors) |
| 0xB8000..0xD8000 | 128 KiB | vkey image copy B (32 sectors) |
| 0xD8000..0xEC000 | 80 KiB | Trussed littlefs (passkeys), as on NK3 Mini |
| 0xEC000..0x100000 | 80 KiB | Nordic secure bootloader, MBR params, bootloader settings |

- **Vault: 128 KiB per copy** (32 sectors, C6 has 53). The maintainer's backup of
  2026-09-14 was 15 KB; 100–200 entries are expected. `STATE_SECTORS` stops being a core
  constant: the board gives the region size in `Layout`, because a second board with a
  different value now exists.
- **No A/B updates.** Two firmware copies need over 800 KiB and do not fit at any vault
  size. The bootloader updates in place; an interrupted update leaves the board in the
  bootloader until a valid signed image arrives.
- **Bootloader: Nordic secure bootloader**, as Nitrokey uses on this chip (C, nRF5 SDK,
  built in Docker like the C6 bootloader; Nitrokey's `utils/nrf-bootloader` is the
  reference). The CLI speaks Nordic DFU to it. `NRF_DFU_APP_DATA_AREA_SIZE` must cover the
  vault and littlefs, 0x97000..0xEC000 (340 KiB): otherwise an update erases the secrets.
  Open: where the DFU signing key (ECDSA P-256) lives.
- **RAM: decided after the stack is measured on the board.** `MAX_ENTRIES` stays 256
  (100–200 entries expected). If RAM is short, the candidates are the item size (8 → 4 KiB
  frees ≈12 KiB) and, last, Argon2 memory (128 → 64 KiB frees 64 KiB but halves the cost of
  each PIN guess after a flash dump, and C6 backups open only if both boards change).

### Fit check, measured 2026-10-03

Nitrokey Passkey v1.1.0 built for thumbv7em-none-eabihf (stable 1.97.1, Arm GNU toolchain
14.2.rel1 for its C code): the whole Trussed + `fido-authenticator` + USB + RTIC firmware.
vkey from the current C6 build (`firmware/target/riscv32imac-unknown-none-elf/release`).

| Flash, 600 KiB firmware region | KiB | How |
|---|---|---|
| Trussed, FIDO, USB, RTIC | 223 | measured: `.text` + `.rodata` + `.data` + vectors |
| vkey without ESP code | ≈185 | measured on RISC-V (209 KiB code, 20 KiB of it ESP crates); Thumb-2 is similar |
| nRF HAL, USB CDC | ≈10–20 | estimate |
| **Total** | **≈420** | ≈180 KiB headroom |

| RAM, 256 KiB | KiB | How |
|---|---|---|
| vkey statics: Argon2, item buffer, index | 156 | measured: C6 `.bss` + `.data` |
| Trussed, FIDO, USB statics | 44 | measured: `.data` + `.bss` + `.uninit`, incl. NFC/CCID channels |
| nRF extras | ≈2 | estimate |
| **Statics total** | **≈202** | **≈54 KiB left for the stack** |

The stack is the one unknown: vkey's peak is ≈12–16 KiB (an 8 KiB frame on the stack plus
crypto), Trussed's is not measured. With vkey and FIDO served from one loop the peak is the
larger of the two plus interrupts, so 54 KiB is likely enough. Measure on the board by
painting the stack at boot and reading the high-water mark over SWD.

Found while building:

- **Trussed's P-256 on this chip is C and assembly**, not RustCrypto: `p256-cortex-m4`
  uses `p256-cortex-m4-sys` (P256-Cortex-M4) whenever it builds for a Cortex-M4 and falls
  back to RustCrypto `p256` only elsewhere. Keeping "crypto from RustCrypto" means patching
  that crate; accepting it adds a second C dependency next to littlefs.
- **The firmware build needs an ARM C toolchain** (`arm-none-eabi-gcc` with newlib
  headers) for those C parts; clang alone fails on `string.h`. `tools/build-vaultkey.sh`
  has to provide it, like the Docker image does for the C6 bootloader.

## Linux login (`sudo`, lock screen)

Decided 2026-10-03: the new key is the base. `sudo vkey auth enable` stays the one command
a user runs, but on the nRF52840 it sets up **`pam_u2f` over FIDO2**, the scheme every
other key uses (YubiKey, Nitrokey, SoloKeys, Token2): a FIDO2 credential with RP ID
`pam://<host>`, the mapping in `/etc/u2f_mappings`, one `sufficient` line in PAM, originals
kept as `*.before-vkey`. The same FIDO2 credential type also gives SSH (`ed25519-sk`) and
LUKS unlock (`systemd-cryptenroll --fido2-device`, needs `hmac-secret`).

Why not keep the current `vkey auth` on the new board: it needs the chip key, which the
nRF52840 lacks, so the firmware refuses it (`Incompatible`). pam_u2f needs no chip key, no
`pam_exec`, and no copy of `vkey` in `/usr/local/bin`.

Other schemes, not chosen: `pam_yubico` (Yubico OTP or HMAC-SHA1 challenge-response,
legacy), `pam_p11`/sssd smartcard (PIV certificates, enterprise setup).

The current Ed25519 `vkey auth` stays only while the C6 is in use, and is isolated so it can
be cut in one change. Its whole surface (2026-10-03):

| Where | What |
|---|---|
| `cli/src/auth.rs` | the whole feature: PAM lines, `/etc/vkey/auth/<user>`, challenge, verification |
| `cli/src/main.rs` | `Auth` subcommand dispatch; `USED_BY_AUTH` refusal on `get` |
| `cli/src/shell.rs` | `USED_BY_AUTH` refusal |
| `cli/src/check.rs` | the auth section of the lifecycle test |
| `cli/src/device.rs` | `respond` |
| CLI, by category | `Category::Auth` in `item.rs`, `sources.rs`, `op.rs`, `backup.rs`, `main.rs` |
| `firmware/core/src/wire.rs` | `Respond` command, `AUTH_CHALLENGE_LEN`, `AUTH_SIGNATURE_LEN`, `AUTH_SIGNED_PREFIX` |
| `firmware/core/src/item.rs`, `oath.rs` | `Category::Auth`, `AUTH_SECRET_LEN` |
| `firmware/core/src/vault.rs` | `auth_key` |
| `firmware/core/src/device.rs` | `item_key`, the carry-over in `reseal_all`, the refusal in `open_named`, `respond`/`sign_with` |
| `firmware/core/src/proto.rs` | parsing of `Respond` |

Removing `Category::Auth` makes the compiler list every remaining site. The general atomic
file write that used to live in `auth.rs` moved to `cli/src/file.rs`, so nothing unrelated
depends on the auth module any more.

## Why nRF52840

| | nRF52840 | RP2350 | ESP32-S3 |
|---|---|---|---|
| USB HID | yes | yes | yes |
| NFC | built-in NFCT (ISO 14443-A), antenna only | no | no |
| Vault storage | internal flash | external QSPI flash | external flash |
| Chip-bound key | none comparable to the C6 eFuse HMAC key | OTP with page locks | eFuse HMAC |
| Secure Boot | no (own signed bootloader instead) | yes | yes |
| Rust on stable, no compiler fork | yes | yes | **no** — Xtensa needs espup |
| Existing Rust FIDO2 | Trussed (`fido-authenticator`, Nitrokey 3A Mini) | C only (pico-fido) | none |

- **Internal flash.** The PIN attempt counter cannot be reset by desoldering or rewriting
  an external flash chip. On RP2350 it can.
- **Core fits unchanged.** 4 KiB pages, 4-byte word writes — exactly what `Store::new`
  checks. The new board is a folder under `firmware/boards/`.
- **ESP32-S3 is rejected** by the project rule: no espup, no compiler fork.

## Why Makerdiary over other nRF52840 dongles

| Board | USB | Case | Button | LED | Verdict |
|---|---|---|---|---|---|
| **Makerdiary MDK USB Dongle w/ Case** | A | plastic 50.8×21.1×7.6 mm | 1 | **RGB** | **chosen** |
| Nordic PCA10059 | A | none (3D-printed OpenSK case) | 1 | RGB | cheaper, no ready case |
| Raytac MDBT50Q-RX | A | plastic | 1 | blue only | one colour is not enough for gestures |
| Raytac MDBT50Q-CX | C | stick, case unconfirmed | 1 | 2 separate | only option worth a look if USB-C matters |
| I-SYST USB-C dongle | C | optional, unconfirmed | 1 | RGB + 1 | small maker, low stock |
| Ebyte E104-BT5040U | A | blue removable shell | 2 (one reset) | — | looks like a generic BT adapter |
| Holyiot HOLYIOT-nRF52840-USB | A | — | unknown | unknown | no schematic, SWD-only, not a PCA10059 |

Makerdiary is the only one with all of: RGB LED (amber/red/blue gestures), a button, NFC
tuning capacitors already fitted (100 pF; only the coil is missing), UF2 bootloader, an
open schematic and a presentable case.

Pins from the Makerdiary wiki (still to be **measured with a probe**, per project rules):

| Function | Pin |
|---|---|
| USER/RESET button | P0.18, active low |
| LED red / green / blue | P0.23 / P0.22 / P0.24, active low |
| NFC1 / NFC2 | P0.09 / P0.10 |

## Known limits

- **The case protects nothing.** It is a removable plastic shell. Opening it exposes the
  chip and SWD.
- **No secure element and no eFuse-style chip key.** APPROTECT on early nRF52840 revisions
  was bypassed by voltage glitching. Buy the newest revision. `docs/threat-model.md` must
  say what this costs before the board holds real secrets.
- **Epoxy potting** (electronics-grade compound) is the only way to get closer to a
  YubiKey physically. Pot only after final flashing and APPROTECT, leaving the button and
  USB free.
- **`vkey auth` does not migrate.** Its key is sealed under the C6 eFuse key; it must be
  re-created and `vkey auth enable` repeated. Items move over a `.vkb` backup (passphrase
  only, no chip key). The Secure Boot signing key held in vkey needs a plan before the move.
- **FIDO2 is the biggest piece of code in the project** (CTAP2.1, COSE, P-256, resident
  keys, PIN protocol). Every line is attack surface.

## Rejected

- **SoloKeys Solo 2 Hacker** (LPC55S69, $35–46, injection-moulded case, Rust/Trussed):
  strong fit on paper, but LPC55 flash has ECC with 512-byte program pages — rewriting a
  word in a programmed page is not allowed, which breaks the one-word attempt counter in
  `store.rs`. Vendor development has slowed. Not chosen for now.
- **Tillitis TKey Unlocked** (RISC-V on iCE40 FPGA): strongest key derivation (own UDS +
  app measurement), but tens of MHz and ~128 KiB app RAM — Argon2id at 128 KiB does not
  fit; apps load from the host each time. Would be a rewrite.
- **Nitrokey 3**: production firmware is signed by the vendor; no hacker edition found.

## To buy

- ~~Makerdiary nRF52840 MDK USB Dongle w/ Case~~ — ordered 2026-10-03.
- An SWD probe (Raspberry Pi Debug Probe or a Pico with debugprobe firmware): needed for
  APPROTECT and recovery. Check that SWD pads are reachable on the Makerdiary board.

## Board folder: `firmware/boards/nrf52840-mdk-dongle` (built 2026-10-04)

vkey alone, no Trussed yet: the same core as the C6, behind the four HAL traits.

| Part | What it is |
|---|---|
| HAL | `nrf52840-hal` 0.19, `cortex-m-rt` with `set-vtor` (the MBR hands over to 0x1000) |
| Port | USB CDC-ACM through `usb-device` + `usbd-serial`, polled from the main loop; VID/PID `1209:0001`, pid.codes' test pair |
| Clock | SysTick exception, 1 ms. Not a counter read on demand: the auto-lock compares times only when the next request comes, so a counter that wraps between requests would keep an idle key unlocked |
| Ui | button P0.18, LEDs P0.23/P0.22/P0.24, all active low, from the wiki; amber = red + green |
| Flash | `Nvmc` over 0x97000..0xD8000 behind a wrapper that fences after every erase and write |
| Entropy | the RNG peripheral, bias correction on |
| DeviceKey | none: `bound() == false`, PIN only, `vkey auth` refused |

Measured on the build: 72 KiB of code, 154 KiB of statics, ≈101 KiB left for the stack.

Rules changed for it (maintainer's decision 2026-10-04): the board has its own lint table
with `unsafe_code = "deny"` for the one `unsafe` in `vault_region`; `tools/checks.sh`
keeps the rest identical. Core changes that came with it: the image copy's size moved from
the `STATE_SECTORS` constant into `Layout::state_sectors` (C6 keeps 53), and the test
flash refuses a third write to a word between erases, the nRF52840's limit.

Known gaps, by design until the board is in hand:

- **USB is serviced only between operations.** During Argon2 (expected ≈3 s at 64 MHz)
  or a flash write the host waits; a control request in that window waits too. If that
  breaks enumeration or `vkey`, USB moves to an interrupt, which is a second `unsafe`
  (unmasking it).
- ~~Argon2 cost is the C6's~~ Done 2026-10-13: the cost is a board value (`KDF_COST` in
  each `main.rs`, handed to `Device::new`). Here it is 20 passes. 48 had measured 2645 ms
  through `vkey check`. With 20 the same unlock takes 1128 ms. The C6 keeps 48.
- **No chip key.** The ACL-locked secret is the next design step.
- **No radio code**: the lock-file check proves nothing here. Since 2026-10-13
  `build-vaultkey.sh` searches the image for the radio's slot (`radio_base` in
  `board.toml`) and finds nothing. The same search finds 24 references to USB, 10 to the
  flash controller and 4 to the RNG. It catches direct addressing only, not a base plus
  offset from a neighbouring peripheral.

## Factory state (board arrived 2026-10-13)

Seen on the bus: `1915:c00a` "nRF52 Connectivity" (Nordic's connectivity firmware for
nRF Connect), one CDC-ACM port. Holding the button while plugging in starts the UF2
bootloader instead (drive `UF2BOOT`, green LED). Its layout, from the Makerdiary wiki:

| Region | Address | Size |
|---|---|---|
| MBR | 0x00000 | 4 KiB |
| Application | 0x01000 | 972 KiB |
| UF2 bootloader | 0xF4000 | 38 KiB |
| Bootloader config | 0xFD800 | 2 KiB |
| MBR parameters | 0xFE000 | 4 KiB |
| Bootloader settings | 0xFF000 | 4 KiB |

No SoftDevice. The application starts at 0x1000, as `memory.x` assumes, and the vault
(0x97000..0xD8000) misses the bootloader, so the board folder needs no change to run under
it. A UF2 is made from `images/vaultkey.bin` with family `0xADA52840` and base 0x1000
(`uf2conv -f 0xADA52840 -c -b 0x1000`). Until our own fork of this bootloader replaces it
(`docs2/roadmap.md`, phase 3; Nordic's secure bootloader was dropped for want of a probe)
the board holds no real secrets, because UF2 flashes anything and its `CURRENT.UF2` reads
the vault's ciphertext out.

Open questions only the board answers:

- ~~Is P0.18 the pin reset?~~ No (2026-10-13): pressing the button under the factory
  firmware did not re-enumerate the board (`udevadm monitor` stayed silent), so UICR
  `PSELRESET` is not set and P0.18 is a plain GPIO. Adafruit's `board.h` marks it
  "unusable: RESET", but that does not describe this unit.
- ~~Is the vault region blank?~~ Yes: the factory `CURRENT.UF2` (bootloader 0.7.1, dated
  2023-07-20, S132 5.1.0 plus the connectivity app in 0x1000..0x35000 and one page at
  0x50000) is all 0xFF over 0x97000..0xD8000. Kept at `~/mdk-factory/`, sha256
  `3022eb28...6aab`; it restores through the same drive.
- ~~Green LED on P0.22?~~ Yes, as far as `vkey check` shows: Adafruit's `board.h` lists
  only red P0.23 and blue P0.24, but amber is red plus green, and the taps on amber went
  through. Red alone (the 5 s hold) has not been watched yet.

- ~~Which revision?~~ **Revision 2** (2026-10-13, the `chip:` line after a replug):
  `nRF52840 AAD0, UICR APPROTECT 0xffffffff, last reset: power-on`. On revision 2 an erased
  `APPROTECT` means the debug port is open: anyone with an SWD probe reads the whole flash
  today. Revision 2 also lacks the fix for the published APPROTECT glitch (IN-133), so
  closing the port in UICR stops a probe but not someone with glitching gear. The bootloader
  reports nrfx 2.0.0 in `INFO_UF2.TXT`.

### Reading the `chip:` line of `vkey info`

The firmware reads three things at boot and `vkey info` prints them (phase 1 of
`docs2/roadmap.md`), so the questions a probe would answer need none:

- **Build code** (FICR `INFO.VARIANT`, ASCII): `AAC0` is revision 1, `AADx` revision 2,
  `AAF0` revision 3 (IN-141). Anything else: Nordic's IC revision overview.
- **UICR `APPROTECT`**, the word as stored. Its low byte decides, and what it means depends
  on the revision:

  | Low byte | Revision 1-2 | Revision 3 |
  |---|---|---|
  | `0xFF` (erased) | debug port open | closed |
  | `0x5A` (HwDisabled) | not a defined value; unverified | open only if the firmware also writes `APPROTECT.DISABLE` at every boot |
  | `0x00` (Enabled) | closed | closed |

  Our firmware never writes `APPROTECT.DISABLE`. The factory bootloader runs first, and
  Nordic's `SystemInit` writes it when UICR holds `0x5A`; whether this build does is not
  checked, so `0x5A` counts as open on every revision.
- **Last reset**, from `RESETREAS`, cleared once read. `soft reset` is either our panic
  handler or the bootloader restarting after a flash. A power-on reset clears every bit,
  so a board that has to be replugged reports `power-on` and nothing about what came
  before. The case behind the first unexplained failure (a reset with the button down,
  the board left in the UF2 bootloader, then replugged) is exactly that, so this line
  cannot explain it. It does catch a lockup, a watchdog or a panic the board recovered
  from by itself.

First run, 2026-10-13. `images/vaultkey.bin` was converted to UF2 (family `0xADA52840`, base
0x1000) and copied to `UF2BOOT`. Read back through `CURRENT.UF2`, it matched byte for byte.
The warm start straight from the bootloader after the copy did not enumerate (`device
descriptor read -110`). A replug did: `1209:0001 vaulttecdev vkey`, and `vkey info` answered
`vaultkey 0.9 nrf52840-mdk-dongle`, PIN not set, 8 attempts, PIN only. After flashing, replug.

`vkey check --wipe-everything`, the same day, second run: every check passed but one. That
covers tap (amber), one tap refused for a backup and two taps accepted (blue), backup and
restore, lock, the attempt counter, the wipe after 8 wrong PINs, `auth` refused without a
chip key, and selftest against an independent HMAC. So the button on P0.18 and the red and
green LEDs work. The one failure is Argon2: the key derivation with the C6's cost takes
2645 ms against the 2 s limit, so the cost has to become a board value.

The first run died at "no code from a password". That step lights amber with no prompt in
the CLI. The board left the bus and came back in the UF2 bootloader, which starts when the
button is held at reset. The second run passed the same step, and an untapped amber at
"no code from an env" ended in a plain `Refused`. The cause is unknown. Suspects: a reset
while the button was down, and USB going unserviced for up to 30 s while a tap is awaited.
- **ModemManager** is active on the maintainer's machine and may probe a new CDC-ACM port.

## First steps when it arrives

> Superseded 2026-10-13 by `docs2/roadmap.md`. The board ran over UF2 without a probe,
> step 4's reset question is answered (P0.18 is a GPIO), and the order of everything after
> step 5 is in the roadmap. Kept for the record.

1. Confirm the chip revision and that the board is genuine.
2. Wire the SWD probe. Save what is on the board first: the factory UF2 bootloader is
   erased by the next step and only comes back from Makerdiary's published hex.
3. Erase the chip and write Nordic's MBR (from the nRF5 SDK) plus
   `images/vaultkey.bin` at 0x1000. With no bootloader address in UICR, the MBR starts
   the application at 0x1000.
4. Check UICR `PSELRESET`: if P0.18 is the pin reset, switch it to a plain GPIO, otherwise
   tap, double tap and hold cannot work. Measure the button and LED pins with a probe.
5. `vkey info` must answer with `nrf52840-mdk-dongle`; then `vkey totp selftest` and, on
   the still-empty board, `vkey check --wipe-everything`.
6. Measure the stack's high-water mark and the Argon2 time.
7. Replace the MBR-only setup with the Nordic secure bootloader that accepts only firmware
   signed by the maintainer's key. UF2 flashes anything - on a key holding secrets that
   is a hole.
8. Record the choice and the rejected options in `docs/hardware.md`.

## Sources

- https://makerdiary.com/products/nrf52840-mdk-usb-dongle-w-case
- https://wiki.makerdiary.com/nrf52840-mdk-usb-dongle/hardware/
- https://www.aliexpress.com/item/32971420565.html (52Pi)
- https://www.thingiverse.com/thing:4132768 (OpenSK case for PCA10059)
- https://www.raytac.com/news/ins.php?index_id=176 (MDBT50Q-CX)
- https://www.adafruit.com/product/5199 (MDBT50Q-RX)
- https://solokeys.com/collections/hacker
- https://www.tillitis.se/products/tkey-unlocked/
