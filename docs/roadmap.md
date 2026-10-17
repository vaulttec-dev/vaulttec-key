# Roadmap: the nRF52840 key

Constraints: no SWD probe and no spare board, ever. Every bootloader or UICR step happens
only while the board holds nothing a `.vkb` cannot restore, on the maintainer's explicit go.
**Real secrets go onto the nRF when phases 3-5 are done**; they are. The full record of
each phase, with every check and measurement, is `git show 72172f3:docs/roadmap.md`.

## Phase 0 - close the work of 2026-10-13

Done: the audit exception for RUSTSEC-2026-0344 (`cli/.cargo/audit.toml`). Not recorded as
done: a live check that two keys plugged in give "more than one key", and re-signing and
flashing the C6.

## Phase 1 - a board that reports itself

Done 2026-10-13: the `chip:` line in `vkey info` ([`makerdiary.md`](makerdiary.md)).
Deferred: moving the C6 docs into its board folder.

## Phase 2 - the revision gate

Revision 2 (`AAD0`): the boot-time APPROTECT glitch stays open. Risk accepted
(maintainer, 2026-10-13).

## Phase 3 - our own UF2 bootloader

**Accepted 2026-10-14.** A fork of `Adafruit_nRF52_Bootloader` 0.9.2 with the board
definition read back from the factory 0.7.1, built reproducibly in Docker by
`tools/build-bootloader.sh` from `firmware/boards/nrf52840-mdk-dongle/bootloader/`:

- `0001` no UICR writes (upstream's `SystemInit` would make P0.18 a reset pin forever);
- `0002` the drive only: no serial DFU, no BLE OTA, no double-reset entry;
- `0003` no read-back: no `CURRENT.UF2`, raw sectors read as zeros;
- `0004` app writes only to 0x1000..0x97000;
- `0005` Ed25519 (Monocypher) signature over the app checked on every boot, signed
  self-update only; slot `VKS1` at 0x96000 for the app, 0xFDF00 for the bootloader;
- `0006` no SoftDevice probe in the USB clock code;
- `0007` the as-app test build.

Checks: `bootloader/check.py` (no UICR address in the code), `bootloader/test/run.sh`
(17 signature cases under qemu-arm before every build), and milestone 4, the on-board
test: the same sources as an app at 0x1000 under the factory bootloader
(`test/app_test.c`, `test/board.sh`), which reports its verdicts in `INFO_UF2.TXT`.
Signing key fingerprint `a1700ebd539b0bfc`. Open: the instruction cache is off during the
check (a speed-up), and the as-app harness must be adapted to the real key before the
fork's next change.

## Phase 4 - APPROTECT

**Accepted 2026-10-15.** The firmware writes UICR `APPROTECT` = Enabled once at boot
(`protect` in `main.rs`), no retry; updates through the fork still work.

## Phase 5 - chip key

**Skipped 2026-10-15.** Both options (an ACL-locked flash secret, or CryptoCell's KDR)
load from flash at boot, so the same glitch reads them. `vkey-signing`, the C6's Secure Boot
key, now lives on the nRF too. Deferred: moving C6 flashing out of the CLI so `espflash`
and its audit exception leave, until the C6 may be touched.

## Phase 6 - passkeys (FIDO2)

All accepted 2026-10-15/16:

1. USB served during every wait (polled, no interrupt).
2. A composite device: CDC for vkey, CTAPHID for FIDO.
3. Trussed + `fido-authenticator`; Argon2's 128 KiB moved to the stack.
4. `vkey auth` became `pam_u2f`; the Ed25519 scheme removed (`4bd49f3`).
5. Passkeys in the `.vkb`.
6. Room for more passkeys: vault copies 32 → 24 sectors, littlefs 20 → 44 blocks.
7. A restore takes the wipe's hold.

## Phase 7 - the login password typed by the key

Built 2026-10-17 and on the board the same day (maintainer's decision): a boot keyboard on the
nRF that types the login password and Enter on an idle double tap, kept in littlefs,
set by `vkey login set` under the PIN and a tap; while the `login` switch in
`/settings` is on, `cosmic-greeter` skips its tap when root asks (the login, not the lock
screen), and off the login opens with a tap as before. A core change, so the C6's image is rebuilt and signed again. Acceptance on the
board: a `.vkb` first, `selftest`, the `login` switch on, then the COSMIC login after a
reboot and the lock screen each by a double tap with the keyring unlocked, a double tap
with Caps Lock on, `sudo` still by a tap, and the switch off leaving a double tap red and the login screen open to a tap again.
The C6 takes `check --wipe-everything` for the core change; until it does, a release
says it was not run. Seen on the board: the reboot by a double tap with the keyring
open, the lock screen and `sudo` by a tap; Caps Lock and the switch off not yet. The
first image did not enumerate (-110): CDC, CTAPHID and the keyboard make a ~132-byte
configuration descriptor, past usb-device's 128-byte control buffer, hence
`control-buffer-256`.

## Open

- Measure the real passkey capacity (fido-authenticator's estimate is 13).
- macOS and Windows for `vkey auth` and `vkey commits`: issues #18, #19.
- Rewrite README once real secrets are on the nRF.
