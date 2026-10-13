# Roadmap: the nRF52840 key, from bring-up to daily use

Written 2026-10-13, after the first green `vkey check --wipe-everything` on the Makerdiary
dongle. Revised the same day for a constraint the maintainer set: **no SWD probe and no
spare board, now or later.** Decided already, not reopened here: the nRF52840 is the
primary board and the C6 the fallback; Trussed + `fido-authenticator` for passkeys. Board
notes, measurements and the factory state: `docs2/makerdiary.md`.

## What "no probe, no spare" changes

- **Everything happens through USB.** That means the UF2 bootloader and our own firmware.
  Firmware can read FICR and UICR itself, so the chip revision and the protection state
  need no probe.
- **A bootloader bug cannot be undone.** A broken bootloader means a dead board and a new
  dongle. So every bootloader and UICR change is done **while this board is still empty**:
  losing it then costs the dongle, never the secrets.
- **The Nordic secure bootloader is dropped** - a change to the decision recorded in
  `makerdiary.md`. Installing it moves the bootloader address in UICR, which without a
  probe is a one-shot operation with no way back. A fork of the bootloader already on the
  board installs through its own update path at the same address.
- **UF2 stays the transport for good.** `vkey setup` for the nRF copies a signed UF2 to
  the bootloader's drive. That is no longer throwaway work.
- **Test without a spare.** The nRF is empty now, so it is the test board until migration.
  Afterwards the C6, wiped and kept as the fallback, takes the full
  `check --wipe-everything` for core changes. nRF-only changes get `selftest` and a `.vkb`
  backup before each update. A release then says plainly that the full lifecycle test was
  not re-run on the nRF, as `CLAUDE.md` requires.

## The rule that orders everything

**Secrets move to the nRF at security parity, not when features are done.** Today the C6
is the stronger key: the eFuse HMAC key, Secure Boot v2 and JTAG off. The nRF has no chip
key, and its bootloader flashes anything and serves the flash back (`CURRENT.UF2`). A copy
of its flash gives up the PIN offline in hours (`docs/threat-model.md`). Until phases 3-5
are done, real secrets stay on the C6. `espflash` stays in the CLI and the audit exception
stays open until the migration.

The order is fixed by what each step depends on. First the **bootloader** with no read-back
and signed images only: APPROTECT means nothing while UF2 hands out the flash. Then
**APPROTECT**. Then the **chip key**.

---

## Phase 0 - close the current work (now)

1. ~~**Audit exception.**~~ Done 2026-10-13: `cli/.cargo/audit.toml`, item 9 of the
   threat model's known limitations. RUSTSEC-2026-0344 (`ruzstd` 0.8 via `object` 0.39 via
   `espflash`).
   - **No upstream fix yet:** `espflash` 4.6.0 still pins `object` 0.39.
   - **Not reachable here:** vkey uses only `Connection`, `Flasher` and `Segment` and
     never parses an ELF.
   - **The change:** `cli/.cargo/audit.toml` with the reason and the exit condition -
     `cargo tree -i ruzstd` shows ≥ 0.9.1, or `espflash` leaves the CLI. One line in the
     threat model.
2. **Live check of the two-key guard.** With the nRF plugged in, plug in the C6 and run
   `vkey info`. It must say "more than one key".
3. **Re-sign and flash the C6.** Unplug the nRF. Then `./tools/sign-vaultkey.sh`,
   `cargo build --release` in `cli/`, `vkey install`, `vkey setup` **without**
   `--erase`, and `vkey totp selftest`.
4. **`auth enable` on the nRF.** `sudo vkey --port <nRF> auth enable` must refuse at once
   and write nothing to `/usr/local/bin/vkey`.
5. **Commit.** `git add` the whole `firmware/boards/nrf52840-mdk-dongle/` folder with
   `images/`, then commit (the maintainer).

## Phase 1 - true docs and a board that reports itself

- **The docs pass.** Done 2026-10-13 for `CLAUDE.md`, the README (a "two boards" note; the
  full rewrite waits for the migration, since the C6 is the key in use until then) and the
  core comments. `docs/hardware.md` and moving the C6 docs into its folder are deferred:
  they describe the C6 correctly as they are.
  - README, `CLAUDE.md` and `docs/hardware.md` put the nRF first.
  - The C6 docs move into its folder.
  - Numbers that hold only for the C6 are marked: "four years for eight digits", 1.3 s a
    try, 300 KiB of stack, 512 KiB of RAM, `TrngSource`.
  - Core comments become chip-neutral: `proto.rs`, `wire.rs`, `hal.rs`, `PIN_LEN`,
    `item.rs`.
- **What `vkey info` shows from the nRF** (code done 2026-10-13). At boot the firmware
  adds a second line to INFO's answer, which `vkey info` and `vkey check` print as
  `chip:`. The command and the first line are unchanged, and there is no new `unsafe`.
  - the build code from FICR `INFO.VARIANT` - `AAF0` means revision 3;
  - the UICR `APPROTECT` word, raw;
  - the last reset cause from `RESETREAS`, cleared after reading.

  How to read them: `docs2/makerdiary.md`, "Reading the `chip:` line". This answers the
  revision question without a probe. It does **not** explain the first unexplained
  failure. A panic and the bootloader's post-flash restart both read as `soft reset`, and
  the replug that failure needed is a power-on reset, which clears the register. It
  catches a lockup, a watchdog or a panic that the board recovers from by itself.

Acceptance: `vkey info` shows the `chip:` line. `selftest` needs a PIN, and the board has
none after `check`, so on the empty board the acceptance is `check --wipe-everything`.

## Phase 2 - the revision gate

**Read 2026-10-13: build code `AAD0`, revision 2.** So the second case below applies.
**Decided the same day by the maintainer: everything moves to this board, and the glitch
risk is accepted** - the key is for personal use. Phases 3-5 still close what a probe and
UF2 open; what stays open is the lab attacker of IN-133.

- **Revision 3 (build code F).** APPROTECT holds against the published glitch (IN-133,
  mitigated in revision 3). Go on.
- **Older.** Someone who takes the key and has a lab can still open the debug port with a
  glitch. Read the flash out, and the PIN falls offline in hours. The maintainer decides:
  accept it as a physical attack on a key in their own pocket, or keep the important
  secrets on the C6. A revision-3 dongle would be a purchase, so that is the maintainer's
  call too.

## Phase 3 - our own UF2 bootloader (while the board is empty)

A fork of the bootloader already on the board (Makerdiary's build of
`Adafruit_nRF52_Bootloader` 0.7.1, MIT), with three changes:

1. **No read-back.** `CURRENT.UF2` and every other path that serves flash to the host are
   removed.
2. **Signed images only.** The bootloader keeps the incoming image invalid until a
   signature over the whole image verifies. An image that fails never runs, and the board
   stays in the bootloader. The signing key lives in vkey, like the C6's.
3. **Writes only to the application region** (0x1000..0x97000). A UF2 cannot touch the
   vault, the settings or the bootloader itself.

**Built** reproducibly in Docker, like the C6 bootloader. **Installed** with the bootloader
update file its own build produces - the path Makerdiary documents for bootloader updates
from 0.4.0 on. Before installing, read in its source how the copy survives a power cut.
Nordic's MBR offers a power-safe copy, but whether this updater uses it is not confirmed.

**`vkey setup` for the nRF** writes the signed UF2 to the bootloader drive.

**What reading the source found (2026-10-14; desk research, nothing flashed).** Base:
upstream `Adafruit_nRF52_Bootloader`. The factory 0.7.1 source is unpublished, but its
binary is in `makerdiary/nrf52840-mdk-usb-dongle` and its submodules match upstream 0.6.4-0.9.2.
The board definition is Makerdiary's, not upstream's: `UF2BOOT`, `2886:F00F`, the button on
P0.18 as a pull-up GPIO, LEDs 23/22/24. Before anything is built:

- **PSELRESET trap.** Upstream's Makefile defines `CONFIG_GPIO_AS_PINRESET` and
  `CONFIG_NFCT_PINS_AS_GPIOS`. nrfx 2.0.0's `SystemInit` then writes UICR `PSELRESET` = P0.18
  on first boot, which turns the only button into a reset pin for good. The factory build
  has neither define (its `SystemInit` was disassembled). The fork drops both, and its
  `SystemInit` is disassembled before install.
- **Board ID.** The factory bootloader takes a self-update UF2 only with board ID
  `0x2886F00F`, or with none. Upstream's dongle builds carry `0x239A0029` and are refused.
  Upstream's "connect-kit" update UF2s carry `0x2886F00F` and would be accepted, with wrong
  pins and the PSELRESET write, so they must never be used.
- **Every write path has to go or be signed.**
  - The UF2 self-update (family `0xD663823C`) is unauthenticated: anyone holding the
    button can put the stock bootloader back.
  - Serial DFU over CDC writes the app, the bootloader and the SoftDevice. Its pre-erase
    reaches the vault, and its only check is public constants plus a CRC16.
  - BLE OTA.

  Removing serial DFU and BLE OTA is also what frees room for the signature check.
- **Read-back is more than `CURRENT.UF2`.** The generator behind it serves any address
  under 1 MiB, so a raw read past the file's end returns the bootloader and the settings
  too. The generator branch goes, not just the directory entry.
- **A partial UF2 boots.** The settings change only when the transfer completes, so a torn
  upload followed by a replug runs half-new code as valid. The fork verifies the signature
  on every boot in `bootloader_app_is_valid()` and fails closed.
- **Size.** The factory image is 33 044 B, leaving 5 868 B before 0xFD800. Signature check
  code sizes are not measured yet.
- **Install.** A self-update UF2 is the bootloader hex itself. The running bootloader stages
  it at 0xE0000 and has the MBR copy it with `SD_MBR_COMMAND_COPY_BL`, which Nordic calls
  power-fail safe; that claim is not tested here. The update is padded to the whole region.
- **Before installing,** the fork's USB and UF2 logic runs as an ordinary application at
  0x1000 under the factory bootloader, which stays in place and makes this step
  reversible.
- **Self-update in the fork: signed** (maintainer's choice, 2026-10-14). Removing it would
  leave a bug in the bootloader unfixable forever. The update is signed with the same key as
  the app images. A signed image can still be downgraded to an older signed one: a known
  limitation, deferred.

Constraints that come with it:

- **Staging must avoid the vault and Trussed.** Upstream stages a self-update at
  0xE0000..0xEA000, inside the 0xD8000..0xEC000 kept for Trussed in phase 6, so a later
  self-update would erase the passkeys. The fork stages inside the application region, and
  the app is flashed again after a bootloader update.
- **The signing key must exist in two places.** Once everything moves here, a broken app
  leaves the board in the bootloader waiting for a signed image. If the only copy of the key
  is on this board, nothing can sign it. Before the key is generated, decide its second home:
  the wiped C6 as the signing device, or a `.vkb` that restores onto it.
- ~~**The page at 0xFD800**~~ is the CF2 config page (`.bootloaderConfig`, 88 B: board ID,
  family, flash and RAM size), part of the bootloader image inside the 40 KiB that `COPY_BL`
  copies. `check.py` pins it to the factory's words. The code region is 0xF4000..0xFD800.
- **A verify bug is the brick.** If the check rejects valid images, no app boots and no fixed
  bootloader is accepted. So the test build at 0x1000 runs the exact same verify code against
  images from the real signing pipeline, altered ones and a self-update image, with
  `COPY_BL` compiled out and its write window on a scratch area.

Milestones, one commit each:

1. A Docker build that reproduces a factory-equivalent binary: same `SystemInit`, no UICR
   writes, the same board ID. **Done 2026-10-14**:
   - `BOARD=nrf52840-mdk-dongle ./tools/build-bootloader.sh` builds upstream 0.9.2 with
     arm-gnu-toolchain 12.3.rel1, the board definition read back from the factory binary
     and `patches/0001-no-uicr-writes.patch`.
   - The code is 31 312 B, the factory's size, with the same INFO string format and
     submodule versions.
   - `SystemInit` stores only to peripherals, and FICR is only read.
   - `check.py` finds no UICR address in the code and the CF2 block equal to the
     factory's.
   - Two builds are byte-identical: `bootloader.bin` sha256 `61aec000…9d73`.
   - The bytes differ from the factory's (another compiler), so "equivalent" means the
     same configuration, not the same binary.
2. The removals (serial DFU, BLE OTA, the read-back generator, single-tap and double-reset
   entry) and the write window. **Built and checked statically 2026-10-14; not run on a
   board** (that is milestone 4). Three patches:
   - `0002-drive-only`: no CDC interface, and with it no serial DFU. No BLE OTA, no
     SoftDevice update path, no double reset, single-tap flag or skip magic. DFU mode is
     entered only with the button held at reset, with no valid application, or on the
     application's GPREGRET `0x57`.
   - `0003-no-readback`: the drive holds `INFO_UF2.TXT` and `INDEX.HTM` and reads as
     zeros everywhere else; `CURRENT.UF2` and its generator are gone.
   - `0004-write-window`: app blocks are written only to 0x1000..0x97000
     (`BOARD_APP_FLASH_END` in `board.h`); the disassembly compiles it to
     `addr - 0x1000 < 0x96000`. A self-update stages at 0x8D000, inside the window.

   Code: 31 312 → 18 096 B, leaving about 20 KiB for the signature check. `check.py` now
   also reads the disassembly for UICR addresses built as immediates or movw/movt pairs.
   The fork's revision is in its version string (`0.9.2-vkey.2`, shown in
   `INFO_UF2.TXT`), the only way to tell builds apart on a board with no probe.
   Reproducible: `bootloader.bin` sha256 `76c90d5b…6064`. **Not installable yet**:
   - the self-update is unsigned, so once installed it would accept upstream's
     connect-kit UF2s (same board ID) and the stock bootloader;
   - a partial app UF2 still boots under the old "valid" flag.

   Milestone 3 closes both.
3. The signed trailer, with length and version inside the signed bytes, checked on every
   boot; the host signing tool. The signature scheme is chosen by measuring the code size
   and boot time of each verify-only candidate.
4. The on-device test as an application.

Install needs its own go and a checklist:

- no UICR address (0x10001xxx) and no NVMC `CONFIG` write in the binary;
- `SystemInit` disassembled;
- the board ID confirmed;
- the update padded to the whole region;
- the UF2 actually installed is checked block by block. Every target address falls in the
  MBR, 0xF4000..0xFE000, the settings page at 0xFF000 or the two UICR words, and its
  0xF4000.. payload equals the checked `bootloader.bin`;
- the MBR: the update carries Nordic's MBR 2.4.1 and a whole settings page. Read in the
  update handler what happens to those blocks, and compare the chip's own MBR (the app can
  read 0x0..0xB00) with 2.4.1;
- a signed app already on the board;
- the key reachable from two places.

**The risk, stated plainly.** A bug in the new bootloader leaves a board no USB tool can
reach. Without a probe that is a new dongle. That is acceptable only because the board
holds nothing yet.

Acceptance:

- an unsigned or altered UF2 is refused and never runs;
- the drive offers no `CURRENT.UF2`;
- a UF2 aimed at the vault region is refused;
- `check --wipe-everything` passes;
- the threat model loses the "flashes anything" and `CURRENT.UF2` lines.

## Phase 4 - APPROTECT, from the firmware

- **Firmware writes the protection itself.** It writes UICR `APPROTECT` to Enabled once,
  verifies the word, and never loops on it. A reset loop has been reported with ad-hoc
  write sequences on Fx parts, so the values come from the product specification and
  errata 249, not from forum posts.
- **It is the last UICR change.** With APPROTECT on, UICR can no longer be changed at
  runtime.
- **Irreversible without a probe.** Recovery would be a full erase over SWD. With no probe
  ever, that costs nothing, and it closes the debug port to anyone who has one.
- **What it changes depends on the revision.** On revision 1-2 an erased word (`0xFF`)
  leaves the port open, and this write is what closes it. On revision 3 the port is
  already closed unless UICR holds `0x5A`. There the write takes away the one value that
  would open it.

Acceptance: after a reset, the `chip:` line shows the `APPROTECT` low byte at `0x00`; the
board still updates through UF2; `selftest` green.

## Phase 5 - chip key, then move daily use

**Chip key.** On this chip any secret is loaded by software, so a chip key is only as
strong as phases 3-4. Two options, decided by the maintainer:

- **A. Secret page plus ACL (recommended).** A random 32-byte secret in its own flash
  page, outside the application region the bootloader may write, created on first boot.
  At boot the firmware copies it to RAM and locks the page with the ACL, read and write,
  until reset. Then neither code nor a debugger can read it. `DeviceKey::mac` becomes HMAC
  with it, `bound() = true`, and `vkey auth` works again. RustCrypto only. **On this
  revision-2 chip** a glitch opens the debug port at boot, before the ACL lock runs, and
  reads the page. Against a lab attacker A then adds almost nothing, and mainly brings
  `vkey auth` back. `vkey info` would print "chip-bound (a copy of the flash is useless
  without this chip)", which is false here, so that text changes with it.
- **B. CryptoCell-310 KDR.** A write-only key register used only by the hardware - closer
  to the C6's eFuse HMAC. It needs Nordic's closed library or undocumented registers,
  which goes against "crypto from RustCrypto".

The existing nRF vault is unbound, so it reads as `Incompatible`. It is wiped, which costs
nothing while it is empty.

**Migration:**

1. Back up the C6 to a `.vkb`.
2. Restore onto the nRF. The cost travels in the file, so this works across boards.
3. Check that the signing keys are on the nRF, and write down where their backups live.
   Losing the C6 Secure Boot key ends C6 updates forever.
4. Wipe the C6. It becomes the fallback and the test board for core changes.
5. C6 flashing moves out of the CLI into a script in its folder. `espflash` leaves, and the
   audit exception goes.

Acceptance: the threat model's nRF section is rewritten to match; `selftest` green on the
nRF; `check --wipe-everything` green on the C6.

## Phase 6 - passkeys (FIDO2)

- **USB moves to interrupts.** CTAPHID must send keepalives while it waits for a touch, and
  a composite device (CDC for vkey + CTAPHID) must serve both interfaces during any wait.
  This is also the real fix for "USB unserviced during the tap wait".
- **Runtime: RTIC (Nitrokey's choice) or Embassy.** Before choosing, check whether its
  macro-generated `unsafe` trips the board's `unsafe_code = "deny"`.
- **Trussed + `fido-authenticator`**, with littlefs at 0xD8000..0xEC000 and P-256 from
  `p256-cortex-m4`. Re-measure the fit and the stack high-water mark.
- **Then Linux login moves to `pam_u2f`**, and the old `vkey auth` is removed, recorded in
  `docs/` with the commit it can be restored from.
- **This is done on the daily key** (no spare). Every update starts with a `.vkb` backup.
  The vault region is out of the bootloader's reach, so a firmware update cannot overwrite
  it.

Acceptance: registration and login on webauthn.io and with `fido2-token`; `pam_u2f` with
`sudo`; `selftest` green; core changes pass `check` on the C6.

---

## Decisions needed from the maintainer

| When | Decision |
|---|---|
| Phase 0 | ~~the audit exception for RUSTSEC-2026-0344~~ - done 2026-10-13 |
| Phase 2 | ~~if the chip is older than revision 3: accept the glitch risk or keep the important secrets on the C6~~ - revision 2; everything moves here, risk accepted (2026-10-13) |
| Phase 3 | ~~own bootloader instead of the Nordic secure bootloader~~ - own fork chosen (2026-10-13); installing it still needs its own go |
| Phase 5 | chip key option A or B; wiping the C6 after migration |
| Phase 6 | RTIC or Embassy, and the `unsafe` rule if the runtime needs it |

## Sources

- Nordic IN-141, nRF52840 revision 3 and the APPROTECT changes: https://infocenter.nordicsemi.com/pdf/in_141_v1.1.pdf
- nRF52840 revision 3 errata 249: https://infocenter.nordicsemi.com/topic/errata_nRF52840_Rev3/ERR/nRF52840/Rev3/latest/config_840_249.html
- APPROTECT revision 3 vs 2: https://devzone.nordicsemi.com/f/nordic-q-a/100570/access-port-protection-nrf52840-rev3-vs-rev2/430101
- Reset loop on Fx parts when writing UICR.APPROTECT: https://devzone.nordicsemi.com/f/nordic-q-a/114591/nrf52840-critical-reset-loop-when-updating-uicr-approtect/502068
- Writing UICR from application code: https://devzone.nordicsemi.com/f/nordic-q-a/82409/example-code-to-write-to-uicr/367066
- ACL, nRF52840 product specification: https://infocenter.nordicsemi.com/topic/ps_nrf52840/acl.html
- Bootloader update over UF2: https://learn.adafruit.com/introducing-the-adafruit-nrf52840-feather/update-bootloader
- Makerdiary UF2 bootloader: https://wiki.makerdiary.com/nrf52840-mdk-usb-dongle/programming/
- Nordic bootloader and the MBR's power-safe copy: https://infocenter.nordicsemi.com/topic/com.nordic.infocenter.sdk5.v15.0.0/lib_bootloader.html
