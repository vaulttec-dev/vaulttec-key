# Roadmap: the nRF52840 key, from bring-up to daily use

Written 2026-10-13, after the first green `vkey check --wipe-everything` on the Makerdiary
dongle. Revised the same day for a constraint the maintainer set: **no SWD probe and no
spare board, now or later.** Decided already, not reopened here: the nRF52840 is the key
and the C6 a test board, not a fallback (2026-10-14); Trussed + `fido-authenticator` for
passkeys. Board
notes, measurements and the factory state: `docs/makerdiary.md`.

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
- **Test without a spare.** Neither board holds real secrets (2026-10-14). The C6 takes
  the full `check --wipe-everything` for core changes, once a `.vkb` holds its Secure Boot
  key `vkey-signing`; the nRF takes it while it holds nothing a `.vkb` cannot restore.
  nRF-only changes get `selftest` and a `.vkb`
  backup before each update. A release then says plainly that the full lifecycle test was
  not re-run on the nRF, as `CLAUDE.md` requires.

## The rule that orders everything

**Real secrets go onto the nRF when phases 3-5 are done, not when features are done.**
No board holds real secrets today, and the C6 is a test board, not a fallback
(2026-10-14), so every feature is built for the nRF alone. The nRF has no chip key, and
its debug port is open. Until 2026-10-14 its bootloader also flashed anything and served
the flash back (`CURRENT.UF2`); our fork has replaced it since (phase 3). A copy of its
flash gives up the PIN offline in hours (`docs/threat-model.md`). `espflash` stays in the
CLI while the C6 is flashed through it, and the audit exception with it.

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
  full rewrite waits until the nRF takes real secrets) and the
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

  How to read them: `docs/makerdiary.md`, "Reading the `chip:` line". This answers the
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
  is on this board, nothing can sign it. Decided 2026-10-14: the second home is a `.vkb`
  that restores onto the C6, which is the test board, not a signing device. The key is an
  item on this board, made with a `.vkb` right after; a wipe test here (phase 3
  acceptance) is followed by a restore.
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

   **Measured 2026-10-14.** Each verify-only path was compiled `-Os` for Cortex-M4. For
   speed, qemu-arm counted the instructions of one verify of a real openssl signature over
   1 KiB:

   | Candidate | Code | Instructions | At 64 MHz (≈1.3 CPI) |
   |---|---|---|---|
   | Monocypher 4.0.2, Ed25519 (SHA-512) | 10.5 KiB | 1.8 M | ≈ 40 ms |
   | micro-ecc 1.1, P-256 + SHA-256 | 4.4 KiB | 7.6 M | ≈ 150 ms |
   | compact25519, Ed25519 | 4.9 KiB | 90 M | ≈ 1.8 s |

   **Chosen: Monocypher Ed25519.** It is the fastest of the three, and the scheme is the
   RFC 8032 one that openssl signs and `ed25519-dalek` in the CLI already verifies.
   Hashing costs ≈113 instructions a byte: ≈0.2 s a boot for today's 77 KiB image, ≈0.7 s
   for a 300 KiB one with Trussed. A SHA-256 pre-hash would be 1.6× faster to hash, but it
   puts a second hash function in the bootloader, so plain Ed25519 it is.

   **Format.** One signature slot per image, the first 256 bytes of a page that the image
   never reaches:
   - for the app at 0x96000, so the app must end by 0x96000 and `memory.x` loses a page;
   - for a bootloader update at 0xFDF00, the end of its CF2 page.

   The slot holds magic `VKS1`, kind (1 app, 2 bootloader), version, length, then the
   signature over `slot[0..64] || image[0..length]`. The bootloader checks it on every
   boot, streaming SHA-512 over the slot header and the flash, so a torn or unsigned
   upload never runs and no "valid" flag is trusted. It checks a bootloader update in
   staging before `COPY_BL`; there the length must cover the whole region up to the slot.
   A bootloader update lands its staging on the app's slot, so the app is flashed again
   after one. The public key is compiled in. The build fails without it, and
   `INFO_UF2.TXT` shows its fingerprint, so a test-key build cannot pass for a real one.

   **Built and tested 2026-10-14 with a throwaway key; not run on a board.**
   - **`src/signature.c`.** Monocypher's own `crypto_ed25519_check`, with the message
     streamed: the slot header, then the image from flash in 4 KiB pieces, with the
     watchdog fed between them.
   - **`patches/0005-signed-images`:**
     - the app is valid only if its signature verifies, checked on every boot, once, with
       nothing written between the check and the jump;
     - DFU mode always ends in a reset;
     - a bootloader update is copied only if signed;
     - the jump address is always 0x1000, and the boot path looks for no SoftDevice;
     - `INFO_UF2.TXT` names the key.

     tinyusb's USB clock code still looked for one, at an address in the app, until
     milestone 4's `0006`; the message of commit a8b50cd overstates this for vkey.3.
   - **`test/run.sh`, run before every build.** It compiles `signature.c` for Cortex-M4
     and runs it under qemu-arm on 17 openssl-signed cases: valid app and bootloader;
     a flipped bit in header, image, R or s; wrong key; s + L; wrong kind; length
     edges; reserved or tail bytes. The streamed check must agree with the one-shot one,
     and a deliberately wrong expectation does fail.
   - **Size and stack.** 28 384 B of code, 10.5 KiB to spare. Stack on the verify path
     ≈1.8 KiB of the 8 KiB reserved.
   - **Signing.** `sign.sh` signs with openssl, checks the signature before writing, and
     wraps the image and slot into a UF2. By the factory bootloader's code it accepts that
     UF2 too, the slot being ordinary app space to it (confirmed in milestone 4). It refuses to sign
     a bootloader that trusts a test key unless `ALLOW_TEST_KEY=1`. `memory.x` now ends
     the firmware at 0x96000; its image did not change.
   - **The build refuses to run without `bootloader/signing-key.pem`.** A test build
     names its key with `BOOTLOADER_TEST_KEY`, and `INFO_UF2.TXT` then says "TEST KEY".
4. The on-device test as an application, and one fix it turned up. **Run on the board
   2026-10-14, with the factory bootloader in place throughout.**
   - **`patches/0006-no-softdevice`, a change to the bootloader itself.** tinyusb's USB
     clock code asked a SoftDevice about the clock whenever the word at 0x3004 held its
     magic number. Here that word is the app's, so an app holding it there would have
     sent DFU mode into an SVC nothing serves: a hang on the drive, and an app no update
     could replace. Found by the test build's `svc` check. The clock is now the CLOCK
     peripheral's alone, and the only `svc` left is `sd_mbr_command`. Version
     `0.9.2-vkey.4`.
   - **`patches/0007-as-app` and `VKEY_AS_APP` in `board.h`: the test build.** The same
     sources linked at 0x1000 (`test/app.ld`) to run under the factory bootloader.
     `COPY_BL` is compiled out, the settings page is never written, the drive writes only
     0x40000..0x80000 and stages a self-update at 0x76000, and its label is `VKEYTEST`.
     Built only with a test key, after the real build. With these hooks the real
     `bootloader.bin` stayed byte-identical. `check.py --as-app` puts it through the same
     UICR search, and it must contain no `svc` and end below 0x40000.
   - **`test/app_test.c`** makes the bootloader's own `signature_valid` calls before the
     drive starts and writes each verdict with its DWT cycle count into `INFO_UF2.TXT`.
     Since the install checklist, the file also carries a `Chip:` line: the leading bytes
     of the SHA-512 of the chip's MBR page and of its factory bootloader.
     **`test/board.py`** moves the real-pipeline signed app into the scratch window (the
     signature covers no address). **`test/board.sh copy`** reads the target drive's
     `INFO_UF2.TXT` first: a bootloader UF2 goes only to `VKEYTEST`, never to the factory
     `UF2BOOT`, which would install it.

   On the chip:

   | Check | Result |
   |---|---|
   | the signed app, 77 100 B | accepted, 15.13 M cycles, ≈ 236 ms at 64 MHz |
   | the same with one bit of R flipped | refused |
   | the app checked as a bootloader | refused, 88 cycles |
   | a signed self-update copied to `VKEYTEST` | staged by the fork's own write path, accepted at the next boot |
   | the same with one bit flipped at 0xF4110 | refused |

   The fork's USB drive works on this board. The measured ≈1.44 cycles an instruction
   matches the qemu estimate, so a 300 KiB image with Trussed would take ≈ 0.8 s. The
   instruction cache was off (`ICACHECNF` 0). Turning it on in the fork before the check
   is an open speed-up, not done. The vkey firmware was then restored from its signed UF2
   through the factory bootloader, which runs it with the slot at 0x96000: the first
   install step, rehearsed with the test key.
5. The real key's tools. **Written 2026-10-14; the key was made the same day, fingerprint
   `a1700ebd539b0bfc`.**
   - **`bootloader/signing-key.sh`** makes the Ed25519 key on tmpfs and stores it on the
     board as the `.env` `vkey-signing-nrf`. It talks to the board through the firmware's
     own port, so a C6 plugged in beside it never gets the key. It needs a PIN on the board
     first, writes `signing-key.pem` and prints the fingerprint.
   - **`bootloader/sign-vaultkey.sh`** takes the key off the board (PIN, one tap). It
     refuses the key unless its public half is `signing-key.pem`. It then signs
     `images/vaultkey.bin`, and `images/bootloader.bin` once there, into `*.signed.uf2`.
     Both are signed as version 1, since the field is not compared yet.
   - **`tools/build-bootloader.sh`** refuses a key file that is not exactly a public
     Ed25519 key before it reaches Docker. A build with the real key writes
     `images/bootloader.bin`.
   - **The hook's `check_signed_uf2`** makes four checks:
     - the pem is a public Ed25519 key and nothing else;
     - each UF2, rebuilt from its unsigned twin with the version and signature from its own
       slot (`signed_image.py verify`), matches byte for byte;
     - the signature verifies under the pem;
     - `bootloader.bin`'s INFO line is `Key: <fingerprint>`, with no `TEST KEY`.

     Tried on the milestone-4 files and on a real-key-mode build with the test key. It
     passes on those, and fails on a stale image, an altered UF2, a test-key bootloader, a
     foreign key, and a private, mixed or empty pem.
   - **`board.toml` names none of these files**, so the CLI embeds none of them.
   - **The key itself**, 2026-10-14: made on the board, then a `.vkb` of it at once.
     The `.vkb` was restored onto the same board and `vaultkey.signed.uf2` signed again
     came out byte for byte the same. `images/bootloader.bin` was built with
     `signing-key.pem`: its INFO line names `a1700ebd539b0bfc`, and the raw key is in it
     once. Not installed.

Install needs its own go and a checklist:

- no UICR address (0x10001xxx) in the binary (`check.py`), and no erase beyond a page.
  Done 2026-10-14 on the real-key build. Three functions use the NVMC:
  - `nrfx_nvmc_page_erase` sets `CONFIG` to 2 and erases through `ERASEPAGE`;
  - `nrfx_nvmc_words_write` and `nvmc_word_write` set it to 1, then back to 0.

  They are called only from `flash_nrf5x_flush`, the app window, and from
  `bootloader_dfu_update_process`, the settings page. No store reaches `ERASEALL` or
  `ERASEUICR`;
- `SystemInit` disassembled. Done 2026-10-14: as in milestone 1, it stores to CLOCK,
  POWER, errata registers and `CPACR`, reads FICR, and never touches UICR;
- the board ID confirmed. Done 2026-10-14: the CF2 block is the factory's (`check.py`),
  and the update UF2 carries 0x2886F00F;
- the update padded to the whole region. Done 2026-10-14: 0xF4000..0xFE000 is covered
  with no gap;
- the UF2 actually installed is checked block by block. Done 2026-10-14 on
  `images/bootloader.signed.uf2`. It has 161 blocks:
  - 159 of the bootloader at 0xF4000..0xFDF00;
  - its slot at 0xFDF00;
  - one UICR block holding 0xF4000 and 0xFE000 at 0x14 and 0x18 and 0xFF everywhere
    else. The factory handler only compares those two words with its own constants and
    writes nothing to UICR.

  There is no MBR and no settings page in it, and its 0xF4000.. payload equals the checked
  `bootloader.bin` (`signed_image.py verify`). The headers, which decide when the factory
  flushes and calls `COPY_BL`, are also right: `blockNo` runs 0..160 in order,
  `numBlocks` is 161 and the payload 256 in every block, with flag 0x2000 and both
  magics;
- the jump into the app, which never ran in milestone 4, put next to the factory's.
  Done 2026-10-14. `board_teardown`, the cleared NVIC lines, `sd_mbr_command` 6 with
  0x1000, and `bootloader_util_reset` (MSP from 0x1000, PC from 0x1004) are the factory's
  instructions one for one. The only change is that the SoftDevice branch is gone. The
  factory takes it only when 0x3004 holds the SoftDevice magic, and vkey does not, so
  vkey already boots today through the path the fork keeps;
- the factory bootloader's handling of it. In the published 0.7.1 hex, the handler writes
  each block 0x14000 lower, to 0xE0000..0xEA000. That is the reserve above the vault, not
  the vault. It calls `COPY_BL` only if the staged image differs from the running one.

  **The chip against the published files, 2026-10-14.** Two readings agree:
  - the as-app build hashed the chip's MBR page and 0xF4000..0xFE000 with SHA-512;
  - `dd` of those sectors of the factory drive returned the same bytes. The drive serves
    flash past `CURRENT.UF2`, and only 0xF4000..0x100000 was read.

  What they showed:
  - **MBR.** The page is Nordic's 2.4.1 byte for byte (`0a1d2691`), with 0xFF8 and 0xFFC
    erased. So it boots the bootloader from UICR `NRFFW[0]`, and `COPY_BL` takes its
    parameter page from `NRFFW[1]`. The MBR header says `COPY_BL` returns
    `NRF_ERROR_NO_MEM` without either. UICR itself was not read, since `check.py` keeps
    every UICR address out of the test build.
  - **Bootloader.** The code is the published 0.7.1 hex (Jul 20 2023, "SoftDevice: not
    found") byte for byte. Only 34 bytes differ:
    - at 0xFD000, `0xDEADC0DE 0xF11E01FF`, a Nordic FDS swap-page tag that some earlier
      application wrote. The bootloader's code holds neither word. The CF2 block at
      0xFD800 is intact, and `COPY_BL` overwrites the page;
    - at 0xFF000, the bootloader's own settings page.

    The handler analysed in the hex is the one on the chip.
- the key reachable from two places, and `signing-key.pem` committed with its
  fingerprint recorded here, `a1700ebd539b0bfc`:
  - the `.vkb` is made right after the key (done 2026-10-14);
  - prove it by restoring it onto the same board and signing again. Ed25519 is
    deterministic, so `images/` must not change (done 2026-10-14);
  - restoring it onto the C6, the decided second home, comes only after a `.vkb` of the
    C6 holding `vkey-signing` exists. A restore replaces everything on the board,
    `vkey-signing` included. `sign-vaultkey.sh` talks only to this board, so signing from
    the C6 needs a change made at that point;
  - the commit that brings the key carries `signing-key.pem`, `images/vaultkey.signed.uf2`
    and the fingerprint here together. Once the pem is tracked, the hook demands the
    signed UF2;
- the bootloader being installed names that fingerprint in its INFO text, not "TEST KEY".
  `sign.sh` refuses a test-key bootloader unless told, and the hook refuses one in
  `images/`;
- `images/bootloader.bin` is what the committed sources and pem build:
  `tools/build-bootloader.sh` again, then `git diff --exit-code`. The hook does not
  rebuild it. Done 2026-10-14, twice, the second time after the as-app readback change;
- the time from making the key to installing the fork kept short. Until the fork is in,
  `CURRENT.UF2` hands the vault, key included, to anyone holding the board
  (`docs/threat-model.md`);
- the order: first copy the signed app (real key) through the factory bootloader and
  confirm it boots under it (done 2026-10-14: `vaultkey.signed.uf2`, `vkey info`, the
  PIN and its 8 attempts intact). Then install the fork, and the board must boot straight
  into that app. If it stays in DFU mode instead, copying the signed app UF2 again is
  the next step.

**Installed 2026-10-14, 22:53,** on the maintainer's go.
- `bootloader.signed.uf2` was copied onto the factory drive once its `INFO_UF2.TXT` showed
  0.7.1 with no SoftDevice.
- The board left USB at once and came back by itself 2 s later, running vkey
  (`last reset: soft reset`).
- With the button held, the drive showed `0.9.2-vkey.4`, `Key: a1700ebd539b0bfc` and only
  `INDEX.HTM` and `INFO_UF2.TXT`.
- Replugged without it, the first cold boot (`power-on`) verified vkey and ran it, with
  the PIN and its 8 attempts intact.

The key had spent 1 h 17 min on a board that served `CURRENT.UF2`.

The as-app harness (`test/board.sh`, `m4.uf2`) ran under the factory bootloader. The fork
runs an app only with a slot at 0x96000 signed by the real key. `board.sh copy` also
looks for 0.7.1 in the drive's INFO, so it now refuses the fork's drive, which fails safe.
Before the fork's next change, the harness has to be adapted: the test build is signed as
an app with the real key, while its test images keep the test key.

**The risk, stated plainly.** A bug in the new bootloader leaves a board no USB tool can
reach. Without a probe that is a new dongle. Since 2026-10-14 the board holds the signing
key. A brick therefore costs the board but not the key: the `.vkb` is proven by a restore
and opens on any vkey, including a new factory dongle, which then takes this same fork.
The power-fail safety of `COPY_BL` is Nordic's claim, untested here, so the board stays
plugged in until it comes back.

Acceptance:

- an unsigned or altered UF2 is refused and never runs. Done 2026-10-14 with two images,
  each copied onto the fork's drive and then cold-booted without the button:
  - `vaultkey.signed.uf2` with one bit flipped at 0x9010;
  - the same app signed with the test key.

  Both times the board came back as the bootloader (`2886:f00f`), not vkey. Then the
  real `vaultkey.signed.uf2` brought vkey back at once, with the PIN and its 8 attempts
  intact;
- the drive offers no `CURRENT.UF2`. Done 2026-10-14: the drive holds only `INDEX.HTM` and
  `INFO_UF2.TXT`. The same 192 raw sectors that gave the factory bootloader's code back
  (`dd`, skip 4411) now read as 98 304 zero bytes;
- a UF2 aimed at the vault region is refused. Done 2026-10-14 at the boundary, with one
  block at 0x97000, the first address past the app window and the vault's attempt
  sector. It was all 0xFF but a zero first word, so a write would have shown as one spent
  attempt without the PIN. The fork did not count the block as part of a transfer, so
  the copy ended no session and caused no reset. After a cold boot, vkey still showed 8
  attempts;
- `check --wipe-everything` passes. Done 2026-10-14 under the fork: every line PASS,
  backup, restore, rekey, the live HMAC selftest and the wipe after 8 wrong PINs
  included. The signing key then came back from its `.vkb` (on the second try, after a
  mistyped passphrase). Signing again gave `vaultkey.signed.uf2` and
  `bootloader.signed.uf2` byte for byte;
- the threat model loses the "flashes anything" and `CURRENT.UF2` lines. Done
  2026-10-14.

**Phase 3 accepted 2026-10-14.**

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

**Written 2026-10-15** (`protect` in the board's `main.rs`, run at boot before INFO is
built). It writes only while the low byte is not 0x00:
- `NVMC.CONFIG` = WEN, then one store of `0xFFFF_FF00` to 0x10001208, then
  `CONFIG` = REN, waiting for READY around each step;
- no retry and no reset. A word that did not stick shows in `vkey info`.

The disassembly holds that sequence and no other store to UICR. The PAC's `write`
starts from the register's reset value, 0xFFFF_FFFF, so only PALL changes.

**Installed and accepted 2026-10-15,** on the maintainer's go:
- copied as `vaultkey.signed.uf2` through the fork; the first boot showed
  `UICR APPROTECT 0xffffff00`, with the PIN and its 8 attempts intact;
- after a reset with the button held, the fork took the same signed UF2 again and ran it,
  so updates go on with the port closed;
- `selftest` green (device 627642 against the independent HMAC).

**Phase 4 accepted 2026-10-15.**

## Phase 5 - chip key, then move daily use

**Skipped on this chip (2026-10-15; the maintainer left the call to the analysis).**
Once APPROTECT is on, a copy of the flash needs the boot-time glitch. A and B both start
from a secret the firmware loads out of flash at boot - B only moves it into CryptoCell's
write-only register afterwards - so the same glitch, before the ACL lock, reads it too.
Neither adds protection against the one attack left. A would mostly bring `vkey auth`
back, and phase 6 removes `vkey auth`. B would also break "crypto from RustCrypto". The
vault stays PIN-only, as `docs/threat-model.md` says. A revision-3 chip would change the
answer, since its glitch fix leaves the ACL lock standing.

The C6 steps below are not done either: the C6 is left alone (maintainer, 2026-10-14).

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

The existing nRF vault is unbound, so it reads as `Incompatible`. It is wiped and its
signing key restored from the `.vkb`, which costs nothing while it holds nothing else.

**What is left of the migration.** No board holds real secrets (2026-10-14), so nothing
moves but the keys:

1. Put `vkey-signing`, the C6's Secure Boot key, on the nRF next to the bootloader key,
   back up to a `.vkb`, and write down where it lives. Losing it ends C6 updates forever.
   `vkey restore --only vkey-signing <C6 .vkb>` (2026-10-15) adds one item from a backup
   without replacing the vault. With the key on the nRF, `tools/sign-vaultkey.sh` signs the
   C6's images again and its signed app returns to the repository, the C6 left alone.
   **Done 2026-10-15**: added from the September `.vkb`, the C6's images signed and
   verified, and the nRF backed up with it.
2. C6 flashing moves out of the CLI into a script in its folder. `espflash` leaves, and the
   audit exception goes. **Deferred** (2026-10-15): the script chooses between the plain
   and the Secure Boot bootloader, and the wrong choice on a plain chip burns its eFuses.
   It waits until the C6 may be touched to test it; until then `vkey setup` keeps doing it.

Acceptance: the threat model's nRF section is rewritten to match; `selftest` green on the
nRF; `check --wipe-everything` green on the C6.

## Phase 6 - passkeys (FIDO2)

- ~~**USB moves to interrupts.**~~ CTAPHID must send keepalives while it waits for a touch,
  and a composite device (CDC for vkey + CTAPHID) must serve both interfaces during any
  wait. That is now done by polling during every wait, not by an interrupt: see "No
  runtime and no interrupt" below. It is also the fix for "USB unserviced during the tap
  wait".
- ~~**Runtime: RTIC (Nitrokey's choice) or Embassy.**~~ Neither: see "No runtime" below.
- **Trussed + `fido-authenticator`**, with littlefs at 0xD8000..0xEC000 (0xC8000..0xF4000
  since milestone 6) and P-256 from `p256-cortex-m4`. Done 2026-10-15 (milestone 3).
- **Then Linux login moves to `pam_u2f`**, and the old `vkey auth` is removed, recorded in
  `docs/` with the commit it can be restored from.
- **This is done on the daily key** (no spare). Every update starts with a `.vkb` backup.
  The vault region is out of the bootloader's reach, so a firmware update cannot overwrite
  it.

Acceptance: registration and login on webauthn.io and with `fido2-token`; `pam_u2f` with
`sudo`; `selftest` green. Core changes pass `check --wipe-everything` on the nRF, followed by
a restore from the `.vkb` and a 1Password sync; the C6 is left alone (2026-10-14).

**What is available (checked 2026-10-15).** The whole stack is on crates.io, recent, and
agrees with the firmware's own versions: `trussed` 0.2, `fido-authenticator` 0.3,
`usbd-ctaphid` 0.5, `ctaphid-dispatch` 0.4 and `littlefs2` 0.8, on `usb-device` 0.3.2 and
`heapless` 0.9. littlefs and `p256-cortex-m4` are C and assembly, built with the host's
clang.

**No runtime and no interrupt (decided 2026-10-15).**
- `nrf-usbd` never enables the USBD interrupt, and enabling it means stealing the
  peripheral back in `unsafe`.
- Polling from `SysTick` fails as well: `usb-device`'s types are not `Send`, so they cannot
  sit in a static behind a critical section without an `unsafe impl`.

So the device is polled in the main context, wherever the key waits:
- for the next request (the protocol's port);
- on every look at the button, which covers a tap wait of seconds;
- in milestone 3, while Trussed waits for user presence.

The bus waits only through Argon2 and flash writes, as it does today. There is no RTIC or
Embassy, and no new `unsafe`.

**The passkey backup is a deliberate export into the `.vkb`** (maintainer, 2026-10-15).
FIDO's rule is non-exportable credentials plus a second key. There is no second key, so
the passkeys go into the backup under its passphrase like every other item, and
`docs/threat-model.md` says what that costs.

Milestones, one commit each, each leaving a key that works:

1. **USB served during waits.** CDC alone, behaviour unchanged: the button check polls the
   device too. Acceptance: `selftest`, and a tap wait of several seconds that no longer
   stalls the bus. **Accepted 2026-10-15** (`b446afd`): `selftest` green with a wait of
   several seconds before the tap.
2. **A composite device.** CDC plus CTAPHID (`usbd-ctaphid`) answering INIT and PING. The
   board's port serves the FIDO dispatch whenever vkey's line has been quiet for 50 ms, so
   a request that waits for a touch never holds up a vkey frame half read. Acceptance:
   `fido2-token -L` lists the key, and vkey works. **Accepted 2026-10-15**: INIT and PING
   answered by `b446afd`. A CBOR request got no answer until the pipe's finished answers
   were picked up on every poll, not only on bus events. That fix ships with milestone 3.
3. **Trussed and `fido-authenticator`.** littlefs on 0xD8000..0xEC000. The factory's stale
   staging bytes sit at 0xE0000..0xEA000, so a mount that fails formats instead of assuming
   blank flash. User presence is the amber tap, on the same button and LED as vkey.
   Acceptance: registration and login on webauthn.io and with `fido2-token`, and the fit
   and the stack measured. **Accepted 2026-10-15**:
   - registration and login passed on webauthn.io in Chrome, with a discoverable
     credential and a FIDO PIN Chrome had set;
   - `fido2-token -L` and `-I` read the key;
   - makeCredential and getAssertion, resident and not, passed through
     `ctap2.py` with the signature checked against the credential's public key;
   - keepalives say "touch needed" every 100 ms while the key waits;
   - authenticatorReset was refused while only tapped and erased after the 5 s hold;
   - `vkey check --wipe-everything` passed, then the restore from the `.vkb`, the
     1Password sync and `selftest`. Its one FAIL, "backup refused for one tap", was the
     maintainer tapping twice: the device rightly took the second tap. The prompt now
     says why a blue light asks for one tap there.

   What changed on the way, and what it leaves:
   - **The core changed after all.** With Argon2's 128 KiB in a static, passkeys had 64 KiB
     of stack and needed more than twice that; the first getInfo locked the core up. The
     core now takes the 128 KiB on the stack for one derivation (`with_kdf_memory`), and
     the stack is 200 KiB at the bottom of RAM, where an overflow resets the chip instead
     of corrupting the statics (`docs/makerdiary.md`, "Passkeys on the board"). The
     C6's image changed with it. Its signed copy can only be made on the C6, which is
     left alone, so it left the repository, and `vkey setup` refuses a Secure Boot chip
     until it is signed again (maintainer's decision, 2026-10-15). Signed again the same
     day with `vkey-signing` restored onto the nRF, and back in the repository.
   - **The stack is bounded, not measured.** Its high-water mark cannot be read without a
     second `unsafe` or a probe. The bound comes from the image's call graph, and a lockup
     in `vkey info`'s reset cause would show an overflow.
   - **CTAP2 only.** U2F's MSG is refused. getInfo still lists `U2F_V2`, as
     fido-authenticator always does. The AAGUID is its placeholder `AAGUID0123456789`,
     since no attestation certificate is loaded.
   - **CTAPHID_CANCEL is not honoured during the 30 s touch wait.** A browser that cancels
     and asks again gets CHANNEL_BUSY until the wait ends: the first webauthn.io login
     failed that way, the second passed. Ending the wait early from the board would mean
     moving the core's clock, and a cancel during a reset's hold would then complete it,
     so the fix is a cancel hook in the core's `ui` with host tests (milestone 4).
4. **`pam_u2f` for `sudo` and the lock screen**, and `vkey auth` removed, recorded in
   `docs/` with the commit it can be restored from. Two core fixes ride along, because
   this milestone changes the core anyway:
   - the cancel hook above;
   - `ui::await_release`, which takes one "not pressed" sample for a release. A bounce in
     the middle of a press could then count as two taps, and two taps at blue let a
     backup out. It gets the same debounce `released` already has.

   **Accepted 2026-10-15**:
   - `vkey auth` kept its name and became `pam_u2f`, as decided on 2026-10-03. The
     Ed25519 scheme is gone, restorable from 4bd49f3 (`docs/threat-model.md`).
   - `sudo` took a tap, the lock screen took a tap, and the password worked with the key
     out.
   - `enable` makes the credential over its own CTAP2: `pamu2fcfg` 1.1.0 calls
     `fido_cred_verify`, which demands an attestation certificate this key does not have.
     Its mapping line has `pamu2fcfg`'s shape, checked against the pam-u2f 1.1.0 source.
   - A CTAPHID_CANCEL during a touch wait answers KEEPALIVE_CANCEL in 0.2 s, and the next
     request goes through.
   - The withdrawn-wait and bounce tests pass on the host. The bounce test fails against
     the old `await_release`, so it catches what it is there for.
   - `check --wipe-everything` passed, then the restore from the `.vkb` through the new
     host-side reseal, the 1Password sync and `selftest`.
5. **The passkeys in the `.vkb`**: backup and restore carry the Trussed filesystem, sealed
   under the passphrase like the items. Built 2026-10-15:
   - The core takes a fifth board trait, `hal::Attachment`: sectors to read and put, a
     freeze and a thaw. The C6 passes `NoAttachment`.
   - A backup carries the non-blank sectors after the items, each sealed under
     `REGION_AAD` plus its position and holding the geometry. Every session begins and
     ends in one place (`start_session`/`end_session`).
   - The board freezes Trussed for the session, lets go by itself after 10 s of a silent
     vkey line, and resets after a restore that changed a sector.
   - The CLI opens the written backup to count items and sectors. It reseals sectors in
     their new positions on restore, or leaves them in the file on a board without
     passkeys.
   - Host tests cover the exact copy, an identical restore that changes nothing, an older
     file that leaves the passkeys alone, the refusal by a board without them or laid out
     otherwise, and every way a session ends.

   Acceptance, still on the board:
   1. Take a fresh `.vkb`.
   2. authenticatorReset (the hold, within 10 s of plugging in).
   3. `sudo` asks for the password and the webauthn.io login fails.
   4. Restore the `.vkb`. The key restarts.
   5. `sudo` takes a tap and webauthn.io logs in again, with nothing enrolled anew.
   6. `check --wipe-everything`, the restore, the 1Password sync and `selftest`.

   **Accepted 2026-10-15**, all six in the order 6, 1-5: `check --wipe-everything`
   green on the new image, the restore, the sync and `selftest` green; a backup of 48
   items "and the passkeys"; authenticatorReset erased them after the hold; `sudo` then
   asked for the password and webauthn.io refused the login; the restore brought back 48
   items and the passkeys and the key restarted ("soft reset"); `sudo` took a tap and
   webauthn.io logged in, nothing enrolled anew. Two `Broken pipe`s during the session
   were the dongle's edge connector moving under a press (re-enumeration within a
   second, the vault still unlocked), not the firmware.
6. **Room for more passkeys** (maintainer's decision, 2026-10-16). GitHub's registration
   failed with "Passkey registration failed": fido-authenticator 0.3 stores a resident
   key only if six blocks and the key's size stay free after it (`can_fit`), and of
   littlefs's 20 blocks the superblock and the directories of a few sites had taken the
   rest. The vault gives up a quarter: copies of 24 sectors (96 KiB) instead of 32, the
   region 0x97000..0xC8000. littlefs moves to 0xC8000..0xF4000, 44 blocks, up to the
   bootloader, whose window ends at 0x97000; a const assert holds the data region to
   0xF4000. fido-authenticator 0.3 keeps each resident key as a small file in one
   directory, inline in its metadata, so the real room is wider than its own estimate,
   which `vkey passkey list` reports (getCredsMetadata: two blocks and 400 bytes per
   key after a margin of five): 13 on the empty filesystem.
   - The old filesystem does not mount at the new place and is formatted: every
     passkey, the FIDO PIN and the `vkey auth` and commit-signing credentials go.
   - The vault moves too, so the order on the board is a `.vkb`, the flash, then the
     restore. A `.vkb` made before carries passkeys laid out for 20 sectors; the CLI
     now leaves sectors of another count in the file and says so, because the device
     refuses them and with them the whole restore (`passkey_sectors` in board.toml).

   Acceptance, on the board: the restore of the `.vkb` taken before, `selftest`, the
   FIDO PIN set again, `vkey passkey list` with the room it reports, the GitHub
   registration that failed, then `sudo vkey auth enable` and `vkey commits enable`
   with a new signing key on GitHub; a backup and a restore of it at 44 sectors that
   changes nothing.

   **Accepted 2026-10-16**: the restore brought back 48 items and left the passkeys in
   the file ("laid out for 20 sectors, this board keeps 44"); `selftest` green; the
   FIDO PIN set through `vkey passkey pin`; the list reported 0 and room for 13. The
   first GitHub registration after the flash made a passkey on the key that GitHub's
   server then refused - most likely a challenge left from a page opened before the
   flash, not proven - and a fresh page registered it. The key holds one `github.com`
   passkey after both: the second, for the same site and user handle, replaced the
   first, as CTAP2 has it. `sudo vkey auth enable` and
   `vkey commits enable` with a new key on GitHub; a backup of 48 items and the
   passkeys and its restore, after which the key did not restart (reset cause still
   power-on, vault still unlocked). The restore's "the key restarts" now reads "if a
   passkey changed": the CLI cannot tell whether one did.
7. **A restore takes the wipe's hold** (maintainer's decision, 2026-10-16). A restore
   replaced the vault and the passkeys under the PIN alone, so a host that learned the
   PIN could swap in passkeys of its own and skip the 5 s hold that authenticatorReset
   takes. `ImportBegin` now waits for that hold before it touches anything. A core
   change: the C6's image is rebuilt with it, but the C6 is left alone, so
   `check --wipe-everything` is not re-run on it. With it, `sudo vkey auth` refuses to
   run as root from a binary anyone but root can change and names the root-owned copy
   `/usr/local/sbin/vkey`, which `/settings` keeps current.

   Acceptance, on the board: a `.vkb` first, `selftest`, a restore refused by a tap
   that leaves the vault and the passkeys as they were, then one that goes through
   with the hold; `/settings` → `auth` through the root copy.

   **Accepted 2026-10-16**, but for `/settings` → `auth`: a `.vkb` of 48 items and the
   passkeys; `selftest` green; the restore with the hold brought back 48 items and the
   passkeys (`github.com` still listed), one with a tap was refused; `sudo
   ~/.local/bin/vkey auth enable` refused and named `/usr/local/sbin/vkey`. The
   switch through the root copy is not yet run on this host.

---

## Decisions needed from the maintainer

| When | Decision |
|---|---|
| Phase 0 | ~~the audit exception for RUSTSEC-2026-0344~~ - done 2026-10-13 |
| Phase 2 | ~~if the chip is older than revision 3: accept the glitch risk or keep the important secrets on the C6~~ - revision 2; everything moves here, risk accepted (2026-10-13) |
| Phase 3 | ~~own bootloader instead of the Nordic secure bootloader~~ - own fork chosen (2026-10-13), installed on the maintainer's go (2026-10-14) |
| Phase 3 | ~~the signing key's second home~~ - a `.vkb` that restores onto the C6; the C6 is the test board, everything else is on the nRF (2026-10-14) |
| Phase 5 | ~~wiping the C6 after migration~~ - the C6 is a test board, not a fallback, and neither board holds real secrets (2026-10-14) |
| Phase 5 | ~~chip key option A or B~~ - neither on this revision-2 chip: the boot-time glitch reads either (2026-10-15) |
| Phase 6 | ~~passkey backup~~ - a deliberate export into the `.vkb`, outside FIDO's no-export rule (2026-10-15) |
| Phase 6 | ~~RTIC or Embassy~~ - neither: USB is polled wherever the key waits, so no new `unsafe` (2026-10-15) |
| Phase 6 | ~~RAM for passkeys~~ - Argon2's memory moves to the stack in the core; the C6's stale signed image leaves the repository (2026-10-15) |

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
