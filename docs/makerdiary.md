# Makerdiary nRF52840 MDK USB Dongle (the key)

The primary board since 2026-10-14. Plan and status: [`roadmap.md`](roadmap.md). Research
notes, factory dumps and bring-up logs: `git show 72172f3:docs/makerdiary.md`.

## Why this board and stack

| Rejected | Why |
|---|---|
| ESP32-C6 for passkeys | No USB HID |
| ESP32-S3 | Xtensa needs espup, a compiler fork |
| RP2350 | External flash: the attempt counter can be rewritten off-chip |
| Solo 2 (LPC55S69) | 512-byte ECC program pages break the one-word attempt counter |
| Tillitis TKey | ~128 KiB app RAM, Argon2 at 128 KiB does not fit |
| Nitrokey 3 | Vendor-signed firmware only |
| Other nRF52840 dongles | Makerdiary alone has an RGB LED, a button, a case and an open schematic |
| Own CTAP2 | 3-5k lines nobody reviewed; PIN protocol bugs are silent UV bypasses |
| Google OpenSK | Tock OS and `alloc` |
| Nordic secure bootloader | Moves the bootloader address in UICR: one-shot without a probe |

Chosen: Trussed + `fido-authenticator` (maintainer, 2026-10-03), production on Nitrokey 3A
Mini, the same chip. Its price: a big dependency tree, littlefs and `p256-cortex-m4` in C
(built by the host's clang with `c-headers/`), two storages, two PINs.

## Pins

Confirmed by watching the board work: button P0.18 (a plain GPIO, `PSELRESET` not set),
LEDs red P0.23, green P0.22, blue P0.24, all active low; amber is red plus green.

## Memory map

| Range | Size | What |
|---|---|---|
| 0x00000..0x01000 | 4 KiB | Nordic MBR 2.4.1 |
| 0x01000..0x96000 | 596 KiB | firmware |
| 0x96000..0x97000 | 4 KiB | the app's signature slot |
| 0x97000..0x98000 | 4 KiB | vkey attempt counter |
| 0x98000..0xC8000 | 2 × 96 KiB | vkey image copies A and B (24 sectors each) |
| 0xC8000..0xF4000 | 176 KiB | Trussed littlefs (passkeys), 44 blocks |
| 0xF4000..0x100000 | 48 KiB | UF2 bootloader fork, CF2 page, MBR params, settings |

No A/B firmware: two copies do not fit. RAM: a 200 KiB stack at the bottom, so an overflow
locks up and resets the chip instead of corrupting statics; Argon2's 128 KiB is taken on it
per derivation, and passkey requests reuse the same RAM.

## Passkeys on the board

Trussed 0.2 and `fido-authenticator` 0.3 in `src/fido.rs`, polled from the main loop with
CDC (no RTIC, no interrupt, no new `unsafe`). CTAP2 only.

| Measured (2026-10-15) | |
|---|---|
| Image | ~268 KB |
| Statics | 46 KiB |
| Deepest key derivation | ≈166 KiB of stack |
| Deepest passkey request | ≤ ≈154 KiB (call-graph bound; the high-water mark needs a probe) |
| Argon2 at `t`=20 | ~1.1 s |

A third USB interface, after CDC and CTAPHID, is a boot keyboard (`src/keyboard.rs`)
that types only the login password, kept in littlefs as `/vkey-login` (2026-10-17).

Room: fido-authenticator stores a resident key only if six blocks and its size stay free
after it. `vkey passkey list` reports its own estimate, 13 on an empty filesystem; the real
limit is not measured.

## Reading the `chip:` line

`vkey info` prints three things the firmware reads at boot:

- **Build code** (FICR `INFO.VARIANT`): `AAC0` revision 1, `AADx` revision 2, `AAF0`
  revision 3. This board is `AAD0`.
- **UICR `APPROTECT`**, low byte: `0x00` closed on every revision; `0xFF` open on
  revisions 1-2, closed on 3; `0x5A` counts as open. This board: `0xffffff00` since
  2026-10-15.
- **Last reset** (`RESETREAS`, cleared on read). `soft reset` is a panic or the bootloader
  after a flash; `lockup` is a stack overflow; a replug reads `power-on` and hides what came
  before.

## Flashing

Hold the button while plugging in, copy `images/vaultkey.signed.uf2` to `UF2BOOT`, run
`timeout 20 sync`, replug: the warm start after a copy does not enumerate.
