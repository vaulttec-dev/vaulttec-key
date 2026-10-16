/* Makerdiary nRF52840 MDK USB Dongle: 1 MiB flash and 256 KiB RAM, all on the chip.
 * FLASH below is only this firmware's part of the map (docs/makerdiary.md):
 *
 *   0x00000..0x01000   MBR
 *   0x01000..0x96000   this firmware
 *   0x96000..0x97000   its signature slot, which the bootloader fork checks on every
 *                      boot (bootloader/src/signature.h)
 *   0x97000..0xC8000   the vault (VAULT_BASE in main.rs)
 *   0xC8000..0xF4000   Trussed's filesystem, the passkeys (FS_LEN in main.rs), up to
 *                      the bootloader: a const assert in main.rs holds it there
 *   0xF4000..0x100000  the UF2 bootloader, its CF2 page, MBR parameters and settings
 *
 * The bootloader writes only 0x01000..0x97000 (BOARD_APP_FLASH_END in bootloader/board),
 * so a firmware update cannot reach the vault or the passkeys. RAM starts 8 bytes in,
 * the way Nordic's own images on the MBR are linked: the MBR keeps its forwarding
 * address there.
 *
 * The stack comes first in RAM and the statics after it. A stack that overflows runs off
 * the bottom of RAM into unmapped addresses, and the fault it takes there cannot even be
 * stacked: the core locks up and the chip resets, which `vkey info` reports as "lockup".
 * Placed the usual way, at the top, it would run down into the vault's index and the
 * working buffer without a sound. Statics that outgrow RAM fail the link.
 *
 * Nearly all of RAM is stack, because the two deepest things the key does take turns in
 * it: a key derivation holds Argon2's 128 KiB there (about 166 KiB deep in all), and a
 * passkey request goes through fido-authenticator and Trussed (at most about 154 KiB,
 * counted over the call graph of the image). The statics, ~46 KiB, get 56 KiB.
 */
MEMORY
{
  FLASH : ORIGIN = 0x00001000, LENGTH = 0x95000
  STACK : ORIGIN = 0x20000008, LENGTH = 0x31FF8
  RAM   : ORIGIN = 0x20032000, LENGTH = 0x0E000
}

_stack_start = ORIGIN(STACK) + LENGTH(STACK);
_stack_end = ORIGIN(STACK);
