/* Makerdiary nRF52840 MDK USB Dongle: 1 MiB flash and 256 KiB RAM, all on the chip.
 * FLASH below is only this firmware's part of the map (docs2/makerdiary.md):
 *
 *   0x00000..0x01000   MBR
 *   0x01000..0x97000   this firmware
 *   0x97000..0xD8000   the vault (VAULT_BASE in main.rs)
 *   0xD8000..0xEC000   Trussed's filesystem, not used yet
 *   0xEC000..0x100000  bootloader and its settings
 *
 * RAM starts 8 bytes in, the way Nordic's own images on the MBR are linked: the MBR
 * keeps its forwarding address there. To be confirmed against the MBR on the board.
 */
MEMORY
{
  FLASH : ORIGIN = 0x00001000, LENGTH = 0x96000
  RAM   : ORIGIN = 0x20000008, LENGTH = 0x3FFF8
}
