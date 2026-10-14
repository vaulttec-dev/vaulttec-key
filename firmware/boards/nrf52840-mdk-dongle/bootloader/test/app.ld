/* The on-board test build (VKEY_AS_APP, test/app_test.c): this bootloader linked as an
 * application at 0x1000, below the scratch window its drive writes (board/board.h).
 * Otherwise upstream's linker/nrf52840.ld. The CF2 block keeps its address but is not
 * loaded: the self-update path compares block addresses with it exactly as the
 * bootloader does, and the image holds nothing at or above 0x40000.
 */

SEARCH_DIR(.)
GROUP(-lgcc -lc -lnosys)

MEMORY
{
  FLASH (rx) : ORIGIN = 0x1000, LENGTH = 0x40000 - 0x1000

  BOOTLOADER_CONFIG (r): ORIGIN = 0xFE000 - 2K, LENGTH = 2K
  MBR_PARAMS_PAGE (rw) : ORIGIN = 0xFE000, LENGTH = 0x1000
  BOOTLOADER_SETTINGS (rw) : ORIGIN = 0xFF000, LENGTH = 0x1000

  RAM (rwx) :  ORIGIN = 0x20008000, LENGTH = 0x20040000-0x20008000
  DBL_RESET (rwx) :  ORIGIN = 0x20007F7C, LENGTH = 0x04
  NOINIT (rwx) :  ORIGIN = 0x20007F80, LENGTH = 0x80

  UICR_BOOTLOADER (r) : ORIGIN = 0x10001014, LENGTH = 0x04
  UICR_MBR_PARAM_PAGE(r) : ORIGIN = 0x10001018, LENGTH = 0x04
}

SECTIONS
{
  .fs_data_out ALIGN(4):
  {
    PROVIDE( __start_fs_data = .);
    KEEP(*(fs_data))
    PROVIDE( __stop_fs_data = .);
  } = 0

  .bootloaderConfig (NOLOAD) :
  {
    KEEP(*(.bootloaderConfig))
  } > BOOTLOADER_CONFIG

  .bootloaderSettings(NOLOAD) :
  {
  } > BOOTLOADER_SETTINGS

  .uicrBootStartAddress :
  {
    KEEP(*(.uicrBootStartAddress))
  } > UICR_BOOTLOADER

  .mbrParamsPage(NOLOAD) :
  {
  } > MBR_PARAMS_PAGE

  .uicrMbrParamsPageAddress :
  {
    KEEP(*(.uicrMbrParamsPageAddress))
  } > UICR_MBR_PARAM_PAGE

  .dbl_reset(NOLOAD) :
  {
  } > DBL_RESET

  .noinit(NOLOAD) :
  {
  } > NOINIT
}

INCLUDE "nrf_common.ld"
