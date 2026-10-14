/*
 * The on-board test of this bootloader fork (docs2/roadmap.md, phase 3, milestone 4).
 *
 * Built with VKEY_AS_APP (patches/0007-as-app.patch), the bootloader runs as an
 * application from 0x1000 under the factory bootloader, which stays in place, so a
 * failure here costs a replug with the button held. Before it serves its drive, it
 * checks with the calls the bootloader itself makes:
 *
 *   - the app the real signing pipeline signed, which test/board.py places in the
 *     scratch window with its slot, and the same slot with one bit of R flipped;
 *   - whatever a bootloader self-update, copied onto this build's own drive, left
 *     staged there.
 *
 * Each verdict and the cycles DWT counted for it go into INFO_UF2.TXT: with no serial
 * port and no probe, the drive is the only way out.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "nrf.h"
#include "app_util.h"
#include "boards.h"
#include "uf2/uf2.h"
#include "signature.h"

/* Where test/board.py puts the app: the image, then its slot and the altered slot. */
#define TEST_APP_IMAGE    BOARD_TEST_SCRATCH
#define TEST_APP_SLOT     (BOARD_TEST_SCRATCH + 0x20000)
#define TEST_APP_ALTERED  (TEST_APP_SLOT + SIGNATURE_SLOT_SIZE)

/* What the installed bootloader allows an app: everything up to its slot at 0x96000. */
#define REAL_APP_MAX      (0x96000 - MBR_SIZE)

_Static_assert(TEST_APP_ALTERED + SIGNATURE_SLOT_SIZE <= BOOTLOADER_ADDR_NEW_RECIEVED,
               "the test app overlaps the staging area");
_Static_assert(USER_FLASH_END <= 0x97000, "the test window reaches the vault");

/* ghostfat.c: one sector, the header already in it. */
extern char infoUf2File[];
#define INFO_SIZE (512 - 1)

__attribute__((format(printf, 1, 2)))
static void say(char const *format, ...) {
  size_t const used = strlen(infoUf2File);
  va_list args;
  va_start(args, format);
  vsnprintf(infoUf2File + used, INFO_SIZE - used, format, args);
  va_end(args);
}

static void check(char const *what, uint8_t const *image, uint8_t const *slot,
                  uint32_t kind, uint32_t max_length, bool exact, char const *want) {
  uint32_t const start = DWT->CYCCNT;
  bool const valid = signature_valid(image, slot, kind, max_length, exact);
  uint32_t const cycles = DWT->CYCCNT - start;
  char const *verdict = valid ? "accepted" : "refused";
  say("%s: %s, %lu cycles%s\r\n", what, verdict, (unsigned long) cycles,
      want == NULL ? "" : strcmp(verdict, want) == 0 ? " - ok" : " - WRONG");
}

void app_test_run(void) {
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

  say("Test: as app at 0x%X, ICACHECNF 0x%lX\r\n", MBR_SIZE,
      (unsigned long) NRF_NVMC->ICACHECNF);

  uint8_t const *image = (uint8_t const *) TEST_APP_IMAGE;
  check("app", image, (uint8_t const *) TEST_APP_SLOT, SIGNATURE_KIND_APP, REAL_APP_MAX,
        false, "accepted");
  check("app, R altered", image, (uint8_t const *) TEST_APP_ALTERED, SIGNATURE_KIND_APP,
        REAL_APP_MAX, false, "refused");
  check("app as bootloader", image, (uint8_t const *) TEST_APP_SLOT,
        SIGNATURE_KIND_BOOTLOADER, REAL_APP_MAX, false, "refused");

  /* The same check msc_uf2.c makes before COPY_BL, on what the last copy staged. */
  uint8_t const *staged = (uint8_t const *) BOOTLOADER_ADDR_NEW_RECIEVED;
  uint32_t const signed_length = DFU_BL_IMAGE_MAX_SIZE - SIGNATURE_SLOT_SIZE;
  if (*(uint32_t const *) staged == 0xFFFFFFFF) {
    say("staged update: none\r\n");
  } else {
    check("staged update", staged, staged + signed_length, SIGNATURE_KIND_BOOTLOADER,
          signed_length, true, NULL);
  }
}
