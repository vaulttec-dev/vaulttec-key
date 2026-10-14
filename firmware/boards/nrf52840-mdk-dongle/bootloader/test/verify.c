/*
 * src/signature.c against the cases test/cases.py made, compiled for the board's core
 * and run under qemu-arm. Exits 0 when every case is decided as expected and the
 * streamed check agrees with Monocypher's one-shot crypto_ed25519_check; otherwise
 * prints the case and exits 1.
 */

#include <stdint.h>
#include <string.h>

#include "cases.h"
#include "monocypher-ed25519.h"
#include "signature.h"
#include "signing_key.h"

static uint8_t const KEY[32] = SIGNING_PUBLIC_KEY_BYTES;

static void sys_write(char const *s) {
  int const n = (int) strlen(s); /* before the register variables: a call clobbers r0-r3 */
  register int r0 __asm__("r0") = 1;
  register char const *r1 __asm__("r1") = s;
  register int r2 __asm__("r2") = n;
  register int r7 __asm__("r7") = 4;
  __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
}

static void sys_exit(int code) {
  register int r0 __asm__("r0") = code;
  register int r7 __asm__("r7") = 1;
  __asm__ volatile("svc 0" :: "r"(r0), "r"(r7));
  for (;;) {}
}

static void fail(char const *what, char const *name) {
  sys_write(what);
  sys_write(name);
  sys_write("\n");
  sys_exit(1);
}

void _start(void) {
  for (unsigned i = 0; i < sizeof CASES / sizeof CASES[0]; i++) {
    struct test_case const *c = &CASES[i];
    bool const got = signature_valid(c->image, c->slot, c->kind, c->max_length, c->exact);
    if (got != (c->expect != 0)) fail(got ? "accepted: " : "refused: ", c->name);
  }
  /* The streamed hash must be exactly the one crypto_ed25519_check computes */
  if (crypto_ed25519_check(CASES[0].slot + 0x40, KEY, APP_MESSAGE, sizeof APP_MESSAGE) != 0)
    fail("one-shot refused: ", CASES[0].name);
  if (crypto_ed25519_check(CASES[14].slot + 0x40, KEY, BOOT_MESSAGE, sizeof BOOT_MESSAGE) != 0)
    fail("one-shot refused: ", CASES[14].name);
  sys_exit(0);
}
