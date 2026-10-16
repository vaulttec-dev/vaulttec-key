/* The C library header littlefs and p256-cortex-m4 include, for a target with no C
 * library. Only what they call: the memory functions come from Rust's
 * compiler-builtins, the string ones from tinyrlibc (littlefs2-sys's `tinyrlibc`
 * feature) and littlefs2's own stubs. A call to anything else fails to compile here
 * instead of linking against something nobody chose. */
#ifndef VKEY_STRING_H
#define VKEY_STRING_H

#include <stddef.h>

int memcmp(const void *a, const void *b, size_t n);
void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
char *strchr(const char *s, int c);
char *strcpy(char *dst, const char *src);
size_t strcspn(const char *s, const char *reject);
size_t strlen(const char *s);
size_t strspn(const char *s, const char *accept);

#endif
