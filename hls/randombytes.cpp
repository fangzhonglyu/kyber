#include "randombytes.h"

#include <stddef.h>
#include <stdlib.h>

#ifdef _WIN32
#include <wincrypt.h>
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#ifdef __linux__
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#elif __NetBSD__
#include <sys/random.h>
#else
#include <unistd.h>
#endif
#endif

#ifdef _WIN32
void randombytes(bit8_t *out, bit32_t outlen) {
  HCRYPTPROV ctx;
  bit32_t len;

  if (!CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT))
    abort();

  while (outlen > 0) {
    len = (outlen > 1048576) ? 1048576 : outlen;
    if (!CryptGenRandom(ctx, len, (BYTE *)out)) abort();

    out += len;
    outlen -= len;
  }

  if (!CryptReleaseContext(ctx, 0)) abort();
}
#elif defined(__linux__) && defined(SYS_getrandom)
void randombytes(bit8_t *out, bit32_t outlen) {
  sbit32_t ret;

  while (outlen > 0) {
    ret = syscall(SYS_getrandom, out, outlen, 0);
    if (ret == -1 && errno == EINTR)
      continue;
    else if (ret == -1)
      abort();

    out += ret;
    outlen -= ret;
  }
}
#elif defined(__NetBSD__)
void randombytes(bit8_t *out, bit32_t outlen) {
  sbit32_t ret;

  while (outlen > 0) {
    ret = getrandom(out, outlen, 0);
    if (ret == -1 && errno == EINTR)
      continue;
    else if (ret == -1)
      abort();

    out += ret;
    outlen -= ret;
  }
}
#else
void randombytes(bit8_t *out, bit32_t outlen) {
  static int fd = -1;
  sbit32_t ret;

  while (fd == -1) {
    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1 && errno == EINTR)
      continue;
    else if (fd == -1)
      abort();
  }

  while (outlen > 0) {
    ret = read(fd, out, outlen);
    if (ret == -1 && errno == EINTR)
      continue;
    else if (ret == -1)
      abort();

    out += ret;
    outlen -= ret;
  }
}
#endif
