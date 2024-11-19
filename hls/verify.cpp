#include "verify.h"

/*************************************************
 * Name:        verify
 *
 * Description: Compare two arrays for equality in constant time.
 *
 * Arguments:   const bit8_t *a: pointer to first byte array
 *              const bit8_t *b: pointer to second byte array
 *              bit32_t len:       length of the byte arrays
 *
 * Returns 0 if the byte arrays are equal, 1 otherwise
 **************************************************/
int verify(const bit8_t *a, const bit8_t *b, bit32_t len) {
  bit32_t i;
  bit8_t r = 0;

  for (i = 0; i < len; i++) r |= a[i] ^ b[i];

  return (-(bit64_t)r) >> 63;
}

/*************************************************
 * Name:        cmov
 *
 * Description: Copy len bytes from x to r if b is 1;
 *              don't modify x if b is 0. Requires b to be in {0,1};
 *              assumes two's complement representation of negative integers.
 *              Runs in constant time.
 *
 * Arguments:   bit8_t *r:       pointer to output byte array
 *              const bit8_t *x: pointer to input byte array
 *              bit32_t len:       Amount of bytes to be copied
 *              bit8_t b:        Condition bit; has to be in {0,1}
 **************************************************/
void cmov(bit8_t *r, const bit8_t *x, bit32_t len, bit8_t b) {
  bit32_t i;

  b = -b;
  for (i = 0; i < len; i++) r[i] ^= (bit8_t)(b & (r[i] ^ x[i]));
}

/*************************************************
 * Name:        cmov_int16
 *
 * Description: Copy input v to *r if b is 1, don't modify *r if b is 0.
 *              Requires b to be in {0,1};
 *              Runs in constant time.
 *
 * Arguments:   int16_t *r:       pointer to output int16_t
 *              int16_t v:        input int16_t
 *              bit8_t b:        Condition bit; has to be in {0,1}
 **************************************************/
void cmov_int16(sbit16_t *r, sbit16_t v, bit16_t b) {
  b = -b;
  *r ^= (sbit16_t)(b & ((*r) ^ v));
}
