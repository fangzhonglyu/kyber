#ifndef VERIFY_H
#define VERIFY_H

#include <stddef.h>

#include "params.h"
#include "typedefs.h"

#define verify KYBER_NAMESPACE(verify)
int verify(const bit8_t *a, const bit8_t *b, bit32_t len);

#define cmov KYBER_NAMESPACE(cmov)
void cmov(bit8_t *r, const bit8_t *x, bit32_t len, bit8_t b);

#define cmov_int16 KYBER_NAMESPACE(cmov_int16)
void cmov_int16(sbit16_t *r, sbit16_t v, bit16_t b);

#endif
