#ifndef VERIFY_H
#define VERIFY_H

#include "params.h"
#include "typedefs.h"

int verify(const bit8_t *a, const bit8_t *b, bit32_t len);

void cmov(bit8_t *r, const bit8_t *x, bit32_t len, bit8_t b);

void cmov_int16(sbit16_t *r, sbit16_t v, bit16_t b);

#endif
