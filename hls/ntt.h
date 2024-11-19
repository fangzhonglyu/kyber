#ifndef NTT_H
#define NTT_H

#include "params.h"
#include "typedefs.h"

extern const sbit16_t zetas[128];

void ntt(sbit16_t poly[256]);

void invntt(sbit16_t poly[256]);

void basemul(sbit16_t r[2], const sbit16_t a[2], const sbit16_t b[2],
             sbit16_t zeta);

#endif
