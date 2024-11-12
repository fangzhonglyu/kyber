#ifndef NTT_H
#define NTT_H

#include <stdint.h>

#include "params.h"
#include "typedefs.h"

#define zetas KYBER_NAMESPACE(zetas)
extern const sbit16_t zetas[128];

#define ntt KYBER_NAMESPACE(ntt)
void ntt(sbit16_t poly[256]);

#define invntt KYBER_NAMESPACE(invntt)
void invntt(sbit16_t poly[256]);

#define basemul KYBER_NAMESPACE(basemul)
void basemul(sbit16_t r[2], const sbit16_t a[2], const sbit16_t b[2],
             sbit16_t zeta);

#endif
