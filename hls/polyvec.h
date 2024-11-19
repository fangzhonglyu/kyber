#ifndef POLYVEC_H
#define POLYVEC_H

#include "params.h"
#include "poly.h"
#include "typedefs.h"

typedef struct {
  poly vec[KYBER_K];
} polyvec;

void print_poly_vec(polyvec *p);
void polyvec_compress(bit8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a);
void polyvec_decompress(polyvec *r,
                        const bit8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

void polyvec_tobytes(bit8_t r[KYBER_POLYVECBYTES], const polyvec *a);
void polyvec_frombytes(polyvec *r, const bit8_t a[KYBER_POLYVECBYTES]);

void polyvec_ntt(polyvec *r);
void polyvec_invntt_tomont(polyvec *r);

void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a,
                                    const polyvec *b);

void polyvec_reduce(polyvec *r);

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif
