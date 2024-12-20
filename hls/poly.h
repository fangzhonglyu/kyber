#ifndef POLY_H
#define POLY_H

#include "params.h"
#include "cbd.h"
#include "reduce.h"
#include "symmetric.h"
#include "verify.h"
#include "typedefs.h"

/*************************************************
 * Name:        poly_reduce
 *
 * Description: Applies Barrett reduction to all coefficients of a polynomial
 *              for details of the Barrett reduction see comments in reduce.c
 *
 * Arguments:   - poly *r: pointer to input/output polynomial
 **************************************************/
void poly_reduce(sbit16_t r[KYBER_N]) {
  bit32_t i;
  for (i = 0; i < KYBER_N; i++) r[i] = barrett_reduce(r[i]);
}


/*************************************************
 * Name:        poly_compress
 *
 * Description: Compression and subsequent serialization of a polynomial
 *
 * Arguments:   - bit8_t *r: pointer to output byte array
 *                            (of length KYBER_POLYCOMPRESSEDBYTES)
 *              - const poly *a: pointer to input polynomial
 **************************************************/
void poly_compress(bit8_t r[KYBER_POLYCOMPRESSEDBYTES], sbit16_t a[KYBER_N]) {
  int i, j;
  sbit16_t u;
  bit32_t d0;
  bit8_t t[8];

#if (KYBER_POLYCOMPRESSEDBYTES == 128)

  for (i = 0; i < KYBER_N / 8; i++) {
    for (j = 0; j < 8; j++) {
      // map to positive standard representatives
      u = a[8 * i + j];
      u += (u >> 15) & KYBER_Q;
      /*    t[j] = ((((usbit16_t)u << 4) + KYBER_Q/2)/KYBER_Q) & 15; */
      d0 = ((bit32_t) u) << 4;
      d0 += 1665;
      d0 *= 80635;
      d0 >>= 28;
      t[j] = (bit8_t)(d0 & 0xf);
    }

    r[0] = (bit8_t)(t[0] | (t[1] << 4));
    r[1] = (bit8_t)(t[2] | (t[3] << 4));
    r[2] = (bit8_t)(t[4] | (t[5] << 4));
    r[3] = (bit8_t)(t[6] | (t[7] << 4));

    r += 4;
  }
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
  for (i = 0; i < KYBER_N / 8; i++) {
    for (j = 0; j < 8; j++) {
      // map to positive standard representatives
      u = a[8 * i + j];
      u += (u >> 15) & KYBER_Q;
      /*    t[j] = ((((bit32_t)u << 5) + KYBER_Q/2)/KYBER_Q) & 31; */
      d0 = u << 5;
      d0 += 1664;
      d0 *= 40318;
      d0 >>= 27;
      t[j] = d0 & 0x1f;
    }

    r[0] = (t[0] >> 0) | (t[1] << 5);
    r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
    r[2] = (t[3] >> 1) | (t[4] << 4);
    r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
    r[4] = (t[6] >> 2) | (t[7] << 3);
    r += 5;
  }
#else
#error "KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
#endif
}

/*************************************************
 * Name:        poly_decompress
 *
 * Description: De-serialization and subsequent decompression of a polynomial;
 *              approximate inverse of poly_compress
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const bit8_t *a: pointer to input byte array
 *                                  (of length KYBER_POLYCOMPRESSEDBYTES bytes)
 **************************************************/
void poly_decompress(sbit16_t r[KYBER_N], const bit8_t a[KYBER_POLYCOMPRESSEDBYTES]) {
  bit32_t i;

#if (KYBER_POLYCOMPRESSEDBYTES == 128)
  for (i = 0; i < KYBER_N / 2; i++) {
    r[2 * i + 0] = (((bit16_t)(a[0] & 15) * KYBER_Q) + 8) >> 4;
    r[2 * i + 1] = (((bit16_t)(a[0] >> 4) * KYBER_Q) + 8) >> 4;
    a += 1;
  }
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
  bit32_t j;
  bit8_t t[8];
  for (i = 0; i < KYBER_N / 8; i++) {
    t[0] = (a[0] >> 0);
    t[1] = (a[0] >> 5) | (a[1] << 3);
    t[2] = (a[1] >> 2);
    t[3] = (a[1] >> 7) | (a[2] << 1);
    t[4] = (a[2] >> 4) | (a[3] << 4);
    t[5] = (a[3] >> 1);
    t[6] = (a[3] >> 6) | (a[4] << 2);
    t[7] = (a[4] >> 3);
    a += 5;

    for (j = 0; j < 8; j++)
      r[8 * i + j] = ((bit32_t)(t[j] & 31) * KYBER_Q + 16) >> 5;
  }
#else
#error "KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
#endif
}

/*************************************************
 * Name:        poly_tobytes
 *
 * Description: Serialization of a polynomial
 *
 * Arguments:   - bit8_t *r: pointer to output byte array
 *                            (needs space for KYBER_POLYBYTES bytes)
 *              - const poly *a: pointer to input polynomial
 **************************************************/
void poly_tobytes(bit8_t r[KYBER_POLYBYTES], const sbit16_t a[KYBER_N]) {
  bit32_t i;
  bit16_t t0, t1;

  for (i = 0; i < KYBER_N / 2; i++) {
    // map to positive standard representatives
    t0 = a[2 * i];
    t0 += ((sbit16_t)t0 >> 15) & KYBER_Q;
    t1 = a[2 * i + 1];
    t1 += ((sbit16_t)t1 >> 15) & KYBER_Q;
    r[3 * i + 0] = (t0 >> 0);
    r[3 * i + 1] = (t0 >> 8) | (t1 << 4);
    r[3 * i + 2] = (t1 >> 4);
  }
}

/*************************************************
 * Name:        poly_frombytes
 *
 * Description: De-serialization of a polynomial;
 *              inverse of poly_tobytes
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const bit8_t *a: pointer to input byte array
 *                                  (of KYBER_POLYBYTES bytes)
 **************************************************/
void poly_frombytes(sbit16_t r[KYBER_N], const bit8_t a[KYBER_POLYBYTES]) {
  bit32_t i;
  for (i = 0; i < KYBER_N / 2; i++) {
    r[2 * i] =
        ((a[3 * i + 0] >> 0) | ((bit16_t)a[3 * i + 1] << 8)) & 0xFFF;
    r[2 * i + 1] =
        ((a[3 * i + 1] >> 4) | ((bit16_t)a[3 * i + 2] << 4)) & 0xFFF;
  }
}

/*************************************************
 * Name:        poly_frommsg
 *
 * Description: Convert 32-byte message to polynomial
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const bit8_t *msg: pointer to input message
 **************************************************/
void poly_frommsg(sbit16_t r[KYBER_N], const bit8_t msg[KYBER_INDCPA_MSGBYTES]) {
  bit32_t i, j;

#if (KYBER_INDCPA_MSGBYTES != KYBER_N / 8)
#error "KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!"
#endif

  for (i = 0; i < KYBER_N / 8; i++) {
    for (j = 0; j < 8; j++) {
      r[8 * i + j] = 0;
      cmov_int16(r + 8 * i + j, ((KYBER_Q + 1) / 2), (msg[i] >> j) & 1);
    }
  }
}

/*************************************************
 * Name:        poly_tomsg
 *
 * Description: Convert polynomial to 32-byte message
 *
 * Arguments:   - bit8_t *msg: pointer to output message
 *              - const poly *a: pointer to input polynomial
 **************************************************/
void poly_tomsg(bit8_t msg[KYBER_INDCPA_MSGBYTES], const sbit16_t a[KYBER_N]) {
  bit32_t i, j;
  bit32_t t;

  for (i = 0; i < KYBER_N / 8; i++) {
    msg[i] = 0;
    for (j = 0; j < 8; j++) {
      t = a[8 * i + j];
      // t += ((sbit16_t)t >> 15) & KYBER_Q;
      // t  = (((t << 1) + KYBER_Q/2)/KYBER_Q) & 1;
      t <<= 1;
      t += 1665;
      t *= 80635;
      t >>= 28;
      t &= 1;
      msg[i] |= (bit8_t)(t << j);
    }
  }
}

/*************************************************
 * Name:        poly_getnoise_eta1
 *
 * Description: Sample a polynomial deterministically from a seed and a nonce,
 *              with output polynomial close to centered binomial distribution
 *              with parameter KYBER_ETA1
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const bit8_t *seed: pointer to input seed
 *                                     (of length KYBER_SYMBYTES bytes)
 *              - bit8_t nonce: one-byte input nonce
 **************************************************/
void poly_getnoise_eta1(sbit16_t r[KYBER_N], const bit8_t seed[KYBER_SYMBYTES],
                        bit8_t nonce) {
  bit8_t buf[KYBER_ETA1 * KYBER_N / 4];
  kyber_shake256_prf<KYBER_ETA1 * KYBER_N / 4>(buf, seed, nonce);
  poly_cbd_eta1(r, buf);
}

/*************************************************
 * Name:        poly_getnoise_eta2
 *
 * Description: Sample a polynomial deterministically from a seed and a nonce,
 *              with output polynomial close to centered binomial distribution
 *              with parameter KYBER_ETA2
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const bit8_t *seed: pointer to input seed
 *                                     (of length KYBER_SYMBYTES bytes)
 *              - bit8_t nonce: one-byte input nonce
 **************************************************/
void poly_getnoise_eta2(sbit16_t r[KYBER_N], const bit8_t seed[KYBER_SYMBYTES],
                        bit8_t nonce) {
  bit8_t buf[KYBER_ETA2 * KYBER_N / 4];
  kyber_shake256_prf<KYBER_ETA2 * KYBER_N / 4>(buf, seed, nonce);
  poly_cbd_eta2(r, buf);
}

/*************************************************
 * Name:        poly_ntt
 *
 * Description: Computes negacyclic number-theoretic transform (NTT) of
 *              a polynomial in place;
 *              inputs assumed to be in normal order, output in bitreversed
 *order
 *
 * Arguments:   - usbit16_t *r: pointer to in/output polynomial
 **************************************************/
void poly_ntt(sbit16_t r[KYBER_N]) {
  ntt(r);
  poly_reduce(r);
}

/*************************************************
 * Name:        poly_invntt_tomont
 *
 * Description: Computes inverse of negacyclic number-theoretic transform (NTT)
 *              of a polynomial in place;
 *              inputs assumed to be in bitreversed order, output in normal
 *order
 *
 * Arguments:   - usbit16_t *a: pointer to in/output polynomial
 **************************************************/
void poly_invntt_tomont(sbit16_t r[KYBER_N]) { invntt(r); }

/*************************************************
 * Name:        poly_basemul_montgomery
 *
 * Description: Multiplication of two polynomials in NTT domain
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const poly *a: pointer to first input polynomial
 *              - const poly *b: pointer to second input polynomial
 **************************************************/
void poly_basemul_montgomery(sbit16_t r[KYBER_N], sbit16_t a[KYBER_N], sbit16_t b[KYBER_N]) {
  bit32_t i;
  for (i = 0; i < KYBER_N / 4; i++) {
    basemul(&r[4 * i], &a[4 * i], &b[4 * i],
            zetas[64 + i]);
    basemul(&r[4 * i + 2], &a[4 * i + 2], &b[4 * i + 2],
            -zetas[64 + i]);
  }
}

/*************************************************
 * Name:        poly_tomont
 *
 * Description: Inplace conversion of all coefficients of a polynomial
 *              from normal domain to Montgomery domain
 *
 * Arguments:   - poly *r: pointer to input/output polynomial
 **************************************************/
void poly_tomont(sbit16_t r[KYBER_N]) {
  bit32_t i;
  const sbit16_t f = (1ULL << 32) % KYBER_Q;
  for (i = 0; i < KYBER_N; i++)
    r[i] = montgomery_reduce((sbit32_t)r[i] * f);
}

/*************************************************
 * Name:        poly_add
 *
 * Description: Add two polynomials; no modular reduction is performed
 *
 * Arguments: - poly *r: pointer to output polynomial
 *            - const poly *a: pointer to first input polynomial
 *            - const poly *b: pointer to second input polynomial
 **************************************************/
void poly_add(sbit16_t r[KYBER_N], const sbit16_t a[KYBER_N], const sbit16_t b[KYBER_N]) {
  bit32_t i;
  for (i = 0; i < KYBER_N; i++) r[i] = a[i] + b[i];
}

/*************************************************
 * Name:        poly_sub
 *
 * Description: Subtract two polynomials; no modular reduction is performed
 *
 * Arguments: - poly *r:       pointer to output polynomial
 *            - const poly *a: pointer to first input polynomial
 *            - const poly *b: pointer to second input polynomial
 **************************************************/
void poly_sub(sbit16_t r[KYBER_N], const sbit16_t a[KYBER_N], const sbit16_t b[KYBER_N]) {
  bit32_t i;
  for (i = 0; i < KYBER_N; i++) r[i] = a[i] - b[i];
}

#endif
