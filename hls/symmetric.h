#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include "fips202.h"
#include "params.h"
#include "typedefs.h"

typedef keccak_state xof_state;

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256<INBYTES>(OUT, IN)
#define hash_g(OUT, IN, INBYTES) sha3_512<INBYTES>(OUT, IN)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define rkprf(OUT, KEY, INPUT) kyber_shake256_rkprf(OUT, KEY, INPUT)

/*************************************************
 * Name:        kyber_shake128_absorb
 *
 * Description: Absorb step of the SHAKE128 specialized for the Kyber context.
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak
 *state
 *              - const bit8_t *seed: pointer to KYBER_SYMBYTES input to be
 *absorbed into state
 *              - bit8_t i: additional byte of input
 *              - bit8_t j: additional byte of input
 **************************************************/
void kyber_shake128_absorb(keccak_state *state,
                           const bit8_t seed[KYBER_SYMBYTES], bit8_t x,
                           bit8_t y) {
  bit8_t extseed[KYBER_SYMBYTES + 2];

  for (int i = 0; i < KYBER_SYMBYTES; i++) {
    extseed[i] = seed[i];
  }
  // memcpy(extseed, seed, KYBER_SYMBYTES);
  extseed[KYBER_SYMBYTES + 0] = x;
  extseed[KYBER_SYMBYTES + 1] = y;

  shake128_absorb_once<KYBER_SYMBYTES + 2>(state, extseed);
}

/*************************************************
 * Name:        kyber_shake256_prf
 *
 * Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
 *              and then generates outlen bytes of SHAKE256 output
 *
 * Arguments:   - bit8_t *out: pointer to output
 *              - bit32_t outlen: number of requested output bytes
 *              - const bit8_t *key: pointer to the key (of length
 *KYBER_SYMBYTES)
 *              - bit8_t nonce: single-byte nonce (public PRF input)
 **************************************************/
template<int outlen>
void kyber_shake256_prf(bit8_t *out, const bit8_t key[KYBER_SYMBYTES], bit8_t nonce) {
  bit8_t extkey[KYBER_SYMBYTES + 1];

  for (int i = 0; i < KYBER_SYMBYTES; i++) {
    extkey[i] = key[i];
  }
  // memcpy(extkey, key, KYBER_SYMBYTES);
  extkey[KYBER_SYMBYTES] = nonce;

  shake256<outlen, KYBER_SYMBYTES>(out, extkey);
}

/*************************************************
 * Name:        kyber_shake256_prf
 *
 * Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
 *              and then generates outlen bytes of SHAKE256 output
 *
 * Arguments:   - bit8_t *out: pointer to output
 *              - bit32_t outlen: number of requested output bytes
 *              - const bit8_t *key: pointer to the key (of length
 *KYBER_SYMBYTES)
 *              - bit8_t nonce: single-byte nonce (public PRF input)
 **************************************************/
void kyber_shake256_rkprf(bit8_t out[KYBER_SSBYTES],
                          const bit8_t key[KYBER_SYMBYTES],
                          const bit8_t input[KYBER_CIPHERTEXTBYTES]) {
  keccak_state s;

  shake256_init(&s);
  shake256_absorb<KYBER_SYMBYTES>(&s, key);
  shake256_absorb<KYBER_CIPHERTEXTBYTES>(&s, input);
  shake256_finalize(&s);
  shake256_squeeze<KYBER_SSBYTES>(out, &s);
}


#endif /* SYMMETRIC_H */