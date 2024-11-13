#include <string.h>

#include "fips202.h"
#include "params.h"
#include "symmetric.h"

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

  memcpy(extseed, seed, KYBER_SYMBYTES);
  extseed[KYBER_SYMBYTES + 0] = x;
  extseed[KYBER_SYMBYTES + 1] = y;

  shake128_absorb_once(state, extseed, sizeof(extseed));
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
void kyber_shake256_prf(bit8_t *out, bit32_t outlen,
                        const bit8_t key[KYBER_SYMBYTES], bit8_t nonce) {
  bit8_t extkey[KYBER_SYMBYTES + 1];

  memcpy(extkey, key, KYBER_SYMBYTES);
  extkey[KYBER_SYMBYTES] = nonce;

  shake256(out, outlen, extkey, sizeof(extkey));
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
  shake256_absorb(&s, key, KYBER_SYMBYTES);
  shake256_absorb(&s, input, KYBER_CIPHERTEXTBYTES);
  shake256_finalize(&s);
  shake256_squeeze(out, KYBER_SSBYTES, &s);
}
