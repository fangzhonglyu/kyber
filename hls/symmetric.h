#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>

#include "fips202.h"
#include "params.h"
#include "typedefs.h"

typedef keccak_state xof_state;

#define kyber_shake128_absorb KYBER_NAMESPACE(kyber_shake128_absorb)
void kyber_shake128_absorb(keccak_state *s, const bit8_t seed[KYBER_SYMBYTES],
                           bit8_t x, bit8_t y);

#define kyber_shake256_prf KYBER_NAMESPACE(kyber_shake256_prf)
void kyber_shake256_prf(bit8_t *out, bit32_t outlen,
                        const bit8_t key[KYBER_SYMBYTES], bit8_t nonce);

#define kyber_shake256_rkprf KYBER_NAMESPACE(kyber_shake256_rkprf)
void kyber_shake256_rkprf(bit8_t out[KYBER_SSBYTES],
                          const bit8_t key[KYBER_SYMBYTES],
                          const bit8_t input[KYBER_CIPHERTEXTBYTES]);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) \
  shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) \
  kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) kyber_shake256_rkprf(OUT, KEY, INPUT)

#endif /* SYMMETRIC_H */
