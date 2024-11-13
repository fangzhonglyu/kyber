#ifndef FIPS202_H
#define FIPS202_H

#include "typedefs.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
  bit64_t s[25];
  bit32_t pos;
} keccak_state;

void shake128_init(keccak_state *state);
void shake128_absorb(keccak_state *state, const bit8_t *in, bit32_t inlen);
void shake128_finalize(keccak_state *state);
void shake128_squeeze(bit8_t *out, bit32_t outlen, keccak_state *state);
void shake128_absorb_once(keccak_state *state, const bit8_t *in,
                          bit32_t inlen);
void shake128_squeezeblocks(bit8_t *out, bit32_t nblocks, keccak_state *state);

void shake256_init(keccak_state *state);
void shake256_absorb(keccak_state *state, const bit8_t *in, bit32_t inlen);
void shake256_finalize(keccak_state *state);
void shake256_squeeze(bit8_t *out, bit32_t outlen, keccak_state *state);
void shake256_absorb_once(keccak_state *state, const bit8_t *in,
                          bit32_t inlen);
void shake256_squeezeblocks(bit8_t *out, bit32_t nblocks, keccak_state *state);

void shake128(bit8_t *out, bit32_t outlen, const bit8_t *in, bit32_t inlen);
void shake256(bit8_t *out, bit32_t outlen, const bit8_t *in, bit32_t inlen);
void sha3_256(bit8_t h[32], const bit8_t *in, bit32_t inlen);
void sha3_512(bit8_t h[64], const bit8_t *in, bit32_t inlen);

#endif
