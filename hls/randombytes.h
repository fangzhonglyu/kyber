#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include "typedefs.h"

bit8_t lfsr_random(bit8_t seed) {
    bool bit;  // Must be a single bit, not int
    bit8_t lfsr = seed;
    if (lfsr == 0) lfsr = 0xACE1u;  // Non-zero seed
    bit  = ((lfsr >> 0) ^ (lfsr >> 2) ^ (lfsr >> 3) ^ (lfsr >> 5) ) & 1;
    lfsr =  (lfsr >> 1) | (bit << 7);
    return lfsr;
}

template <int L>
void randombytes(bit8_t out[L]) {
  static bit8_t seed = 0xc0;
  for (int i = 0; i < L; i++) {
    out[i] = lfsr_random(seed);
    seed = out[i];
  }
}

#endif
