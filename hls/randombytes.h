#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include "typedefs.h"

bit8_t lfsr_random(bit8_t seed);

template <int L>
void randombytes(bit8_t out[L]) {
  static bit8_t seed = 0;
  for (int i = 0; i < L; i++) {
    out[i] = lfsr_random(seed);
    seed = out[i];
  }
}

#endif
