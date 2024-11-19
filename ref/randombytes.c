#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "randombytes.h"

uint8_t lfsr_random(uint8_t seed) {
    uint8_t bit;  // Must be a single bit, not int
    uint8_t lfsr = seed;
    if (lfsr == 0) lfsr = 0xACE1u;  // Non-zero seed
    bit  = ((lfsr >> 0) ^ (lfsr >> 2) ^ (lfsr >> 3) ^ (lfsr >> 5) ) & 1;
    lfsr =  (lfsr >> 1) | (bit << 7);
    return lfsr;
}

void randombytes(uint8_t *out, size_t L) {
  static uint8_t seed = 0xc0;
  for (int i = 0; i < L; i++) {
    out[i] = lfsr_random(seed);
    seed = out[i];
  }
}