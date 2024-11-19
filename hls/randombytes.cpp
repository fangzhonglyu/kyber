#include "randombytes.h"

bit8_t lfsr_random(bit8_t seed) {
    bool bit;  // Must be a single bit, not int
    bit8_t lfsr = seed;
    if (lfsr == 0) lfsr = 0xACE1u;  // Non-zero seed
    bit  = ((lfsr >> 0) ^ (lfsr >> 2) ^ (lfsr >> 3) ^ (lfsr >> 5) ) & 1;
    lfsr =  (lfsr >> 1) | (bit << 7);
    return lfsr;
}