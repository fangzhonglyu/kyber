#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <assert.h>

#include <iostream>
#include <fstream>

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "top.h"

#define NTESTS 10
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#ifndef PRINT_UINT_ARR
#define PRINT_UINT_ARR(name, arr, len) \
  printf("\n%s: ", (name)); \
  for (int ii = 0; ii < (len); ii++) { \
    printf("%2x ", (int)(arr)[ii]); \
  } \
  printf("\n");
#endif

void ntt(sbit16_t r[256], int fdr, int fdw) {
  // Write select word
  bit32_t sel = 0;
  int nbytes = write(fdw, (void *)&sel, sizeof(sel));
  assert(nbytes == sizeof(sel));

  // Write input
  for ( int i = 0; i < 256; i = i + 2 ) {
    bit32_t input_word;
    input_word( 15, 0 )  = poly[i + 0];
    input_word( 31, 16 ) = poly[i + 1];

    int nbytes = write(fdw, (void *)&input_word, sizeof(input_word));
    assert(nbytes == sizeof(input_word));
  }

  // Read output
  for ( int i = 0; i < 256; i = i + 2 ) {
    bit32_t output_word;
    int nbytes = read(fdr, (void *)&output_word, sizeof(output_word));
    assert(nbytes == sizeof(output_word));

    poly[i + 0] = output_word( 15, 0 );
    poly[i + 1] = output_word( 31, 16 );
  }
}
void invntt(sbit16_t r[256], int fdr, int fdw) {
  // Write select word
  bit32_t sel = 1;
  int nbytes = write(fdw, (void *)&sel, sizeof(sel));
  assert(nbytes == sizeof(sel));

  // Write input
  for ( int i = 0; i < 256; i = i + 2 ) {
    bit32_t input_word;
    input_word( 15, 0 )  = poly[i + 0];
    input_word( 31, 16 ) = poly[i + 1];

    int nbytes = write(fdw, (void *)&input_word, sizeof(input_word));
    assert(nbytes == sizeof(input_word));
  }

  // Read output
  for ( int i = 0; i < 256; i = i + 2 ) {
    bit32_t output_word;
    int nbytes = read(fdr, (void *)&output_word, sizeof(output_word));
    assert(nbytes == sizeof(output_word));

    poly[i + 0] = output_word( 15, 0 );
    poly[i + 1] = output_word( 31, 16 );
  }
}

/*************************************************
* Name:        ntt_gold
*
* Description: Inplace number-theoretic transform (NTT) in Rq.
*              input is in standard order, output is in bitreversed order
*
* Arguments:   - sbit16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/
void ntt_gold(sbit16_t r[256]) {
  unsigned int len, start, j, k;
  sbit16_t t, zeta;

  k = 1;
  for(len = 128; len >= 2; len >>= 1) {
    for(start = 0; start < 256; start = j + len) {
      zeta = zetas[k++];
      for(j = start; j < start + len; j++) {
        t = fqmul(zeta, r[j + len]);
        r[j + len] = r[j] - t;
        r[j] = r[j] + t;
      }
    }
  }
}

/*************************************************
* Name:        invntt_gold
*
* Description: Inplace inverse number-theoretic transform in Rq and
*              multiplication by Montgomery factor 2^16.
*              Input is in bitreversed order, output is in standard order
*
* Arguments:   - sbit16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/
void invntt_gold(sbit16_t r[256]) {
  unsigned int start, len, j, k;
  sbit16_t t, zeta;
  const sbit16_t f = 1441; // mont^2/128

  k = 127;
  for(len = 2; len <= 128; len <<= 1) {
    for(start = 0; start < 256; start = j + len) {
      zeta = zetas[k--];
      for(j = start; j < start + len; j++) {
        t = r[j];
        r[j] = barrett_reduce(t + r[j + len]);
        r[j + len] = r[j + len] - t;
        r[j + len] = fqmul(zeta, r[j + len]);
      }
    }
  }

  for(j = 0; j < 256; j++)
    r[j] = fqmul(r[j], f);
}

static int test_ntt(int fdr, int fdw)
{
  bit8_t bytes[512];
  randombytes<sizeof(bytes)>(bytes);

  sbit16_t r_gold[256];
  for (int i = 0; i < 256; i++) {
    r_gold[i](7, 0) = bytes[2*i];
    r_gold[i](15, 8) = bytes[2*i + 1];
  }

  sbit16_t r[256];
  for (int i = 0; i < 256; i++) {
    r[i](15, 0) = r_gold[i];
  }

  ntt(r, fdr, fdw);
  ntt_gold(r_gold);

  for (int i = 0; i < 256; i++) {
    if (r[i] != r_gold[i]) {
      printf(ANSI_COLOR_RED "ERROR" ANSI_COLOR_RESET " ntt[%d] = %d, ntt_gold[%d] = %d\n", i, r[i], i, r_gold[i]);
      return 1;
    }
  }

  return 0;
}

static int test_invntt(int fdr, int fdw)
{
  bit8_t bytes[512];
  randombytes<sizeof(bytes)>(bytes);

  sbit16_t r_gold[256];
  for (int i = 0; i < 256; i++) {
    r_gold[i](7, 0) = bytes[2*i];
    r_gold[i](15, 8) = bytes[2*i + 1];
  }

  sbit16_t r[256];
  for (int i = 0; i < 256; i++) {
    r[i](15, 0) = r_gold[i];
  }

  invntt(r, fdr, fdw);
  invntt_gold(r_gold);

  for (int i = 0; i < 256; i++) {
    if (r[i] != r_gold[i]) {
      printf(ANSI_COLOR_RED "ERROR" ANSI_COLOR_RESET " ntt[%d] = %d, ntt_gold[%d] = %d\n", i, r[i], i, r_gold[i]);
      return 1;
    }
  }

  return 0;
}

int main()
{
  unsigned int i;
  int r;

  int fdr = open("/dev/xillybus_read_32", O_RDONLY);
  int fdw = open("/dev/xillybus_write_32", O_WRONLY);
  
  // Check that the channels are correctly opened
  if ((fdr < 0) || (fdw < 0)) {
    fprintf(stderr, "Failed to open Xillybus device channels\n");
    exit(-1);
  }

  for(i=0;i<NTESTS;i++) {
    r  = test_ntt(fdr, fdw);
    r |= test_invntt(fdr, fdw);
    if(r)
      return 1;
  }

  return 0;
}
