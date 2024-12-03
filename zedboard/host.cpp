#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <assert.h>

#include <iostream>
#include <fstream>

#include "timer.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "top.h"

#define REPS 20
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


bit8_t lfsr_random(bit8_t seed);

template <int L>
void gen_randombytes(bit8_t out[L]) {
  static bit8_t seed = 0xc0;
  for (int i = 0; i < L; i++) {
    out[i] = lfsr_random(seed);
    seed = out[i];
  }
}


int main(int argc, char **argv)
{
  // Open channels to the FPGA board.
  // These channels appear as files to the Linux OS
  int fdr = open("/dev/xillybus_read_32", O_RDONLY);
  int fdw = open("/dev/xillybus_write_32", O_WRONLY);
  
  // Check that the channels are correctly opened
  if ((fdr < 0) || (fdw < 0)) {
    fprintf(stderr, "Failed to open Xillybus device channels\n");
    exit(-1);
  }


  bit8_t pk[REPS][CRYPTO_PUBLICKEYBYTES];
  bit8_t sk[REPS][CRYPTO_SECRETKEYBYTES];
  bit8_t ct[REPS][CRYPTO_CIPHERTEXTBYTES];

  bit8_t key_a[REPS][CRYPTO_BYTES];
  bit8_t key_b[REPS][CRYPTO_BYTES];

  //Alice generates a public key
  for (int i = 0; i < REPS; i++) {
    keypair(pk[i], sk[i]);
  }

  //Bob derives a secret key and creates a response
  // Timer
  Timer timer("kyber on FPGA");

  std::cout << "Running " << REPS << " reps" << std::endl;
  
  timer.start();
  // Send public keys to Bob
  for (int rep = 0; rep < REPS; rep++) {
    for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i = i + 4) {
      bit32_t pk_word;
      pk_word(7, 0) = pk[rep][i + 0];
      pk_word(15, 8) = pk[rep][i + 1];
      pk_word(23, 16) = pk[rep][i + 2];
      pk_word(31, 24) = pk[rep][i + 3];

      int nbytes = write(fdw, (void *)&pk_word, sizeof(pk_word));
      assert(nbytes == sizeof(pk_word));
    }
  }

  for (int rep = 0; rep < REPS; rep++) {
    // Receive shared secret from Bob
    for (int i = 0; i < CRYPTO_BYTES; i = i + 4) {
      bit32_t key_b_word;
      int nbytes = read(fdr, (void *)&key_b_word, sizeof(key_b_word));
      assert(nbytes == sizeof(key_b_word));

      key_b[rep][i + 0] = key_b_word(7, 0);
      key_b[rep][i + 1] = key_b_word(15, 8);
      key_b[rep][i + 2] = key_b_word(23, 16);
      key_b[rep][i + 3] = key_b_word(31, 24);
    }
    // Receive ciphertext from Bob
    for (int i = 0; i < CRYPTO_CIPHERTEXTBYTES; i = i + 4) {
      bit32_t ct_word;
      int nbytes = read(fdr, (void *)&ct_word, sizeof(ct_word));
      assert(nbytes == sizeof(ct_word));

      ct[rep][i + 0] = ct_word(7, 0);
      ct[rep][i + 1] = ct_word(15, 8);
      ct[rep][i + 2] = ct_word(23, 16);
      ct[rep][i + 3] = ct_word(31, 24);
    }
  }
  timer.stop();

  //Alice uses Bobs response to get her shared key
  for (int rep = 0; rep < REPS; rep++) {
    dec(key_a[rep], ct[rep], sk[rep]);

    for(int i = 0; i < CRYPTO_BYTES; i++) {
      if(key_a[rep][i] != key_b[rep][i]) {
        printf("ERROR keys\n");
        for (int i = 0; i < CRYPTO_BYTES; i++) {
          if (key_a[rep][i] == key_b[rep][i]) {
            printf(ANSI_COLOR_GREEN "%d: %s == %s\n" ANSI_COLOR_RESET, i, key_a[rep][i].to_string(AP_HEX).c_str(), key_b[rep][i].to_string(AP_HEX).c_str());
          } else {
            printf(ANSI_COLOR_RED "%d: %s != %s\n" ANSI_COLOR_RESET, i, key_a[rep][i].to_string(AP_HEX).c_str(), key_b[rep][i].to_string(AP_HEX).c_str());
          }
        }
        return 1;
      }
    }
  }

  printf("SUCCESS\n");

  return 0;
}