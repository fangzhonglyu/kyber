#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../top.h"

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

bit8_t lfsr_random(bit8_t seed);

template <int L>
void gen_randombytes(bit8_t out[L]) {
  static bit8_t seed = 0xc0;
  for (int i = 0; i < L; i++) {
    out[i] = lfsr_random(seed);
    seed = out[i];
  }
}

static int test_keys(void)
{
  bit8_t pk[CRYPTO_PUBLICKEYBYTES];
  bit8_t sk[CRYPTO_SECRETKEYBYTES];
  bit8_t ct[CRYPTO_CIPHERTEXTBYTES];

  for(int i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) {
    ct[i] = 0;
  }

  bit8_t key_a[CRYPTO_BYTES];
  bit8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  keypair(pk, sk);

  hls::stream<bit32_t> dut_in;
  hls::stream<bit32_t> dut_out;

  // Read public key
  for ( int i = 0; i < CRYPTO_PUBLICKEYBYTES; i = i + 4 ) {
    bit32_t pk_word;
    pk_word( 7, 0 ) = pk[i + 0];
    pk_word( 15, 8 ) = pk[i + 1];
    pk_word( 23, 16 ) = pk[i + 2];
    pk_word( 31, 24 ) = pk[i + 3 ];
    dut_in.write(pk_word);
  }

  //Bob derives a secret key and creates a response
  dut_enc(dut_in, dut_out);

  for ( int i = 0; i < CRYPTO_BYTES; i = i + 4 ) {
    bit32_t key_b_word = dut_out.read();
    key_b[i + 0] = key_b_word( 7, 0 );
    key_b[i + 1] = key_b_word( 15, 8 );
    key_b[i + 2] = key_b_word( 23, 16 );
    key_b[i + 3] = key_b_word( 31, 24 );
  }

  for(int i = 0; i < CRYPTO_CIPHERTEXTBYTES; i = i + 4) {
    bit32_t ct_word = dut_out.read();
    ct[i + 0] = ct_word( 7, 0 );
    ct[i + 1] = ct_word( 15, 8 );
    ct[i + 2] = ct_word( 23, 16 );
    ct[i + 3] = ct_word( 31, 24 );
  }

  //Alice uses Bobs response to get her shared key
  dec(key_a, ct, sk);

  for(int i = 0; i < CRYPTO_BYTES; i++) {
    if(key_a[i] != key_b[i]) {
      printf("ERROR keys\n");
      for (int i = 0; i < CRYPTO_BYTES; i++) {
        if (key_a[i] == key_b[i]) {
          printf(ANSI_COLOR_GREEN "%d: %hhx == %hhx\n" ANSI_COLOR_RESET, i, key_a[i], key_b[i]);
        } else {
          printf(ANSI_COLOR_RED "%d: %hhx != %hhx\n" ANSI_COLOR_RESET, i, key_a[i], key_b[i]);
        }
      }
      return 1;
    }
  }

  return 0;
}

static int test_invalid_sk_a(void)
{
  bit8_t pk[CRYPTO_PUBLICKEYBYTES];
  bit8_t sk[CRYPTO_SECRETKEYBYTES];
  bit8_t ct[CRYPTO_CIPHERTEXTBYTES];
  bit8_t key_a[CRYPTO_BYTES];
  bit8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  keypair(pk, sk);

  enc(ct, key_b, pk);

  //Replace secret key with random values

  gen_randombytes<CRYPTO_SECRETKEYBYTES>(sk);

  //Alice uses Bobs response to get her shared key
  dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid sk\n");
    return 1;
  }

  return 0;
}

static int test_invalid_ciphertext(void)
{
  bit8_t pk[CRYPTO_PUBLICKEYBYTES];
  bit8_t sk[CRYPTO_SECRETKEYBYTES];
  bit8_t ct[CRYPTO_CIPHERTEXTBYTES];
  bit8_t key_a[CRYPTO_BYTES];
  bit8_t key_b[CRYPTO_BYTES];
  bit8_t b;
  size_t pos;

  do {
    gen_randombytes<sizeof(bit8_t)>(&b);
  } while(!b);
  gen_randombytes<sizeof(size_t)>((bit8_t *)&pos);

  //Alice generates a public key
  keypair(pk, sk);

  //Bob derives a secret key and creates a response
  enc(ct, key_b, pk);

  //Change some byte in the ciphertext (i.e., encapsulated key)
  ct[pos % CRYPTO_CIPHERTEXTBYTES] ^= b;

  //Alice uses Bobs response to get her shared key
  dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid ciphertext\n");
    return 1;
  }

  return 0;
}

int main()
{
  unsigned int i;
  int r;

  for(i=0;i<NTESTS;i++) {
    r  = test_keys();
    r |= test_invalid_sk_a();
    r |= test_invalid_ciphertext();
    if(r)
      return 1;
  }

  printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);

  return 0;
}
