#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../kem.h"
#include "../randombytes.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define NTESTS 1000

static int test_keys(void)
{
  bit8_t pk[CRYPTO_PUBLICKEYBYTES];
  bit8_t sk[CRYPTO_SECRETKEYBYTES];
  bit8_t ct[CRYPTO_CIPHERTEXTBYTES];
  bit8_t key_a[CRYPTO_BYTES];
  bit8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(memcmp(key_a, key_b, CRYPTO_BYTES)) {
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
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Replace secret key with random values

  randombytes<CRYPTO_SECRETKEYBYTES>(sk);

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

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
    randombytes<sizeof(bit8_t)>(&b);
  } while(!b);
  randombytes<sizeof(size_t)>((bit8_t *)&pos);

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Change some byte in the ciphertext (i.e., encapsulated key)
  ct[pos % CRYPTO_CIPHERTEXTBYTES] ^= b;

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

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
