#include "kem.h"

#include <string.h>

#include "indcpa.h"
#include "params.h"
#include "randombytes.h"
#include "symmetric.h"
#include "verify.h"
/*************************************************
 * Name:        crypto_kem_keypair_derand
 *
 * Description: Generates public and private key
 *              for CCA-secure Kyber key encapsulation mechanism
 *
 * Arguments:   - bit8_t *pk: pointer to output public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - bit8_t *sk: pointer to output private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *              - bit8_t *coins: pointer to input randomness
 *                (an already allocated array filled with 2*KYBER_SYMBYTES
 *random bytes)
 **
 * Returns 0 (success)
 **************************************************/
void crypto_kem_keypair_derand(bit8_t *pk, bit8_t *sk, const bit8_t *coins) {
  indcpa_keypair_derand(pk, sk, coins);
  for (int i = 0; i < KYBER_PUBLICKEYBYTES; i++) {
    sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
  }
  //memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk,
         KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  for (int i = 0; i < KYBER_SYMBYTES; i++) {
    sk[i + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES] = coins[i + KYBER_SYMBYTES];
  }
  // memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, coins + KYBER_SYMBYTES,
  //        KYBER_SYMBYTES);
}

/*************************************************
 * Name:        crypto_kem_keypair
 *
 * Description: Generates public and private key
 *              for CCA-secure Kyber key encapsulation mechanism
 *
 * Arguments:   - bit8_t *pk: pointer to output public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - bit8_t *sk: pointer to output private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
void crypto_kem_keypair(bit8_t *pk, bit8_t *sk) {
  bit8_t coins[2 * KYBER_SYMBYTES];
  for(int i = 0; i < 2 * KYBER_SYMBYTES; i++) {
    coins[i] = 0;
  }
  randombytes<2*KYBER_SYMBYTES>(coins);
  crypto_kem_keypair_derand(pk, sk, coins);
}

/*************************************************
 * Name:        crypto_kem_enc_derand
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - bit8_t *ct: pointer to output cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - bit8_t *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const bit8_t *pk: pointer to input public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - const bit8_t *coins: pointer to input randomness
 *                (an already allocated array filled with KYBER_SYMBYTES random
 *bytes)
 **
 * Returns 0 (success)
 **************************************************/
void crypto_kem_enc_derand(bit8_t *ct, bit8_t *ss, const bit8_t *pk,
                           const bit8_t *coins) {
  bit8_t buf[2 * KYBER_SYMBYTES];
  /* Will contain key, coins */
  bit8_t kr[2 * KYBER_SYMBYTES];

  for (int i = 0; i < KYBER_SYMBYTES; i++) {
    buf[i] = 0;
  }
  //memcpy(buf, coins, KYBER_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_g(kr, buf, 2 * KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

  for (int i = 0; i < KYBER_SYMBYTES; i++) {
    ss[i] = kr[i];
  }
  //memcpy(ss, kr, KYBER_SYMBYTES);
}

/*************************************************
 * Name:        crypto_kem_enc
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - bit8_t *ct: pointer to output cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - bit8_t *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const bit8_t *pk: pointer to input public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
void crypto_kem_enc(bit8_t *ct, bit8_t *ss, const bit8_t *pk) {
  bit8_t coins[KYBER_SYMBYTES] = {0};
  // randombytes<KYBER_SYMBYTES>(coins);
  crypto_kem_enc_derand(ct, ss, pk, coins);
}

/*************************************************
 * Name:        crypto_kem_dec
 *
 * Description: Generates shared secret for given
 *              cipher text and private key
 *
 * Arguments:   - bit8_t *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const bit8_t *ct: pointer to input cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - const bit8_t *sk: pointer to input private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0.
 *
 * On failure, ss will contain a pseudo-random value.
 **************************************************/
void crypto_kem_dec(bit8_t *ss, const bit8_t *ct, const bit8_t *sk) {
  bit fail;
  bit8_t buf[2 * KYBER_SYMBYTES];
  /* Will contain key, coins */
  bit8_t kr[2 * KYBER_SYMBYTES];
  bit8_t cmp[KYBER_CIPHERTEXTBYTES + KYBER_SYMBYTES];
  const bit8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  for(int i = 0; i < KYBER_SYMBYTES; i++) {
    buf[i + KYBER_SYMBYTES] = sk[i + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES];
  }

  hash_g(kr, buf, 2 * KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* Compute rejection key */
  rkprf(ss, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, ct);

  /* Copy true key to return buffer if fail is false */
  cmov(ss, kr, KYBER_SYMBYTES, !fail);
}
