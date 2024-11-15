#ifndef KEM_H
#define KEM_H

#include "params.h"
#include "typedefs.h"

#define CRYPTO_SECRETKEYBYTES KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES KYBER_SSBYTES

#if (KYBER_K == 2)
#define CRYPTO_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#define CRYPTO_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#define CRYPTO_ALGNAME "Kyber1024"
#endif

#define crypto_kem_keypair_derand KYBER_NAMESPACE(keypair_derand)
void crypto_kem_keypair_derand(bit8_t *pk, bit8_t *sk, const bit8_t *coins);

#define crypto_kem_keypair KYBER_NAMESPACE(keypair)
void crypto_kem_keypair(bit8_t *pk, bit8_t *sk);

#define crypto_kem_enc_derand KYBER_NAMESPACE(enc_derand)
void crypto_kem_enc_derand(bit8_t *ct, bit8_t *ss, const bit8_t *pk,
                           const bit8_t *coins);

#define crypto_kem_enc KYBER_NAMESPACE(enc)
void crypto_kem_enc(bit8_t *ct, bit8_t *ss, const bit8_t *pk);

#define crypto_kem_dec KYBER_NAMESPACE(dec)
void crypto_kem_dec(bit8_t *ss, const bit8_t *ct, const bit8_t *sk);

#endif
