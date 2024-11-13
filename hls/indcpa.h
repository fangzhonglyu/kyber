#ifndef INDCPA_H
#define INDCPA_H

#include "params.h"
#include "polyvec.h"
#include "typedefs.h"

#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(polyvec *a, const bit8_t seed[KYBER_SYMBYTES], bit transposed);

#define indcpa_keypair_derand KYBER_NAMESPACE(indcpa_keypair_derand)
void indcpa_keypair_derand(bit8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           bit8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const bit8_t coins[KYBER_SYMBYTES]);

#define indcpa_enc KYBER_NAMESPACE(indcpa_enc)
void indcpa_enc(bit8_t c[KYBER_INDCPA_BYTES],
                const bit8_t m[KYBER_INDCPA_MSGBYTES],
                const bit8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const bit8_t coins[KYBER_SYMBYTES]);

#define indcpa_dec KYBER_NAMESPACE(indcpa_dec)
void indcpa_dec(bit8_t m[KYBER_INDCPA_MSGBYTES],
                const bit8_t c[KYBER_INDCPA_BYTES],
                const bit8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

#endif
