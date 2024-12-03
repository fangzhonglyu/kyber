#ifndef INDCPA_H
#define INDCPA_H

#include "params.h"
#include "typedefs.h"
#include "ntt.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "symmetric.h"

/*************************************************
 * Name:        pack_pk
 *
 * Description: Serialize the public key as concatenation of the
 *              serialized vector of polynomials pk
 *              and the public seed used to generate the matrix A.
 *
 * Arguments:   bit8_t *r: pointer to the output serialized public key
 *              polyvec *pk: pointer to the input public-key polyvec
 *              const bit8_t *seed: pointer to the input public seed
 **************************************************/
static void pack_pk(bit8_t r[KYBER_INDCPA_PUBLICKEYBYTES], sbit16_t pk[KYBER_K][KYBER_N],
                    const bit8_t seed[KYBER_SYMBYTES]) {
  polyvec_tobytes(r, pk);
  for (int i = 0; i < KYBER_SYMBYTES; i++) {
    r[KYBER_POLYVECBYTES + i] = seed[i];
  }
  //memcpy(r + KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}

/*************************************************
 * Name:        unpack_pk
 *
 * Description: De-serialize public key from a byte array;
 *              approximate inverse of pack_pk
 *
 * Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
 *              - bit8_t *seed: pointer to output seed to generate matrix A
 *              - const bit8_t *packedpk: pointer to input serialized public key
 **************************************************/
static void unpack_pk(sbit16_t pk[KYBER_K][KYBER_N], bit8_t seed[KYBER_SYMBYTES],
                      const bit8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]) {
  polyvec_frombytes(pk, packedpk);
  for (int i = 0; i < KYBER_SYMBYTES; i++) {
    seed[i] = packedpk[KYBER_POLYVECBYTES + i];
  }
  // memcpy(seed, packedpk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

/*************************************************
 * Name:        pack_sk
 *
 * Description: Serialize the secret key
 *
 * Arguments:   - bit8_t *r: pointer to output serialized secret key
 *              - polyvec *sk: pointer to input vector of polynomials (secret
 *key)
 **************************************************/
static void pack_sk(bit8_t r[KYBER_INDCPA_SECRETKEYBYTES], sbit16_t sk[KYBER_K][KYBER_N]) {
  polyvec_tobytes(r, sk);
}

/*************************************************
 * Name:        unpack_sk
 *
 * Description: De-serialize the secret key; inverse of pack_sk
 *
 * Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret
 *key)
 *              - const bit8_t *packedsk: pointer to input serialized secret key
 **************************************************/
static void unpack_sk(sbit16_t sk[KYBER_K][KYBER_N],
                      const bit8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
  polyvec_frombytes(sk, packedsk);
}

/*************************************************
 * Name:        pack_ciphertext
 *
 * Description: Serialize the ciphertext as concatenation of the
 *              compressed and serialized vector of polynomials b
 *              and the compressed and serialized polynomial v
 *
 * Arguments:   bit8_t *r: pointer to the output serialized ciphertext
 *              poly *pk: pointer to the input vector of polynomials b
 *              poly *v: pointer to the input polynomial v
 **************************************************/
static void pack_ciphertext(bit8_t r[KYBER_INDCPA_BYTES], sbit16_t b[KYBER_K][KYBER_N], sbit16_t v[KYBER_N]) {
  polyvec_compress(r, b);
  poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
 * Name:        unpack_ciphertext
 *
 * Description: De-serialize and decompress ciphertext from a byte array;
 *              approximate inverse of pack_ciphertext
 *
 * Arguments:   - polyvec *b: pointer to the output vector of polynomials b
 *              - poly *v: pointer to the output polynomial v
 *              - const bit8_t *c: pointer to the input serialized ciphertext
 **************************************************/
static void unpack_ciphertext(sbit16_t b[KYBER_K][KYBER_N], sbit16_t v[KYBER_N],
                              const bit8_t c[KYBER_INDCPA_BYTES]) {
  polyvec_decompress(b, c);
  poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
 * Name:        rej_uniform
 *
 * Description: Run rejection sampling on uniform random bytes to generate
 *              uniform random integers mod q
 *
 * Arguments:   - int16_t *r: pointer to output buffer
 *              - bit32_t len: requested number of 16-bit integers (uniform mod
 *q)
 *              - const bit8_t *buf: pointer to input buffer (assumed to be
 *uniformly random bytes)
 *
 * Returns number of sampled 16-bit integers (at most len)
 **************************************************/
template<int BUF_LEN>
static bit32_t rej_uniform(sbit16_t *r, bit32_t len, const bit8_t buf[BUF_LEN]) {
    bit32_t ctr = 0;
    bit32_t pos = 0;

REJ_SAMPLE:
    for (bit32_t i = 0; i < BUF_LEN / 3; i++) {
        #pragma HLS pipeline II=3
        if (ctr >= len) break;
        bit8_t buf0 = buf[pos + 0];
        bit8_t buf1 = buf[pos + 1];
        bit8_t buf2 = buf[pos + 2];

        sbit16_t val0 = ((buf0 >> 0) | ((sbit16_t)buf1 << 8)) & 0xFFF;
        sbit16_t val1 = ((buf1 >> 4) | ((sbit16_t)buf2 << 4)) & 0xFFF;

        pos += 3;

        if (val0 < KYBER_Q) {
            r[ctr] = val0;
            ctr++;
        }
        if (ctr < len && val1 < KYBER_Q) {
            r[ctr] = val1;
            ctr++;
        }
    }

    return ctr;
}
#ifndef GEN_MATRIX_MACROS
#define GEN_MATRIX_MACROS
#define gen_a(A, B) gen_matrix(A, B, 0)
#define gen_at(A, B) gen_matrix(A, B, 1)
#endif


/*************************************************
 * Name:        gen_matrix
 *
 * Description: Deterministically generate matrix A (or the transpose of A)
 *              from a seed. Entries of the matrix are polynomials that look
 *              uniformly random. Performs rejection sampling on output of
 *              a XOF
 *
 * Arguments:   - polyvec a[KYBER_K]: output matrix A
 *              - const bit8_t *seed: pointer to input seed
 *              - int transposed: boolean deciding whether A or A^T is generated
 **************************************************/
#if (XOF_BLOCKBYTES % 3)
#error \
    "Implementation of gen_matrix assumes that XOF_BLOCKBYTES is a multiple of 3"
#endif

#define GEN_MATRIX_NBLOCKS ((12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES)

#define MAX_UNIFORM_REJECTIONS (KYBER_N + XOF_BLOCKBYTES - 1) / XOF_BLOCKBYTES

void gen_matrix(sbit16_t a[KYBER_K][KYBER_K][KYBER_N], const bit8_t seed[KYBER_SYMBYTES], bit transposed) {
  bit32_t ctr, i, j, k;
  bit8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
  xof_state state;

GEN_ROW:
  for (i = 0; i < KYBER_K; i++) {
GEN_COL:
    for (j = 0; j < KYBER_K; j++) {
      if (transposed)
        xof_absorb(&state, seed, i, j);
      else
        xof_absorb(&state, seed, j, i);

      shake128_squeezeblocks<GEN_MATRIX_NBLOCKS>(buf, &state);
      ctr = rej_uniform<GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES>(a[i][j], KYBER_N, buf);

REJECTION_SAMPLE:
      while (ctr < KYBER_N) {
        shake128_squeezeblocks<1>(buf, &state);
        ctr += rej_uniform<XOF_BLOCKBYTES>(a[i][j] + ctr, KYBER_N - ctr, buf);
      }
    }
  }
}


/*************************************************
 * Name:        indcpa_keypair_derand
 *
 * Description: Generates public and private key for the CPA-secure
 *              public-key encryption scheme underlying Kyber
 *
 * Arguments:   - bit8_t *pk: pointer to output public key
 *                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
 *              - bit8_t *sk: pointer to output private key
 *                             (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
 *              - const bit8_t *coins: pointer to input randomness
 *                             (of length KYBER_SYMBYTES bytes)
 **************************************************/
void indcpa_keypair_derand(bit8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           bit8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const bit8_t coins[KYBER_SYMBYTES]) {
  bit32_t i;
  bit8_t buf[2 * KYBER_SYMBYTES];
  const bit8_t *publicseed = buf;
  const bit8_t *noiseseed = buf + KYBER_SYMBYTES;
  bit8_t nonce = 0;
  sbit16_t a[KYBER_K][KYBER_K][KYBER_N];
  sbit16_t e[KYBER_K][KYBER_N];
  sbit16_t pkpv[KYBER_K][KYBER_N];
  sbit16_t skpv[KYBER_K][KYBER_N];

  for (i = 0; i < KYBER_SYMBYTES; i++) {
    buf[i] = coins[i];
  }
  buf[KYBER_SYMBYTES] = KYBER_K;
  hash_g(buf, buf, KYBER_SYMBYTES + 1);

  gen_a(a, publicseed);

  for (i = 0; i < KYBER_K; i++)
    poly_getnoise_eta1(skpv[i], noiseseed, nonce++);
  for (i = 0; i < KYBER_K; i++)
    poly_getnoise_eta1(e[i], noiseseed, nonce++);

  polyvec_ntt(skpv);
  polyvec_ntt(e);

  // matrix-vector multiplication
  for (i = 0; i < KYBER_K; i++) {
    polyvec_basemul_acc_montgomery(pkpv[i], a[i], skpv);
    poly_tomont(pkpv[i]);
  }

  polyvec_add(pkpv, pkpv, e);
  polyvec_reduce(pkpv);

  pack_sk(sk, skpv);
  pack_pk(pk, pkpv, publicseed);
}

/*************************************************
 * Name:        indcpa_enc
 *
 * Description: Encryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - bit8_t *c: pointer to output ciphertext
 *                            (of length KYBER_INDCPA_BYTES bytes)
 *              - const bit8_t *m: pointer to input message
 *                                  (of length KYBER_INDCPA_MSGBYTES bytes)
 *              - const bit8_t *pk: pointer to input public key
 *                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
 *              - const bit8_t *coins: pointer to input random coins used as
 *seed (of length KYBER_SYMBYTES) to deterministically generate all randomness
 **************************************************/
void indcpa_enc(bit8_t c[KYBER_INDCPA_BYTES],
                const bit8_t m[KYBER_INDCPA_MSGBYTES],
                const bit8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const bit8_t coins[KYBER_SYMBYTES]) {
  bit32_t i;
  bit8_t seed[KYBER_SYMBYTES];
  bit8_t nonce = 0;
  sbit16_t sp[KYBER_K][KYBER_N], pkpv[KYBER_K][KYBER_N], ep[KYBER_K][KYBER_N], at[KYBER_K][KYBER_K][KYBER_N], b[KYBER_K][KYBER_N];
  sbit16_t v[KYBER_N], k[KYBER_N], epp[KYBER_N];

  unpack_pk(pkpv, seed, pk);
  poly_frommsg(k, m);
  gen_at(at, seed);

  for (i = 0; i < KYBER_K; i++) poly_getnoise_eta1(sp[i], coins, nonce++);
  for (i = 0; i < KYBER_K; i++) poly_getnoise_eta2(ep[i], coins, nonce++);
  poly_getnoise_eta2(epp, coins, nonce++);

  polyvec_ntt(sp);

  // matrix-vector multiplication
  for (i = 0; i < KYBER_K; i++)
    polyvec_basemul_acc_montgomery(b[i], at[i], sp);

  polyvec_basemul_acc_montgomery(v, pkpv, sp);

  polyvec_invntt_tomont(b);
  poly_invntt_tomont(v);

  polyvec_add(b, b, ep);
  poly_add(v, v, epp);
  poly_add(v, v, k);
  polyvec_reduce(b);
  poly_reduce(v);

  pack_ciphertext(c, b, v);
}

/*************************************************
 * Name:        indcpa_dec
 *
 * Description: Decryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - bit8_t *m: pointer to output decrypted message
 *                            (of length KYBER_INDCPA_MSGBYTES)
 *              - const bit8_t *c: pointer to input ciphertext
 *                                  (of length KYBER_INDCPA_BYTES)
 *              - const bit8_t *sk: pointer to input secret key
 *                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
 **************************************************/
void indcpa_dec(bit8_t m[KYBER_INDCPA_MSGBYTES],
                const bit8_t c[KYBER_INDCPA_BYTES],
                const bit8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
  sbit16_t b[KYBER_K][KYBER_N], skpv[KYBER_K][KYBER_N];
  sbit16_t v[KYBER_N], mp[KYBER_N];

  unpack_ciphertext(b, v, c);
  unpack_sk(skpv, sk);

  polyvec_ntt(b);
  polyvec_basemul_acc_montgomery(mp, skpv, b);
  poly_invntt_tomont(mp);

  poly_sub(mp, v, mp);
  poly_reduce(mp);

  poly_tomsg(m, mp);
}

#endif
