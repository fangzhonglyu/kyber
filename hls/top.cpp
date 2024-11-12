//==========================================================================
// top.cpp
//==========================================================================
// The top-level modules for Kyber on the FPGA

#ifndef TOP_CPP
#define TOP_CPP

#include "top.h"

#include "kem.h"

//--------------------------------------------------------------------------
// Encryption
//--------------------------------------------------------------------------

void dut_enc(hls::stream<bit32_t> &strm_in, hls::stream<bit32_t> &strm_out) {
  bit8_t pk[CRYPTO_PUBLICKEYBYTES];
  bit8_t ct[CRYPTO_CIPHERTEXTBYTES];
  bit8_t key_b[CRYPTO_BYTES];

  // Read public key
  for( int i = 0; i < CRYPTO_PUBLICKEYBYTES; i = i + 4 ){
    bit32_t pk_word;
    pk_word = strm_in.read();

    pk[i + 0] = pk_word(7,0);
    pk[i + 1] = pk_word(15,8);
    pk[i + 2] = pk_word(23,16);
    pk[i + 3] = pk_word(31,24);
  }

  // Perform encryption
  crypto_kem_enc(ct, key_b, pk);

  // Write resulting shared secret
  for( int i = 0; i < CRYPTO_PUBLICKEYBYTES; i = i + 4 ){
    bit32_t key_b_word;
    key_b_word(7,0) = key_b[i + 0];
    key_b_word(15,8) = key_b[i + 1];
    key_b_word(23,16) = key_b[i + 2];
    key_b_word(31,24) = key_b[i + 3];

    strm_out.write(key_b_word);
  }

  // Write resulting ciphertext
  for( int i = 0; i < CRYPTO_CIPHERTEXTBYTES; i = i + 4 ){
    bit32_t ct_word;
    key_b_word(7,0) = ct[i + 0];
    key_b_word(15,8) = ct[i + 1];
    key_b_word(23,16) = ct[i + 2];
    key_b_word(31,24) = ct[i + 3];

    strm_out.write(ct_word);
  }
}

#endif  // TOP_H