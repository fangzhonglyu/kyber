#ifndef NTT_H
#define NTT_H

#include "params.h"
#include "reduce.h"
#include "typedefs.h"

/* Code to generate zetas and zetas_inv used in the number-theoretic
transform:

#define KYBER_ROOT_OF_UNITY 17

static const uint8_t tree[128] = {
  0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120,
  4, 68, 36, 100, 20, 84, 52, 116, 12, 76, 44, 108, 28, 92, 60, 124,
  2, 66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122,
  6, 70, 38, 102, 22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126,
  1, 65, 33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121,
  5, 69, 37, 101, 21, 85, 53, 117, 13, 77, 45, 109, 29, 93, 61, 125,
  3, 67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91, 59, 123,
  7, 71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127
};

void init_ntt() {
  unsigned int i;
  sbit16_t tmp[128];

  tmp[0] = MONT;
  for(i=1;i<128;i++)
    tmp[i] = fqmul(tmp[i-1],MONT*KYBER_ROOT_OF_UNITY % KYBER_Q);

  for(i=0;i<128;i++) {
    zetas[i] = tmp[tree[i]];
    if(zetas[i] > KYBER_Q/2)
      zetas[i] -= KYBER_Q;
    if(zetas[i] < -KYBER_Q/2)
      zetas[i] += KYBER_Q;
  }
}
*/

const sbit16_t zetas[128] = {
    -1044, -758,  -359,  -1517, 1493,  1422,  287,   202,   -171,  622,
    1577,  182,   962,   -1202, -1474, 1468,  573,   -1325, 264,   383,
    -829,  1458,  -1602, -130,  -681,  1017,  732,   608,   -1542, 411,
    -205,  -1571, 1223,  652,   -552,  1015,  -1293, 1491,  -282,  -1544,
    516,   -8,    -320,  -666,  -1618, -1162, 126,   1469,  -853,  -90,
    -271,  830,   107,   -1421, -247,  -951,  -398,  961,   -1508, -725,
    448,   -1065, 677,   -1275, -1103, 430,   555,   843,   -1251, 871,
    1550,  105,   422,   587,   177,   -235,  -291,  -460,  1574,  1653,
    -246,  778,   1159,  -147,  -777,  1483,  -602,  1119,  -1590, 644,
    -872,  349,   418,   329,   -156,  -75,   817,   1097,  603,   610,
    1322,  -1285, -1465, 384,   -1215, -136,  1218,  -1335, -874,  220,
    -1187, -1659, -1185, -1530, -1278, 794,   -1510, -854,  -870,  478,
    -108,  -308,  996,   991,   958,   -1460, 1522,  1628 };

/*************************************************
 * Name:        fqmul
 *
 * Description: Multiplication followed by Montgomery reduction
 *
 * Arguments:   - sbit16_t a: first factor
 *              - sbit16_t b: second factor
 *
 * Returns 16-bit integer congruent to a*b*R^{-1} mod q
 **************************************************/
static sbit16_t fqmul( sbit16_t a, sbit16_t b )
{
  return montgomery_reduce( (sbit32_t) a * b );
}

/*************************************************
 * Name:        ntt
 *
 * Description: Inplace number-theoretic transform (NTT) in Rq.
 *              input is in standard order, output is in bitreversed order
 *
 * Arguments:   - sbit16_t r[256]: pointer to input/output vector of
 *elements of Zq
 **************************************************/
template <int LEN, int K>
void ntt_fpga_helper( sbit16_t r[256] )
{
#pragma HLS INLINE
  bit32_t  start, j, j_loop, k;
  sbit16_t t, zeta;
  sbit16_t r_j, r_j_len;

  k = K;
  for ( start = 0; start < 256; start += ( 2 * LEN ) ) {
    zeta = zetas[k++];
    for ( j_loop = 0; j_loop < LEN; j_loop++ ) {
#pragma HLS PIPELINE
      j          = j_loop + start;
      r_j        = r[j];
      r_j_len    = r[j + LEN];
      t          = fqmul( zeta, r_j_len );
      r[j + LEN] = r_j - t;
      r[j]       = r_j + t;
    }
  }
}

void ntt( sbit16_t r[256] )
{
  // bit32_t  len, start, j, j_loop, k;
  // sbit16_t t, zeta;

  // k = 1;
  // for ( len = 128; len >= 2; len >>= 1 ) {
  //   for ( start = 0; start < 256; start += 4 ) {
  //     if ( start % ( 2 * len ) == 0 ) {
  //       zeta = zetas[k++];
  //       for ( j_loop = 0; j_loop < 128; j_loop++ ) {
  //         j = j_loop + start;
  //         if ( j < start + len ) {
  //           t          = fqmul( zeta, r[j + len] );
  //           r[j + len] = r[j] - t;
  //           r[j]       = r[j] + t;
  //         }
  //       }
  //     }
  //   }
  // }
  ntt_fpga_helper<128, 1>( r );
  ntt_fpga_helper<64, 2>( r );
  ntt_fpga_helper<32, 4>( r );
  ntt_fpga_helper<16, 8>( r );
  ntt_fpga_helper<8, 16>( r );
  ntt_fpga_helper<4, 32>( r );
  ntt_fpga_helper<2, 64>( r );
}

/*************************************************
 * Name:        invntt_tomont
 *
 * Description: Inplace inverse number-theoretic transform in Rq and
 *              multiplication by Montgomery factor 2^16.
 *              Input is in bitreversed order, output is in standard order
 *
 * Arguments:   - sbit16_t r[256]: pointer to input/output vector of
 *elements of Zq
 **************************************************/
template <int LEN, int K>
void invntt_fpga_helper( sbit16_t r[256] )
{
#pragma HLS INLINE
  bit32_t        start, j, j_loop, k;
  sbit16_t       t, zeta;
  const sbit16_t f = 1441;  // mont^2/128
  sbit16_t       r_j, r_j_len;

  k = K;
  for ( start = 0; start < 256; start += ( 2 * LEN ) ) {
    zeta = zetas[k--];
    for ( j_loop = 0; j_loop < LEN; j_loop++ ) {
#pragma HLS PIPELINE
      j          = j_loop + start;
      r_j        = r[j];
      r_j_len    = r[j + LEN];
      r[j]       = barrett_reduce( r_j + r_j_len );
      r_j_len    = r_j_len - r_j;
      r[j + LEN] = fqmul( zeta, r_j_len );
    }
  }
}

void invntt( sbit16_t r[256] )
{
  // bit32_t        start, len, j, k;
  // sbit16_t       t, zeta;
  bit32_t        j;
  const sbit16_t f = 1441;  // mont^2/128

  // k = 127;
  // for ( len = 2; len <= 128; len <<= 1 ) {
  //   for ( start = 0; start < 256; start = j + len ) {
  //     zeta = zetas[k--];
  //     for ( j = start; j < start + len; j++ ) {
  //       t          = r[j];
  //       r[j]       = barrett_reduce( t + r[j + len] );
  //       r[j + len] = r[j + len] - t;
  //       r[j + len] = fqmul( zeta, r[j + len] );
  //     }
  //   }
  // }
  invntt_fpga_helper<2, 127>( r );
  invntt_fpga_helper<4, 63>( r );
  invntt_fpga_helper<8, 31>( r );
  invntt_fpga_helper<16, 15>( r );
  invntt_fpga_helper<32, 7>( r );
  invntt_fpga_helper<64, 3>( r );
  invntt_fpga_helper<128, 1>( r );

  for ( j = 0; j < 256; j++ )
#pragma HLS PIPELINE
    r[j] = fqmul( r[j], f );
}

/*************************************************
 * Name:        basemul
 *
 * Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
 *              used for multiplication of elements in Rq in NTT domain
 *
 * Arguments:   - sbit16_t r[2]: pointer to the output polynomial
 *              - const sbit16_t a[2]: pointer to the first factor
 *              - const sbit16_t b[2]: pointer to the second factor
 *              - sbit16_t zeta: integer defining the reduction polynomial
 **************************************************/
void basemul( sbit16_t r[2], const sbit16_t a[2], const sbit16_t b[2],
              sbit16_t zeta )
{
  r[0] = fqmul( a[1], b[1] );
  r[0] = fqmul( r[0], zeta );
  r[0] += fqmul( a[0], b[0] );
  r[1] = fqmul( a[0], b[1] );
  r[1] += fqmul( a[1], b[0] );
}

#endif
