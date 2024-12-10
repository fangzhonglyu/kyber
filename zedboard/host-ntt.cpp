// =======================================================================
// host-ntt.cpp
// =======================================================================
// A host for running only ntt/invntt on the FPGA

#include "params.h"
#include "randombytes.h"
#include "timer.h"
#include "typedefs.h"
#include <assert.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REPS 1000
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

#ifndef PRINT_UINT_ARR
#define PRINT_UINT_ARR( name, arr, len )   \
  printf( "\n%s: ", ( name ) );            \
  for ( int ii = 0; ii < ( len ); ii++ ) { \
    printf( "%2x ", (int) ( arr )[ii] );   \
  }                                        \
  printf( "\n" );
#endif

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

sbit16_t montgomery_reduce( sbit32_t a );
sbit16_t fqmul( sbit16_t a, sbit16_t b )
{
  return montgomery_reduce( (sbit32_t) a * b );
}
sbit16_t barrett_reduce( sbit16_t a );

void ntt_stream( sbit16_t poly[REPS][256], int fdr, int fdw,
                 Timer *timer )
{
  bit32_t sel = 0;

  // Start timer
  timer->start();

  // Write input
  for ( int r = 0; r < REPS; r++ ) {
    // Write select word
    int nbytes = write( fdw, (void *) &sel, sizeof( sel ) );
    assert( nbytes == sizeof( sel ) );

    for ( int i = 0; i < 256; i = i + 2 ) {
      bit32_t input_word;
      input_word( 15, 0 )  = poly[r][i + 0];
      input_word( 31, 16 ) = poly[r][i + 1];

      int nbytes =
          write( fdw, (void *) &input_word, sizeof( input_word ) );
      assert( nbytes == sizeof( input_word ) );
    }
  }

  // Read output
  for ( int r = 0; r < REPS; r++ ) {
    for ( int i = 0; i < 256; i = i + 2 ) {
      bit32_t output_word;
      int     nbytes =
          read( fdr, (void *) &output_word, sizeof( output_word ) );
      assert( nbytes == sizeof( output_word ) );

      poly[r][i + 0] = output_word( 15, 0 );
      poly[r][i + 1] = output_word( 31, 16 );
    }
  }

  // Stop timer
  timer->stop();
}
void invntt_stream( sbit16_t poly[REPS][256], int fdr, int fdw,
                    Timer *timer )
{
  bit32_t sel = 1;

  // Start timer
  timer->start();

  // Write input
  for ( int r = 0; r < REPS; r++ ) {
    // Write select word
    int nbytes = write( fdw, (void *) &sel, sizeof( sel ) );
    assert( nbytes == sizeof( sel ) );

    for ( int i = 0; i < 256; i = i + 2 ) {
      bit32_t input_word;
      input_word( 15, 0 )  = poly[r][i + 0];
      input_word( 31, 16 ) = poly[r][i + 1];

      int nbytes =
          write( fdw, (void *) &input_word, sizeof( input_word ) );
      assert( nbytes == sizeof( input_word ) );
    }
  }

  // Read output
  for ( int r = 0; r < REPS; r++ ) {
    for ( int i = 0; i < 256; i = i + 2 ) {
      bit32_t output_word;
      int     nbytes =
          read( fdr, (void *) &output_word, sizeof( output_word ) );
      assert( nbytes == sizeof( output_word ) );

      poly[r][i + 0] = output_word( 15, 0 );
      poly[r][i + 1] = output_word( 31, 16 );
    }
  }

  // Stop timer
  timer->stop();
}

/*************************************************
 * Name:        ntt_gold
 *
 * Description: Inplace number-theoretic transform (NTT) in Rq.
 *              input is in standard order, output is in bitreversed order
 *
 * Arguments:   - sbit16_t r[256]: pointer to input/output vector of
 *elements of Zq
 **************************************************/
void ntt_gold( sbit16_t r[256] )
{
  unsigned int len, start, j, k;
  sbit16_t     t, zeta;

  k = 1;
  for ( len = 128; len >= 2; len >>= 1 ) {
    for ( start = 0; start < 256; start = j + len ) {
      zeta = zetas[k++];
      for ( j = start; j < start + len; j++ ) {
        t          = fqmul( zeta, r[j + len] );
        r[j + len] = r[j] - t;
        r[j]       = r[j] + t;
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
 * Arguments:   - sbit16_t r[256]: pointer to input/output vector of
 *elements of Zq
 **************************************************/
void invntt_gold( sbit16_t r[256] )
{
  unsigned int   start, len, j, k;
  sbit16_t       t, zeta;
  const sbit16_t f = 1441;  // mont^2/128

  k = 127;
  for ( len = 2; len <= 128; len <<= 1 ) {
    for ( start = 0; start < 256; start = j + len ) {
      zeta = zetas[k--];
      for ( j = start; j < start + len; j++ ) {
        t          = r[j];
        r[j]       = barrett_reduce( t + r[j + len] );
        r[j + len] = r[j + len] - t;
        r[j + len] = fqmul( zeta, r[j + len] );
      }
    }
  }

  for ( j = 0; j < 256; j++ )
    r[j] = fqmul( r[j], f );
}

static int test_ntt( int fdr, int fdw )
{
  bit8_t bytes[REPS][512];
  for ( int r = 0; r < REPS; r++ ) {
    randombytes<sizeof( bytes[r] )>( bytes[r] );
  }

  sbit16_t poly_gold[REPS][256];
  for ( int r = 0; r < REPS; r++ ) {
    for ( int i = 0; i < 256; i++ ) {
      poly_gold[r][i]( 7, 0 )  = bytes[r][2 * i];
      poly_gold[r][i]( 15, 8 ) = bytes[r][2 * i + 1];
    }
  }

  sbit16_t poly[REPS][256];
  for ( int r = 0; r < REPS; r++ ) {
    for ( int i = 0; i < 256; i++ ) {
      poly[r][i] = poly_gold[r][i];
    }
  }

  Timer timer( "ntt test" );

  ntt_stream( poly, fdr, fdw, &timer );
  for ( int r = 0; r < REPS; r++ ) {
    ntt_gold( poly_gold[r] );
  }

  for ( int r = 0; r < REPS; r++ ) {
    for ( int i = 0; i < 256; i++ ) {
      if ( poly[r][i] != poly_gold[r][i] ) {
        printf( ANSI_COLOR_RED
                "ERROR" ANSI_COLOR_RESET
                " ntt[%d][%d] = %d, ntt_gold[%d][%d] = %d\n",
                r, i, int( poly[r][i] ), r, i, int( poly_gold[r][i] ) );
        return 1;
      }
    }
  }

  return 0;
}

static int test_invntt( int fdr, int fdw )
{
  bit8_t bytes[REPS][512];
  for ( int r = 0; r < REPS; r++ ) {
    randombytes<sizeof( bytes[r] )>( bytes[r] );
  }

  sbit16_t poly_gold[REPS][256];
  for ( int r = 0; r < REPS; r++ ) {
    for ( int i = 0; i < 256; i++ ) {
      poly_gold[r][i]( 7, 0 )  = bytes[r][2 * i];
      poly_gold[r][i]( 15, 8 ) = bytes[r][2 * i + 1];
    }
  }

  sbit16_t poly[REPS][256];
  for ( int r = 0; r < REPS; r++ ) {
    for ( int i = 0; i < 256; i++ ) {
      poly[r][i] = poly_gold[r][i];
    }
  }

  Timer timer( "invntt test" );

  invntt_stream( poly, fdr, fdw, &timer );
  for ( int r = 0; r < REPS; r++ ) {
    invntt_gold( poly_gold[r] );
  }

  for ( int r = 0; r < REPS; r++ ) {
    for ( int i = 0; i < 256; i++ ) {
      if ( poly[r][i] != poly_gold[r][i] ) {
        printf( ANSI_COLOR_RED
                "ERROR" ANSI_COLOR_RESET
                " invntt[%d][%d] = %d, invntt_gold[%d][%d] = %d\n",
                r, i, int( poly[r][i] ), r, i, int( poly_gold[r][i] ) );
        return 1;
      }
    }
  }

  return 0;
}

int main()
{
  unsigned int i;
  int          r;

  int fdr = open( "/dev/xillybus_read_32", O_RDONLY );
  int fdw = open( "/dev/xillybus_write_32", O_WRONLY );

  // Check that the channels are correctly opened
  if ( ( fdr < 0 ) || ( fdw < 0 ) ) {
    fprintf( stderr, "Failed to open Xillybus device channels\n" );
    exit( -1 );
  }

  r = test_ntt( fdr, fdw );
  r |= test_invntt( fdr, fdw );
  if ( r )
    return 1;

  return 0;
}
