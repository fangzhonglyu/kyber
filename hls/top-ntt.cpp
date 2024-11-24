//==========================================================================
// top-ntt.cpp
//==========================================================================
// The top-level modules for NTT on the FPGA

#ifndef TOP_NTT_CPP
#define TOP_NTT_CPP

#include "ntt.h"
#include "top-ntt.h"

void dut_ntt( hls::stream<bit32_t> &strm_in,
              hls::stream<bit32_t> &strm_out )
{
  sbit16_t poly[256];

  // Read input
  for ( int i = 0; i < 256; i = i + 2 ) {
    bit32_t input_word;
    input_word = strm_in.read();

    poly[i + 0] = input_word( 15, 0 );
    poly[i + 1] = input_word( 31, 16 );
  }

  // Perform ntt
  ntt( poly );

  // Write resulting output
  for ( int i = 0; i < 256; i = i + 2 ) {
    bit32_t output_word;
    output_word( 15, 0 )  = poly[i + 0];
    output_word( 31, 16 ) = poly[i + 1];

    strm_out.write( output_word );
  }
}

#endif  // TOP_NTT_H