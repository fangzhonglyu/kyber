//===========================================================================
// top.h
//===========================================================================
// @brief: This header file defines the interface for the core functions.

#ifndef TOP_H
#define TOP_H
#include "typedefs.h"
#include <hls_stream.h>

// Top function for ntt
void dut_ntt( hls::stream<bit32_t> &strm_in,
              hls::stream<bit32_t> &strm_out );

#endif
