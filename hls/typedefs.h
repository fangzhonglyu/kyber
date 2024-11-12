//===========================================================================
// typedefs.h
//===========================================================================
// @brief: This header defines the shorthand of several ap_uint data types.

#ifndef TYPEDEFS
#define TYPEDEFS

#include <ap_int.h>

typedef bool bit;
typedef ap_uint<8> bit8_t;
typedef ap_int<16> sbit16_t;
typedef ap_uint<16> bit16_t;
typedef ap_int<32> sbit32_t;
typedef ap_uint<32> bit32_t;
typedef ap_uint<64> bit64_t;

#endif
