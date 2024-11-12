#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>

#include "params.h"
#include "typedefs.h"

#define MONT -1044  // 2^16 mod q
#define QINV -3327  // q^-1 mod 2^16

#define montgomery_reduce KYBER_NAMESPACE(montgomery_reduce)
sbit16_t montgomery_reduce(sbit32_t a);

#define barrett_reduce KYBER_NAMESPACE(barrett_reduce)
sbit16_t barrett_reduce(sbit16_t a);

#endif
