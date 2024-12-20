#ifndef REDUCE_H
#define REDUCE_H

#include "params.h"
#include "typedefs.h"

#define MONT -1044  // 2^16 mod q
#define QINV -3327  // q^-1 mod 2^16

/*************************************************
 * Name:        montgomery_reduce
 *
 * Description: Montgomery reduction; given a 32-bit integer a, computes
 *              16-bit integer congruent to a * R^-1 mod q, where R=2^16
 *
 * Arguments:   - int32_t a: input integer to be reduced;
 *                           has to be in {-q2^15,...,q2^15-1}
 *
 * Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
 **************************************************/
sbit16_t montgomery_reduce(sbit32_t a) {
  sbit16_t t;

  t = (sbit16_t)a * QINV;
  t = (a - (sbit32_t)t * KYBER_Q) >> 16;
  return t;
}

/*************************************************
 * Name:        barrett_reduce
 *
 * Description: Barrett reduction; given a 16-bit integer a, computes
 *              centered representative congruent to a mod q in
 *{-(q-1)/2,...,(q-1)/2}
 *
 * Arguments:   - int16_t a: input integer to be reduced
 *
 * Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
 **************************************************/
sbit16_t barrett_reduce(sbit16_t a) {
  sbit16_t t;
  const sbit16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;

  t = ((sbit32_t)v * a + (1 << 25)) >> 26;
  t *= KYBER_Q;
  return a - t;
}

#endif
