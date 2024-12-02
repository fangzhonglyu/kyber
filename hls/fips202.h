#ifndef FIPS202_H
#define FIPS202_H

#include "typedefs.h"
#include "fips202.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
  bit64_t s[25];
  bit32_t pos;
} keccak_state;

/* Based on the public domain implementation in crypto_hash/keccakc512/simple/
 * from http://bench.cr.yp.to/supercop.html by Ronny Van Keer and the public
 * domain "TweetFips202" implementation from https://twitter.com/tweetfips202 by
 * Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe */

#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64 - offset)))

/*************************************************
 * Name:        load64
 *
 * Description: Load 8 bytes into bit64_t in little-endian order
 *
 * Arguments:   - const bit8_t *x: pointer to input byte array
 *
 * Returns the loaded 64-bit bit32_teger
 **************************************************/
static bit64_t load64(const bit8_t x[8]) {
  bit64_t r = 0;

  for (int i = 0; i < 8; i++) r |= (bit64_t)x[i] << 8 * i;

  return r;
}

/*************************************************
 * Name:        store64
 *
 * Description: Store a 64-bit integer to array of 8 bytes in little-endian
 *order
 *
 * Arguments:   - bit8_t *x: pointer to the output byte array (allocated)
 *              - bit64_t u: input 64-bit bit32_teger
 **************************************************/
static void store64(bit8_t x[8], bit64_t u) {
  for (int i = 0; i < 8; i++) x[i] = u >> 8 * i;
}

/* Keccak round constants */
static const bit64_t KeccakF_RoundConstants[NROUNDS] = {
    (bit64_t)0x0000000000000001ULL, (bit64_t)0x0000000000008082ULL,
    (bit64_t)0x800000000000808aULL, (bit64_t)0x8000000080008000ULL,
    (bit64_t)0x000000000000808bULL, (bit64_t)0x0000000080000001ULL,
    (bit64_t)0x8000000080008081ULL, (bit64_t)0x8000000000008009ULL,
    (bit64_t)0x000000000000008aULL, (bit64_t)0x0000000000000088ULL,
    (bit64_t)0x0000000080008009ULL, (bit64_t)0x000000008000000aULL,
    (bit64_t)0x000000008000808bULL, (bit64_t)0x800000000000008bULL,
    (bit64_t)0x8000000000008089ULL, (bit64_t)0x8000000000008003ULL,
    (bit64_t)0x8000000000008002ULL, (bit64_t)0x8000000000000080ULL,
    (bit64_t)0x000000000000800aULL, (bit64_t)0x800000008000000aULL,
    (bit64_t)0x8000000080008081ULL, (bit64_t)0x8000000000008080ULL,
    (bit64_t)0x0000000080000001ULL, (bit64_t)0x8000000080008008ULL};

/*************************************************
 * Name:        KeccakF1600_StatePermute
 *
 * Description: The Keccak F1600 Permutation
 *
 * Arguments:   - bit64_t *state: pointer to input/output Keccak state
 **************************************************/
static void KeccakF1600_StatePermute(bit64_t state[25]) {
  int round;

  bit64_t Aba, Abe, Abi, Abo, Abu;
  bit64_t Aga, Age, Agi, Ago, Agu;
  bit64_t Aka, Ake, Aki, Ako, Aku;
  bit64_t Ama, Ame, Ami, Amo, Amu;
  bit64_t Asa, Ase, Asi, Aso, Asu;
  bit64_t BCa, BCe, BCi, BCo, BCu;
  bit64_t Da, De, Di, Do, Du;
  bit64_t Eba, Ebe, Ebi, Ebo, Ebu;
  bit64_t Ega, Ege, Egi, Ego, Egu;
  bit64_t Eka, Eke, Eki, Eko, Eku;
  bit64_t Ema, Eme, Emi, Emo, Emu;
  bit64_t Esa, Ese, Esi, Eso, Esu;

  // copyFromState(A, state)
  Aba = state[0];
  Abe = state[1];
  Abi = state[2];
  Abo = state[3];
  Abu = state[4];
  Aga = state[5];
  Age = state[6];
  Agi = state[7];
  Ago = state[8];
  Agu = state[9];
  Aka = state[10];
  Ake = state[11];
  Aki = state[12];
  Ako = state[13];
  Aku = state[14];
  Ama = state[15];
  Ame = state[16];
  Ami = state[17];
  Amo = state[18];
  Amu = state[19];
  Asa = state[20];
  Ase = state[21];
  Asi = state[22];
  Aso = state[23];
  Asu = state[24];

  for (round = 0; round < NROUNDS; round += 2) {
    //    prepareTheta
    BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

    // thetaRhoPiChiIotaPrepareTheta(round, A, E)
    Da = BCu ^ ROL(BCe, 1);
    De = BCa ^ ROL(BCi, 1);
    Di = BCe ^ ROL(BCo, 1);
    Do = BCi ^ ROL(BCu, 1);
    Du = BCo ^ ROL(BCa, 1);

    Aba ^= Da;
    BCa = Aba;
    Age ^= De;
    BCe = ROL(Age, 44);
    Aki ^= Di;
    BCi = ROL(Aki, 43);
    Amo ^= Do;
    BCo = ROL(Amo, 21);
    Asu ^= Du;
    BCu = ROL(Asu, 14);
    Eba = BCa ^ ((~BCe) & BCi);
    Eba ^= (bit64_t)KeccakF_RoundConstants[round];
    Ebe = BCe ^ ((~BCi) & BCo);
    Ebi = BCi ^ ((~BCo) & BCu);
    Ebo = BCo ^ ((~BCu) & BCa);
    Ebu = BCu ^ ((~BCa) & BCe);

    Abo ^= Do;
    BCa = ROL(Abo, 28);
    Agu ^= Du;
    BCe = ROL(Agu, 20);
    Aka ^= Da;
    BCi = ROL(Aka, 3);
    Ame ^= De;
    BCo = ROL(Ame, 45);
    Asi ^= Di;
    BCu = ROL(Asi, 61);
    Ega = BCa ^ ((~BCe) & BCi);
    Ege = BCe ^ ((~BCi) & BCo);
    Egi = BCi ^ ((~BCo) & BCu);
    Ego = BCo ^ ((~BCu) & BCa);
    Egu = BCu ^ ((~BCa) & BCe);

    Abe ^= De;
    BCa = ROL(Abe, 1);
    Agi ^= Di;
    BCe = ROL(Agi, 6);
    Ako ^= Do;
    BCi = ROL(Ako, 25);
    Amu ^= Du;
    BCo = ROL(Amu, 8);
    Asa ^= Da;
    BCu = ROL(Asa, 18);
    Eka = BCa ^ ((~BCe) & BCi);
    Eke = BCe ^ ((~BCi) & BCo);
    Eki = BCi ^ ((~BCo) & BCu);
    Eko = BCo ^ ((~BCu) & BCa);
    Eku = BCu ^ ((~BCa) & BCe);

    Abu ^= Du;
    BCa = ROL(Abu, 27);
    Aga ^= Da;
    BCe = ROL(Aga, 36);
    Ake ^= De;
    BCi = ROL(Ake, 10);
    Ami ^= Di;
    BCo = ROL(Ami, 15);
    Aso ^= Do;
    BCu = ROL(Aso, 56);
    Ema = BCa ^ ((~BCe) & BCi);
    Eme = BCe ^ ((~BCi) & BCo);
    Emi = BCi ^ ((~BCo) & BCu);
    Emo = BCo ^ ((~BCu) & BCa);
    Emu = BCu ^ ((~BCa) & BCe);

    Abi ^= Di;
    BCa = ROL(Abi, 62);
    Ago ^= Do;
    BCe = ROL(Ago, 55);
    Aku ^= Du;
    BCi = ROL(Aku, 39);
    Ama ^= Da;
    BCo = ROL(Ama, 41);
    Ase ^= De;
    BCu = ROL(Ase, 2);
    Esa = BCa ^ ((~BCe) & BCi);
    Ese = BCe ^ ((~BCi) & BCo);
    Esi = BCi ^ ((~BCo) & BCu);
    Eso = BCo ^ ((~BCu) & BCa);
    Esu = BCu ^ ((~BCa) & BCe);

    //    prepareTheta
    BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
    BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
    BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
    BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
    BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

    // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
    Da = BCu ^ ROL(BCe, 1);
    De = BCa ^ ROL(BCi, 1);
    Di = BCe ^ ROL(BCo, 1);
    Do = BCi ^ ROL(BCu, 1);
    Du = BCo ^ ROL(BCa, 1);

    Eba ^= Da;
    BCa = Eba;
    Ege ^= De;
    BCe = ROL(Ege, 44);
    Eki ^= Di;
    BCi = ROL(Eki, 43);
    Emo ^= Do;
    BCo = ROL(Emo, 21);
    Esu ^= Du;
    BCu = ROL(Esu, 14);
    Aba = BCa ^ ((~BCe) & BCi);
    Aba ^= (bit64_t)KeccakF_RoundConstants[round + 1];
    Abe = BCe ^ ((~BCi) & BCo);
    Abi = BCi ^ ((~BCo) & BCu);
    Abo = BCo ^ ((~BCu) & BCa);
    Abu = BCu ^ ((~BCa) & BCe);

    Ebo ^= Do;
    BCa = ROL(Ebo, 28);
    Egu ^= Du;
    BCe = ROL(Egu, 20);
    Eka ^= Da;
    BCi = ROL(Eka, 3);
    Eme ^= De;
    BCo = ROL(Eme, 45);
    Esi ^= Di;
    BCu = ROL(Esi, 61);
    Aga = BCa ^ ((~BCe) & BCi);
    Age = BCe ^ ((~BCi) & BCo);
    Agi = BCi ^ ((~BCo) & BCu);
    Ago = BCo ^ ((~BCu) & BCa);
    Agu = BCu ^ ((~BCa) & BCe);

    Ebe ^= De;
    BCa = ROL(Ebe, 1);
    Egi ^= Di;
    BCe = ROL(Egi, 6);
    Eko ^= Do;
    BCi = ROL(Eko, 25);
    Emu ^= Du;
    BCo = ROL(Emu, 8);
    Esa ^= Da;
    BCu = ROL(Esa, 18);
    Aka = BCa ^ ((~BCe) & BCi);
    Ake = BCe ^ ((~BCi) & BCo);
    Aki = BCi ^ ((~BCo) & BCu);
    Ako = BCo ^ ((~BCu) & BCa);
    Aku = BCu ^ ((~BCa) & BCe);

    Ebu ^= Du;
    BCa = ROL(Ebu, 27);
    Ega ^= Da;
    BCe = ROL(Ega, 36);
    Eke ^= De;
    BCi = ROL(Eke, 10);
    Emi ^= Di;
    BCo = ROL(Emi, 15);
    Eso ^= Do;
    BCu = ROL(Eso, 56);
    Ama = BCa ^ ((~BCe) & BCi);
    Ame = BCe ^ ((~BCi) & BCo);
    Ami = BCi ^ ((~BCo) & BCu);
    Amo = BCo ^ ((~BCu) & BCa);
    Amu = BCu ^ ((~BCa) & BCe);

    Ebi ^= Di;
    BCa = ROL(Ebi, 62);
    Ego ^= Do;
    BCe = ROL(Ego, 55);
    Eku ^= Du;
    BCi = ROL(Eku, 39);
    Ema ^= Da;
    BCo = ROL(Ema, 41);
    Ese ^= De;
    BCu = ROL(Ese, 2);
    Asa = BCa ^ ((~BCe) & BCi);
    Ase = BCe ^ ((~BCi) & BCo);
    Asi = BCi ^ ((~BCo) & BCu);
    Aso = BCo ^ ((~BCu) & BCa);
    Asu = BCu ^ ((~BCa) & BCe);
  }

  // copyToState(state, A)
  state[0] = Aba;
  state[1] = Abe;
  state[2] = Abi;
  state[3] = Abo;
  state[4] = Abu;
  state[5] = Aga;
  state[6] = Age;
  state[7] = Agi;
  state[8] = Ago;
  state[9] = Agu;
  state[10] = Aka;
  state[11] = Ake;
  state[12] = Aki;
  state[13] = Ako;
  state[14] = Aku;
  state[15] = Ama;
  state[16] = Ame;
  state[17] = Ami;
  state[18] = Amo;
  state[19] = Amu;
  state[20] = Asa;
  state[21] = Ase;
  state[22] = Asi;
  state[23] = Aso;
  state[24] = Asu;
}

/*************************************************
 * Name:        keccak_init
 *
 * Description: Initializes the Keccak state.
 *
 * Arguments:   - bit64_t *s: pointer to Keccak state
 **************************************************/
static void keccak_init(bit64_t s[25]) {
  for (int i = 0; i < 25; i++) s[i] = 0;
}

/*************************************************
 * Name:        keccak_absorb
 *
 * Description: Absorb step of Keccak; incremental.
 *
 * Arguments:   - bit64_t *s: pointer to Keccak state
 *              - bit32_t pos: position in current block to be absorbed
 *              - bit32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const bit8_t *in: pointer to input to be absorbed into s
 *              - bit32_t inlen: length of input in bytes
 *
 * Returns new position pos in current block
 **************************************************/
template <int r, int inlen>
static bit32_t keccak_absorb(bit64_t s[25], bit32_t pos,
                             const bit8_t *in) {
  int i;
  int il = inlen;

  while(pos+il >= r) {
    for(i=pos;i<r;i++)
      s[i/8] ^= (bit64_t)*in++ << 8*(i%8);
    il -= r-pos;
    KeccakF1600_StatePermute(s);
    pos = 0;
  }

  for(i=pos;i<pos+il;i++)
    s[i/8] ^= (bit64_t)*in++ << 8*(i%8);

  return i;
}

/*************************************************
 * Name:        keccak_finalize
 *
 * Description: Finalize absorb step.
 *
 * Arguments:   - bit64_t *s: pointer to Keccak state
 *              - bit32_t pos: position in current block to be absorbed
 *              - bit32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - bit8_t p: domain separation byte
 **************************************************/
static void keccak_finalize(bit64_t s[25], bit32_t pos, bit32_t r, bit8_t p) {
  s[pos / 8] ^= (bit64_t)p << 8 * (pos % 8);
  s[r / 8 - 1] ^= 1ULL << 63;
}

/*************************************************
 * Name:        keccak_squeeze
 *
 * Description: Squeeze step of Keccak. Squeezes arbitratrily many bytes.
 *              Modifies the state. Can be called multiple times to keep
 *              squeezing, i.e., is incremental.
 *
 * Arguments:   - bit8_t *out: pointer to output
 *              - bit32_t outlen: number of bytes to be squeezed (written to
 *out)
 *              - bit64_t *s: pointer to input/output Keccak state
 *              - bit32_t pos: number of bytes in current block already
 *squeezed
 *              - bit32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *
 * Returns new position pos in current block
 **************************************************/
template <int outlen, int r>
static bit32_t keccak_squeeze(bit8_t *out, bit64_t s[25], bit32_t pos) {
  int i;
  int ol = outlen;

  while(ol) {
    if(pos == r) {
      KeccakF1600_StatePermute(s);
      pos = 0;
    }
    for(i=pos;i < r && i < pos+ol; i++)
      *out++ = s[i/8] >> 8*(i%8);

    ol -= i-pos;
    pos = i;
  }

  return pos;
}

/*************************************************
 * Name:        keccak_absorb_once
 *
 * Description: Absorb step of Keccak;
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - bit64_t *s: pointer to (uninitialized) output Keccak state
 *              - bit32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const bit8_t *in: pointer to input to be absorbed into s
 *              - bit32_t inlen: length of input in bytes
 *              - bit8_t p: domain-separation byte for different Keccak-derived
 *functions
 **************************************************/
template <int r, int inlen, int p>
static void keccak_absorb_once(bit64_t s[25], const bit8_t *in) {
  bit32_t i;

  for (i = 0; i < 25; i++) s[i] = 0;

  int il = inlen;

  while(il >= r) {
    for(i=0;i<r/8;i++)
      s[i] ^= load64(in+8*i);
    in += r;
    il -= r;
    KeccakF1600_StatePermute(s);
  }

  for(i=0;i<il;i++)
    s[i/8] ^= (bit64_t)in[i] << 8*(i%8);

  s[i/8] ^= (bit64_t)((bit8_t) p) << 8*(i%8);
  s[(r-1)/8] ^= 1ULL << 63;
}

/*************************************************
 * Name:        keccak_squeezeblocks
 *
 * Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
 *              Modifies the state. Can be called multiple times to keep
 *              squeezing, i.e., is incremental. Assumes zero bytes of current
 *              block have already been squeezed.
 *
 * Arguments:   - bit8_t *out: pointer to output blocks
 *              - bit32_t nblocks: number of blocks to be squeezed (written to
 *out)
 *              - bit64_t *s: pointer to input/output Keccak state
 *              - bit32_t r: rate in bytes (e.g., 168 for SHAKE128)
 **************************************************/
template <int nblocks, int r>
static void keccak_squeezeblocks(bit8_t *out, bit64_t s[25]) {
  bit32_t i;

  for (int j = nblocks; j > 0; j--) {
    KeccakF1600_StatePermute(s);
    for (i = 0; i < r / 8; i++) store64(out + 8 * i, s[i]);
    out += r;
  }
}

/*************************************************
 * Name:        shake128_init
 *
 * Description: Initilizes Keccak state for use as SHAKE128 XOF
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
 **************************************************/
void shake128_init(keccak_state *state) {
  keccak_init(state->s);
  state->pos = 0;
}

/*************************************************
 * Name:        shake128_absorb
 *
 * Description: Absorb step of the SHAKE128 XOF; incremental.
 *
 * Arguments:   - keccak_state *state: pointer to (initialized) output Keccak
 *state
 *              - const bit8_t *in: pointer to input to be absorbed into s
 *              - bit32_t inlen: length of input in bytes
 **************************************************/
template <int inlen>
void shake128_absorb(keccak_state *state, const bit8_t *in) {
  state->pos = keccak_absorb<SHAKE128_RATE, inlen>(state->s, state->pos, in);
}

/*************************************************
 * Name:        shake128_finalize
 *
 * Description: Finalize absorb step of the SHAKE128 XOF.
 *
 * Arguments:   - keccak_state *state: pointer to Keccak state
 **************************************************/
void shake128_finalize(keccak_state *state) {
  keccak_finalize(state->s, state->pos, SHAKE128_RATE, 0x1F);
  state->pos = SHAKE128_RATE;
}

/*************************************************
 * Name:        shake128_squeeze
 *
 * Description: Squeeze step of SHAKE128 XOF. Squeezes arbitraily many
 *              bytes. Can be called multiple times to keep squeezing.
 *
 * Arguments:   - bit8_t *out: pointer to output blocks
 *              - bit32_t outlen : number of bytes to be squeezed (written to
 *output)
 *              - keccak_state *s: pointer to input/output Keccak state
 **************************************************/
template<int outlen>
void shake128_squeeze(bit8_t *out, keccak_state *state) {
  state->pos = keccak_squeeze<outlen, SHAKE128_RATE>(out, state->s, state->pos);
}

/*************************************************
 * Name:        shake128_absorb_once
 *
 * Description: Initialize, absorb into and finalize SHAKE128 XOF;
 *non-incremental.
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak
 *state
 *              - const bit8_t *in: pointer to input to be absorbed into s
 *              - bit32_t inlen: length of input in bytes
 **************************************************/
template <int inlen>
void shake128_absorb_once(keccak_state *state, const bit8_t *in) {
  keccak_absorb_once<SHAKE128_RATE, inlen, 0x1F>(state->s, in);
  state->pos = SHAKE128_RATE;
}

/*************************************************
 * Name:        shake128_squeezeblocks
 *
 * Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
 *              SHAKE128_RATE bytes each. Can be called multiple times
 *              to keep squeezing. Assumes new block has not yet been
 *              started (state->pos = SHAKE128_RATE).
 *
 * Arguments:   - bit8_t *out: pointer to output blocks
 *              - bit32_t nblocks: number of blocks to be squeezed (written to
 *output)
 *              - keccak_state *s: pointer to input/output Keccak state
 **************************************************/
template <int nblocks>
void shake128_squeezeblocks(bit8_t *out, keccak_state *state) {
  keccak_squeezeblocks<nblocks, SHAKE128_RATE>(out, state->s);
}

/*************************************************
 * Name:        shake256_init
 *
 * Description: Initilizes Keccak state for use as SHAKE256 XOF
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
 **************************************************/
void shake256_init(keccak_state *state) {
  keccak_init(state->s);
  state->pos = 0;
}

/*************************************************
 * Name:        shake256_absorb
 *
 * Description: Absorb step of the SHAKE256 XOF; incremental.
 *
 * Arguments:   - keccak_state *state: pointer to (initialized) output Keccak
 *state
 *              - const bit8_t *in: pointer to input to be absorbed into s
 *              - bit32_t inlen: length of input in bytes
 **************************************************/
template <int inlen>
void shake256_absorb(keccak_state *state, const bit8_t *in) {
  state->pos = keccak_absorb<SHAKE256_RATE, inlen>(state->s, state->pos, in);
}

/*************************************************
 * Name:        shake256_finalize
 *
 * Description: Finalize absorb step of the SHAKE256 XOF.
 *
 * Arguments:   - keccak_state *state: pointer to Keccak state
 **************************************************/
void shake256_finalize(keccak_state *state) {
  keccak_finalize(state->s, state->pos, SHAKE256_RATE, 0x1F);
  state->pos = SHAKE256_RATE;
}

/*************************************************
 * Name:        shake256_squeeze
 *
 * Description: Squeeze step of SHAKE256 XOF. Squeezes arbitraily many
 *              bytes. Can be called multiple times to keep squeezing.
 *
 * Arguments:   - bit8_t *out: pointer to output blocks
 *              - bit32_t outlen : number of bytes to be squeezed (written to
 *output)
 *              - keccak_state *s: pointer to input/output Keccak state
 **************************************************/
template <int outlen>
void shake256_squeeze(bit8_t *out, keccak_state *state) {
  state->pos = keccak_squeeze<outlen, SHAKE256_RATE>(out, state->s, state->pos);
}

/*************************************************
 * Name:        shake256_absorb_once
 *
 * Description: Initialize, absorb into and finalize SHAKE256 XOF;
 *non-incremental.
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak
 *state
 *              - const bit8_t *in: pointer to input to be absorbed into s
 *              - bit32_t inlen: length of input in bytes
 **************************************************/
template <int inlen>
void shake256_absorb_once(keccak_state *state, const bit8_t *in) {
  keccak_absorb_once<SHAKE256_RATE, inlen, 0x1F>(state->s, in);
  state->pos = SHAKE256_RATE;
}

/*************************************************
 * Name:        shake256_squeezeblocks
 *
 * Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
 *              SHAKE256_RATE bytes each. Can be called multiple times
 *              to keep squeezing. Assumes next block has not yet been
 *              started (state->pos = SHAKE256_RATE).
 *
 * Arguments:   - bit8_t *out: pointer to output blocks
 *              - bit32_t nblocks: number of blocks to be squeezed (written to
 *output)
 *              - keccak_state *s: pointer to input/output Keccak state
 **************************************************/
template <int nblocks>
void shake256_squeezeblocks(bit8_t *out, keccak_state *state) {
  keccak_squeezeblocks<nblocks, SHAKE256_RATE>(out, state->s);
}

/*************************************************
 * Name:        shake128
 *
 * Description: SHAKE128 XOF with non-incremental API
 *
 * Arguments:   - bit8_t *out: pointer to output
 *              - bit32_t outlen: requested output length in bytes
 *              - const bit8_t *in: pointer to input
 *              - bit32_t inlen: length of input in bytes
 **************************************************/
template <int outlen, int inlen>
void shake128(bit8_t *out, const bit8_t *in) {
  keccak_state state;

  shake128_absorb_once<inlen>(&state, in);
  constexpr int nblocks = outlen / SHAKE128_RATE;
  shake128_squeezeblocks<nblocks>(out, &state);
  shake128_squeeze<outlen - nblocks * SHAKE128_RATE>(
    out + nblocks * SHAKE128_RATE, &state
  );
}

/*************************************************
 * Name:        shake256
 *
 * Description: SHAKE256 XOF with non-incremental API
 *
 * Arguments:   - bit8_t *out: pointer to output
 *              - bit32_t outlen: requested output length in bytes
 *              - const bit8_t *in: pointer to input
 *              - bit32_t inlen: length of input in bytes
 **************************************************/
template<int outlen, int inlen>
void shake256(bit8_t *out, const bit8_t *in) {
  keccak_state state;

  constexpr int nblocks = outlen / SHAKE256_RATE;

  shake256_absorb_once<inlen>(&state, in);
  shake256_squeezeblocks<nblocks>(out, &state);
  shake256_squeeze<outlen - nblocks * SHAKE256_RATE>(
    out + nblocks * SHAKE256_RATE, &state
  );
}

/*************************************************
 * Name:        sha3_256
 *
 * Description: SHA3-256 with non-incremental API
 *
 * Arguments:   - bit8_t *h: pointer to output (32 bytes)
 *              - const bit8_t *in: pointer to input
 *              - bit32_t inlen: length of input in bytes
 **************************************************/
template<int inlen>
void sha3_256(bit8_t h[32], const bit8_t *in) {
  bit32_t i;
  bit64_t s[25];

  keccak_absorb_once<SHA3_256_RATE, inlen, 0x06>(s, in);
  KeccakF1600_StatePermute(s);
  for (i = 0; i < 4; i++) store64(h + 8 * i, s[i]);
}

/*************************************************
 * Name:        sha3_512
 *
 * Description: SHA3-512 with non-incremental API
 *
 * Arguments:   - bit8_t *h: pointer to output (64 bytes)
 *              - const bit8_t *in: pointer to input
 *              - bit32_t inlen: length of input in bytes
 **************************************************/
template <int inlen>
void sha3_512(bit8_t h[64], const bit8_t *in) {
  bit32_t i;
  bit64_t s[25];

  keccak_absorb_once<SHA3_512_RATE, inlen, 0x06>(s, in);
  KeccakF1600_StatePermute(s);
  for (i = 0; i < 8; i++) store64(h + 8 * i, s[i]);
}

#endif
