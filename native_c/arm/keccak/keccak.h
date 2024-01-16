
#ifndef BC_LTS_C_KECCAK_H
#define BC_LTS_C_KECCAK_H

//
// Based on https://github.com/cothan/NEON-SHA3_2x/blob/main/fips202.c
//


#include <stdint.h>
#include <arm_neon.h>
#include "../util/util.h"

#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))

#define vxor(c, a, b) c = veorq_u64(a, b);

// Xor chain: out = a ^ b ^ c ^ d ^ e
#define vXOR5(out, a, b, c, d, e) \
  out = veor3q_u64(a, b, c);      \
  out = veor3q_u64(out, d, e);

// Rotate left by 1 bit, then XOR: a ^ ROL(b)
#define vRXOR(c, a, b) c = vrax1q_u64(a, b);

// XOR then Rotate by n bit: c = ROL(a^b, n)
#define vXORR(c, a, b, n) c = vxarq_u64(a, b, n);

// Xor Not And: out = a ^ ( (~b) & c)
#define vXNA(out, a, b, c) out = vbcaxq_u64(a, c, b);

static const uint64x2_t k_zero = {0UL, 0UL};

static inline void KF1600_StatePermute(uint64x2_t *state, const uint64_t *K) {
    int round;


    uint64x2_t Aba, Abe, Abi, Abo, Abu;
    uint64x2_t Aga, Age, Agi, Ago, Agu;
    uint64x2_t Aka, Ake, Aki, Ako, Aku;
    uint64x2_t Ama, Ame, Ami, Amo, Amu;
    uint64x2_t Asa, Ase, Asi, Aso, Asu;
    uint64x2_t BCa, BCe, BCi, BCo, BCu; // tmp
    uint64x2_t Da, De, Di, Do, Du;      // D
    uint64x2_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64x2_t Ega, Ege, Egi, Ego, Egu;
    uint64x2_t Eka, Eke, Eki, Eko, Eku;
    uint64x2_t Ema, Eme, Emi, Emo, Emu;
    uint64x2_t Esa, Ese, Esi, Eso, Esu;


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


    for (round = 0; round < 24; round += 2) {
        //    prepareTheta

        //    prepareTheta
        vXOR5(BCa, Aba, Aga, Aka, Ama, Asa);
        vXOR5(BCe, Abe, Age, Ake, Ame, Ase);
        vXOR5(BCi, Abi, Agi, Aki, Ami, Asi);
        vXOR5(BCo, Abo, Ago, Ako, Amo, Aso);
        vXOR5(BCu, Abu, Agu, Aku, Amu, Asu);

        vRXOR(Da, BCu, BCe);
        vRXOR(De, BCa, BCi);
        vRXOR(Di, BCe, BCo);
        vRXOR(Do, BCi, BCu);
        vRXOR(Du, BCo, BCa);

        vxor(Aba, Aba, Da);
        vXORR(BCe, Age, De, 20);
        vXORR(BCi, Aki, Di, 21);
        vXORR(BCo, Amo, Do, 43);
        vXORR(BCu, Asu, Du, 50);

        vXNA(Eba, Aba, BCe, BCi);
        vxor(Eba, Eba, vld1q_dup_u64(&K[round]));
        vXNA(Ebe, BCe, BCi, BCo);
        vXNA(Ebi, BCi, BCo, BCu);
        vXNA(Ebo, BCo, BCu, Aba);
        vXNA(Ebu, BCu, Aba, BCe);

        vXORR(BCa, Abo, Do, 36);
        vXORR(BCe, Agu, Du, 44);
        vXORR(BCi, Aka, Da, 61);
        vXORR(BCo, Ame, De, 19);
        vXORR(BCu, Asi, Di, 3);

        vXNA(Ega, BCa, BCe, BCi);
        vXNA(Ege, BCe, BCi, BCo);
        vXNA(Egi, BCi, BCo, BCu);
        vXNA(Ego, BCo, BCu, BCa);
        vXNA(Egu, BCu, BCa, BCe);

        vXORR(BCa, Abe, De, 63);
        vXORR(BCe, Agi, Di, 58);
        vXORR(BCi, Ako, Do, 39);
        vXORR(BCo, Amu, Du, 56);
        vXORR(BCu, Asa, Da, 46);

        vXNA(Eka, BCa, BCe, BCi);
        vXNA(Eke, BCe, BCi, BCo);
        vXNA(Eki, BCi, BCo, BCu);
        vXNA(Eko, BCo, BCu, BCa);
        vXNA(Eku, BCu, BCa, BCe);

        vXORR(BCa, Abu, Du, 37);
        vXORR(BCe, Aga, Da, 28);
        vXORR(BCi, Ake, De, 54);
        vXORR(BCo, Ami, Di, 49);
        vXORR(BCu, Aso, Do, 8);

        vXNA(Ema, BCa, BCe, BCi);
        vXNA(Eme, BCe, BCi, BCo);
        vXNA(Emi, BCi, BCo, BCu);
        vXNA(Emo, BCo, BCu, BCa);
        vXNA(Emu, BCu, BCa, BCe);

        vXORR(BCa, Abi, Di, 2);
        vXORR(BCe, Ago, Do, 9);
        vXORR(BCi, Aku, Du, 25);
        vXORR(BCo, Ama, Da, 23);
        vXORR(BCu, Ase, De, 62);

        vXNA(Esa, BCa, BCe, BCi);
        vXNA(Ese, BCe, BCi, BCo);
        vXNA(Esi, BCi, BCo, BCu);
        vXNA(Eso, BCo, BCu, BCa);
        vXNA(Esu, BCu, BCa, BCe);

        // Next Round

        //    prepareTheta
        vXOR5(BCa, Eba, Ega, Eka, Ema, Esa);
        vXOR5(BCe, Ebe, Ege, Eke, Eme, Ese);
        vXOR5(BCi, Ebi, Egi, Eki, Emi, Esi);
        vXOR5(BCo, Ebo, Ego, Eko, Emo, Eso);
        vXOR5(BCu, Ebu, Egu, Eku, Emu, Esu);

        // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        vRXOR(Da, BCu, BCe);
        vRXOR(De, BCa, BCi);
        vRXOR(Di, BCe, BCo);
        vRXOR(Do, BCi, BCu);
        vRXOR(Du, BCo, BCa);

        vxor(Eba, Eba, Da);
        vXORR(BCe, Ege, De, 20);
        vXORR(BCi, Eki, Di, 21);
        vXORR(BCo, Emo, Do, 43);
        vXORR(BCu, Esu, Du, 50);

        vXNA(Aba, Eba, BCe, BCi);
        vxor(Aba, Aba, vld1q_dup_u64(&K[round + 1]));
        vXNA(Abe, BCe, BCi, BCo);
        vXNA(Abi, BCi, BCo, BCu);
        vXNA(Abo, BCo, BCu, Eba);
        vXNA(Abu, BCu, Eba, BCe);

        vXORR(BCa, Ebo, Do, 36);
        vXORR(BCe, Egu, Du, 44);
        vXORR(BCi, Eka, Da, 61);
        vXORR(BCo, Eme, De, 19);
        vXORR(BCu, Esi, Di, 3);

        vXNA(Aga, BCa, BCe, BCi);
        vXNA(Age, BCe, BCi, BCo);
        vXNA(Agi, BCi, BCo, BCu);
        vXNA(Ago, BCo, BCu, BCa);
        vXNA(Agu, BCu, BCa, BCe);

        vXORR(BCa, Ebe, De, 63);
        vXORR(BCe, Egi, Di, 58);
        vXORR(BCi, Eko, Do, 39);
        vXORR(BCo, Emu, Du, 56);
        vXORR(BCu, Esa, Da, 46);

        vXNA(Aka, BCa, BCe, BCi);
        vXNA(Ake, BCe, BCi, BCo);
        vXNA(Aki, BCi, BCo, BCu);
        vXNA(Ako, BCo, BCu, BCa);
        vXNA(Aku, BCu, BCa, BCe);

        vXORR(BCa, Ebu, Du, 37);
        vXORR(BCe, Ega, Da, 28);
        vXORR(BCi, Eke, De, 54);
        vXORR(BCo, Emi, Di, 49);
        vXORR(BCu, Eso, Do, 8);

        vXNA(Ama, BCa, BCe, BCi);
        vXNA(Ame, BCe, BCi, BCo);
        vXNA(Ami, BCi, BCo, BCu);
        vXNA(Amo, BCo, BCu, BCa);
        vXNA(Amu, BCu, BCa, BCe);

        vXORR(BCa, Ebi, Di, 2);
        vXORR(BCe, Ego, Do, 9);
        vXORR(BCi, Eku, Du, 25);
        vXORR(BCo, Ema, Da, 23);
        vXORR(BCu, Ese, De, 62);

        vXNA(Asa, BCa, BCe, BCi);
        vXNA(Ase, BCe, BCi, BCo);
        vXNA(Asi, BCi, BCo, BCu);
        vXNA(Aso, BCo, BCu, BCa);
        vXNA(Asu, BCu, BCa, BCe);

    }

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


static inline void keccak_absorb_buf(uint64x2_t *state, uint8_t *buf, size_t rateBytes, const uint64_t *K) {
    size_t rate_64 = rateBytes >> 3;
    uint64x2_t tmp;
    uint64x2_t *s = state;

    while (rate_64 > 0) {
        tmp = vsetq_lane_u64(vreinterpret_u64_u8(vld1_u8(buf))[0], k_zero, 0);
        *s = veorq_u64(*s, tmp);
        s++;
        buf += 8;
        rate_64--;
    }

    KF1600_StatePermute(state, K);
}


#endif //BC_LTS_C_KECCAK_H
