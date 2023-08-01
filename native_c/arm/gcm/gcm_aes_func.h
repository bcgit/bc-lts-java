
#ifndef BC_LTS_C_GCM_AES_FUNC_H
#define BC_LTS_C_GCM_AES_FUNC_H

#include "arm_neon.h"
#include "../aes/aes_common_neon.h"
#include "gcm_common.h"


/**
 * Process two blocks.
 * @param key
 * @param in1 input 1
 * @param in2  input block 2
 * @param out1 output block 1
 * @param out2 output block 2
 */
static inline void dual_block(
        aes_key *key,
        uint8x16_t in1,
        uint8x16_t in2,
        uint8x16_t *out1,
        uint8x16_t *out2) {

    const size_t rounds = key->rounds;
    const uint8x16_t *rk = key->round_keys;
    if (key->encryption) {
        size_t r = 0;
        for (r = 0; r < rounds - 1; r++) {
            in1 = vaeseq_u8(in1, rk[r]);
            in1 = vaesmcq_u8(in1);
            in2 = vaeseq_u8(in2, rk[r]);
            in2 = vaesmcq_u8(in2);
        }

        const uint8x16_t r0 = rk[r];

        in1 = vaeseq_u8(in1, r0);
        in2 = vaeseq_u8(in2, r0);

        const uint8x16_t r1 = rk[r + 1];
        *out1 = veorq_u8(in1, r1);
        *out2 = veorq_u8(in2, r1);

    } else {

        //
        // Decryption
        //

        size_t r = rounds;
        for (; r > 1; r--) {
            in1 = vaesdq_u8(in1, rk[r]);
            in2 = vaesdq_u8(in2, rk[r]);
            in1 = vaesimcq_u8(in1);
            in2 = vaesimcq_u8(in2);
        }

        const uint8x16_t r0 = rk[1];
        in1 = vaesdq_u8(in1, r0);
        in2 = vaesdq_u8(in2, r0);

        const uint8x16_t r1 = rk[0];

        *out1 = veorq_u8(in1, r1);
        *out2 = veorq_u8(in2, r1);
    }
}


/**
 * Process one block.
 * @param key
 * @param in1 input 1
 * @param out1 output block 1
 */
static inline void single_block(
        aes_key *key,
        uint8x16_t in1,
        uint8x16_t *out1
) {

    const size_t rounds = key->rounds;
    const uint8x16_t *rk = key->round_keys;
    if (key->encryption) {

        if (rounds == 10) {
            in1 = vaeseq_u8(in1, rk[0]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[1]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[2]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[3]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[4]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[5]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[6]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[7]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[8]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[9]);
            *out1 = veorq_u8(in1, rk[10]);
        } else if (rounds == 12) {
            in1 = vaeseq_u8(in1, rk[0]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[1]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[2]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[3]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[4]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[5]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[6]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[7]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[8]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[9]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[10]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[11]);
            *out1 = veorq_u8(in1, rk[12]);
        } else {
            in1 = vaeseq_u8(in1, rk[0]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[1]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[2]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[3]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[4]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[5]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[6]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[7]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[8]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[9]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[10]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[11]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[12]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[13]);
            *out1 = veorq_u8(in1, rk[14]);
        }
    } else {

        //
        // Decryption
        //


        if (rounds == 10) {
            in1 = vaesdq_u8(in1, rk[0]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[1]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[2]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[3]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[4]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[5]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[6]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[7]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[8]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[9]);
            *out1 = veorq_u8(in1, rk[10]);

        } else if (rounds == 12) {
            in1 = vaesdq_u8(in1, rk[0]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[1]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[2]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[3]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[4]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[5]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[6]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[7]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[8]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[9]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[10]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[11]);
            *out1 = veorq_u8(in1, rk[12]);

        } else {
            in1 = vaesdq_u8(in1, rk[0]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[1]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[2]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[3]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[4]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[5]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[6]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[7]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[8]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[9]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[10]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[11]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[12]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[13]);
            *out1 = veorq_u8(in1, rk[14]);

        }
    }
}


/**
 * Process one block.
 * @param key
 * @param in1 input 1
 * @param out1 output block 1
 */
static inline void quad_block(
        aes_key *key,
        uint8x16_t *d1,
        uint8x16_t *d2,
        uint8x16_t *d3,
        uint8x16_t *d4
) {

    uint8x16_t in1 = *d1;
    uint8x16_t in2 = *d2;
    uint8x16_t in3 = *d3;
    uint8x16_t in4 = *d4;

    const size_t rounds = key->rounds;
    const uint8x16_t *rk = key->round_keys;
    if (key->encryption) {
        size_t r = 0;
        for (r = 0; r < rounds - 1; r++) {
            const uint8x16_t k = rk[r];
            in1 = vaeseq_u8(in1, k);
            in1 = vaesmcq_u8(in1);
            in2 = vaeseq_u8(in2, k);
            in2 = vaesmcq_u8(in2);
            in3 = vaeseq_u8(in3, k);
            in3 = vaesmcq_u8(in3);
            in4 = vaeseq_u8(in4, k);
            in4 = vaesmcq_u8(in4);
        }

        const uint8x16_t r0 = rk[r];

        in1 = vaeseq_u8(in1, r0);
        in2 = vaeseq_u8(in2, r0);
        in3 = vaeseq_u8(in3, r0);
        in4 = vaeseq_u8(in4, r0);

        const uint8x16_t r1 = rk[r + 1];
        *d1 = veorq_u8(in1, r1);
        *d2 = veorq_u8(in2, r1);
        *d3 = veorq_u8(in3, r1);
        *d4 = veorq_u8(in4, r1);

    } else {

        //
        // Decryption
        //

        size_t r = rounds;
        for (; r > 1; r--) {
            const uint8x16_t k = rk[r];
            in1 = vaesdq_u8(in1, k);
            in1 = vaesimcq_u8(in1);
            in2 = vaesdq_u8(in2, k);
            in2 = vaesimcq_u8(in2);
            in3 = vaesdq_u8(in3, k);
            in3 = vaesimcq_u8(in3);
            in4 = vaesdq_u8(in4, k);
            in4 = vaesimcq_u8(in4);
        }

        const uint8x16_t r0 = rk[1];
        in1 = vaesdq_u8(in1, r0);
        in2 = vaesdq_u8(in2, r0);
        in3 = vaesdq_u8(in3, r0);
        in4 = vaesdq_u8(in4, r0);

        const uint8x16_t r1 = rk[0];

        *d1 = veorq_u8(in1, r1);
        *d2 = veorq_u8(in2, r1);
        *d3 = veorq_u8(in3, r1);
        *d4 = veorq_u8(in4, r1);
    }
}


#endif //BC_LTS_C_GCM_AES_FUNC_H
