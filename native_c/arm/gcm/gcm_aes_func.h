
#ifndef BC_LTS_C_GCM_AES_FUNC_H
#define BC_LTS_C_GCM_AES_FUNC_H

#include "arm_neon.h"
#include "../aes/aes_common_neon.h"


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
    }

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


/**
 * Process two blocks.
 * @param key
 * @param in1 input 1
 * @param in2  input block 2
 * @param out1 output block 1
 * @param out2 output block 2
 */
static inline void single_block(
        aes_key *key,
        uint8x16_t in1,
        uint8x16_t *out1
        ) {

    const size_t rounds = key->rounds;
    const uint8x16_t *rk = key->round_keys;
    if (key->encryption) {
        size_t r = 0;
        for (r = 0; r < rounds - 1; r++) {
            in1 = vaeseq_u8(in1, rk[r]);
            in1 = vaesmcq_u8(in1);
        }

        const uint8x16_t r0 = rk[r];

        in1 = vaeseq_u8(in1, r0);

        const uint8x16_t r1 = rk[r + 1];
        *out1 = veorq_u8(in1, r1);

    }

    //
    // Decryption
    //

    size_t r = rounds;
    for (; r > 1; r--) {
        in1 = vaesdq_u8(in1, rk[r]);
        in1 = vaesimcq_u8(in1);
    }

    const uint8x16_t r0 = rk[1];
    in1 = vaesdq_u8(in1, r0);

    const uint8x16_t r1 = rk[0];

    *out1 = veorq_u8(in1, r1);
}




#endif //BC_LTS_C_GCM_AES_FUNC_H
