//
//


#include "../aes/aes_common_neon.h"
#include "ecb.h"
#include "../debug_neon.h"


static inline void
enc_blocks(const uint8x16_t *rk, uint8_t *src, uint8_t *dest, const uint32_t blocks, const size_t rounds) {

    uint8x16_t tmp1, tmp2, tmp3, tmp4;


    if (blocks >= 4) {
        tmp1 = vld1q_u8(&src[0 * 16]);
        tmp2 = vld1q_u8(&src[1 * 16]);
        tmp3 = vld1q_u8(&src[2 * 16]);
        tmp4 = vld1q_u8(&src[3 * 16]);
        size_t r = 0;
        for (r = 0; r < rounds - 1; r++) {
            const uint8x16_t rk0 = rk[r];
            tmp1 = vaeseq_u8(tmp1, rk0);
            tmp2 = vaeseq_u8(tmp2, rk0);
            tmp3 = vaeseq_u8(tmp3, rk0);
            tmp4 = vaeseq_u8(tmp4, rk0);
            tmp1 = vaesmcq_u8(tmp1);
            tmp2 = vaesmcq_u8(tmp2);
            tmp3 = vaesmcq_u8(tmp3);
            tmp4 = vaesmcq_u8(tmp4);
        }

        const uint8x16_t r0 = rk[r];

        tmp1 = vaeseq_u8(tmp1, r0);
        tmp2 = vaeseq_u8(tmp2, r0);
        tmp3 = vaeseq_u8(tmp3, r0);
        tmp4 = vaeseq_u8(tmp4, r0);

        const uint8x16_t r1 = rk[r + 1];

        tmp1 = veorq_u8(tmp1, r1);
        tmp2 = veorq_u8(tmp2, r1);
        tmp3 = veorq_u8(tmp3, r1);
        tmp4 = veorq_u8(tmp4, r1);

        vst1q_u8(&dest[0 * 16], tmp1);
        vst1q_u8(&dest[1 * 16], tmp2);
        vst1q_u8(&dest[2 * 16], tmp3);
        vst1q_u8(&dest[3 * 16], tmp4);


    } else if (blocks >= 3) {
        tmp1 = vld1q_u8(&src[0 * 16]);
        tmp2 = vld1q_u8(&src[1 * 16]);
        tmp3 = vld1q_u8(&src[2 * 16]);

        size_t r = 0;
        for (r = 0; r < rounds - 1; r++) {
            tmp1 = vaeseq_u8(tmp1, rk[r]);
            tmp2 = vaeseq_u8(tmp2, rk[r]);
            tmp3 = vaeseq_u8(tmp3, rk[r]);
            tmp1 = vaesmcq_u8(tmp1);
            tmp2 = vaesmcq_u8(tmp2);
            tmp3 = vaesmcq_u8(tmp3);
        }

        const uint8x16_t r0 = rk[r];

        tmp1 = vaeseq_u8(tmp1, r0);
        tmp2 = vaeseq_u8(tmp2, r0);
        tmp3 = vaeseq_u8(tmp3, r0);

        const uint8x16_t r1 = rk[r + 1];

        tmp1 = veorq_u8(tmp1, r1);
        tmp2 = veorq_u8(tmp2, r1);
        tmp3 = veorq_u8(tmp3, r1);

        vst1q_u8(&dest[0 * 16], tmp1);
        vst1q_u8(&dest[1 * 16], tmp2);
        vst1q_u8(&dest[2 * 16], tmp3);


    } else if (blocks >= 2) {
        tmp1 = vld1q_u8(&src[0 * 16]);
        tmp2 = vld1q_u8(&src[1 * 16]);


        size_t r = 0;
        for (r = 0; r < rounds - 1; r++) {
            tmp1 = vaeseq_u8(tmp1, rk[r]);
            tmp2 = vaeseq_u8(tmp2, rk[r]);
            tmp1 = vaesmcq_u8(tmp1);
            tmp2 = vaesmcq_u8(tmp2);
        }

        const uint8x16_t r0 = rk[r];

        tmp1 = vaeseq_u8(tmp1, r0);
        tmp2 = vaeseq_u8(tmp2, r0);


        const uint8x16_t r1 = rk[r + 1];

        tmp1 = veorq_u8(tmp1, r1);
        tmp2 = veorq_u8(tmp2, r1);


        vst1q_u8(&dest[0 * 16], tmp1);
        vst1q_u8(&dest[1 * 16], tmp2);

    } else if (blocks >= 1) {
        tmp1 = vld1q_u8(&src[0 * 16]);


        size_t r = 0;
        for (r = 0; r < rounds - 1; r++) {
            tmp1 = vaeseq_u8(tmp1, rk[r]);
            tmp1 = vaesmcq_u8(tmp1);
        }

        const uint8x16_t r0 = rk[r];
        tmp1 = vaeseq_u8(tmp1, r0);

        const uint8x16_t r1 = rk[r + 1];
        tmp1 = veorq_u8(tmp1, r1);
        vst1q_u8(&dest[0 * 16], tmp1);
    }

}


static inline void
dec_blocks(const uint8x16_t *rk, uint8_t *src, uint8_t *dest, const uint32_t blocks, const size_t rounds) {

    uint8x16_t tmp1, tmp2, tmp3, tmp4;

    /*
     * tmp1 = vld1q_u8(src);
            for (r = key->rounds; r > 1; r--) {
                tmp1 = vaesdq_u8(tmp1, rk[r]);
                tmp1 = vaesimcq_u8(tmp1);
            }
            tmp1 = vaesdq_u8(tmp1, rk[1]);
            tmp1 = veorq_u8(tmp1, rk[0]);

            vst1q_u8(dest, tmp1);
     */

    if (blocks >= 4) {
        tmp1 = vld1q_u8(&src[0 * 16]);
        tmp2 = vld1q_u8(&src[1 * 16]);
        tmp3 = vld1q_u8(&src[2 * 16]);
        tmp4 = vld1q_u8(&src[3 * 16]);
        size_t r = rounds;
        for (; r > 1; r--) {
            tmp1 = vaesdq_u8(tmp1, rk[r]);
            tmp2 = vaesdq_u8(tmp2, rk[r]);
            tmp3 = vaesdq_u8(tmp3, rk[r]);
            tmp4 = vaesdq_u8(tmp4, rk[r]);
            tmp1 = vaesimcq_u8(tmp1);
            tmp2 = vaesimcq_u8(tmp2);
            tmp3 = vaesimcq_u8(tmp3);
            tmp4 = vaesimcq_u8(tmp4);
        }

        const uint8x16_t r0 = rk[1];

        tmp1 = vaesdq_u8(tmp1, r0);
        tmp2 = vaesdq_u8(tmp2, r0);
        tmp3 = vaesdq_u8(tmp3, r0);
        tmp4 = vaesdq_u8(tmp4, r0);

        const uint8x16_t r1 = rk[0];

        tmp1 = veorq_u8(tmp1, r1);
        tmp2 = veorq_u8(tmp2, r1);
        tmp3 = veorq_u8(tmp3, r1);
        tmp4 = veorq_u8(tmp4, r1);

        vst1q_u8(&dest[0 * 16], tmp1);
        vst1q_u8(&dest[1 * 16], tmp2);
        vst1q_u8(&dest[2 * 16], tmp3);
        vst1q_u8(&dest[3 * 16], tmp4);

    } else if (blocks >= 3) {
        tmp1 = vld1q_u8(&src[0 * 16]);
        tmp2 = vld1q_u8(&src[1 * 16]);
        tmp3 = vld1q_u8(&src[2 * 16]);

        size_t r = rounds;
        for (; r > 1; r--) {
            tmp1 = vaesdq_u8(tmp1, rk[r]);
            tmp2 = vaesdq_u8(tmp2, rk[r]);
            tmp3 = vaesdq_u8(tmp3, rk[r]);

            tmp1 = vaesimcq_u8(tmp1);
            tmp2 = vaesimcq_u8(tmp2);
            tmp3 = vaesimcq_u8(tmp3);

        }

        const uint8x16_t r0 = rk[1];

        tmp1 = vaesdq_u8(tmp1, r0);
        tmp2 = vaesdq_u8(tmp2, r0);
        tmp3 = vaesdq_u8(tmp3, r0);


        const uint8x16_t r1 = rk[0];

        tmp1 = veorq_u8(tmp1, r1);
        tmp2 = veorq_u8(tmp2, r1);
        tmp3 = veorq_u8(tmp3, r1);


        vst1q_u8(&dest[0 * 16], tmp1);
        vst1q_u8(&dest[1 * 16], tmp2);
        vst1q_u8(&dest[2 * 16], tmp3);


    } else if (blocks >= 2) {
        tmp1 = vld1q_u8(&src[0 * 16]);
        tmp2 = vld1q_u8(&src[1 * 16]);
        size_t r = rounds;
        for (; r > 1; r--) {
            tmp1 = vaesdq_u8(tmp1, rk[r]);
            tmp2 = vaesdq_u8(tmp2, rk[r]);
            tmp1 = vaesimcq_u8(tmp1);
            tmp2 = vaesimcq_u8(tmp2);
        }

        const uint8x16_t r0 = rk[1];
        tmp1 = vaesdq_u8(tmp1, r0);
        tmp2 = vaesdq_u8(tmp2, r0);

        const uint8x16_t r1 = rk[0];

        tmp1 = veorq_u8(tmp1, r1);
        tmp2 = veorq_u8(tmp2, r1);
        vst1q_u8(&dest[0 * 16], tmp1);
        vst1q_u8(&dest[1 * 16], tmp2);


    } else if (blocks >= 1) {
        tmp1 = vld1q_u8(&src[0 * 16]);
        size_t r = rounds;
        for (; r > 1; r--) {
            tmp1 = vaesdq_u8(tmp1, rk[r]);
            tmp1 = vaesimcq_u8(tmp1);
        }

        const uint8x16_t r0 = rk[1];
        tmp1 = vaesdq_u8(tmp1, r0);

        const uint8x16_t r1 = rk[0];
        tmp1 = veorq_u8(tmp1, r1);

        vst1q_u8(&dest[0 * 16], tmp1);

    }


}


size_t ecb_process_blocks(aes_key *key, uint8_t *src, uint32_t blocks, uint8_t *dest) {

    uint8_t *destStart = dest;

    if (key->encryption) {
        while (blocks >= 4) {
            enc_blocks(key->round_keys, src, dest, 4, key->rounds);
            blocks -= 4;
            src += 4 * ECB_BLOCK_SIZE;
            dest += 4 * ECB_BLOCK_SIZE;
        }

        enc_blocks(key->round_keys, src, dest, blocks, key->rounds);
        dest += blocks * ECB_BLOCK_SIZE;


    } else {

            while (blocks >= 4) {
                dec_blocks(key->round_keys, src, dest, 4, key->rounds);
                blocks -= 4;
                src += 4 * ECB_BLOCK_SIZE;
                dest += 4 * ECB_BLOCK_SIZE;
            }

            dec_blocks(key->round_keys, src, dest, blocks, key->rounds);
            dest += blocks * ECB_BLOCK_SIZE;
    }

    return dest - destStart;

}