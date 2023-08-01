//
//

#include <assert.h>
#include "cbc.h"
#include "../aes/aes_common_neon.h"


static inline void decrypt_blocks(uint8x16_t *rk,
                                  uint8x16_t *b1,
                                  uint8x16_t *b2,
                                  uint8x16_t *b3,
                                  uint8x16_t *b4,
                                  const size_t blocks,
                                  const size_t rounds
) {

    if (blocks == 4) {
        size_t r = rounds;
        for (; r > 1; r--) {
            *b1 = vaesdq_u8(*b1, rk[r]);
            *b2 = vaesdq_u8(*b2, rk[r]);
            *b3 = vaesdq_u8(*b3, rk[r]);
            *b4 = vaesdq_u8(*b4, rk[r]);
            *b1 = vaesimcq_u8(*b1);
            *b2 = vaesimcq_u8(*b2);
            *b3 = vaesimcq_u8(*b3);
            *b4 = vaesimcq_u8(*b4);
        }

        const uint8x16_t r0 = rk[1];

        *b1 = vaesdq_u8(*b1, r0);
        *b2 = vaesdq_u8(*b2, r0);
        *b3 = vaesdq_u8(*b3, r0);
        *b4 = vaesdq_u8(*b4, r0);

        const uint8x16_t r1 = rk[0];

        *b1 = veorq_u8(*b1, r1);
        *b2 = veorq_u8(*b2, r1);
        *b3 = veorq_u8(*b3, r1);
        *b4 = veorq_u8(*b4, r1);
    } else if (blocks == 3) {
        size_t r = rounds;
        for (; r > 1; r--) {
            *b1 = vaesdq_u8(*b1, rk[r]);
            *b2 = vaesdq_u8(*b2, rk[r]);
            *b3 = vaesdq_u8(*b3, rk[r]);

            *b1 = vaesimcq_u8(*b1);
            *b2 = vaesimcq_u8(*b2);
            *b3 = vaesimcq_u8(*b3);

        }

        const uint8x16_t r0 = rk[1];

        *b1 = vaesdq_u8(*b1, r0);
        *b2 = vaesdq_u8(*b2, r0);
        *b3 = vaesdq_u8(*b3, r0);


        const uint8x16_t r1 = rk[0];

        *b1 = veorq_u8(*b1, r1);
        *b2 = veorq_u8(*b2, r1);
        *b3 = veorq_u8(*b3, r1);

    } else if (blocks == 2) {
        size_t r = rounds;
        for (; r > 1; r--) {
            *b1 = vaesdq_u8(*b1, rk[r]);
            *b2 = vaesdq_u8(*b2, rk[r]);
            *b1 = vaesimcq_u8(*b1);
            *b2 = vaesimcq_u8(*b2);
        }

        const uint8x16_t r0 = rk[1];

        *b1 = vaesdq_u8(*b1, r0);
        *b2 = vaesdq_u8(*b2, r0);

        const uint8x16_t r1 = rk[0];
        *b1 = veorq_u8(*b1, r1);
        *b2 = veorq_u8(*b2, r1);

    } else if (blocks == 1) {
        size_t r = rounds;
        for (; r > 1; r--) {
            *b1 = vaesdq_u8(*b1, rk[r]);
            *b1 = vaesimcq_u8(*b1);
        }

        const uint8x16_t r0 = rk[1];

        *b1 = vaesdq_u8(*b1, r0);

        const uint8x16_t r1 = rk[0];
        *b1 = veorq_u8(*b1, r1);
    }

    // Do nothing on zero blocks


}


size_t cbc_decrypt(cbc_ctx *cbc, unsigned char *src, uint32_t blocks, unsigned char *dest) {
    assert(cbc != NULL);
    unsigned char *destStart = dest;

    while (blocks >= 4) {

        uint8x16_t d0 = vld1q_u8(&src[16 * 0]);
        uint8x16_t d1 = vld1q_u8(&src[16 * 1]);
        uint8x16_t d2 = vld1q_u8(&src[16 * 2]);
        uint8x16_t d3 = vld1q_u8(&src[16 * 3]);

        uint8x16_t iv0 = cbc->chain_block;
        uint8x16_t iv1 = d0;
        uint8x16_t iv2 = d1;
        uint8x16_t iv3 = d2;
        cbc->chain_block = d3;

        decrypt_blocks(cbc->key.round_keys, &d0, &d1, &d2, &d3, 4, cbc->num_rounds);

        d0 = veorq_u8(d0, iv0);
        d1 = veorq_u8(d1, iv1);
        d2 = veorq_u8(d2, iv2);
        d3 = veorq_u8(d3, iv3);

        vst1q_u8(&dest[16 * 0], d0);
        vst1q_u8(&dest[16 * 1], d1);
        vst1q_u8(&dest[16 * 2], d2);
        vst1q_u8(&dest[16 * 3], d3);

        blocks -= 4;
        src += CBC_BLOCK_SIZE * 4;
        dest += CBC_BLOCK_SIZE * 4;
    }

    if (blocks == 3) {

        uint8x16_t d0 = vld1q_u8(&src[16 * 0]);
        uint8x16_t d1 = vld1q_u8(&src[16 * 1]);
        uint8x16_t d2 = vld1q_u8(&src[16 * 2]);

        uint8x16_t iv0 = cbc->chain_block;
        uint8x16_t iv1 = d0;
        uint8x16_t iv2 = d1;
        cbc->chain_block = d2;

        decrypt_blocks(cbc->key.round_keys, &d0, &d1, &d2, &d2, 3, cbc->num_rounds);

        d0 = veorq_u8(d0, iv0);
        d1 = veorq_u8(d1, iv1);
        d2 = veorq_u8(d2, iv2);


        vst1q_u8(&dest[16 * 0], d0);
        vst1q_u8(&dest[16 * 1], d1);
        vst1q_u8(&dest[16 * 2], d2);


        blocks -= 3;
        src += CBC_BLOCK_SIZE * 3;
        dest += CBC_BLOCK_SIZE * 3;

    } else if (blocks == 2) {

        uint8x16_t d0 = vld1q_u8(&src[16 * 0]);
        uint8x16_t d1 = vld1q_u8(&src[16 * 1]);


        uint8x16_t iv0 = cbc->chain_block;
        uint8x16_t iv1 = d0;
        cbc->chain_block = d1;

        decrypt_blocks(cbc->key.round_keys, &d0, &d1, &d1, &d1, 2, cbc->num_rounds);

        d0 = veorq_u8(d0, iv0);
        d1 = veorq_u8(d1, iv1);


        vst1q_u8(&dest[16 * 0], d0);
        vst1q_u8(&dest[16 * 1], d1);

        blocks -= 2;
        src += CBC_BLOCK_SIZE * 2;
        dest += CBC_BLOCK_SIZE * 2;
    } else if (blocks == 1) {
        uint8x16_t d0 = vld1q_u8(&src[16 * 0]);

        uint8x16_t iv0 = cbc->chain_block;

        cbc->chain_block = d0;

        decrypt_blocks(cbc->key.round_keys, &d0, &d0, &d0, &d0, 1, cbc->num_rounds);

        d0 = veorq_u8(d0, iv0);

        vst1q_u8(&dest[16 * 0], d0);

        blocks -= 1;
        src += CBC_BLOCK_SIZE;
        dest += CBC_BLOCK_SIZE;
    }


    dest += blocks * CBC_BLOCK_SIZE;
    return (size_t) (dest - destStart);
}