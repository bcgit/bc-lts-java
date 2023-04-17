//
// Created by meganwoods on 3/15/23.
//

#include <stdint.h>


#include "../aes/aes_common_128b.h"
#include "ecb.h"


static inline void aes_ecb_blocks_128b(uint8_t *in, uint8_t *out,
                                       const __m128i *roundKeys, const uint32_t num_blocks,
                                       const int num_rounds, const int is_encrypt) {

    if (num_blocks >= 8) {
        __m128i b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        __m128i b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);
        __m128i b3 = _mm_loadu_si128((const __m128i *) &in[2 * 16]);
        __m128i b4 = _mm_loadu_si128((const __m128i *) &in[3 * 16]);
        __m128i b5 = _mm_loadu_si128((const __m128i *) &in[4 * 16]);
        __m128i b6 = _mm_loadu_si128((const __m128i *) &in[5 * 16]);
        __m128i b7 = _mm_loadu_si128((const __m128i *) &in[6 * 16]);
        __m128i b8 = _mm_loadu_si128((const __m128i *) &in[7 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(&b1, &b2, &b3, &b4, &b5, &b6, &b7, &b8, roundKeys, num_rounds, 8);
        else
            aesdec_8_blocks_128b(&b1, &b2, &b3, &b4, &b5, &b6, &b7, &b8, roundKeys, num_rounds, 8);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 16], b3);
        _mm_storeu_si128((__m128i *) &out[3 * 16], b4);
        _mm_storeu_si128((__m128i *) &out[4 * 16], b5);
        _mm_storeu_si128((__m128i *) &out[5 * 16], b6);
        _mm_storeu_si128((__m128i *) &out[6 * 16], b7);
        _mm_storeu_si128((__m128i *) &out[7 * 16], b8);
    } else if (num_blocks == 7) {
        __m128i b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        __m128i b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);
        __m128i b3 = _mm_loadu_si128((const __m128i *) &in[2 * 16]);
        __m128i b4 = _mm_loadu_si128((const __m128i *) &in[3 * 16]);
        __m128i b5 = _mm_loadu_si128((const __m128i *) &in[4 * 16]);
        __m128i b6 = _mm_loadu_si128((const __m128i *) &in[5 * 16]);
        __m128i b7 = _mm_loadu_si128((const __m128i *) &in[6 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(&b1, &b2, &b3, &b4, &b5, &b6, &b7, &b7, roundKeys, num_rounds, 7);
        else
            aesdec_8_blocks_128b(&b1, &b2, &b3, &b4, &b5, &b6, &b7, &b7, roundKeys, num_rounds, 7);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 16], b3);
        _mm_storeu_si128((__m128i *) &out[3 * 16], b4);
        _mm_storeu_si128((__m128i *) &out[4 * 16], b5);
        _mm_storeu_si128((__m128i *) &out[5 * 16], b6);
        _mm_storeu_si128((__m128i *) &out[6 * 16], b7);
    } else if (num_blocks == 6) {
        __m128i b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        __m128i b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);
        __m128i b3 = _mm_loadu_si128((const __m128i *) &in[2 * 16]);
        __m128i b4 = _mm_loadu_si128((const __m128i *) &in[3 * 16]);
        __m128i b5 = _mm_loadu_si128((const __m128i *) &in[4 * 16]);
        __m128i b6 = _mm_loadu_si128((const __m128i *) &in[5 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(&b1, &b2, &b3, &b4, &b5, &b6, &b6, &b6, roundKeys, num_rounds, 6);
        else
            aesdec_8_blocks_128b(&b1, &b2, &b3, &b4, &b5, &b6, &b6, &b6, roundKeys, num_rounds, 6);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 16], b3);
        _mm_storeu_si128((__m128i *) &out[3 * 16], b4);
        _mm_storeu_si128((__m128i *) &out[4 * 16], b5);
        _mm_storeu_si128((__m128i *) &out[5 * 16], b6);
    } else if (num_blocks == 5) {
        __m128i b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        __m128i b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);
        __m128i b3 = _mm_loadu_si128((const __m128i *) &in[2 * 16]);
        __m128i b4 = _mm_loadu_si128((const __m128i *) &in[3 * 16]);
        __m128i b5 = _mm_loadu_si128((const __m128i *) &in[4 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(&b1, &b2, &b3, &b4, &b5, &b5, &b5, &b5, roundKeys, num_rounds, 5);
        else
            aesdec_8_blocks_128b(&b1, &b2, &b3, &b4, &b5, &b5, &b5, &b5, roundKeys, num_rounds, 5);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 16], b3);
        _mm_storeu_si128((__m128i *) &out[3 * 16], b4);
        _mm_storeu_si128((__m128i *) &out[4 * 16], b5);
    } else if (num_blocks == 4) {
        __m128i b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        __m128i b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);
        __m128i b3 = _mm_loadu_si128((const __m128i *) &in[2 * 16]);
        __m128i b4 = _mm_loadu_si128((const __m128i *) &in[3 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(&b1, &b2, &b3, &b4, &b4, &b4, &b4, &b4, roundKeys, num_rounds, 4);
        else
            aesdec_8_blocks_128b(&b1, &b2, &b3, &b4, &b4, &b4, &b4, &b4, roundKeys, num_rounds, 4);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 16], b3);
        _mm_storeu_si128((__m128i *) &out[3 * 16], b4);
    } else if (num_blocks == 3) {
        __m128i b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        __m128i b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);
        __m128i b3 = _mm_loadu_si128((const __m128i *) &in[2 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(&b1, &b2, &b3, &b3, &b3, &b3, &b3, &b3, roundKeys, num_rounds, 3);
        else
            aesdec_8_blocks_128b(&b1, &b2, &b3, &b3, &b3, &b3, &b3, &b3, roundKeys, num_rounds, 3);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 16], b3);
    } else if (num_blocks == 2) {
        __m128i b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        __m128i b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(&b1, &b2, &b2, &b2, &b2, &b2, &b2, &b2, roundKeys, num_rounds, 2);
        else
            aesdec_8_blocks_128b(&b1, &b2, &b2, &b2, &b2, &b2, &b2, &b2, roundKeys, num_rounds, 2);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
    } else if (num_blocks == 1) {
        __m128i b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(&b1, &b1, &b1, &b1, &b1, &b1, &b1, &b1, roundKeys, num_rounds, 1);
        else
            aesdec_8_blocks_128b(&b1, &b1, &b1, &b1, &b1, &b1, &b1, &b1, roundKeys, num_rounds, 1);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
    }

}


size_t ecb_process_blocks(ecb_ctx *ctx, uint8_t *src, uint32_t blocks, uint8_t *dest){
    uint8_t *destStart = dest;

    while (blocks >= 8) {
        aes_ecb_blocks_128b(src, dest, ctx->roundKeys, 8, ctx->num_rounds, ctx->encryption);
        blocks -= 8;
        dest += ECB_BLOCK_SIZE * 8;
        src += ECB_BLOCK_SIZE * 8;
    }

    aes_ecb_blocks_128b(src, dest, ctx->roundKeys, blocks, ctx->num_rounds, ctx->encryption);
    dest += ECB_BLOCK_SIZE * blocks;

    return (size_t) (dest - destStart);
}
