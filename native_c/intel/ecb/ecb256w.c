//
//



#include <immintrin.h>
#include "../aes/aes_common_256b.h"
#include "ecb.h"

static inline void aes_ecb_blocks_256b(uint8_t *in, uint8_t *out,
                                       const __m128i *roundKeys, const uint32_t num_blocks,
                                       const int num_rounds, const int is_encrypt) {

    if (num_blocks >= 16) {
        __m256i b0 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        __m256i b3 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        __m256i b4 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);
        __m256i b5 = _mm256_loadu_si256((const __m256i *) &in[5 * 32]);
        __m256i b6 = _mm256_loadu_si256((const __m256i *) &in[6 * 32]);
        __m256i b7 = _mm256_loadu_si256((const __m256i *) &in[7 * 32]);

        if (is_encrypt)
            aesenc_16_blocks_256b(&b0, &b1, &b2, &b3, &b4, &b5, &b6, &b7, roundKeys, num_rounds, 16);
        else
            aesdec_16_blocks_256b(&b0, &b1, &b2, &b3, &b4, &b5, &b6, &b7, roundKeys, num_rounds, 16);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], b5);
        _mm256_storeu_si256((__m256i *) &out[6 * 32], b6);
        _mm256_storeu_si256((__m256i *) &out[7 * 32], b7);
    } else if (num_blocks >= 15) {
        __m256i b0 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        __m256i b3 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        __m256i b4 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);
        __m256i b5 = _mm256_loadu_si256((const __m256i *) &in[5 * 32]);
        __m256i b6 = _mm256_loadu_si256((const __m256i *) &in[6 * 32]);
        __m256i b7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *) &in[7 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(&b0, &b1, &b2, &b3, &b4, &b5, &b6, &b7, roundKeys, num_rounds, 16);
        else
            aesdec_16_blocks_256b(&b0, &b1, &b2, &b3, &b4, &b5, &b6, &b7, roundKeys, num_rounds, 16);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], b5);
        _mm256_storeu_si256((__m256i *) &out[6 * 32], b6);
        _mm_storeu_si128((__m128i *) &out[7 * 32], _mm256_castsi256_si128(b7));
    } else if (num_blocks == 14) {
        __m256i b0 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        __m256i b3 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        __m256i b4 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);
        __m256i b5 = _mm256_loadu_si256((const __m256i *) &in[5 * 32]);
        __m256i b6 = _mm256_loadu_si256((const __m256i *) &in[6 * 32]);

        if (is_encrypt)
            aesenc_16_blocks_256b(&b0, &b1, &b2, &b3, &b4, &b5, &b6, &b6, roundKeys, num_rounds, 14);
        else
            aesdec_16_blocks_256b(&b0, &b1, &b2, &b3, &b4, &b5, &b6, &b6, roundKeys, num_rounds, 14);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], b5);
        _mm256_storeu_si256((__m256i *) &out[6 * 32], b6);

    } else if (num_blocks == 13) {
        __m256i b0 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        __m256i b3 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        __m256i b4 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);
        __m256i b5 = _mm256_loadu_si256((const __m256i *) &in[5 * 32]);
        __m256i b6 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *) &in[6 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(&b0, &b1, &b2, &b3, &b4, &b5, &b6, &b6, roundKeys, num_rounds, 14);
        else
            aesdec_16_blocks_256b(&b0, &b1, &b2, &b3, &b4, &b5, &b6, &b6, roundKeys, num_rounds, 14);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], b5);
        _mm_storeu_si128((__m128i *) &out[6 * 32], _mm256_castsi256_si128(b6));

    } else if (num_blocks == 12) {
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        __m256i b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        __m256i b4 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        __m256i b5 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);
        __m256i b6 = _mm256_loadu_si256((const __m256i *) &in[5 * 32]);


        if (is_encrypt)
            aesenc_16_blocks_256b(&b1, &b2, &b3, &b4, &b5, &b6, &b6, &b6, roundKeys, num_rounds, 12);
        else
            aesdec_16_blocks_256b(&b1, &b2, &b3, &b4, &b5, &b6, &b6, &b6, roundKeys, num_rounds, 12);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b5);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], b6);
    } else if (num_blocks == 11) {
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        __m256i b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        __m256i b4 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        __m256i b5 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);
        __m256i b6 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *) &in[5 * 32]));


        if (is_encrypt)
            aesenc_16_blocks_256b(&b1, &b2, &b3, &b4, &b5, &b6, &b6, &b6, roundKeys, num_rounds, 12);
        else
            aesdec_16_blocks_256b(&b1, &b2, &b3, &b4, &b5, &b6, &b6, &b6, roundKeys, num_rounds, 12);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b5);
        _mm_storeu_si128((__m128i *) &out[5 * 32], _mm256_castsi256_si128(b6));
    } else if (num_blocks == 10) {
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        __m256i b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        __m256i b4 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        __m256i b5 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);


        if (is_encrypt)
            aesenc_16_blocks_256b(&b1, &b2, &b3, &b4, &b5, &b5, &b5, &b5, roundKeys, num_rounds, 10);
        else
            aesdec_16_blocks_256b(&b1, &b2, &b3, &b4, &b5, &b5, &b5, &b5, roundKeys, num_rounds, 10);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b5);

    } else if (num_blocks == 9) {
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        __m256i b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        __m256i b4 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        __m256i b5 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *) &in[4 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(&b1, &b2, &b3, &b4, &b5, &b5, &b5, &b5, roundKeys, num_rounds, 10);
        else
            aesdec_16_blocks_256b(&b1, &b2, &b3, &b4, &b5, &b5, &b5, &b5, roundKeys, num_rounds, 10);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b4);
        _mm_storeu_si128((__m128i *) &out[4 * 32], _mm256_castsi256_si128(b5));
    } else if (num_blocks == 8) {
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        __m256i b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        __m256i b4 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);

        if (is_encrypt)
            aesenc_16_blocks_256b(&b1, &b2, &b3, &b4, &b4, &b4, &b4, &b4, roundKeys, num_rounds, 8);
        else
            aesdec_16_blocks_256b(&b1, &b2, &b3, &b4, &b4, &b4, &b4, &b4, roundKeys, num_rounds, 8);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b4);


    } else if (num_blocks == 7) {
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        __m256i b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        __m256i b4 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *) &in[3 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(&b1, &b2, &b3, &b4, &b4, &b4, &b4, &b4, roundKeys, num_rounds, 8);
        else
            aesdec_16_blocks_256b(&b1, &b2, &b3, &b4, &b4, &b4, &b4, &b4, roundKeys, num_rounds, 8);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);
        _mm_storeu_si128((__m128i *) &out[3 * 32], _mm256_castsi256_si128(b4));
    } else if (num_blocks == 6) {
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        __m256i b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);


        if (is_encrypt)
            aesenc_16_blocks_256b(&b1, &b2, &b3, &b3, &b3, &b3, &b3, &b3, roundKeys, num_rounds, 6);
        else
            aesdec_16_blocks_256b(&b1, &b2, &b3, &b3, &b3, &b3, &b3, &b3, roundKeys, num_rounds, 6);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);

    } else if (num_blocks == 5) {
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        __m256i b3 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *) &in[2 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(&b1, &b2, &b3, &b3, &b3, &b3, &b3, &b3, roundKeys, num_rounds, 6);
        else
            aesdec_16_blocks_256b(&b1, &b2, &b3, &b3, &b3, &b3, &b3, &b3, roundKeys, num_rounds, 6);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 32], _mm256_castsi256_si128(b3));
    } else if (num_blocks == 4) {
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);


        if (is_encrypt)
            aesenc_16_blocks_256b(&b1, &b2, &b2, &b2, &b2, &b2, &b2, &b2, roundKeys, num_rounds, 4);
        else
            aesdec_16_blocks_256b(&b1, &b2, &b2, &b2, &b2, &b2, &b2, &b2, roundKeys, num_rounds, 4);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);


    } else if (num_blocks == 3) {
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        __m256i b2 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *) &in[1 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(&b1, &b2, &b2, &b2, &b2, &b2, &b2, &b2, roundKeys, num_rounds, 4);
        else
            aesdec_16_blocks_256b(&b1, &b2, &b2, &b2, &b2, &b2, &b2, &b2, roundKeys, num_rounds, 4);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 32], _mm256_castsi256_si128(b2));
    } else if (num_blocks == 2) {
        __m256i b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);

        if (is_encrypt)
            aesenc_16_blocks_256b(&b1, &b1, &b1, &b1, &b1, &b1, &b1, &b1, roundKeys, num_rounds, 2);
        else
            aesdec_16_blocks_256b(&b1, &b1, &b1, &b1, &b1, &b1, &b1, &b1, roundKeys, num_rounds, 2);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);


    } else if (num_blocks == 1) {

        __m256i b1 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *) &in[0 * 16]));

        if (is_encrypt)
            aesenc_16_blocks_256b(&b1, &b1, &b1, &b1, &b1, &b1, &b1, &b1, roundKeys, num_rounds, 2);
        else
            aesdec_16_blocks_256b(&b1, &b1, &b1, &b1, &b1, &b1, &b1, &b1, roundKeys, num_rounds, 2);

        _mm_storeu_si128((__m128i *) &out[0 * 16], _mm256_castsi256_si128(b1));
    }


}


size_t ecb_process_blocks(ecb_ctx *ctx, uint8_t *src, uint32_t blocks, uint8_t *dest) {
    uint8_t *destStart = dest;

    while (blocks >= 16) {
        aes_ecb_blocks_256b(src, dest, ctx->roundKeys, 16, ctx->num_rounds, ctx->encryption);
        blocks -= 16;
        dest += ECB_BLOCK_SIZE * 16;
        src += ECB_BLOCK_SIZE * 16;
    }

    aes_ecb_blocks_256b(src, dest, ctx->roundKeys, blocks, ctx->num_rounds, ctx->encryption);
    dest += ECB_BLOCK_SIZE * blocks;

    return (size_t) (dest - destStart);
}
