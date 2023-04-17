//
//

#include <immintrin.h>
#include "../aes/aes_common_512b.h"
#include "ecb.h"

static inline void aes_ecb_blocks_512b(uint8_t *in, uint8_t *out,
                                  const __m128i *roundKeys, const uint32_t blocks,
                                  const int num_rounds, const int is_encrypt) {

    if (blocks >= 16) {
        __m512i tmp1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        __m512i tmp2 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
        __m512i tmp3 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
        __m512i tmp4 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);

        if (is_encrypt)
            aesenc_16_blocks_512b(&tmp1, &tmp2, &tmp3, &tmp4, roundKeys, num_rounds, 16);
        else
            aesdec_16_blocks_512b(&tmp1, &tmp2, &tmp3, &tmp4, roundKeys, num_rounds, 16);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], tmp1);
        _mm512_storeu_si512((__m512i *) &out[1 * 64], tmp2);
        _mm512_storeu_si512((__m512i *) &out[2 * 64], tmp3);
        _mm512_storeu_si512((__m512i *) &out[3 * 64], tmp4);
    } else if (blocks > 12) {
        const uint32_t partial_blocks = blocks - 12;
        __m512i tmp1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        __m512i tmp2 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
        __m512i tmp3 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
        __m512i tmp4 = mm512_loadu_128b_blocks(&in[3 * 64], partial_blocks);

        if (is_encrypt)
            aesenc_16_blocks_512b(&tmp1, &tmp2, &tmp3, &tmp4, roundKeys, num_rounds, 16);
        else
            aesdec_16_blocks_512b(&tmp1, &tmp2, &tmp3, &tmp4, roundKeys, num_rounds, 16);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], tmp1);
        _mm512_storeu_si512((__m512i *) &out[1 * 64], tmp2);
        _mm512_storeu_si512((__m512i *) &out[2 * 64], tmp3);
        mm512_storeu_128b_blocks(&out[3 * 64], &tmp4, partial_blocks);
    } else if (blocks > 8) {
        const uint32_t partial_blocks = blocks - 8;
        __m512i tmp1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        __m512i tmp2 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
        __m512i tmp3 = mm512_loadu_128b_blocks(&in[2 * 64], partial_blocks);

        if (is_encrypt)
            aesenc_16_blocks_512b(&tmp1, &tmp2, &tmp3, &tmp3, roundKeys, num_rounds, 12);
        else
            aesdec_16_blocks_512b(&tmp1, &tmp2, &tmp3, &tmp3, roundKeys, num_rounds, 12);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], tmp1);
        _mm512_storeu_si512((__m512i *) &out[1 * 64], tmp2);
        mm512_storeu_128b_blocks(&out[2 * 64], &tmp3, partial_blocks);
    } else if (blocks > 4) {
        const uint32_t partial_blocks = blocks - 4;
        __m512i tmp1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        __m512i tmp2 = mm512_loadu_128b_blocks(&in[1 * 64], partial_blocks);

        if (is_encrypt)
            aesenc_16_blocks_512b(&tmp1, &tmp2, &tmp2, &tmp2, roundKeys, num_rounds, 8);
        else
            aesdec_16_blocks_512b(&tmp1, &tmp2, &tmp2, &tmp2, roundKeys, num_rounds, 8);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], tmp1);
        mm512_storeu_128b_blocks(&out[1 * 64], &tmp2, partial_blocks);
    } else if (blocks > 0) {
        const uint32_t partial_blocks = blocks;
        __m512i tmp1 = mm512_loadu_128b_blocks(in, partial_blocks);

        if (is_encrypt)
            aesenc_16_blocks_512b(&tmp1, &tmp1, &tmp1, &tmp1, roundKeys, num_rounds, 4);
        else
            aesdec_16_blocks_512b(&tmp1, &tmp1, &tmp1, &tmp1, roundKeys, num_rounds, 4);

        mm512_storeu_128b_blocks(out, &tmp1, partial_blocks);
    }

}

size_t ecb_process_blocks(ecb_ctx *ctx, uint8_t *src, uint32_t blocks, uint8_t *dest) {
    uint8_t *destStart = dest;

    while (blocks >= 16) {
        aes_ecb_blocks_512b(src, dest, ctx->roundKeys, 16, ctx->num_rounds, ctx->encryption);
        blocks -= 16;
        dest += ECB_BLOCK_SIZE * 16;
        src += ECB_BLOCK_SIZE * 16;
    }

    aes_ecb_blocks_512b(src, dest, ctx->roundKeys, blocks, ctx->num_rounds, ctx->encryption);
    dest += ECB_BLOCK_SIZE * blocks;

    return (size_t) (dest - destStart);
}
