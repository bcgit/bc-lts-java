

#include <stddef.h>
#include <assert.h>
#include "cbc.h"
#include "../aes/aes_common_512b.h"


static inline __m128i set_feedback(const __m512i in_cipher_blocks, const uint32_t num_blocks) {
    if (num_blocks == 1) {
        return _mm512_castsi512_si128(in_cipher_blocks);
    } else if (num_blocks == 2) {
        return _mm512_extracti32x4_epi32(in_cipher_blocks, 1);
    } else if (num_blocks == 3) {
        return _mm512_extracti32x4_epi32(in_cipher_blocks, 2);
    } else if (num_blocks == 4) {
        return _mm512_extracti32x4_epi32(in_cipher_blocks, 3);
    } else {
        assert(0);
    }
}

static inline void aes_cbc_dec_blocks_512b(unsigned char *in, unsigned char *out,
                                           __m512i *fb512, __m128i *feedback, const __m128i *roundKeys,
                                           const int num_rounds, const uint32_t num_blocks) {

    if (num_blocks >= 16) {
        __m512i d0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        __m512i d1 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
        __m512i d2 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
        __m512i d3 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);

        const __m512i iv0 = _mm512_alignr_epi64(d0, *fb512, 6);
        const __m512i iv1 = _mm512_alignr_epi64(d1, d0, 6);
        const __m512i iv2 = _mm512_alignr_epi64(d2, d1, 6);
        const __m512i iv3 = _mm512_alignr_epi64(d3, d2, 6);

        *fb512 = d3; // keep as feedback for the next iteration, 'feedback' not used in this case
        aesdec_16_blocks_512b(&d0, &d1, &d2, &d3, roundKeys, num_rounds, 16);

        d0 = _mm512_xor_si512(d0, iv0);
        d1 = _mm512_xor_si512(d1, iv1);
        d2 = _mm512_xor_si512(d2, iv2);
        d3 = _mm512_xor_si512(d3, iv3);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], d0);
        _mm512_storeu_si512((__m512i *) &out[1 * 64], d1);
        _mm512_storeu_si512((__m512i *) &out[2 * 64], d2);
        _mm512_storeu_si512((__m512i *) &out[3 * 64], d3);
    } else if (num_blocks > 12) {
        const uint32_t partial_blocks = num_blocks - 12;
        __m512i d0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        __m512i d1 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
        __m512i d2 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
        __m512i d3 = mm512_loadu_128b_blocks(&in[3 * 64], partial_blocks);

        const __m512i iv0 = _mm512_alignr_epi64(d0, *fb512, 6);
        const __m512i iv1 = _mm512_alignr_epi64(d1, d0, 6);
        const __m512i iv2 = _mm512_alignr_epi64(d2, d1, 6);
        const __m512i iv3 = _mm512_alignr_epi64(d3, d2, 6);

        *feedback = set_feedback(d3, partial_blocks); // keep as feedback for the next time

        aesdec_16_blocks_512b(&d0, &d1, &d2, &d3, roundKeys, num_rounds, 16);

        d0 = _mm512_xor_si512(d0, iv0);
        d1 = _mm512_xor_si512(d1, iv1);
        d2 = _mm512_xor_si512(d2, iv2);
        d3 = _mm512_xor_si512(d3, iv3);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], d0);
        _mm512_storeu_si512((__m512i *) &out[1 * 64], d1);
        _mm512_storeu_si512((__m512i *) &out[2 * 64], d2);
        mm512_storeu_128b_blocks(&out[3 * 64], &d3, partial_blocks);
    } else if (num_blocks > 8) {
        const uint32_t partial_blocks = num_blocks - 8;
        __m512i d0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        __m512i d1 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
        __m512i d2 = mm512_loadu_128b_blocks(&in[2 * 64], partial_blocks);

        const __m512i iv0 = _mm512_alignr_epi64(d0, *fb512, 6);
        const __m512i iv1 = _mm512_alignr_epi64(d1, d0, 6);
        const __m512i iv2 = _mm512_alignr_epi64(d2, d1, 6);

        *feedback = set_feedback(d2, partial_blocks); // keep as feedback for the next time

        aesdec_16_blocks_512b(&d0, &d1, &d2, &d2, roundKeys, num_rounds, 12);

        d0 = _mm512_xor_si512(d0, iv0);
        d1 = _mm512_xor_si512(d1, iv1);
        d2 = _mm512_xor_si512(d2, iv2);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], d0);
        _mm512_storeu_si512((__m512i *) &out[1 * 64], d1);
        mm512_storeu_128b_blocks(&out[2 * 64], &d2, partial_blocks);
    } else if (num_blocks > 4) {
        const uint32_t partial_blocks = num_blocks - 4;
        __m512i d0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        __m512i d1 = mm512_loadu_128b_blocks(&in[1 * 64], partial_blocks);

        const __m512i iv0 = _mm512_alignr_epi64(d0, *fb512, 6);
        const __m512i iv1 = _mm512_alignr_epi64(d1, d0, 6);

        *feedback = set_feedback(d1, partial_blocks); // keep as feedback for the next time

        aesdec_16_blocks_512b(&d0, &d1, &d1, &d1, roundKeys, num_rounds, 8);

        d0 = _mm512_xor_si512(d0, iv0);
        d1 = _mm512_xor_si512(d1, iv1);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], d0);
        mm512_storeu_128b_blocks(&out[1 * 64], &d1, partial_blocks);
    } else if (num_blocks > 0) {
        const uint32_t partial_blocks = num_blocks;
        __m512i d0 = mm512_loadu_128b_blocks(in, partial_blocks);

        const __m512i iv0 = _mm512_alignr_epi64(d0, *fb512, 6);

        *feedback = set_feedback(d0, partial_blocks); // keep as feedback for the next time

        aesdec_16_blocks_512b(&d0, &d0, &d0, &d0, roundKeys, num_rounds, 4);

        d0 = _mm512_xor_si512(d0, iv0);

        mm512_storeu_128b_blocks(out, &d0, partial_blocks);
    } else if (num_blocks == 0) {
        *feedback = set_feedback(*fb512, 4);
    }
}



//
// VAES or 512b single block implementation.
//

size_t cbc_decrypt(cbc_ctx *cbc, unsigned char *src, uint32_t blocks, unsigned char *dest) {
    assert(cbc != NULL);
    unsigned char *destStart = dest;


    __m512i fb512 = _mm512_broadcast_i32x4(cbc->chainblock);

    __m128i fb = cbc->chainblock;

    while (blocks >= 16) {
        aes_cbc_dec_blocks_512b(src, dest, &fb512, &fb, cbc->roundKeys, cbc->num_rounds, 16);
        blocks -= 16;
        src += CBC_BLOCK_SIZE * 16;
        dest += CBC_BLOCK_SIZE * 16;
    }
    aes_cbc_dec_blocks_512b(src, dest, &fb512, &fb, cbc->roundKeys, cbc->num_rounds, blocks);
    dest += blocks * CBC_BLOCK_SIZE;
    cbc->chainblock = fb;
    return (size_t) (dest - destStart);
}
