//
// Created  on 7/6/2022.
//

#include <cstring>
#include <immintrin.h>

#include "AesCBCDecryptVaes.h"
#include "../aes/aes_common_256b.h"
#include "../aes/aes_common_128b.h"


static inline void aes_cbc_dec_blocks_256b(unsigned char *in, unsigned char *out,
                                           __m256i &fb256, const __m128i *roundKeys,
                                           const int num_rounds, const uint32_t num_blocks) {

    if (num_blocks >= 16) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);
        __m256i d2 = _mm256_loadu_si256((__m256i *) &in[2 * 32]);
        __m256i d3 = _mm256_loadu_si256((__m256i *) &in[3 * 32]);
        __m256i d4 = _mm256_loadu_si256((__m256i *) &in[4 * 32]);
        __m256i d5 = _mm256_loadu_si256((__m256i *) &in[5 * 32]);
        __m256i d6 = _mm256_loadu_si256((__m256i *) &in[6 * 32]);
        __m256i d7 = _mm256_loadu_si256((__m256i *) &in[7 * 32]);

        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));
        const __m256i iv2 = _mm256_set_m128i(_mm256_extracti128_si256(d2, 0), _mm256_extracti128_si256(d1, 1));
        const __m256i iv3 = _mm256_set_m128i(_mm256_extracti128_si256(d3, 0), _mm256_extracti128_si256(d2, 1));
        const __m256i iv4 = _mm256_set_m128i(_mm256_extracti128_si256(d4, 0), _mm256_extracti128_si256(d3, 1));
        const __m256i iv5 = _mm256_set_m128i(_mm256_extracti128_si256(d5, 0), _mm256_extracti128_si256(d4, 1));
        const __m256i iv6 = _mm256_set_m128i(_mm256_extracti128_si256(d6, 0), _mm256_extracti128_si256(d5, 1));
        const __m256i iv7 = _mm256_set_m128i(_mm256_extracti128_si256(d7, 0), _mm256_extracti128_si256(d6, 1));

        fb256 = d7;
        aesdec_16_blocks_256b(d0, d1, d2, d3, d4, d5, d6, d7, roundKeys, num_rounds, 16);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);
        d2 = _mm256_xor_si256(d2, iv2);
        d3 = _mm256_xor_si256(d3, iv3);
        d4 = _mm256_xor_si256(d4, iv4);
        d5 = _mm256_xor_si256(d5, iv5);
        d6 = _mm256_xor_si256(d6, iv6);
        d7 = _mm256_xor_si256(d7, iv7);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], d2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], d3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], d4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], d5);
        _mm256_storeu_si256((__m256i *) &out[6 * 32], d6);
        _mm256_storeu_si256((__m256i *) &out[7 * 32], d7);

    } else if (num_blocks == 15) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);
        __m256i d2 = _mm256_loadu_si256((__m256i *) &in[2 * 32]);
        __m256i d3 = _mm256_loadu_si256((__m256i *) &in[3 * 32]);
        __m256i d4 = _mm256_loadu_si256((__m256i *) &in[4 * 32]);
        __m256i d5 = _mm256_loadu_si256((__m256i *) &in[5 * 32]);
        __m256i d6 = _mm256_loadu_si256((__m256i *) &in[6 * 32]);
        __m256i d7 = _mm256_broadcastsi128_si256(
                _mm_loadu_si128((__m128i *) &in[7 * 32]));//   _mm256_loadu_si256((__m256i *) &in[7 * 32]);

        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));
        const __m256i iv2 = _mm256_set_m128i(_mm256_extracti128_si256(d2, 0), _mm256_extracti128_si256(d1, 1));
        const __m256i iv3 = _mm256_set_m128i(_mm256_extracti128_si256(d3, 0), _mm256_extracti128_si256(d2, 1));
        const __m256i iv4 = _mm256_set_m128i(_mm256_extracti128_si256(d4, 0), _mm256_extracti128_si256(d3, 1));
        const __m256i iv5 = _mm256_set_m128i(_mm256_extracti128_si256(d5, 0), _mm256_extracti128_si256(d4, 1));
        const __m256i iv6 = _mm256_set_m128i(_mm256_extracti128_si256(d6, 0), _mm256_extracti128_si256(d5, 1));
        const __m256i iv7 = _mm256_set_m128i(_mm256_extracti128_si256(d7, 0), _mm256_extracti128_si256(d6, 1));

        fb256 = d7;
        aesdec_16_blocks_256b(d0, d1, d2, d3, d4, d5, d6, d7, roundKeys, num_rounds, 16);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);
        d2 = _mm256_xor_si256(d2, iv2);
        d3 = _mm256_xor_si256(d3, iv3);
        d4 = _mm256_xor_si256(d4, iv4);
        d5 = _mm256_xor_si256(d5, iv5);
        d6 = _mm256_xor_si256(d6, iv6);
        d7 = _mm256_xor_si256(d7, iv7);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], d2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], d3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], d4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], d5);
        _mm256_storeu_si256((__m256i *) &out[6 * 32], d6);
        _mm_storeu_si128((__m128i *) &out[7 * 32], _mm256_extracti128_si256(d7, 0));


    } else if (num_blocks == 14) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);
        __m256i d2 = _mm256_loadu_si256((__m256i *) &in[2 * 32]);
        __m256i d3 = _mm256_loadu_si256((__m256i *) &in[3 * 32]);
        __m256i d4 = _mm256_loadu_si256((__m256i *) &in[4 * 32]);
        __m256i d5 = _mm256_loadu_si256((__m256i *) &in[5 * 32]);
        __m256i d6 = _mm256_loadu_si256((__m256i *) &in[6 * 32]);


        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));
        const __m256i iv2 = _mm256_set_m128i(_mm256_extracti128_si256(d2, 0), _mm256_extracti128_si256(d1, 1));
        const __m256i iv3 = _mm256_set_m128i(_mm256_extracti128_si256(d3, 0), _mm256_extracti128_si256(d2, 1));
        const __m256i iv4 = _mm256_set_m128i(_mm256_extracti128_si256(d4, 0), _mm256_extracti128_si256(d3, 1));
        const __m256i iv5 = _mm256_set_m128i(_mm256_extracti128_si256(d5, 0), _mm256_extracti128_si256(d4, 1));
        const __m256i iv6 = _mm256_set_m128i(_mm256_extracti128_si256(d6, 0), _mm256_extracti128_si256(d5, 1));


        fb256 = d6;
        aesdec_16_blocks_256b(d0, d1, d2, d3, d4, d5, d6, d6, roundKeys, num_rounds, 14);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);
        d2 = _mm256_xor_si256(d2, iv2);
        d3 = _mm256_xor_si256(d3, iv3);
        d4 = _mm256_xor_si256(d4, iv4);
        d5 = _mm256_xor_si256(d5, iv5);
        d6 = _mm256_xor_si256(d6, iv6);


        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], d2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], d3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], d4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], d5);
        _mm256_storeu_si256((__m256i *) &out[6 * 32], d6);
    } else if (num_blocks == 13) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);
        __m256i d2 = _mm256_loadu_si256((__m256i *) &in[2 * 32]);
        __m256i d3 = _mm256_loadu_si256((__m256i *) &in[3 * 32]);
        __m256i d4 = _mm256_loadu_si256((__m256i *) &in[4 * 32]);
        __m256i d5 = _mm256_loadu_si256((__m256i *) &in[5 * 32]);
        __m256i d6 = _mm256_broadcastsi128_si256(
                _mm_loadu_si128((__m128i *) &in[6 * 32]));//   _mm256_loadu_si256((__m256i *) &in[7 * 32]);

        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));
        const __m256i iv2 = _mm256_set_m128i(_mm256_extracti128_si256(d2, 0), _mm256_extracti128_si256(d1, 1));
        const __m256i iv3 = _mm256_set_m128i(_mm256_extracti128_si256(d3, 0), _mm256_extracti128_si256(d2, 1));
        const __m256i iv4 = _mm256_set_m128i(_mm256_extracti128_si256(d4, 0), _mm256_extracti128_si256(d3, 1));
        const __m256i iv5 = _mm256_set_m128i(_mm256_extracti128_si256(d5, 0), _mm256_extracti128_si256(d4, 1));
        const __m256i iv6 = _mm256_set_m128i(_mm256_extracti128_si256(d6, 0), _mm256_extracti128_si256(d5, 1));

        fb256 = d6;
        aesdec_16_blocks_256b(d0, d1, d2, d3, d4, d5, d6, d6, roundKeys, num_rounds, 14);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);
        d2 = _mm256_xor_si256(d2, iv2);
        d3 = _mm256_xor_si256(d3, iv3);
        d4 = _mm256_xor_si256(d4, iv4);
        d5 = _mm256_xor_si256(d5, iv5);
        d6 = _mm256_xor_si256(d6, iv6);


        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], d2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], d3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], d4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], d5);
        _mm_storeu_si128((__m128i *) &out[6 * 32], _mm256_extracti128_si256(d6, 0));

    } else if (num_blocks == 12) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);
        __m256i d2 = _mm256_loadu_si256((__m256i *) &in[2 * 32]);
        __m256i d3 = _mm256_loadu_si256((__m256i *) &in[3 * 32]);
        __m256i d4 = _mm256_loadu_si256((__m256i *) &in[4 * 32]);
        __m256i d5 = _mm256_loadu_si256((__m256i *) &in[5 * 32]);


        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));
        const __m256i iv2 = _mm256_set_m128i(_mm256_extracti128_si256(d2, 0), _mm256_extracti128_si256(d1, 1));
        const __m256i iv3 = _mm256_set_m128i(_mm256_extracti128_si256(d3, 0), _mm256_extracti128_si256(d2, 1));
        const __m256i iv4 = _mm256_set_m128i(_mm256_extracti128_si256(d4, 0), _mm256_extracti128_si256(d3, 1));
        const __m256i iv5 = _mm256_set_m128i(_mm256_extracti128_si256(d5, 0), _mm256_extracti128_si256(d4, 1));


        fb256 = d5;
        aesdec_16_blocks_256b(d0, d1, d2, d3, d4, d5, d5, d5, roundKeys, num_rounds, 12);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);
        d2 = _mm256_xor_si256(d2, iv2);
        d3 = _mm256_xor_si256(d3, iv3);
        d4 = _mm256_xor_si256(d4, iv4);
        d5 = _mm256_xor_si256(d5, iv5);


        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], d2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], d3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], d4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], d5);

    } else if (num_blocks == 11) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);
        __m256i d2 = _mm256_loadu_si256((__m256i *) &in[2 * 32]);
        __m256i d3 = _mm256_loadu_si256((__m256i *) &in[3 * 32]);
        __m256i d4 = _mm256_loadu_si256((__m256i *) &in[4 * 32]);
        __m256i d5 = _mm256_broadcastsi128_si256(
                _mm_loadu_si128((__m128i *) &in[5 * 32]));//   _mm256_loadu_si256((__m256i *) &in[7 * 32]);

        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));
        const __m256i iv2 = _mm256_set_m128i(_mm256_extracti128_si256(d2, 0), _mm256_extracti128_si256(d1, 1));
        const __m256i iv3 = _mm256_set_m128i(_mm256_extracti128_si256(d3, 0), _mm256_extracti128_si256(d2, 1));
        const __m256i iv4 = _mm256_set_m128i(_mm256_extracti128_si256(d4, 0), _mm256_extracti128_si256(d3, 1));
        const __m256i iv5 = _mm256_set_m128i(_mm256_extracti128_si256(d5, 0), _mm256_extracti128_si256(d4, 1));

        fb256 = d5;
        aesdec_16_blocks_256b(d0, d1, d2, d3, d4, d5, d5, d5, roundKeys, num_rounds, 12);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);
        d2 = _mm256_xor_si256(d2, iv2);
        d3 = _mm256_xor_si256(d3, iv3);
        d4 = _mm256_xor_si256(d4, iv4);
        d5 = _mm256_xor_si256(d5, iv5);


        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], d2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], d3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], d4);
        _mm_storeu_si128((__m128i *) &out[5 * 32], _mm256_extracti128_si256(d5, 0));

    } else if (num_blocks == 10) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);
        __m256i d2 = _mm256_loadu_si256((__m256i *) &in[2 * 32]);
        __m256i d3 = _mm256_loadu_si256((__m256i *) &in[3 * 32]);
        __m256i d4 = _mm256_loadu_si256((__m256i *) &in[4 * 32]);


        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));
        const __m256i iv2 = _mm256_set_m128i(_mm256_extracti128_si256(d2, 0), _mm256_extracti128_si256(d1, 1));
        const __m256i iv3 = _mm256_set_m128i(_mm256_extracti128_si256(d3, 0), _mm256_extracti128_si256(d2, 1));
        const __m256i iv4 = _mm256_set_m128i(_mm256_extracti128_si256(d4, 0), _mm256_extracti128_si256(d3, 1));


        fb256 = d4;
        aesdec_16_blocks_256b(d0, d1, d2, d3, d4, d4, d4, d4, roundKeys, num_rounds, 10);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);
        d2 = _mm256_xor_si256(d2, iv2);
        d3 = _mm256_xor_si256(d3, iv3);
        d4 = _mm256_xor_si256(d4, iv4);


        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], d2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], d3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], d4);

    } else if (num_blocks == 9) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);
        __m256i d2 = _mm256_loadu_si256((__m256i *) &in[2 * 32]);
        __m256i d3 = _mm256_loadu_si256((__m256i *) &in[3 * 32]);
        __m256i d4 = _mm256_broadcastsi128_si256(
                _mm_loadu_si128((__m128i *) &in[4 * 32]));//   _mm256_loadu_si256((__m256i *) &in[7 * 32]);

        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));
        const __m256i iv2 = _mm256_set_m128i(_mm256_extracti128_si256(d2, 0), _mm256_extracti128_si256(d1, 1));
        const __m256i iv3 = _mm256_set_m128i(_mm256_extracti128_si256(d3, 0), _mm256_extracti128_si256(d2, 1));
        const __m256i iv4 = _mm256_set_m128i(_mm256_extracti128_si256(d4, 0), _mm256_extracti128_si256(d3, 1));


        fb256 = d4;
        aesdec_16_blocks_256b(d0, d1, d2, d3, d4, d4, d4, d4, roundKeys, num_rounds, 10);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);
        d2 = _mm256_xor_si256(d2, iv2);
        d3 = _mm256_xor_si256(d3, iv3);
        d4 = _mm256_xor_si256(d4, iv4);


        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], d2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], d3);
        _mm_storeu_si128((__m128i *) &out[4 * 32], _mm256_extracti128_si256(d4, 0));

    } else if (num_blocks == 8) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);
        __m256i d2 = _mm256_loadu_si256((__m256i *) &in[2 * 32]);
        __m256i d3 = _mm256_loadu_si256((__m256i *) &in[3 * 32]);


        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));
        const __m256i iv2 = _mm256_set_m128i(_mm256_extracti128_si256(d2, 0), _mm256_extracti128_si256(d1, 1));
        const __m256i iv3 = _mm256_set_m128i(_mm256_extracti128_si256(d3, 0), _mm256_extracti128_si256(d2, 1));


        fb256 = d3;
        aesdec_16_blocks_256b(d0, d1, d2, d3, d3, d3, d3, d3, roundKeys, num_rounds, 8);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);
        d2 = _mm256_xor_si256(d2, iv2);
        d3 = _mm256_xor_si256(d3, iv3);


        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], d2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], d3);

    } else if (num_blocks == 7) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);
        __m256i d2 = _mm256_loadu_si256((__m256i *) &in[2 * 32]);
        __m256i d3 = _mm256_broadcastsi128_si256(
                _mm_loadu_si128((__m128i *) &in[3 * 32]));//   _mm256_loadu_si256((__m256i *) &in[7 * 32]);

        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));
        const __m256i iv2 = _mm256_set_m128i(_mm256_extracti128_si256(d2, 0), _mm256_extracti128_si256(d1, 1));
        const __m256i iv3 = _mm256_set_m128i(_mm256_extracti128_si256(d3, 0), _mm256_extracti128_si256(d2, 1));


        fb256 = d3;
        aesdec_16_blocks_256b(d0, d1, d2, d3, d3, d3, d3, d3, roundKeys, num_rounds, 8);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);
        d2 = _mm256_xor_si256(d2, iv2);
        d3 = _mm256_xor_si256(d3, iv3);


        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], d2);
        _mm_storeu_si128((__m128i *) &out[3 * 32], _mm256_extracti128_si256(d3, 0));

    } else if (num_blocks == 6) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);
        __m256i d2 = _mm256_loadu_si256((__m256i *) &in[2 * 32]);

        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));
        const __m256i iv2 = _mm256_set_m128i(_mm256_extracti128_si256(d2, 0), _mm256_extracti128_si256(d1, 1));


        fb256 = d2;
        aesdec_16_blocks_256b(d0, d1, d2, d2, d2, d2, d2, d2, roundKeys, num_rounds, 6);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);
        d2 = _mm256_xor_si256(d2, iv2);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], d2);

    } else if (num_blocks == 5) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);
        __m256i d2 = _mm256_broadcastsi128_si256(
                _mm_loadu_si128((__m128i *) &in[2 * 32]));//   _mm256_loadu_si256((__m256i *) &in[7 * 32]);

        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));
        const __m256i iv2 = _mm256_set_m128i(_mm256_extracti128_si256(d2, 0), _mm256_extracti128_si256(d1, 1));


        fb256 = d2;
        aesdec_16_blocks_256b(d0, d1, d2, d2, d2, d2, d2, d2, roundKeys, num_rounds, 6);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);
        d2 = _mm256_xor_si256(d2, iv2);


        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);
        _mm_storeu_si128((__m128i *) &out[2 * 32], _mm256_extracti128_si256(d2, 0));

    } else if (num_blocks == 4) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &in[1 * 32]);

        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));

        fb256 = d1;
        aesdec_16_blocks_256b(d0, d1, d1, d1, d1, d1, d1, d1, roundKeys, num_rounds, 4);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], d1);

    } else if (num_blocks == 3) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        __m256i d1 = _mm256_broadcastsi128_si256(
                _mm_loadu_si128((__m128i *) &in[1 * 32]));//   _mm256_loadu_si256((__m256i *) &in[7 * 32]);

        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        const __m256i iv1 = _mm256_set_m128i(_mm256_extracti128_si256(d1, 0), _mm256_extracti128_si256(d0, 1));

        fb256 = _mm256_broadcastsi128_si256(_mm256_extracti128_si256(d1, 0));
        aesdec_16_blocks_256b(d0, d1, d1, d1, d1, d1, d1, d1, roundKeys, num_rounds, 4);

        d0 = _mm256_xor_si256(d0, iv0);
        d1 = _mm256_xor_si256(d1, iv1);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);
        _mm_storeu_si128((__m128i *) &out[1 * 32], _mm256_extracti128_si256(d1, 0));

    } else if (num_blocks == 2) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &in[0 * 32]);
        const __m256i iv0 = _mm256_set_m128i(_mm256_extracti128_si256(d0, 0), _mm256_extracti128_si256(fb256, 1));
        fb256 = d0;
        aesdec_16_blocks_256b(d0, d0, d0, d0, d0, d0, d0, d0, roundKeys, num_rounds, 2);
        d0 = _mm256_xor_si256(d0, iv0);
        _mm256_storeu_si256((__m256i *) &out[0 * 32], d0);

    } else if (num_blocks == 1) {

        __m128i d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
        __m128i iv = _mm256_extracti128_si256(fb256, 1);
        fb256 = _mm256_broadcastsi128_si256(d0);

        aesdec_8_blocks_128b(d0, d0, d0, d0, d0, d0, d0, d0, roundKeys, num_rounds, 1);

        d0 = _mm_xor_si128(d0, iv);
        _mm_storeu_si128((__m128i *) &out[0 * 16], d0);

    }


}


namespace intel {
    namespace cbc {


        //
        // AES CBC 128 Decryption
        //
        AesCBC128VaesDec::AesCBC128VaesDec() : CBC256wide() {

        }

        AesCBC128VaesDec::~AesCBC128VaesDec() = default;

        size_t AesCBC128VaesDec::processBlocks(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;

            __m256i fb256 = _mm256_broadcastsi128_si256(feedback);

            while (blocks >= 16) {
                aes_cbc_dec_blocks_256b(in, out, fb256, roundKeys, 10, 16);
                in += CBC_BLOCK_SIZE_16;
                out += CBC_BLOCK_SIZE_16;
                blocks -= 16;
            }


            aes_cbc_dec_blocks_256b(in, out, fb256, roundKeys, 10, blocks);
            out += (blocks * CBC_BLOCK_SIZE);

            feedback = _mm256_extracti128_si256(fb256, 1);

            return (size_t) (out - outStart);
        }


        //
        // AES CBC 192 Decryption
        //
        AesCBC192VaesDec::AesCBC192VaesDec() : CBC256wide() {

        }

        AesCBC192VaesDec::~AesCBC192VaesDec() = default;


        size_t AesCBC192VaesDec::processBlocks(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;

            __m256i fb256 = _mm256_broadcastsi128_si256(feedback);


            while (blocks >= 16) {
                aes_cbc_dec_blocks_256b(in, out, fb256, roundKeys, 12, 16);
                in += CBC_BLOCK_SIZE_16;
                out += CBC_BLOCK_SIZE_16;
                blocks -= 16;
            }


            aes_cbc_dec_blocks_256b(in, out, fb256, roundKeys, 12, blocks);
            out += (blocks * CBC_BLOCK_SIZE);

            feedback = _mm256_extracti128_si256(fb256, 1);

            return (size_t) (out - outStart);
        }


        //
        // AES CBC 256 Decryption
        //
        AesCBC256VaesDec::AesCBC256VaesDec() : CBC256wide() {

        }

        AesCBC256VaesDec::~AesCBC256VaesDec() = default;


        size_t AesCBC256VaesDec::processBlocks(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;

            __m256i fb256 = _mm256_broadcastsi128_si256(feedback);
            while (blocks >= 16) {
                aes_cbc_dec_blocks_256b(in, out, fb256, roundKeys, 14, 16);
                in += CBC_BLOCK_SIZE_16;
                out += CBC_BLOCK_SIZE_16;
                blocks -= 16;
            }


            aes_cbc_dec_blocks_256b(in, out, fb256, roundKeys, 14, blocks);
            out += (blocks * CBC_BLOCK_SIZE);

            feedback = _mm256_extracti128_si256(fb256, 1);


            return (size_t) (out - outStart);
        }


    }
}


