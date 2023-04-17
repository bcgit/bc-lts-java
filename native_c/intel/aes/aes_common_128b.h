#ifndef BCN_AESCOMMON128_H
#define BCN_AESCOMMON128_H

#include <immintrin.h>


static inline void aesenc_8_blocks_128b(__m128i *b1, __m128i *b2, __m128i *b3, __m128i *b4,
                                        __m128i *b5, __m128i *b6, __m128i *b7, __m128i *b8,
                                        const __m128i *round_keys, const int num_rounds,
                                        const int num_blocks) {

    const __m128i rk_ark = round_keys[0];

    *b1 = _mm_xor_si128(*b1, rk_ark);
    if (num_blocks > 1)
        *b2 = _mm_xor_si128(*b2, rk_ark);
    if (num_blocks > 2)
        *b3 = _mm_xor_si128(*b3, rk_ark);
    if (num_blocks > 3)
        *b4 = _mm_xor_si128(*b4, rk_ark);
    if (num_blocks > 4)
        *b5 = _mm_xor_si128(*b5, rk_ark);
    if (num_blocks > 5)
        *b6 = _mm_xor_si128(*b6, rk_ark);
    if (num_blocks > 6)
        *b7 = _mm_xor_si128(*b7, rk_ark);
    if (num_blocks > 7)
        *b8 = _mm_xor_si128(*b8, rk_ark);

    int round;
    for (round = 1; round < num_rounds; round++) {
        const __m128i rk = round_keys[round];

        *b1 = _mm_aesenc_si128(*b1, rk);
        if (num_blocks > 1)
            *b2 = _mm_aesenc_si128(*b2, rk);
        if (num_blocks > 2)
            *b3 = _mm_aesenc_si128(*b3, rk);
        if (num_blocks > 3)
            *b4 = _mm_aesenc_si128(*b4, rk);
        if (num_blocks > 4)
            *b5 = _mm_aesenc_si128(*b5, rk);
        if (num_blocks > 5)
            *b6 = _mm_aesenc_si128(*b6, rk);
        if (num_blocks > 6)
            *b7 = _mm_aesenc_si128(*b7, rk);
        if (num_blocks > 7)
            *b8 = _mm_aesenc_si128(*b8, rk);
    }

    const __m128i rk_last = round_keys[round];

    *b1 = _mm_aesenclast_si128(*b1, rk_last);
    if (num_blocks > 1)
        *b2 = _mm_aesenclast_si128(*b2, rk_last);
    if (num_blocks > 2)
        *b3 = _mm_aesenclast_si128(*b3, rk_last);
    if (num_blocks > 3)
        *b4 = _mm_aesenclast_si128(*b4, rk_last);
    if (num_blocks > 4)
        *b5 = _mm_aesenclast_si128(*b5, rk_last);
    if (num_blocks > 5)
        *b6 = _mm_aesenclast_si128(*b6, rk_last);
    if (num_blocks > 6)
        *b7 = _mm_aesenclast_si128(*b7, rk_last);
    if (num_blocks > 7)
        *b8 = _mm_aesenclast_si128(*b8, rk_last);
}

static inline void aesdec_8_blocks_128b(__m128i *b1, __m128i *b2, __m128i *b3, __m128i *b4,
                                        __m128i *b5, __m128i *b6, __m128i *b7, __m128i *b8,
                                        const __m128i *round_keys, const int num_rounds,
                                        const int num_blocks) {

    const __m128i rk_ark = round_keys[0];

    *b1 = _mm_xor_si128(*b1, rk_ark);
    if (num_blocks > 1)
        *b2 = _mm_xor_si128(*b2, rk_ark);
    if (num_blocks > 2)
        *b3 = _mm_xor_si128(*b3, rk_ark);
    if (num_blocks > 3)
        *b4 = _mm_xor_si128(*b4, rk_ark);
    if (num_blocks > 4)
        *b5 = _mm_xor_si128(*b5, rk_ark);
    if (num_blocks > 5)
        *b6 = _mm_xor_si128(*b6, rk_ark);
    if (num_blocks > 6)
        *b7 = _mm_xor_si128(*b7, rk_ark);
    if (num_blocks > 7)
        *b8 = _mm_xor_si128(*b8, rk_ark);

    int round;
    for (round = 1; round < num_rounds; round++) {
        const __m128i rk = round_keys[round];

        *b1 = _mm_aesdec_si128(*b1, rk);
        if (num_blocks > 1)
            *b2 = _mm_aesdec_si128(*b2, rk);
        if (num_blocks > 2)
            *b3 = _mm_aesdec_si128(*b3, rk);
        if (num_blocks > 3)
            *b4 = _mm_aesdec_si128(*b4, rk);
        if (num_blocks > 4)
            *b5 = _mm_aesdec_si128(*b5, rk);
        if (num_blocks > 5)
            *b6 = _mm_aesdec_si128(*b6, rk);
        if (num_blocks > 6)
            *b7 = _mm_aesdec_si128(*b7, rk);
        if (num_blocks > 7)
            *b8 = _mm_aesdec_si128(*b8, rk);
    }

    const __m128i rk_last = round_keys[round];

    *b1 = _mm_aesdeclast_si128(*b1, rk_last);
    if (num_blocks > 1)
        *b2 = _mm_aesdeclast_si128(*b2, rk_last);
    if (num_blocks > 2)
        *b3 = _mm_aesdeclast_si128(*b3, rk_last);
    if (num_blocks > 3)
        *b4 = _mm_aesdeclast_si128(*b4, rk_last);
    if (num_blocks > 4)
        *b5 = _mm_aesdeclast_si128(*b5, rk_last);
    if (num_blocks > 5)
        *b6 = _mm_aesdeclast_si128(*b6, rk_last);
    if (num_blocks > 6)
        *b7 = _mm_aesdeclast_si128(*b7, rk_last);
    if (num_blocks > 7)
        *b8 = _mm_aesdeclast_si128(*b8, rk_last);
}


#endif // BCN_AESCOMMON128_H
