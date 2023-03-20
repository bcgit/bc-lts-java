#ifndef BCN_AESCOMMON512_H
#define BCN_AESCOMMON512_H

#include <immintrin.h>
#include <cstdint>


static inline void aesenc_16_blocks_256b(
        __m256i &b1, __m256i &b2, __m256i &b3, __m256i &b4,
        __m256i &b5, __m256i &b6, __m256i &b7, __m256i &b8,
        const __m128i *round_keys, const int num_rounds,
        const int num_blocks) {

    const __m256i rk_first = _mm256_broadcastsi128_si256(round_keys[0]);


    b1 = _mm256_xor_si256(b1, rk_first);
    if (num_blocks > 2)
        b2 = _mm256_xor_si256(b2, rk_first);
    if (num_blocks > 4)
        b3 = _mm256_xor_si256(b3, rk_first);
    if (num_blocks > 6)
        b4 = _mm256_xor_si256(b4, rk_first);
    if (num_blocks > 8)
        b5 = _mm256_xor_si256(b5, rk_first);
    if (num_blocks > 10)
        b6 = _mm256_xor_si256(b6, rk_first);
    if (num_blocks > 12)
        b7 = _mm256_xor_si256(b7, rk_first);
    if (num_blocks > 14)
        b8 = _mm256_xor_si256(b8, rk_first);

    int round;
    for (round = 1; round < num_rounds; round++) {
        const __m256i rk = _mm256_broadcastsi128_si256(round_keys[round]);
        b1 = _mm256_aesenc_epi128(b1, rk);
        if (num_blocks > 2)
            b2 = _mm256_aesenc_epi128(b2, rk);
        if (num_blocks > 4)
            b3 = _mm256_aesenc_epi128(b3, rk);
        if (num_blocks > 6)
            b4 = _mm256_aesenc_epi128(b4, rk);
        if (num_blocks > 8)
            b5 = _mm256_aesenc_epi128(b5, rk);
        if (num_blocks > 10)
            b6 = _mm256_aesenc_epi128(b6, rk);
        if (num_blocks > 12)
            b7 = _mm256_aesenc_epi128(b7, rk);
        if (num_blocks > 14)
            b8 = _mm256_aesenc_epi128(b8, rk);

    }


    const __m256i rk_last = _mm256_broadcastsi128_si256(round_keys[round]);

    b1 = _mm256_aesenclast_epi128(b1, rk_last);

    if (num_blocks > 2)
        b2 = _mm256_aesenclast_epi128(b2, rk_last);
    if (num_blocks > 4)
        b3 = _mm256_aesenclast_epi128(b3, rk_last);
    if (num_blocks > 6)
        b4 = _mm256_aesenclast_epi128(b4, rk_last);
    if (num_blocks > 8)
        b5 = _mm256_aesenclast_epi128(b5, rk_last);
    if (num_blocks > 10)
        b6 = _mm256_aesenclast_epi128(b6, rk_last);
    if (num_blocks > 12)
        b7 = _mm256_aesenclast_epi128(b7, rk_last);
    if (num_blocks > 14)
        b8 = _mm256_aesenclast_epi128(b8, rk_last);

}


static inline void aesdec_16_blocks_256b(
        __m256i &b1, __m256i &b2, __m256i &b3, __m256i &b4,
        __m256i &b5, __m256i &b6, __m256i &b7, __m256i &b8,
        const __m128i *round_keys, const int num_rounds,
        const int num_blocks) {

    const __m256i rk_first = _mm256_broadcastsi128_si256(round_keys[0]);

    b1 = _mm256_xor_si256(b1, rk_first);

    if (num_blocks > 2)
        b2 = _mm256_xor_si256(b2, rk_first);
    if (num_blocks > 4)
        b3 = _mm256_xor_si256(b3, rk_first);
    if (num_blocks > 6)
        b4 = _mm256_xor_si256(b4, rk_first);
    if (num_blocks > 8)
        b5 = _mm256_xor_si256(b5, rk_first);
    if (num_blocks > 10)
        b6 = _mm256_xor_si256(b6, rk_first);
    if (num_blocks > 12)
        b7 = _mm256_xor_si256(b7, rk_first);
    if (num_blocks > 14)
        b8 = _mm256_xor_si256(b8, rk_first);

    int round;
    for (round = 1; round < num_rounds; round++) {
        const __m256i rk = _mm256_broadcastsi128_si256(round_keys[round]);
        b1 = _mm256_aesdec_epi128(b1, rk);
        if (num_blocks > 2)
            b2 = _mm256_aesdec_epi128(b2, rk);
        if (num_blocks > 4)
            b3 = _mm256_aesdec_epi128(b3, rk);
        if (num_blocks > 6)
            b4 = _mm256_aesdec_epi128(b4, rk);
        if (num_blocks > 8)
            b5 = _mm256_aesdec_epi128(b5, rk);
        if (num_blocks > 10)
            b6 = _mm256_aesdec_epi128(b6, rk);
        if (num_blocks > 12)
            b7 = _mm256_aesdec_epi128(b7, rk);
        if (num_blocks > 14)
            b8 = _mm256_aesdec_epi128(b8, rk);
    }


    const __m256i rk_last = _mm256_broadcastsi128_si256(round_keys[round]);

    b1 = _mm256_aesdeclast_epi128(b1, rk_last);

    if (num_blocks > 2)
        b2 = _mm256_aesdeclast_epi128(b2, rk_last);
    if (num_blocks > 4)
        b3 = _mm256_aesdeclast_epi128(b3, rk_last);
    if (num_blocks > 6)
        b4 = _mm256_aesdeclast_epi128(b4, rk_last);
    if (num_blocks > 8)
        b5 = _mm256_aesdeclast_epi128(b5, rk_last);
    if (num_blocks > 10)
        b6 = _mm256_aesdeclast_epi128(b6, rk_last);
    if (num_blocks > 12)
        b7 = _mm256_aesdeclast_epi128(b7, rk_last);
    if (num_blocks > 14)
        b8 = _mm256_aesdeclast_epi128(b8, rk_last);

}


#endif // BCN_AESCOMMON512_H
