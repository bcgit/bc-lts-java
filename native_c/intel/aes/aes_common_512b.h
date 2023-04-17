#ifndef BCN_AESCOMMON512_H
#define BCN_AESCOMMON512_H

#include <immintrin.h>
#include <stdint.h>

static inline __m512i mm512_loadu_128b_blocks(const unsigned char *in,
                                              const uint32_t num_blocks) {
    static const __mmask8 mask_table[5] = {
            0x00, 0x03, 0x0f, 0x3f, 0xff
    };

    return _mm512_maskz_loadu_epi64(mask_table[num_blocks],
                                    (const __m512i *) in);
}

static inline void mm512_storeu_128b_blocks(unsigned char *out, __m512i *b,
                                            const uint32_t num_blocks) {
    static const __mmask8 mask_table[5] = {
            0x00, 0x03, 0x0f, 0x3f, 0xff
    };

    return _mm512_mask_storeu_epi64((__m512i *) out, mask_table[num_blocks], *b);
}

static inline void aesenc_16_blocks_512b(__m512i *b1, __m512i *b2, __m512i *b3, __m512i *b4,
                                         const __m128i *round_keys, const int num_rounds,
                                         const int num_blocks) {

        const __m512i rk_ark = _mm512_broadcast_i32x4(round_keys[0]);

        *b1 = _mm512_xor_si512(*b1, rk_ark);
        if (num_blocks > 4)
            *b2 = _mm512_xor_si512(*b2, rk_ark);
        if (num_blocks > 8)
            *b3 = _mm512_xor_si512(*b3, rk_ark);
        if (num_blocks > 12)
            *b4 = _mm512_xor_si512(*b4, rk_ark);

        int round;
        for (round = 1; round < num_rounds; round++) {
            const __m512i rk = _mm512_broadcast_i32x4(round_keys[round]);

            *b1 = _mm512_aesenc_epi128(*b1, rk);
            if (num_blocks > 4)
                *b2 = _mm512_aesenc_epi128(*b2, rk);
            if (num_blocks > 8)
                *b3 = _mm512_aesenc_epi128(*b3, rk);
            if (num_blocks > 12)
                *b4 = _mm512_aesenc_epi128(*b4, rk);
        }

        const __m512i rk_last = _mm512_broadcast_i32x4(round_keys[round]);

        *b1 = _mm512_aesenclast_epi128(*b1, rk_last);
        if (num_blocks > 4)
            *b2 = _mm512_aesenclast_epi128(*b2, rk_last);
        if (num_blocks > 8)
            *b3 = _mm512_aesenclast_epi128(*b3, rk_last);
        if (num_blocks > 12)
            *b4 = _mm512_aesenclast_epi128(*b4, rk_last);
}

static inline void aesdec_16_blocks_512b(__m512i *b1, __m512i *b2, __m512i *b3, __m512i *b4,
                                         const __m128i *round_keys, const int num_rounds,
                                         const int num_blocks) {

        const __m512i rk_ark = _mm512_broadcast_i32x4(round_keys[0]);

        *b1 = _mm512_xor_si512(*b1, rk_ark);
        if (num_blocks > 4)
            *b2 = _mm512_xor_si512(*b2, rk_ark);
        if (num_blocks > 8)
            *b3 = _mm512_xor_si512(*b3, rk_ark);
        if (num_blocks > 12)
            *b4 = _mm512_xor_si512(*b4, rk_ark);

        int round;
        for (round = 1; round < num_rounds; round++) {
            const __m512i rk = _mm512_broadcast_i32x4(round_keys[round]);

            *b1 = _mm512_aesdec_epi128(*b1, rk);
            if (num_blocks > 4)
                *b2 = _mm512_aesdec_epi128(*b2, rk);
            if (num_blocks > 8)
                *b3 = _mm512_aesdec_epi128(*b3, rk);
            if (num_blocks > 12)
                *b4 = _mm512_aesdec_epi128(*b4, rk);
        }

        const __m512i rk_last = _mm512_broadcast_i32x4(round_keys[round]);

        *b1 = _mm512_aesdeclast_epi128(*b1, rk_last);
        if (num_blocks > 4)
            *b2 = _mm512_aesdeclast_epi128(*b2, rk_last);
        if (num_blocks > 8)
            *b3 = _mm512_aesdeclast_epi128(*b3, rk_last);
        if (num_blocks > 12)
            *b4 = _mm512_aesdeclast_epi128(*b4, rk_last);
}



#endif // BCN_AESCOMMON512_H
