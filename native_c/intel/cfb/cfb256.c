//

//

#include <stddef.h>
#include "cfb.h"


/**
 *
 * @param d0 in / out
 * @param d1 in / out
 * @param d2 in / out
 * @param d3 in / out
 * @param d4 in / out
 * @param d5 in / out
 * @param d6 in / out
 * @param d7 in / out
 * @param feedback the chainblock
 * @param roundKeys
 * @param blocks blocks must be even number 16 to 2, 1 does odd block processing, any other value does nothing.
 * @param max_rounds The maximum number of rounds.
 *
 * Odd block assumes that cipher text has been broadcast into both lanes of d0.
 *
 */
static inline void aes256w_cfb_decrypt(
        __m256i *d0, __m256i *d1, __m256i *d2, __m256i *d3,
        __m256i *d4, __m256i *d5, __m256i *d6, __m256i *d7,
        __m128i *feedback, __m128i *roundKeys, const uint32_t blocks,
        const uint32_t max_rounds) {

    __m256i tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7;

    if (blocks == 16) {

        tmp0 = _mm256_set_m128i(_mm256_extracti128_si256(*d0, 0), *feedback);
        tmp1 = _mm256_set_m128i(_mm256_extracti128_si256(*d1, 0), _mm256_extracti128_si256(*d0, 1));
        tmp2 = _mm256_set_m128i(_mm256_extracti128_si256(*d2, 0), _mm256_extracti128_si256(*d1, 1));
        tmp3 = _mm256_set_m128i(_mm256_extracti128_si256(*d3, 0), _mm256_extracti128_si256(*d2, 1));
        tmp4 = _mm256_set_m128i(_mm256_extracti128_si256(*d4, 0), _mm256_extracti128_si256(*d3, 1));
        tmp5 = _mm256_set_m128i(_mm256_extracti128_si256(*d5, 0), _mm256_extracti128_si256(*d4, 1));
        tmp6 = _mm256_set_m128i(_mm256_extracti128_si256(*d6, 0), _mm256_extracti128_si256(*d5, 1));
        tmp7 = _mm256_set_m128i(_mm256_extracti128_si256(*d7, 0), _mm256_extracti128_si256(*d6, 1));
        *feedback = _mm256_extracti128_si256(*d7, 1);

        tmp0 = _mm256_xor_si256(tmp0, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp1 = _mm256_xor_si256(tmp1, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp2 = _mm256_xor_si256(tmp2, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp3 = _mm256_xor_si256(tmp3, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp4 = _mm256_xor_si256(tmp4, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp5 = _mm256_xor_si256(tmp5, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp6 = _mm256_xor_si256(tmp6, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp7 = _mm256_xor_si256(tmp7, _mm256_broadcastsi128_si256(roundKeys[0]));


        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm256_aesenc_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp1 = _mm256_aesenc_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp2 = _mm256_aesenc_epi128(tmp2, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp3 = _mm256_aesenc_epi128(tmp3, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp4 = _mm256_aesenc_epi128(tmp4, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp5 = _mm256_aesenc_epi128(tmp5, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp6 = _mm256_aesenc_epi128(tmp6, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp7 = _mm256_aesenc_epi128(tmp7, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        }

        tmp0 = _mm256_aesenclast_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp1 = _mm256_aesenclast_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp2 = _mm256_aesenclast_epi128(tmp2, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp3 = _mm256_aesenclast_epi128(tmp3, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp4 = _mm256_aesenclast_epi128(tmp4, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp5 = _mm256_aesenclast_epi128(tmp5, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp6 = _mm256_aesenclast_epi128(tmp6, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp7 = _mm256_aesenclast_epi128(tmp7, _mm256_broadcastsi128_si256(roundKeys[rounds]));

        *d0 = _mm256_xor_si256(*d0, tmp0);
        *d1 = _mm256_xor_si256(*d1, tmp1);
        *d2 = _mm256_xor_si256(*d2, tmp2);
        *d3 = _mm256_xor_si256(*d3, tmp3);
        *d4 = _mm256_xor_si256(*d4, tmp4);
        *d5 = _mm256_xor_si256(*d5, tmp5);
        *d6 = _mm256_xor_si256(*d6, tmp6);
        *d7 = _mm256_xor_si256(*d7, tmp7);
    } else if (blocks == 14) {
        tmp0 = _mm256_set_m128i(_mm256_extracti128_si256(*d0, 0), *feedback);
        tmp1 = _mm256_set_m128i(_mm256_extracti128_si256(*d1, 0), _mm256_extracti128_si256(*d0, 1));
        tmp2 = _mm256_set_m128i(_mm256_extracti128_si256(*d2, 0), _mm256_extracti128_si256(*d1, 1));
        tmp3 = _mm256_set_m128i(_mm256_extracti128_si256(*d3, 0), _mm256_extracti128_si256(*d2, 1));
        tmp4 = _mm256_set_m128i(_mm256_extracti128_si256(*d4, 0), _mm256_extracti128_si256(*d3, 1));
        tmp5 = _mm256_set_m128i(_mm256_extracti128_si256(*d5, 0), _mm256_extracti128_si256(*d4, 1));
        tmp6 = _mm256_set_m128i(_mm256_extracti128_si256(*d6, 0), _mm256_extracti128_si256(*d5, 1));
        *feedback = _mm256_extracti128_si256(*d6, 1);

        tmp0 = _mm256_xor_si256(tmp0, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp1 = _mm256_xor_si256(tmp1, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp2 = _mm256_xor_si256(tmp2, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp3 = _mm256_xor_si256(tmp3, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp4 = _mm256_xor_si256(tmp4, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp5 = _mm256_xor_si256(tmp5, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp6 = _mm256_xor_si256(tmp6, _mm256_broadcastsi128_si256(roundKeys[0]));


        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm256_aesenc_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp1 = _mm256_aesenc_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp2 = _mm256_aesenc_epi128(tmp2, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp3 = _mm256_aesenc_epi128(tmp3, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp4 = _mm256_aesenc_epi128(tmp4, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp5 = _mm256_aesenc_epi128(tmp5, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp6 = _mm256_aesenc_epi128(tmp6, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        }

        tmp0 = _mm256_aesenclast_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp1 = _mm256_aesenclast_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp2 = _mm256_aesenclast_epi128(tmp2, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp3 = _mm256_aesenclast_epi128(tmp3, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp4 = _mm256_aesenclast_epi128(tmp4, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp5 = _mm256_aesenclast_epi128(tmp5, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp6 = _mm256_aesenclast_epi128(tmp6, _mm256_broadcastsi128_si256(roundKeys[rounds]));

        *d0 = _mm256_xor_si256(*d0, tmp0);
        *d1 = _mm256_xor_si256(*d1, tmp1);
        *d2 = _mm256_xor_si256(*d2, tmp2);
        *d3 = _mm256_xor_si256(*d3, tmp3);
        *d4 = _mm256_xor_si256(*d4, tmp4);
        *d5 = _mm256_xor_si256(*d5, tmp5);
        *d6 = _mm256_xor_si256(*d6, tmp6);

    } else if (blocks == 12) {
        tmp0 = _mm256_set_m128i(_mm256_extracti128_si256(*d0, 0), *feedback);
        tmp1 = _mm256_set_m128i(_mm256_extracti128_si256(*d1, 0), _mm256_extracti128_si256(*d0, 1));
        tmp2 = _mm256_set_m128i(_mm256_extracti128_si256(*d2, 0), _mm256_extracti128_si256(*d1, 1));
        tmp3 = _mm256_set_m128i(_mm256_extracti128_si256(*d3, 0), _mm256_extracti128_si256(*d2, 1));
        tmp4 = _mm256_set_m128i(_mm256_extracti128_si256(*d4, 0), _mm256_extracti128_si256(*d3, 1));
        tmp5 = _mm256_set_m128i(_mm256_extracti128_si256(*d5, 0), _mm256_extracti128_si256(*d4, 1));
        *feedback = _mm256_extracti128_si256(*d5, 1);

        tmp0 = _mm256_xor_si256(tmp0, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp1 = _mm256_xor_si256(tmp1, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp2 = _mm256_xor_si256(tmp2, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp3 = _mm256_xor_si256(tmp3, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp4 = _mm256_xor_si256(tmp4, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp5 = _mm256_xor_si256(tmp5, _mm256_broadcastsi128_si256(roundKeys[0]));


        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm256_aesenc_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp1 = _mm256_aesenc_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp2 = _mm256_aesenc_epi128(tmp2, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp3 = _mm256_aesenc_epi128(tmp3, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp4 = _mm256_aesenc_epi128(tmp4, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp5 = _mm256_aesenc_epi128(tmp5, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        }

        tmp0 = _mm256_aesenclast_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp1 = _mm256_aesenclast_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp2 = _mm256_aesenclast_epi128(tmp2, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp3 = _mm256_aesenclast_epi128(tmp3, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp4 = _mm256_aesenclast_epi128(tmp4, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp5 = _mm256_aesenclast_epi128(tmp5, _mm256_broadcastsi128_si256(roundKeys[rounds]));


        *d0 = _mm256_xor_si256(*d0, tmp0);
        *d1 = _mm256_xor_si256(*d1, tmp1);
        *d2 = _mm256_xor_si256(*d2, tmp2);
        *d3 = _mm256_xor_si256(*d3, tmp3);
        *d4 = _mm256_xor_si256(*d4, tmp4);
        *d5 = _mm256_xor_si256(*d5, tmp5);


    } else if (blocks == 10) {
        tmp0 = _mm256_set_m128i(_mm256_extracti128_si256(*d0, 0), *feedback);
        tmp1 = _mm256_set_m128i(_mm256_extracti128_si256(*d1, 0), _mm256_extracti128_si256(*d0, 1));
        tmp2 = _mm256_set_m128i(_mm256_extracti128_si256(*d2, 0), _mm256_extracti128_si256(*d1, 1));
        tmp3 = _mm256_set_m128i(_mm256_extracti128_si256(*d3, 0), _mm256_extracti128_si256(*d2, 1));
        tmp4 = _mm256_set_m128i(_mm256_extracti128_si256(*d4, 0), _mm256_extracti128_si256(*d3, 1));
        *feedback = _mm256_extracti128_si256(*d4, 1);


        tmp0 = _mm256_xor_si256(tmp0, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp1 = _mm256_xor_si256(tmp1, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp2 = _mm256_xor_si256(tmp2, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp3 = _mm256_xor_si256(tmp3, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp4 = _mm256_xor_si256(tmp4, _mm256_broadcastsi128_si256(roundKeys[0]));


        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm256_aesenc_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp1 = _mm256_aesenc_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp2 = _mm256_aesenc_epi128(tmp2, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp3 = _mm256_aesenc_epi128(tmp3, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp4 = _mm256_aesenc_epi128(tmp4, _mm256_broadcastsi128_si256(roundKeys[rounds]));

        }

        tmp0 = _mm256_aesenclast_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp1 = _mm256_aesenclast_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp2 = _mm256_aesenclast_epi128(tmp2, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp3 = _mm256_aesenclast_epi128(tmp3, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp4 = _mm256_aesenclast_epi128(tmp4, _mm256_broadcastsi128_si256(roundKeys[rounds]));

        *d0 = _mm256_xor_si256(*d0, tmp0);
        *d1 = _mm256_xor_si256(*d1, tmp1);
        *d2 = _mm256_xor_si256(*d2, tmp2);
        *d3 = _mm256_xor_si256(*d3, tmp3);
        *d4 = _mm256_xor_si256(*d4, tmp4);

    } else if (blocks == 8) {
        tmp0 = _mm256_set_m128i(_mm256_extracti128_si256(*d0, 0), *feedback);
        tmp1 = _mm256_set_m128i(_mm256_extracti128_si256(*d1, 0), _mm256_extracti128_si256(*d0, 1));
        tmp2 = _mm256_set_m128i(_mm256_extracti128_si256(*d2, 0), _mm256_extracti128_si256(*d1, 1));
        tmp3 = _mm256_set_m128i(_mm256_extracti128_si256(*d3, 0), _mm256_extracti128_si256(*d2, 1));
        *feedback = _mm256_extracti128_si256(*d3, 1);

        tmp0 = _mm256_xor_si256(tmp0, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp1 = _mm256_xor_si256(tmp1, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp2 = _mm256_xor_si256(tmp2, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp3 = _mm256_xor_si256(tmp3, _mm256_broadcastsi128_si256(roundKeys[0]));

        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm256_aesenc_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp1 = _mm256_aesenc_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp2 = _mm256_aesenc_epi128(tmp2, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp3 = _mm256_aesenc_epi128(tmp3, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        }

        tmp0 = _mm256_aesenclast_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp1 = _mm256_aesenclast_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp2 = _mm256_aesenclast_epi128(tmp2, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp3 = _mm256_aesenclast_epi128(tmp3, _mm256_broadcastsi128_si256(roundKeys[rounds]));

        *d0 = _mm256_xor_si256(*d0, tmp0);
        *d1 = _mm256_xor_si256(*d1, tmp1);
        *d2 = _mm256_xor_si256(*d2, tmp2);
        *d3 = _mm256_xor_si256(*d3, tmp3);

    } else if (blocks == 6) {
        tmp0 = _mm256_set_m128i(_mm256_extracti128_si256(*d0, 0), *feedback);
        tmp1 = _mm256_set_m128i(_mm256_extracti128_si256(*d1, 0), _mm256_extracti128_si256(*d0, 1));
        tmp2 = _mm256_set_m128i(_mm256_extracti128_si256(*d2, 0), _mm256_extracti128_si256(*d1, 1));
        *feedback = _mm256_extracti128_si256(*d2, 1);

        tmp0 = _mm256_xor_si256(tmp0, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp1 = _mm256_xor_si256(tmp1, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp2 = _mm256_xor_si256(tmp2, _mm256_broadcastsi128_si256(roundKeys[0]));


        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm256_aesenc_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp1 = _mm256_aesenc_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp2 = _mm256_aesenc_epi128(tmp2, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        }

        tmp0 = _mm256_aesenclast_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp1 = _mm256_aesenclast_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp2 = _mm256_aesenclast_epi128(tmp2, _mm256_broadcastsi128_si256(roundKeys[rounds]));

        *d0 = _mm256_xor_si256(*d0, tmp0);
        *d1 = _mm256_xor_si256(*d1, tmp1);
        *d2 = _mm256_xor_si256(*d2, tmp2);

    } else if (blocks == 4) {
        tmp0 = _mm256_set_m128i(_mm256_extracti128_si256(*d0, 0), *feedback);
        tmp1 = _mm256_set_m128i(_mm256_extracti128_si256(*d1, 0), _mm256_extracti128_si256(*d0, 1));
        *feedback = _mm256_extracti128_si256(*d1, 1);

        tmp0 = _mm256_xor_si256(tmp0, _mm256_broadcastsi128_si256(roundKeys[0]));
        tmp1 = _mm256_xor_si256(tmp1, _mm256_broadcastsi128_si256(roundKeys[0]));

        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm256_aesenc_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
            tmp1 = _mm256_aesenc_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        }

        tmp0 = _mm256_aesenclast_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        tmp1 = _mm256_aesenclast_epi128(tmp1, _mm256_broadcastsi128_si256(roundKeys[rounds]));

        *d0 = _mm256_xor_si256(*d0, tmp0);
        *d1 = _mm256_xor_si256(*d1, tmp1);

    } else if (blocks == 2) {
        tmp0 = _mm256_set_m128i(_mm256_extracti128_si256(*d0, 0), *feedback);
        *feedback = _mm256_extracti128_si256(*d0, 1);

        tmp0 = _mm256_xor_si256(tmp0, _mm256_broadcastsi128_si256(roundKeys[0]));


        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm256_aesenc_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        }

        tmp0 = _mm256_aesenclast_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));

        *d0 = _mm256_xor_si256(*d0, tmp0);


    } else {
// The odd block assumes block as been broadcast into both lanes.
// Feedback is broadcast into both lanes.
// Result can be extracted by doing cast down to __m128i

        tmp0 = _mm256_broadcastsi128_si256(*feedback);
        *feedback = _mm256_castsi256_si128(*d0);
        tmp0 = _mm256_xor_si256(tmp0, _mm256_broadcastsi128_si256(roundKeys[0]));

        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm256_aesenc_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        }

        tmp0 = _mm256_aesenclast_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
        *d0 = _mm256_xor_si256(*d0, tmp0);
    }
}


size_t cfb_decrypt(cfb_ctx *cfb, unsigned char *src, size_t len, unsigned char *dest) {
    unsigned char *destStart = dest;

    //
    // Round out buffer.
    //
    while (cfb->buf_index > 0 && len > 0) {
        *dest = cfb_decrypt_byte(cfb, *src);
        len--;
        dest++;
        src++;
    }

    while (len >= 16 * CFB_BLOCK_SIZE) {
        __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
        __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);
        __m256i d2 = _mm256_loadu_si256((__m256i *) &src[2 * 32]);
        __m256i d3 = _mm256_loadu_si256((__m256i *) &src[3 * 32]);
        __m256i d4 = _mm256_loadu_si256((__m256i *) &src[4 * 32]);
        __m256i d5 = _mm256_loadu_si256((__m256i *) &src[5 * 32]);
        __m256i d6 = _mm256_loadu_si256((__m256i *) &src[6 * 32]);
        __m256i d7 = _mm256_loadu_si256((__m256i *) &src[7 * 32]);

        aes256w_cfb_decrypt(&d0, &d1, &d2, &d3, &d4, &d5, &d6, &d7, &cfb->feedback, cfb->roundKeys, 16,
                            cfb->num_rounds);

        _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
        _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);
        _mm256_storeu_si256((__m256i *) &dest[2 * 32], d2);
        _mm256_storeu_si256((__m256i *) &dest[3 * 32], d3);
        _mm256_storeu_si256((__m256i *) &dest[4 * 32], d4);
        _mm256_storeu_si256((__m256i *) &dest[5 * 32], d5);
        _mm256_storeu_si256((__m256i *) &dest[6 * 32], d6);
        _mm256_storeu_si256((__m256i *) &dest[7 * 32], d7);

        len -= 16 * CFB_BLOCK_SIZE;
        src += 16 * CFB_BLOCK_SIZE;
        dest += 16 * CFB_BLOCK_SIZE;

    }


    while (len >= CFB_BLOCK_SIZE) {
       if (len >= 14 * CFB_BLOCK_SIZE) {
            __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
            __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);
            __m256i d2 = _mm256_loadu_si256((__m256i *) &src[2 * 32]);
            __m256i d3 = _mm256_loadu_si256((__m256i *) &src[3 * 32]);
            __m256i d4 = _mm256_loadu_si256((__m256i *) &src[4 * 32]);
            __m256i d5 = _mm256_loadu_si256((__m256i *) &src[5 * 32]);
            __m256i d6 = _mm256_loadu_si256((__m256i *) &src[6 * 32]);


            aes256w_cfb_decrypt(&d0, &d1, &d2, &d3, &d4, &d5, &d6, &d6, &cfb->feedback, cfb->roundKeys, 14,
                                cfb->num_rounds);

            _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
            _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);
            _mm256_storeu_si256((__m256i *) &dest[2 * 32], d2);
            _mm256_storeu_si256((__m256i *) &dest[3 * 32], d3);
            _mm256_storeu_si256((__m256i *) &dest[4 * 32], d4);
            _mm256_storeu_si256((__m256i *) &dest[5 * 32], d5);
            _mm256_storeu_si256((__m256i *) &dest[6 * 32], d6);

            len -= 14 * CFB_BLOCK_SIZE;
            src += 14 * CFB_BLOCK_SIZE;
            dest += 14 * CFB_BLOCK_SIZE;

        } else if (len >= 12 * CFB_BLOCK_SIZE) {
            __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
            __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);
            __m256i d2 = _mm256_loadu_si256((__m256i *) &src[2 * 32]);
            __m256i d3 = _mm256_loadu_si256((__m256i *) &src[3 * 32]);
            __m256i d4 = _mm256_loadu_si256((__m256i *) &src[4 * 32]);
            __m256i d5 = _mm256_loadu_si256((__m256i *) &src[5 * 32]);

            aes256w_cfb_decrypt(&d0, &d1, &d2, &d3, &d4, &d5, &d5, &d5, &cfb->feedback, cfb->roundKeys, 12,
                                cfb->num_rounds);

            _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
            _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);
            _mm256_storeu_si256((__m256i *) &dest[2 * 32], d2);
            _mm256_storeu_si256((__m256i *) &dest[3 * 32], d3);
            _mm256_storeu_si256((__m256i *) &dest[4 * 32], d4);
            _mm256_storeu_si256((__m256i *) &dest[5 * 32], d5);

            len -= 12 * CFB_BLOCK_SIZE;
            src += 12 * CFB_BLOCK_SIZE;
            dest += 12 * CFB_BLOCK_SIZE;

        } else if (len >= 10 * CFB_BLOCK_SIZE) {
            __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
            __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);
            __m256i d2 = _mm256_loadu_si256((__m256i *) &src[2 * 32]);
            __m256i d3 = _mm256_loadu_si256((__m256i *) &src[3 * 32]);
            __m256i d4 = _mm256_loadu_si256((__m256i *) &src[4 * 32]);

            aes256w_cfb_decrypt(&d0, &d1, &d2, &d3, &d4, &d4, &d4, &d4, &cfb->feedback, cfb->roundKeys, 10,
                                cfb->num_rounds);

            _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
            _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);
            _mm256_storeu_si256((__m256i *) &dest[2 * 32], d2);
            _mm256_storeu_si256((__m256i *) &dest[3 * 32], d3);
            _mm256_storeu_si256((__m256i *) &dest[4 * 32], d4);

            len -= 10 * CFB_BLOCK_SIZE;
            src += 10 * CFB_BLOCK_SIZE;
            dest += 10 * CFB_BLOCK_SIZE;

        } else if (len >= 8 * CFB_BLOCK_SIZE) {
            __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
            __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);
            __m256i d2 = _mm256_loadu_si256((__m256i *) &src[2 * 32]);
            __m256i d3 = _mm256_loadu_si256((__m256i *) &src[3 * 32]);


            aes256w_cfb_decrypt(&d0, &d1, &d2, &d3, &d3, &d3, &d3, &d3, &cfb->feedback, cfb->roundKeys, 8,
                                cfb->num_rounds);

            _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
            _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);
            _mm256_storeu_si256((__m256i *) &dest[2 * 32], d2);
            _mm256_storeu_si256((__m256i *) &dest[3 * 32], d3);


            len -= 8 * CFB_BLOCK_SIZE;
            src += 8 * CFB_BLOCK_SIZE;
            dest += 8 * CFB_BLOCK_SIZE;

        } else if (len >= 6 * CFB_BLOCK_SIZE) {
            __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
            __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);
            __m256i d2 = _mm256_loadu_si256((__m256i *) &src[2 * 32]);

            aes256w_cfb_decrypt(&d0, &d1, &d2, &d2, &d2, &d2, &d2, &d2, &cfb->feedback, cfb->roundKeys, 6,
                                cfb->num_rounds);

            _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
            _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);
            _mm256_storeu_si256((__m256i *) &dest[2 * 32], d2);

            len -= 6 * CFB_BLOCK_SIZE;
            src += 6 * CFB_BLOCK_SIZE;
            dest += 6 * CFB_BLOCK_SIZE;
        } else if (len >= 4 * CFB_BLOCK_SIZE) {
            __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);
            __m256i d1 = _mm256_loadu_si256((__m256i *) &src[1 * 32]);

            aes256w_cfb_decrypt(&d0, &d1, &d1, &d1, &d1, &d1, &d1, &d1, &cfb->feedback, cfb->roundKeys, 4,
                                cfb->num_rounds);

            _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);
            _mm256_storeu_si256((__m256i *) &dest[1 * 32], d1);

            len -= 4 * CFB_BLOCK_SIZE;
            src += 4 * CFB_BLOCK_SIZE;
            dest += 4 * CFB_BLOCK_SIZE;
        } else if (len >= 2 * CFB_BLOCK_SIZE) {
            __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);


            aes256w_cfb_decrypt(&d0, &d0, &d0, &d0, &d0, &d0, &d0, &d0, &cfb->feedback, cfb->roundKeys, 2,
                                cfb->num_rounds);

            _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);


            len -= 2 * CFB_BLOCK_SIZE;
            src += 2 * CFB_BLOCK_SIZE;
            dest += 2 * CFB_BLOCK_SIZE;

        } else {
            //
            // If we get here we have an odd block
            // The odd block is broadcast into both lanes of d0
            //
            __m256i d0 = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i *) &src[0 * 16]));
            aes256w_cfb_decrypt(&d0, &d0, &d0, &d0, &d0, &d0, &d0, &d0, &cfb->feedback, cfb->roundKeys, 1,
                                cfb->num_rounds);
            _mm_storeu_si128(((__m128i *) &dest[0 * 16]), _mm256_castsi256_si128(d0));

            len -= CFB_BLOCK_SIZE;
            src += CFB_BLOCK_SIZE;
            dest += CFB_BLOCK_SIZE;
        }
    }



    //
    // load any trailing bytes into the buffer, the expectation is that
    // whatever is passed in has to be decrypted, ideally callers will
    // try and stick to the AES block size for as long as possible.
    //
    while (len > 0) {
        *dest = cfb_decrypt_byte(cfb, *src);
        len--;
        dest++;
        src++;
    }

    return (size_t) (dest - destStart);
}

unsigned char cfb_decrypt_byte(cfb_ctx *cfbCtx, unsigned char b) {
    if (cfbCtx->buf_index == 0) {

        // We need to generate a new encrypted feedback block to xor into the data.,

        cfbCtx->mask = _mm_xor_si128(cfbCtx->feedback, cfbCtx->roundKeys[0]);
        int j;
        for (j = 1; j < cfbCtx->num_rounds; j++) {
            cfbCtx->mask = _mm_aesenc_si128(cfbCtx->mask, cfbCtx->roundKeys[j]);
        }
        cfbCtx->mask = _mm_aesenclast_si128(cfbCtx->mask, cfbCtx->roundKeys[j]);

    }

    //
    // incrementally mask becomes the last block of cipher text
    //

    unsigned char pt = ((unsigned char *) &cfbCtx->mask)[cfbCtx->buf_index] ^ b;
    ((unsigned char *) &cfbCtx->mask)[cfbCtx->buf_index++] = b; // Mask fills with last cipher text directly.

    if (cfbCtx->buf_index == CFB_BLOCK_SIZE) {
        cfbCtx->buf_index = 0;
        cfbCtx->feedback = cfbCtx->mask;
    }

    return pt;
}