
#include "immintrin.h"
#include "cfb_pc.h"


static inline void aes256_trailing(__m256i *d0, __m128i *feedback, __m128i *roundKeys, const uint32_t blocks,
                                   const int max_rounds) {
    __m256i tmp0;
    tmp0 = _mm256_set_m128i(_mm256_extracti128_si256(*d0, 0), *feedback);
    *feedback = _mm256_extracti128_si256(*d0, 1);

    tmp0 = _mm256_xor_si256(tmp0, _mm256_broadcastsi128_si256(roundKeys[0]));


    int rounds;
    for (rounds = 1; rounds < max_rounds; rounds++) {
        tmp0 = _mm256_aesenc_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));
    }

    tmp0 = _mm256_aesenclast_epi128(tmp0, _mm256_broadcastsi128_si256(roundKeys[rounds]));

    *d0 = _mm256_xor_si256(*d0, tmp0);
}

static inline void aes128_trailing(
        __m128i *d0,
        __m128i *feedback, __m128i *roundKeys, const uint32_t blocks,
        const int max_rounds) {

    __m128i tmp0;
    tmp0 = _mm_xor_si128(*feedback, roundKeys[0]);
    *feedback = *d0;

    int rounds;
    for (rounds = 1; rounds < max_rounds; rounds++) {
        tmp0 = _mm_aesenc_si128(tmp0, roundKeys[rounds]);
    }

    tmp0 = _mm_aesenclast_si128(tmp0, roundKeys[rounds]);
    *d0 = _mm_xor_si128(*d0, tmp0);
}


static inline __m128i set_feedback(const __m512i in_cipher_blocks, const uint32_t num_blocks) {
    if (num_blocks == 1) {
        return _mm512_castsi512_si128(in_cipher_blocks);
    } else if (num_blocks == 2) {
        return _mm512_extracti32x4_epi32(in_cipher_blocks, 1);
    } else if (num_blocks == 3) {
        return _mm512_extracti32x4_epi32(in_cipher_blocks, 2);
    }
    return _mm512_extracti32x4_epi32(in_cipher_blocks, 3);
}


/**
 *
 * @param d0 in / out
 * @param d1 in / out
 * @param d2 in / out
 * @param d3 in / out
 * @param d4 in / out
 * @param feedback the chainblock
 * @param roundKeys
 * @param blocks blocks must be even number 16 to 2, 1 does odd block processing, any other value does nothing.
 * @param max_rounds The maximum number of rounds.
 *
 */
static inline void aes512w_cfb_decrypt(
        __m512i *d0, __m512i *d1, __m512i *d2, __m512i *d3,
        __m128i *feedback, __m128i *roundKeys, const uint32_t blocks,
        const int max_rounds) {

    __m512i tmp0, tmp1, tmp2, tmp3;

    if (blocks >= 16) {

        tmp0 = _mm512_alignr_epi64(*d0, _mm512_broadcast_i32x4(*feedback), 6);
        tmp1 = _mm512_alignr_epi64(*d1, *d0, 6);
        tmp2 = _mm512_alignr_epi64(*d2, *d1, 6);
        tmp3 = _mm512_alignr_epi64(*d3, *d2, 6);

        *feedback = _mm512_extracti32x4_epi32(*d3, 3);

        tmp0 = _mm512_xor_si512(tmp0, _mm512_broadcast_i32x4(roundKeys[0]));
        tmp1 = _mm512_xor_si512(tmp1, _mm512_broadcast_i32x4(roundKeys[0]));
        tmp2 = _mm512_xor_si512(tmp2, _mm512_broadcast_i32x4(roundKeys[0]));
        tmp3 = _mm512_xor_si512(tmp3, _mm512_broadcast_i32x4(roundKeys[0]));

        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm512_aesenc_epi128(tmp0, _mm512_broadcast_i32x4(roundKeys[rounds]));
            tmp1 = _mm512_aesenc_epi128(tmp1, _mm512_broadcast_i32x4(roundKeys[rounds]));
            tmp2 = _mm512_aesenc_epi128(tmp2, _mm512_broadcast_i32x4(roundKeys[rounds]));
            tmp3 = _mm512_aesenc_epi128(tmp3, _mm512_broadcast_i32x4(roundKeys[rounds]));
        }

        tmp0 = _mm512_aesenclast_epi128(tmp0, _mm512_broadcast_i32x4(roundKeys[rounds]));
        tmp1 = _mm512_aesenclast_epi128(tmp1, _mm512_broadcast_i32x4(roundKeys[rounds]));
        tmp2 = _mm512_aesenclast_epi128(tmp2, _mm512_broadcast_i32x4(roundKeys[rounds]));
        tmp3 = _mm512_aesenclast_epi128(tmp3, _mm512_broadcast_i32x4(roundKeys[rounds]));


        *d0 = _mm512_xor_si512(*d0, tmp0);
        *d1 = _mm512_xor_si512(*d1, tmp1);
        *d2 = _mm512_xor_si512(*d2, tmp2);
        *d3 = _mm512_xor_si512(*d3, tmp3);

    } else if (blocks >= 12) {
        const uint32_t partial_blocks = blocks - 12;
        tmp0 = _mm512_alignr_epi64(*d0, _mm512_broadcast_i32x4(*feedback), 6);
        tmp1 = _mm512_alignr_epi64(*d1, *d0, 6);
        tmp2 = _mm512_alignr_epi64(*d2, *d1, 6);


        *feedback = set_feedback(*d2, partial_blocks);

        tmp0 = _mm512_xor_si512(tmp0, _mm512_broadcast_i32x4(roundKeys[0]));
        tmp1 = _mm512_xor_si512(tmp1, _mm512_broadcast_i32x4(roundKeys[0]));
        tmp2 = _mm512_xor_si512(tmp2, _mm512_broadcast_i32x4(roundKeys[0]));

        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm512_aesenc_epi128(tmp0, _mm512_broadcast_i32x4(roundKeys[rounds]));
            tmp1 = _mm512_aesenc_epi128(tmp1, _mm512_broadcast_i32x4(roundKeys[rounds]));
            tmp2 = _mm512_aesenc_epi128(tmp2, _mm512_broadcast_i32x4(roundKeys[rounds]));
        }

        tmp0 = _mm512_aesenclast_epi128(tmp0, _mm512_broadcast_i32x4(roundKeys[rounds]));
        tmp1 = _mm512_aesenclast_epi128(tmp1, _mm512_broadcast_i32x4(roundKeys[rounds]));
        tmp2 = _mm512_aesenclast_epi128(tmp2, _mm512_broadcast_i32x4(roundKeys[rounds]));


        *d0 = _mm512_xor_si512(*d0, tmp0);
        *d1 = _mm512_xor_si512(*d1, tmp1);
        *d2 = _mm512_xor_si512(*d2, tmp2);


    } else if (blocks >= 8) {
        const uint32_t partial_blocks = blocks - 8;
        tmp0 = _mm512_alignr_epi64(*d0, _mm512_broadcast_i32x4(*feedback), 6);
        tmp1 = _mm512_alignr_epi64(*d1, *d0, 6);

        *feedback = set_feedback(*d1, partial_blocks);

        tmp0 = _mm512_xor_si512(tmp0, _mm512_broadcast_i32x4(roundKeys[0]));
        tmp1 = _mm512_xor_si512(tmp1, _mm512_broadcast_i32x4(roundKeys[0]));

        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm512_aesenc_epi128(tmp0, _mm512_broadcast_i32x4(roundKeys[rounds]));
            tmp1 = _mm512_aesenc_epi128(tmp1, _mm512_broadcast_i32x4(roundKeys[rounds]));
        }

        tmp0 = _mm512_aesenclast_epi128(tmp0, _mm512_broadcast_i32x4(roundKeys[rounds]));
        tmp1 = _mm512_aesenclast_epi128(tmp1, _mm512_broadcast_i32x4(roundKeys[rounds]));

        *d0 = _mm512_xor_si512(*d0, tmp0);
        *d1 = _mm512_xor_si512(*d1, tmp1);

    } else {
        const uint32_t partial_blocks = blocks - 4;
        tmp0 = _mm512_alignr_epi64(*d0, _mm512_broadcast_i32x4(*feedback), 6);

        *feedback = set_feedback(*d0, partial_blocks);

        tmp0 = _mm512_xor_si512(tmp0, _mm512_broadcast_i32x4(roundKeys[0]));


        int rounds;
        for (rounds = 1; rounds < max_rounds; rounds++) {
            tmp0 = _mm512_aesenc_epi128(tmp0, _mm512_broadcast_i32x4(roundKeys[rounds]));
        }

        tmp0 = _mm512_aesenclast_epi128(tmp0, _mm512_broadcast_i32x4(roundKeys[rounds]));
        *d0 = _mm512_xor_si512(*d0, tmp0);
    }
}


size_t cfb_pc_decrypt(uint8_t *src, size_t len, unsigned char *dest, __m128i *roundKeys, __m128i *mask,
                      __m128i *feedback, uint32_t *buf_index, int num_rounds) {
    unsigned char *destStart = dest;

    //
    // Round out buffer.
    //
//    while (buf_index > 0 && len > 0) {
//        *dest = cfb_pc_decrypt_byte( *src, roundKeys, mask, feedback, buf_index, num_rounds);
//        len--;
//        dest++;
//        src++;
//    }

    while (len >= 16 * CFB_BLOCK_SIZE) {
        __m512i d0 = _mm512_loadu_si512((__m512i *) &src[0 * 64]);
        __m512i d1 = _mm512_loadu_si512((__m512i *) &src[1 * 64]);
        __m512i d2 = _mm512_loadu_si512((__m512i *) &src[2 * 64]);
        __m512i d3 = _mm512_loadu_si512((__m512i *) &src[3 * 64]);

        aes512w_cfb_decrypt(&d0, &d1, &d2, &d3, feedback, roundKeys, 16, num_rounds);

        _mm512_storeu_si512((__m512i *) &dest[0 * 64], d0);
        _mm512_storeu_si512((__m512i *) &dest[1 * 64], d1);
        _mm512_storeu_si512((__m512i *) &dest[2 * 64], d2);
        _mm512_storeu_si512((__m512i *) &dest[3 * 64], d3);

        len -= 16 * CFB_BLOCK_SIZE;
        src += 16 * CFB_BLOCK_SIZE;
        dest += 16 * CFB_BLOCK_SIZE;
    }


    while (len >= CFB_BLOCK_SIZE) {

        if (len >= 12 * CFB_BLOCK_SIZE) {
            __m512i d0 = _mm512_loadu_si512((__m512i *) &src[0 * 64]);
            __m512i d1 = _mm512_loadu_si512((__m512i *) &src[1 * 64]);
            __m512i d2 = _mm512_loadu_si512((__m512i *) &src[2 * 64]);

            aes512w_cfb_decrypt(&d0, &d1, &d2, &d2, feedback, roundKeys, 12, num_rounds);

            _mm512_storeu_si512((__m512i *) &dest[0 * 64], d0);
            _mm512_storeu_si512((__m512i *) &dest[1 * 64], d1);
            _mm512_storeu_si512((__m512i *) &dest[2 * 64], d2);

            len -= 12 * CFB_BLOCK_SIZE;
            src += 12 * CFB_BLOCK_SIZE;
            dest += 12 * CFB_BLOCK_SIZE;

        } else if (len >= 8 * CFB_BLOCK_SIZE) {
            __m512i d0 = _mm512_loadu_si512((__m512i *) &src[0 * 64]);
            __m512i d1 = _mm512_loadu_si512((__m512i *) &src[1 * 64]);


            aes512w_cfb_decrypt(&d0, &d1, &d1, &d1, feedback, roundKeys, 8, num_rounds);

            _mm512_storeu_si512((__m512i *) &dest[0 * 64], d0);
            _mm512_storeu_si512((__m512i *) &dest[1 * 64], d1);

            len -= 8 * CFB_BLOCK_SIZE;
            src += 8 * CFB_BLOCK_SIZE;
            dest += 8 * CFB_BLOCK_SIZE;

        } else if (len >= 4 * CFB_BLOCK_SIZE) {
            __m512i d0 = _mm512_loadu_si512((__m512i *) &src[0 * 64]);

            aes512w_cfb_decrypt(&d0, &d0, &d0, &d0, feedback, roundKeys, 4, num_rounds);

            _mm512_storeu_si512((__m512i *) &dest[0 * 64], d0);

            len -= 4 * CFB_BLOCK_SIZE;
            src += 4 * CFB_BLOCK_SIZE;
            dest += 4 * CFB_BLOCK_SIZE;
        } else if (len >= 2 * CFB_BLOCK_SIZE) {
            __m256i d0 = _mm256_loadu_si256((__m256i *) &src[0 * 32]);

            aes256_trailing(&d0, feedback, roundKeys, 2,
                            num_rounds);

            _mm256_storeu_si256((__m256i *) &dest[0 * 32], d0);

            len -= 2 * CFB_BLOCK_SIZE;
            src += 2 * CFB_BLOCK_SIZE;
            dest += 2 * CFB_BLOCK_SIZE;

        } else { // single block
            __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);

            aes128_trailing(&d0, feedback, roundKeys, 1,
                            num_rounds);

            _mm_storeu_si128(((__m128i *) &dest[0 * 16]), d0);

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
        *dest = cfb_pc_decrypt_byte( *src, roundKeys, mask, feedback, buf_index, num_rounds);
        len--;
        dest++;
        src++;
    }

    return (size_t) (dest - destStart);

}

unsigned char
cfb_pc_decrypt_byte(unsigned char b, __m128i *roundKeys, __m128i *mask, __m128i *feedback, uint32_t *buf_index,
                    int num_rounds) {
    if (buf_index == 0) {
        // We need to generate a new encrypted feedback block to xor into the data.

        *mask = _mm_xor_si128(*feedback, roundKeys[0]);
        int j;
        for (j = 1; j < num_rounds; j++) {
            *mask = _mm_aesenc_si128(*mask, roundKeys[j]);
        }
        *mask = _mm_aesenclast_si128(*mask, roundKeys[j]);
    }

    //
    // incrementally mask becomes the last block of cipher text
    //

    unsigned char pt = ((unsigned char *) mask)[*buf_index] ^ b;
    ((unsigned char *) mask)[(*buf_index)++] = b; // Mask fills with last cipher text directly.

    if (*buf_index == CFB_BLOCK_SIZE) {
        *buf_index = 0;
        *feedback = *mask;
    }

    return pt;
}