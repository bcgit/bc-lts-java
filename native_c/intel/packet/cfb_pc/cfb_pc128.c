//
//
//

#include "cfb_pc.h"

static inline void aes128w_cfb128_decrypt(
        __m128i *d0, __m128i *d1, __m128i *d2, __m128i *d3,
        __m128i *d4, __m128i *d5, __m128i *d6, __m128i *d7,
        __m128i *feedback, __m128i *roundKeys, const uint32_t blocks,
        const int num_rounds) {

    __m128i tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7;

    if (blocks == 8) {
        tmp0 = _mm_xor_si128(*feedback, roundKeys[0]);
        tmp1 = _mm_xor_si128(*d0, roundKeys[0]);
        tmp2 = _mm_xor_si128(*d1, roundKeys[0]);
        tmp3 = _mm_xor_si128(*d2, roundKeys[0]);
        tmp4 = _mm_xor_si128(*d3, roundKeys[0]);
        tmp5 = _mm_xor_si128(*d4, roundKeys[0]);
        tmp6 = _mm_xor_si128(*d5, roundKeys[0]);
        tmp7 = _mm_xor_si128(*d6, roundKeys[0]);
        *feedback = *d7;


        int rounds;
        for (rounds = 1; rounds < num_rounds; rounds++) {
            tmp0 = _mm_aesenc_si128(tmp0, roundKeys[rounds]);
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[rounds]);
            tmp2 = _mm_aesenc_si128(tmp2, roundKeys[rounds]);
            tmp3 = _mm_aesenc_si128(tmp3, roundKeys[rounds]);
            tmp4 = _mm_aesenc_si128(tmp4, roundKeys[rounds]);
            tmp5 = _mm_aesenc_si128(tmp5, roundKeys[rounds]);
            tmp6 = _mm_aesenc_si128(tmp6, roundKeys[rounds]);
            tmp7 = _mm_aesenc_si128(tmp7, roundKeys[rounds]);
        }

        tmp0 = _mm_aesenclast_si128(tmp0, roundKeys[rounds]);
        tmp1 = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);
        tmp2 = _mm_aesenclast_si128(tmp2, roundKeys[rounds]);
        tmp3 = _mm_aesenclast_si128(tmp3, roundKeys[rounds]);
        tmp4 = _mm_aesenclast_si128(tmp4, roundKeys[rounds]);
        tmp5 = _mm_aesenclast_si128(tmp5, roundKeys[rounds]);
        tmp6 = _mm_aesenclast_si128(tmp6, roundKeys[rounds]);
        tmp7 = _mm_aesenclast_si128(tmp7, roundKeys[rounds]);

        *d0 = _mm_xor_si128(*d0, tmp0);
        *d1 = _mm_xor_si128(*d1, tmp1);
        *d2 = _mm_xor_si128(*d2, tmp2);
        *d3 = _mm_xor_si128(*d3, tmp3);
        *d4 = _mm_xor_si128(*d4, tmp4);
        *d5 = _mm_xor_si128(*d5, tmp5);
        *d6 = _mm_xor_si128(*d6, tmp6);
        *d7 = _mm_xor_si128(*d7, tmp7);
    } else if (blocks == 7) {

        tmp0 = _mm_xor_si128(*feedback, roundKeys[0]);
        tmp1 = _mm_xor_si128(*d0, roundKeys[0]);
        tmp2 = _mm_xor_si128(*d1, roundKeys[0]);
        tmp3 = _mm_xor_si128(*d2, roundKeys[0]);
        tmp4 = _mm_xor_si128(*d3, roundKeys[0]);
        tmp5 = _mm_xor_si128(*d4, roundKeys[0]);
        tmp6 = _mm_xor_si128(*d5, roundKeys[0]);
        *feedback = *d6;

        int rounds;
        for (rounds = 1; rounds < num_rounds; rounds++) {
            tmp0 = _mm_aesenc_si128(tmp0, roundKeys[rounds]);
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[rounds]);
            tmp2 = _mm_aesenc_si128(tmp2, roundKeys[rounds]);
            tmp3 = _mm_aesenc_si128(tmp3, roundKeys[rounds]);
            tmp4 = _mm_aesenc_si128(tmp4, roundKeys[rounds]);
            tmp5 = _mm_aesenc_si128(tmp5, roundKeys[rounds]);
            tmp6 = _mm_aesenc_si128(tmp6, roundKeys[rounds]);
        }

        tmp0 = _mm_aesenclast_si128(tmp0, roundKeys[rounds]);
        tmp1 = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);
        tmp2 = _mm_aesenclast_si128(tmp2, roundKeys[rounds]);
        tmp3 = _mm_aesenclast_si128(tmp3, roundKeys[rounds]);
        tmp4 = _mm_aesenclast_si128(tmp4, roundKeys[rounds]);
        tmp5 = _mm_aesenclast_si128(tmp5, roundKeys[rounds]);
        tmp6 = _mm_aesenclast_si128(tmp6, roundKeys[rounds]);

        *d0 = _mm_xor_si128(*d0, tmp0);
        *d1 = _mm_xor_si128(*d1, tmp1);
        *d2 = _mm_xor_si128(*d2, tmp2);
        *d3 = _mm_xor_si128(*d3, tmp3);
        *d4 = _mm_xor_si128(*d4, tmp4);
        *d5 = _mm_xor_si128(*d5, tmp5);
        *d6 = _mm_xor_si128(*d6, tmp6);

    } else if (blocks == 6) {

        tmp0 = _mm_xor_si128(*feedback, roundKeys[0]);
        tmp1 = _mm_xor_si128(*d0, roundKeys[0]);
        tmp2 = _mm_xor_si128(*d1, roundKeys[0]);
        tmp3 = _mm_xor_si128(*d2, roundKeys[0]);
        tmp4 = _mm_xor_si128(*d3, roundKeys[0]);
        tmp5 = _mm_xor_si128(*d4, roundKeys[0]);
        *feedback = *d5;

        int rounds;
        for (rounds = 1; rounds < num_rounds; rounds++) {
            tmp0 = _mm_aesenc_si128(tmp0, roundKeys[rounds]);
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[rounds]);
            tmp2 = _mm_aesenc_si128(tmp2, roundKeys[rounds]);
            tmp3 = _mm_aesenc_si128(tmp3, roundKeys[rounds]);
            tmp4 = _mm_aesenc_si128(tmp4, roundKeys[rounds]);
            tmp5 = _mm_aesenc_si128(tmp5, roundKeys[rounds]);
        }

        tmp0 = _mm_aesenclast_si128(tmp0, roundKeys[rounds]);
        tmp1 = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);
        tmp2 = _mm_aesenclast_si128(tmp2, roundKeys[rounds]);
        tmp3 = _mm_aesenclast_si128(tmp3, roundKeys[rounds]);
        tmp4 = _mm_aesenclast_si128(tmp4, roundKeys[rounds]);
        tmp5 = _mm_aesenclast_si128(tmp5, roundKeys[rounds]);


        *d0 = _mm_xor_si128(*d0, tmp0);
        *d1 = _mm_xor_si128(*d1, tmp1);
        *d2 = _mm_xor_si128(*d2, tmp2);
        *d3 = _mm_xor_si128(*d3, tmp3);
        *d4 = _mm_xor_si128(*d4, tmp4);
        *d5 = _mm_xor_si128(*d5, tmp5);

    } else if (blocks == 5) {

        tmp0 = _mm_xor_si128(*feedback, roundKeys[0]);
        tmp1 = _mm_xor_si128(*d0, roundKeys[0]);
        tmp2 = _mm_xor_si128(*d1, roundKeys[0]);
        tmp3 = _mm_xor_si128(*d2, roundKeys[0]);
        tmp4 = _mm_xor_si128(*d3, roundKeys[0]);

        *feedback = *d4;

        int rounds;
        for (rounds = 1; rounds < num_rounds; rounds++) {
            tmp0 = _mm_aesenc_si128(tmp0, roundKeys[rounds]);
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[rounds]);
            tmp2 = _mm_aesenc_si128(tmp2, roundKeys[rounds]);
            tmp3 = _mm_aesenc_si128(tmp3, roundKeys[rounds]);
            tmp4 = _mm_aesenc_si128(tmp4, roundKeys[rounds]);
        }

        tmp0 = _mm_aesenclast_si128(tmp0, roundKeys[rounds]);
        tmp1 = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);
        tmp2 = _mm_aesenclast_si128(tmp2, roundKeys[rounds]);
        tmp3 = _mm_aesenclast_si128(tmp3, roundKeys[rounds]);
        tmp4 = _mm_aesenclast_si128(tmp4, roundKeys[rounds]);

        *d0 = _mm_xor_si128(*d0, tmp0);
        *d1 = _mm_xor_si128(*d1, tmp1);
        *d2 = _mm_xor_si128(*d2, tmp2);
        *d3 = _mm_xor_si128(*d3, tmp3);
        *d4 = _mm_xor_si128(*d4, tmp4);
    } else if (blocks == 4) {

        tmp0 = _mm_xor_si128(*feedback, roundKeys[0]);
        tmp1 = _mm_xor_si128(*d0, roundKeys[0]);
        tmp2 = _mm_xor_si128(*d1, roundKeys[0]);
        tmp3 = _mm_xor_si128(*d2, roundKeys[0]);

        *feedback = *d3;

        int rounds;
        for (rounds = 1; rounds < num_rounds; rounds++) {
            tmp0 = _mm_aesenc_si128(tmp0, roundKeys[rounds]);
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[rounds]);
            tmp2 = _mm_aesenc_si128(tmp2, roundKeys[rounds]);
            tmp3 = _mm_aesenc_si128(tmp3, roundKeys[rounds]);

        }

        tmp0 = _mm_aesenclast_si128(tmp0, roundKeys[rounds]);
        tmp1 = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);
        tmp2 = _mm_aesenclast_si128(tmp2, roundKeys[rounds]);
        tmp3 = _mm_aesenclast_si128(tmp3, roundKeys[rounds]);

        *d0 = _mm_xor_si128(*d0, tmp0);
        *d1 = _mm_xor_si128(*d1, tmp1);
        *d2 = _mm_xor_si128(*d2, tmp2);
        *d3 = _mm_xor_si128(*d3, tmp3);

    } else if (blocks == 3) {

        tmp0 = _mm_xor_si128(*feedback, roundKeys[0]);
        tmp1 = _mm_xor_si128(*d0, roundKeys[0]);
        tmp2 = _mm_xor_si128(*d1, roundKeys[0]);

        *feedback = *d2;

        int rounds;
        for (rounds = 1; rounds < num_rounds; rounds++) {
            tmp0 = _mm_aesenc_si128(tmp0, roundKeys[rounds]);
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[rounds]);
            tmp2 = _mm_aesenc_si128(tmp2, roundKeys[rounds]);
        }

        tmp0 = _mm_aesenclast_si128(tmp0, roundKeys[rounds]);
        tmp1 = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);
        tmp2 = _mm_aesenclast_si128(tmp2, roundKeys[rounds]);


        *d0 = _mm_xor_si128(*d0, tmp0);
        *d1 = _mm_xor_si128(*d1, tmp1);
        *d2 = _mm_xor_si128(*d2, tmp2);

    } else if (blocks == 2) {

        tmp0 = _mm_xor_si128(*feedback, roundKeys[0]);
        tmp1 = _mm_xor_si128(*d0, roundKeys[0]);

        *feedback = *d1;

        int rounds;
        for (rounds = 1; rounds < num_rounds; rounds++) {
            tmp0 = _mm_aesenc_si128(tmp0, roundKeys[rounds]);
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[rounds]);
        }

        tmp0 = _mm_aesenclast_si128(tmp0, roundKeys[rounds]);
        tmp1 = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);

        *d0 = _mm_xor_si128(*d0, tmp0);
        *d1 = _mm_xor_si128(*d1, tmp1);

    } else /*if (blocks == 1)*/ {
        tmp0 = _mm_xor_si128(*feedback, roundKeys[0]);
        *feedback = *d0;

        int rounds;
        for (rounds = 1; rounds < num_rounds; rounds++) {
            tmp0 = _mm_aesenc_si128(tmp0, roundKeys[rounds]);
        }

        tmp0 = _mm_aesenclast_si128(tmp0, roundKeys[rounds]);
        *d0 = _mm_xor_si128(*d0, tmp0);
    }

}


size_t
cfb_pc_decrypt(unsigned char *src, size_t len, unsigned char *dest, __m128i *roundKeys, __m128i *mask,
               __m128i *feedback, uint32_t *buf_index, int num_rounds) {
    unsigned char *destStart = dest;

    //
    // Round out buffer.
    //
//    while (buf_index > 0 && len > 0) {
//        *dest = cfb_pc_decrypt_byte(*src, roundKeys, mask, feedback, buf_index, num_rounds);
//        len--;
//        dest++;
//        src++;
//    }


    while (len >= CFB_BLOCK_SIZE * 8) {
        __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
        __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
        __m128i d2 = _mm_loadu_si128((__m128i *) &src[2 * 16]);
        __m128i d3 = _mm_loadu_si128((__m128i *) &src[3 * 16]);
        __m128i d4 = _mm_loadu_si128((__m128i *) &src[4 * 16]);
        __m128i d5 = _mm_loadu_si128((__m128i *) &src[5 * 16]);
        __m128i d6 = _mm_loadu_si128((__m128i *) &src[6 * 16]);
        __m128i d7 = _mm_loadu_si128((__m128i *) &src[7 * 16]);

        aes128w_cfb128_decrypt(&d0, &d1, &d2, &d3, &d4, &d5, &d6, &d7, feedback, roundKeys, 8,
                               num_rounds);

        _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
        _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);
        _mm_storeu_si128((__m128i *) &dest[2 * 16], d2);
        _mm_storeu_si128((__m128i *) &dest[3 * 16], d3);
        _mm_storeu_si128((__m128i *) &dest[4 * 16], d4);
        _mm_storeu_si128((__m128i *) &dest[5 * 16], d5);
        _mm_storeu_si128((__m128i *) &dest[6 * 16], d6);
        _mm_storeu_si128((__m128i *) &dest[7 * 16], d7);
        len -= 16 * 8;
        src += 16 * 8;
        dest += 16 * 8;
    }



    //
    // Process as many whole blocks as possible.
    //
    while (len >= CFB_BLOCK_SIZE) {

        if (len >= CFB_BLOCK_SIZE * 7) {
            __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
            __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
            __m128i d2 = _mm_loadu_si128((__m128i *) &src[2 * 16]);
            __m128i d3 = _mm_loadu_si128((__m128i *) &src[3 * 16]);
            __m128i d4 = _mm_loadu_si128((__m128i *) &src[4 * 16]);
            __m128i d5 = _mm_loadu_si128((__m128i *) &src[5 * 16]);
            __m128i d6 = _mm_loadu_si128((__m128i *) &src[6 * 16]);


            aes128w_cfb128_decrypt(&d0, &d1, &d2, &d3, &d4, &d5, &d6, &d6, feedback, roundKeys, 7,
                                   num_rounds);

            _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
            _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);
            _mm_storeu_si128((__m128i *) &dest[2 * 16], d2);
            _mm_storeu_si128((__m128i *) &dest[3 * 16], d3);
            _mm_storeu_si128((__m128i *) &dest[4 * 16], d4);
            _mm_storeu_si128((__m128i *) &dest[5 * 16], d5);
            _mm_storeu_si128((__m128i *) &dest[6 * 16], d6);
            len -= 16 * 7;
            src += 16 * 7;
            dest += 16 * 7;

        } else if (len >= CFB_BLOCK_SIZE * 6) {
            __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
            __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
            __m128i d2 = _mm_loadu_si128((__m128i *) &src[2 * 16]);
            __m128i d3 = _mm_loadu_si128((__m128i *) &src[3 * 16]);
            __m128i d4 = _mm_loadu_si128((__m128i *) &src[4 * 16]);
            __m128i d5 = _mm_loadu_si128((__m128i *) &src[5 * 16]);


            aes128w_cfb128_decrypt(&d0, &d1, &d2, &d3, &d4, &d5, &d5, &d5, feedback, roundKeys, 6,
                                   num_rounds);

            _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
            _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);
            _mm_storeu_si128((__m128i *) &dest[2 * 16], d2);
            _mm_storeu_si128((__m128i *) &dest[3 * 16], d3);
            _mm_storeu_si128((__m128i *) &dest[4 * 16], d4);
            _mm_storeu_si128((__m128i *) &dest[5 * 16], d5);

            len -= 16 * 6;
            src += 16 * 6;
            dest += 16 * 6;

        } else if (len >= CFB_BLOCK_SIZE * 5) {
            __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
            __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
            __m128i d2 = _mm_loadu_si128((__m128i *) &src[2 * 16]);
            __m128i d3 = _mm_loadu_si128((__m128i *) &src[3 * 16]);
            __m128i d4 = _mm_loadu_si128((__m128i *) &src[4 * 16]);


            aes128w_cfb128_decrypt(&d0, &d1, &d2, &d3, &d4, &d4, &d4, &d4, feedback, roundKeys, 5,
                                   num_rounds);

            _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
            _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);
            _mm_storeu_si128((__m128i *) &dest[2 * 16], d2);
            _mm_storeu_si128((__m128i *) &dest[3 * 16], d3);
            _mm_storeu_si128((__m128i *) &dest[4 * 16], d4);

            len -= 16 * 5;
            src += 16 * 5;
            dest += 16 * 5;

        } else if (len >= CFB_BLOCK_SIZE * 4) {
            __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
            __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
            __m128i d2 = _mm_loadu_si128((__m128i *) &src[2 * 16]);
            __m128i d3 = _mm_loadu_si128((__m128i *) &src[3 * 16]);

            aes128w_cfb128_decrypt(&d0, &d1, &d2, &d3, &d3, &d3, &d3, &d3, feedback, roundKeys, 4,
                                   num_rounds);

            _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
            _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);
            _mm_storeu_si128((__m128i *) &dest[2 * 16], d2);
            _mm_storeu_si128((__m128i *) &dest[3 * 16], d3);

            len -= 16 * 4;
            src += 16 * 4;
            dest += 16 * 4;

        } else if (len >= CFB_BLOCK_SIZE * 3) {
            __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
            __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
            __m128i d2 = _mm_loadu_si128((__m128i *) &src[2 * 16]);
            aes128w_cfb128_decrypt(&d0, &d1, &d2, &d2, &d2, &d2, &d2, &d2, feedback, roundKeys, 3,
                                   num_rounds);
            _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
            _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);
            _mm_storeu_si128((__m128i *) &dest[2 * 16], d2);

            len -= 16 * 3;
            src += 16 * 3;
            dest += 16 * 3;

        } else if (len >= CFB_BLOCK_SIZE * 2) {
            __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
            __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
            aes128w_cfb128_decrypt(&d0, &d1, &d1, &d1, &d1, &d1, &d1, &d1, feedback, roundKeys, 2,
                                   num_rounds);
            _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
            _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);

            len -= 16 * 2;
            src += 16 * 2;
            dest += 16 * 2;

        } else {
            __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
            aes128w_cfb128_decrypt(&d0, &d0, &d0, &d0, &d0, &d0, &d0, &d0, feedback, roundKeys, 1,
                                   num_rounds);
            _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
            len -= 16 * 1;
            src += 16 * 1;
            dest += 16 * 1;

        }
    }


    //
    // load any trailing bytes into the buffer, the expectation is that
    // whatever is passed in has to be decrypted, ideally callers will
    // try and stick to the AES block size for as long as possible.
    //
    while (len > 0) {
        *dest = cfb_pc_decrypt_byte(*src, roundKeys, mask, feedback, buf_index, num_rounds);
        len--;
        dest++;
        src++;
    }

    return (size_t) (dest - destStart);
}


unsigned char
cfb_pc_decrypt_byte(unsigned char b, __m128i *roundKeys, __m128i *mask, __m128i *feedback, uint32_t *buf_index,
                    int num_rounds) {
    if (*buf_index == 0) {

        // We need to generate a new encrypted feedback block to xor into the data.,

        *mask = _mm_xor_si128(*feedback, roundKeys[0]);
        int j;
        for (j = 1; j < num_rounds; j++) {
            *mask = _mm_aesenc_si128(*mask, roundKeys[j]);
        }
        *mask = _mm_aesenclast_si128(*mask, roundKeys[j]);

    }

    //
    // incrementally mask becomes the last block of plain text
    //

    unsigned char pt = ((unsigned char *) mask)[*buf_index] ^ b;
    ((unsigned char *) mask)[(*buf_index)++] = b; // Mask fills with last cipher text directly.

    if (*buf_index == CFB_BLOCK_SIZE) {
        *buf_index = 0;
        *feedback = *mask;
    }

    return pt;
}
