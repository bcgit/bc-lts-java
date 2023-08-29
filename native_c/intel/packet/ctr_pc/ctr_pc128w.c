#ifndef BC_AES_CTR_PC_128_H
#define BC_AES_CTR_PC_128_H


#include <immintrin.h>
#include "ctr_pc.h"

static inline void
aes_ctr128_wide(__m128i *d0, __m128i *d1, __m128i *d2, __m128i *d3, __m128i *d4, __m128i *d5, __m128i *d6, __m128i *d7,
                __m128i *roundKeys, const __m128i ctr, const int max_rounds, const uint32_t blocks) {

    __m128i t0, t1, t2, t3, t4, t5, t6, t7;
    if (blocks == 8) {
        t1 = _mm_add_epi64(ctr, *ONE);
        t2 = _mm_add_epi64(ctr, *TWO);
        t3 = _mm_add_epi64(ctr, *THREE);
        t4 = _mm_add_epi64(ctr, *FOUR);
        t5 = _mm_add_epi64(ctr, *FIVE);
        t6 = _mm_add_epi64(ctr, *SIX);
        t7 = _mm_add_epi64(ctr, *SEVEN);

        t0 = _mm_shuffle_epi8(ctr, *SWAP_ENDIAN_128);
        t1 = _mm_shuffle_epi8(t1, *SWAP_ENDIAN_128);
        t2 = _mm_shuffle_epi8(t2, *SWAP_ENDIAN_128);
        t3 = _mm_shuffle_epi8(t3, *SWAP_ENDIAN_128);
        t4 = _mm_shuffle_epi8(t4, *SWAP_ENDIAN_128);
        t5 = _mm_shuffle_epi8(t5, *SWAP_ENDIAN_128);
        t6 = _mm_shuffle_epi8(t6, *SWAP_ENDIAN_128);
        t7 = _mm_shuffle_epi8(t7, *SWAP_ENDIAN_128);
        const __m128i rkFirst = roundKeys[0];
        t0 = _mm_xor_si128(t0, rkFirst);
        t1 = _mm_xor_si128(t1, rkFirst);
        t2 = _mm_xor_si128(t2, rkFirst);
        t3 = _mm_xor_si128(t3, rkFirst);
        t4 = _mm_xor_si128(t4, rkFirst);
        t5 = _mm_xor_si128(t5, rkFirst);
        t6 = _mm_xor_si128(t6, rkFirst);
        t7 = _mm_xor_si128(t7, rkFirst);

        int round;
        for (round = 1; round < max_rounds; round++) {
            const __m128i rk = roundKeys[round];
            t0 = _mm_aesenc_si128(t0, rk);
            t1 = _mm_aesenc_si128(t1, rk);
            t2 = _mm_aesenc_si128(t2, rk);
            t3 = _mm_aesenc_si128(t3, rk);
            t4 = _mm_aesenc_si128(t4, rk);
            t5 = _mm_aesenc_si128(t5, rk);
            t6 = _mm_aesenc_si128(t6, rk);
            t7 = _mm_aesenc_si128(t7, rk);
        }
        const __m128i rkLast = roundKeys[round];
        t0 = _mm_aesenclast_si128(t0, rkLast);
        t1 = _mm_aesenclast_si128(t1, rkLast);
        t2 = _mm_aesenclast_si128(t2, rkLast);
        t3 = _mm_aesenclast_si128(t3, rkLast);
        t4 = _mm_aesenclast_si128(t4, rkLast);
        t5 = _mm_aesenclast_si128(t5, rkLast);
        t6 = _mm_aesenclast_si128(t6, rkLast);
        t7 = _mm_aesenclast_si128(t7, rkLast);

        *d0 = _mm_xor_si128(*d0, t0);
        *d1 = _mm_xor_si128(*d1, t1);
        *d2 = _mm_xor_si128(*d2, t2);
        *d3 = _mm_xor_si128(*d3, t3);
        *d4 = _mm_xor_si128(*d4, t4);
        *d5 = _mm_xor_si128(*d5, t5);
        *d6 = _mm_xor_si128(*d6, t6);
        *d7 = _mm_xor_si128(*d7, t7);

    } else if (blocks == 7) {
        t1 = _mm_add_epi64(ctr, *ONE);
        t2 = _mm_add_epi64(ctr, *TWO);
        t3 = _mm_add_epi64(ctr, *THREE);
        t4 = _mm_add_epi64(ctr, *FOUR);
        t5 = _mm_add_epi64(ctr, *FIVE);
        t6 = _mm_add_epi64(ctr, *SIX);

        t0 = _mm_shuffle_epi8(ctr, *SWAP_ENDIAN_128);
        t1 = _mm_shuffle_epi8(t1, *SWAP_ENDIAN_128);
        t2 = _mm_shuffle_epi8(t2, *SWAP_ENDIAN_128);
        t3 = _mm_shuffle_epi8(t3, *SWAP_ENDIAN_128);
        t4 = _mm_shuffle_epi8(t4, *SWAP_ENDIAN_128);
        t5 = _mm_shuffle_epi8(t5, *SWAP_ENDIAN_128);
        t6 = _mm_shuffle_epi8(t6, *SWAP_ENDIAN_128);


        const __m128i rkFirst = roundKeys[0];

        t0 = _mm_xor_si128(t0, rkFirst);
        t1 = _mm_xor_si128(t1, rkFirst);
        t2 = _mm_xor_si128(t2, rkFirst);
        t3 = _mm_xor_si128(t3, rkFirst);
        t4 = _mm_xor_si128(t4, rkFirst);
        t5 = _mm_xor_si128(t5, rkFirst);
        t6 = _mm_xor_si128(t6, rkFirst);


        int round;
        for (round = 1; round < max_rounds; round++) {
            const __m128i rk = roundKeys[round];
            t0 = _mm_aesenc_si128(t0, rk);
            t1 = _mm_aesenc_si128(t1, rk);
            t2 = _mm_aesenc_si128(t2, rk);
            t3 = _mm_aesenc_si128(t3, rk);
            t4 = _mm_aesenc_si128(t4, rk);
            t5 = _mm_aesenc_si128(t5, rk);
            t6 = _mm_aesenc_si128(t6, rk);

        }
        const __m128i rkLast = roundKeys[round];
        t0 = _mm_aesenclast_si128(t0, rkLast);
        t1 = _mm_aesenclast_si128(t1, rkLast);
        t2 = _mm_aesenclast_si128(t2, rkLast);
        t3 = _mm_aesenclast_si128(t3, rkLast);
        t4 = _mm_aesenclast_si128(t4, rkLast);
        t5 = _mm_aesenclast_si128(t5, rkLast);
        t6 = _mm_aesenclast_si128(t6, rkLast);
        *d0 = _mm_xor_si128(*d0, t0);
        *d1 = _mm_xor_si128(*d1, t1);
        *d2 = _mm_xor_si128(*d2, t2);
        *d3 = _mm_xor_si128(*d3, t3);
        *d4 = _mm_xor_si128(*d4, t4);
        *d5 = _mm_xor_si128(*d5, t5);
        *d6 = _mm_xor_si128(*d6, t6);
    } else if (blocks == 6) {
        t1 = _mm_add_epi64(ctr, *ONE);
        t2 = _mm_add_epi64(ctr, *TWO);
        t3 = _mm_add_epi64(ctr, *THREE);
        t4 = _mm_add_epi64(ctr, *FOUR);
        t5 = _mm_add_epi64(ctr, *FIVE);
        t0 = _mm_shuffle_epi8(ctr, *SWAP_ENDIAN_128);
        t1 = _mm_shuffle_epi8(t1, *SWAP_ENDIAN_128);
        t2 = _mm_shuffle_epi8(t2, *SWAP_ENDIAN_128);
        t3 = _mm_shuffle_epi8(t3, *SWAP_ENDIAN_128);
        t4 = _mm_shuffle_epi8(t4, *SWAP_ENDIAN_128);
        t5 = _mm_shuffle_epi8(t5, *SWAP_ENDIAN_128);
        const __m128i rkFirst = roundKeys[0];
        t0 = _mm_xor_si128(t0, rkFirst);
        t1 = _mm_xor_si128(t1, rkFirst);
        t2 = _mm_xor_si128(t2, rkFirst);
        t3 = _mm_xor_si128(t3, rkFirst);
        t4 = _mm_xor_si128(t4, rkFirst);
        t5 = _mm_xor_si128(t5, rkFirst);
        int round;
        for (round = 1; round < max_rounds; round++) {
            const __m128i rk = roundKeys[round];
            t0 = _mm_aesenc_si128(t0, rk);
            t1 = _mm_aesenc_si128(t1, rk);
            t2 = _mm_aesenc_si128(t2, rk);
            t3 = _mm_aesenc_si128(t3, rk);
            t4 = _mm_aesenc_si128(t4, rk);
            t5 = _mm_aesenc_si128(t5, rk);
        }
        const __m128i rkLast = roundKeys[round];
        t0 = _mm_aesenclast_si128(t0, rkLast);
        t1 = _mm_aesenclast_si128(t1, rkLast);
        t2 = _mm_aesenclast_si128(t2, rkLast);
        t3 = _mm_aesenclast_si128(t3, rkLast);
        t4 = _mm_aesenclast_si128(t4, rkLast);
        t5 = _mm_aesenclast_si128(t5, rkLast);
        *d0 = _mm_xor_si128(*d0, t0);
        *d1 = _mm_xor_si128(*d1, t1);
        *d2 = _mm_xor_si128(*d2, t2);
        *d3 = _mm_xor_si128(*d3, t3);
        *d4 = _mm_xor_si128(*d4, t4);
        *d5 = _mm_xor_si128(*d5, t5);
    } else if (blocks == 5) {
        t1 = _mm_add_epi64(ctr, *ONE);
        t2 = _mm_add_epi64(ctr, *TWO);
        t3 = _mm_add_epi64(ctr, *THREE);
        t4 = _mm_add_epi64(ctr, *FOUR);
        t0 = _mm_shuffle_epi8(ctr, *SWAP_ENDIAN_128);
        t1 = _mm_shuffle_epi8(t1, *SWAP_ENDIAN_128);
        t2 = _mm_shuffle_epi8(t2, *SWAP_ENDIAN_128);
        t3 = _mm_shuffle_epi8(t3, *SWAP_ENDIAN_128);
        t4 = _mm_shuffle_epi8(t4, *SWAP_ENDIAN_128);
        const __m128i rkFirst = roundKeys[0];
        t0 = _mm_xor_si128(t0, rkFirst);
        t1 = _mm_xor_si128(t1, rkFirst);
        t2 = _mm_xor_si128(t2, rkFirst);
        t3 = _mm_xor_si128(t3, rkFirst);
        t4 = _mm_xor_si128(t4, rkFirst);
        int round;
        for (round = 1; round < max_rounds; round++) {
            const __m128i rk = roundKeys[round];
            t0 = _mm_aesenc_si128(t0, rk);
            t1 = _mm_aesenc_si128(t1, rk);
            t2 = _mm_aesenc_si128(t2, rk);
            t3 = _mm_aesenc_si128(t3, rk);
            t4 = _mm_aesenc_si128(t4, rk);
        }
        const __m128i rkLast = roundKeys[round];
        t0 = _mm_aesenclast_si128(t0, rkLast);
        t1 = _mm_aesenclast_si128(t1, rkLast);
        t2 = _mm_aesenclast_si128(t2, rkLast);
        t3 = _mm_aesenclast_si128(t3, rkLast);
        t4 = _mm_aesenclast_si128(t4, rkLast);
        *d0 = _mm_xor_si128(*d0, t0);
        *d1 = _mm_xor_si128(*d1, t1);
        *d2 = _mm_xor_si128(*d2, t2);
        *d3 = _mm_xor_si128(*d3, t3);
        *d4 = _mm_xor_si128(*d4, t4);
    } else if (blocks == 4) {
        t1 = _mm_add_epi64(ctr, *ONE);
        t2 = _mm_add_epi64(ctr, *TWO);
        t3 = _mm_add_epi64(ctr, *THREE);
        t0 = _mm_shuffle_epi8(ctr, *SWAP_ENDIAN_128);
        t1 = _mm_shuffle_epi8(t1, *SWAP_ENDIAN_128);
        t2 = _mm_shuffle_epi8(t2, *SWAP_ENDIAN_128);
        t3 = _mm_shuffle_epi8(t3, *SWAP_ENDIAN_128);
        const __m128i rkFirst = roundKeys[0];
        t0 = _mm_xor_si128(t0, rkFirst);
        t1 = _mm_xor_si128(t1, rkFirst);
        t2 = _mm_xor_si128(t2, rkFirst);
        t3 = _mm_xor_si128(t3, rkFirst);


        int round;
        for (round = 1; round < max_rounds; round++) {
            const __m128i rk = roundKeys[round];
            t0 = _mm_aesenc_si128(t0, rk);
            t1 = _mm_aesenc_si128(t1, rk);
            t2 = _mm_aesenc_si128(t2, rk);
            t3 = _mm_aesenc_si128(t3, rk);


        }
        const __m128i rkLast = roundKeys[round];
        t0 = _mm_aesenclast_si128(t0, rkLast);
        t1 = _mm_aesenclast_si128(t1, rkLast);
        t2 = _mm_aesenclast_si128(t2, rkLast);
        t3 = _mm_aesenclast_si128(t3, rkLast);


        *d0 = _mm_xor_si128(*d0, t0);
        *d1 = _mm_xor_si128(*d1, t1);
        *d2 = _mm_xor_si128(*d2, t2);
        *d3 = _mm_xor_si128(*d3, t3);

    } else if (blocks == 3) {
        t1 = _mm_add_epi64(ctr, *ONE);
        t2 = _mm_add_epi64(ctr, *TWO);

        t0 = _mm_shuffle_epi8(ctr, *SWAP_ENDIAN_128);
        t1 = _mm_shuffle_epi8(t1, *SWAP_ENDIAN_128);
        t2 = _mm_shuffle_epi8(t2, *SWAP_ENDIAN_128);

        const __m128i rkFirst = roundKeys[0];

        t0 = _mm_xor_si128(t0, rkFirst);
        t1 = _mm_xor_si128(t1, rkFirst);
        t2 = _mm_xor_si128(t2, rkFirst);

        int round;
        for (round = 1; round < max_rounds; round++) {
            const __m128i rk = roundKeys[round];
            t0 = _mm_aesenc_si128(t0, rk);
            t1 = _mm_aesenc_si128(t1, rk);
            t2 = _mm_aesenc_si128(t2, rk);
        }

        const __m128i rkLast = roundKeys[round];
        t0 = _mm_aesenclast_si128(t0, rkLast);
        t1 = _mm_aesenclast_si128(t1, rkLast);
        t2 = _mm_aesenclast_si128(t2, rkLast);

        *d0 = _mm_xor_si128(*d0, t0);
        *d1 = _mm_xor_si128(*d1, t1);
        *d2 = _mm_xor_si128(*d2, t2);

    } else if (blocks == 2) {
        t1 = _mm_add_epi64(ctr, *ONE);

        t0 = _mm_shuffle_epi8(ctr, *SWAP_ENDIAN_128);
        t1 = _mm_shuffle_epi8(t1, *SWAP_ENDIAN_128);

        const __m128i rkFirst = roundKeys[0];

        t0 = _mm_xor_si128(t0, rkFirst);
        t1 = _mm_xor_si128(t1, rkFirst);


        int round;
        for (round = 1; round < max_rounds; round++) {
            const __m128i rk = roundKeys[round];
            t0 = _mm_aesenc_si128(t0, rk);
            t1 = _mm_aesenc_si128(t1, rk);
        }

        const __m128i rkLast = roundKeys[round];
        t0 = _mm_aesenclast_si128(t0, rkLast);
        t1 = _mm_aesenclast_si128(t1, rkLast);

        *d0 = _mm_xor_si128(*d0, t0);
        *d1 = _mm_xor_si128(*d1, t1);

    } else {
        t0 = _mm_shuffle_epi8(ctr, *SWAP_ENDIAN_128);
        const __m128i rkFirst = roundKeys[0];

        t0 = _mm_xor_si128(t0, rkFirst);

        int round;
        for (round = 1; round < max_rounds; round++) {
            const __m128i rk = roundKeys[round];
            t0 = _mm_aesenc_si128(t0, rk);
        }

        const __m128i rkLast = roundKeys[round];
        t0 = _mm_aesenclast_si128(t0, rkLast);

        *d0 = _mm_xor_si128(*d0, t0);
    }

}

bool ctr_pc_process_bytes(unsigned char *src, size_t len, unsigned char *dest, size_t *written, uint32_t *buf_pos,
                              uint64_t *ctr, uint64_t initialCTR, uint64_t ctrMast, bool *ctrAtEnd, __m128i *IV_le,
                              __m128i *roundKeys, int num_rounds, __m128i *partialBlock) {
    unsigned char *destStart = dest;
    if (*buf_pos == 0 && len >= 16) {

        while (len >= BLOCK_SIZE) {
            uint64_t const_ctr = *ctr;
            if (len >= 8 * BLOCK_SIZE) {
                if (!ctr_pc_incCtr(8, ctr, initialCTR, ctrMast, ctrAtEnd)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(*IV_le, _mm_set_epi64x(0, (int64_t) const_ctr));
                __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
                __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
                __m128i d2 = _mm_loadu_si128((__m128i *) &src[2 * 16]);
                __m128i d3 = _mm_loadu_si128((__m128i *) &src[3 * 16]);
                __m128i d4 = _mm_loadu_si128((__m128i *) &src[4 * 16]);
                __m128i d5 = _mm_loadu_si128((__m128i *) &src[5 * 16]);
                __m128i d6 = _mm_loadu_si128((__m128i *) &src[6 * 16]);
                __m128i d7 = _mm_loadu_si128((__m128i *) &src[7 * 16]);
                aes_ctr128_wide(
                        &d0, &d1, &d2, &d3,
                        &d4, &d5, &d6, &d7,
                        roundKeys, c0, num_rounds,
                        8);
                _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
                _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);
                _mm_storeu_si128((__m128i *) &dest[2 * 16], d2);
                _mm_storeu_si128((__m128i *) &dest[3 * 16], d3);
                _mm_storeu_si128((__m128i *) &dest[4 * 16], d4);
                _mm_storeu_si128((__m128i *) &dest[5 * 16], d5);
                _mm_storeu_si128((__m128i *) &dest[6 * 16], d6);
                _mm_storeu_si128((__m128i *) &dest[7 * 16], d7);
                len -= 8 * BLOCK_SIZE;
                src += 8 * BLOCK_SIZE;
                dest += 8 * BLOCK_SIZE;

            } else if (len >= 7 * BLOCK_SIZE) {
                if (!ctr_pc_incCtr(7, ctr, initialCTR, ctrMast, ctrAtEnd)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(*IV_le, _mm_set_epi64x(0, (int64_t) const_ctr));
                __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
                __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
                __m128i d2 = _mm_loadu_si128((__m128i *) &src[2 * 16]);
                __m128i d3 = _mm_loadu_si128((__m128i *) &src[3 * 16]);
                __m128i d4 = _mm_loadu_si128((__m128i *) &src[4 * 16]);
                __m128i d5 = _mm_loadu_si128((__m128i *) &src[5 * 16]);
                __m128i d6 = _mm_loadu_si128((__m128i *) &src[6 * 16]);


                aes_ctr128_wide(
                        &d0, &d1, &d2, &d3,
                        &d4, &d5, &d6, &d6,
                        roundKeys, c0, num_rounds,
                        7);

                _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
                _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);
                _mm_storeu_si128((__m128i *) &dest[2 * 16], d2);
                _mm_storeu_si128((__m128i *) &dest[3 * 16], d3);
                _mm_storeu_si128((__m128i *) &dest[4 * 16], d4);
                _mm_storeu_si128((__m128i *) &dest[5 * 16], d5);
                _mm_storeu_si128((__m128i *) &dest[6 * 16], d6);


                len -= 7 * BLOCK_SIZE;
                src += 7 * BLOCK_SIZE;
                dest += 7 * BLOCK_SIZE;

            } else if (len >= 6 * BLOCK_SIZE) {
                if (!ctr_pc_incCtr(6, ctr, initialCTR, ctrMast, ctrAtEnd)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(*IV_le, _mm_set_epi64x(0, (int64_t) const_ctr));

                __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
                __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
                __m128i d2 = _mm_loadu_si128((__m128i *) &src[2 * 16]);
                __m128i d3 = _mm_loadu_si128((__m128i *) &src[3 * 16]);
                __m128i d4 = _mm_loadu_si128((__m128i *) &src[4 * 16]);
                __m128i d5 = _mm_loadu_si128((__m128i *) &src[5 * 16]);


                aes_ctr128_wide(
                        &d0, &d1, &d2, &d3,
                        &d4, &d5, &d5, &d5,
                        roundKeys, c0, num_rounds,
                        6);

                _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
                _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);
                _mm_storeu_si128((__m128i *) &dest[2 * 16], d2);
                _mm_storeu_si128((__m128i *) &dest[3 * 16], d3);
                _mm_storeu_si128((__m128i *) &dest[4 * 16], d4);
                _mm_storeu_si128((__m128i *) &dest[5 * 16], d5);

                len -= 6 * BLOCK_SIZE;
                src += 6 * BLOCK_SIZE;
                dest += 6 * BLOCK_SIZE;
            } else if (len >= 5 * BLOCK_SIZE) {
                if (!ctr_pc_incCtr(5, ctr, initialCTR, ctrMast, ctrAtEnd)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(*IV_le, _mm_set_epi64x(0, (int64_t) const_ctr));

                __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
                __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
                __m128i d2 = _mm_loadu_si128((__m128i *) &src[2 * 16]);
                __m128i d3 = _mm_loadu_si128((__m128i *) &src[3 * 16]);
                __m128i d4 = _mm_loadu_si128((__m128i *) &src[4 * 16]);
                aes_ctr128_wide(
                        &d0, &d1, &d2, &d3,
                        &d4, &d4, &d4, &d4,
                        roundKeys, c0, num_rounds,
                        5);
                _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
                _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);
                _mm_storeu_si128((__m128i *) &dest[2 * 16], d2);
                _mm_storeu_si128((__m128i *) &dest[3 * 16], d3);
                _mm_storeu_si128((__m128i *) &dest[4 * 16], d4);
                len -= 5 * BLOCK_SIZE;
                src += 5 * BLOCK_SIZE;
                dest += 5 * BLOCK_SIZE;
            } else if (len >= 4 * BLOCK_SIZE) {
                if (!ctr_pc_incCtr(4, ctr, initialCTR, ctrMast, ctrAtEnd)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(*IV_le, _mm_set_epi64x(0, (int64_t) const_ctr));

                __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
                __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
                __m128i d2 = _mm_loadu_si128((__m128i *) &src[2 * 16]);
                __m128i d3 = _mm_loadu_si128((__m128i *) &src[3 * 16]);

                aes_ctr128_wide(
                        &d0, &d1, &d2, &d3,
                        &d3, &d3, &d3, &d3,
                        roundKeys, c0, num_rounds,
                        4);

                _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
                _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);
                _mm_storeu_si128((__m128i *) &dest[2 * 16], d2);
                _mm_storeu_si128((__m128i *) &dest[3 * 16], d3);

                len -= 4 * BLOCK_SIZE;
                src += 4 * BLOCK_SIZE;
                dest += 4 * BLOCK_SIZE;


            } else if (len >= 3 * BLOCK_SIZE) {
                if (!ctr_pc_incCtr(3, ctr, initialCTR, ctrMast, ctrAtEnd)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(*IV_le, _mm_set_epi64x(0, (int64_t) const_ctr));


                __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
                __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);
                __m128i d2 = _mm_loadu_si128((__m128i *) &src[2 * 16]);

                aes_ctr128_wide(
                        &d0, &d1, &d2, &d2,
                        &d2, &d2, &d2, &d2,
                        roundKeys, c0, num_rounds,
                        3);

                _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
                _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);
                _mm_storeu_si128((__m128i *) &dest[2 * 16], d2);

                len -= 3 * BLOCK_SIZE;
                src += 3 * BLOCK_SIZE;
                dest += 3 * BLOCK_SIZE;

            } else if (len >= 2 * BLOCK_SIZE) {

                if (!ctr_pc_incCtr(2, ctr, initialCTR, ctrMast, ctrAtEnd)) {
                    return false;
                }
                const __m128i c0 = _mm_xor_si128(*IV_le, _mm_set_epi64x(0, (int64_t) const_ctr));

                __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);
                __m128i d1 = _mm_loadu_si128((__m128i *) &src[1 * 16]);

                aes_ctr128_wide(
                        &d0, &d1, &d1, &d1,
                        &d1, &d1, &d1, &d1,
                        roundKeys, c0, num_rounds,
                        2);

                _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
                _mm_storeu_si128((__m128i *) &dest[1 * 16], d1);

                len -= 2 * BLOCK_SIZE;
                src += 2 * BLOCK_SIZE;
                dest += 2 * BLOCK_SIZE;

            } else {
                if (!ctr_pc_incCtr(1, ctr, initialCTR, ctrMast, ctrAtEnd)) {
                    return false;
                }

                const __m128i c0 = _mm_xor_si128(*IV_le, _mm_set_epi64x(0, (int64_t) const_ctr));
                __m128i d0 = _mm_loadu_si128((__m128i *) &src[0 * 16]);

                aes_ctr128_wide(
                        &d0, &d0, &d0, &d0,
                        &d0, &d0, &d0, &d0,
                        roundKeys, c0, num_rounds,
                        1);
                _mm_storeu_si128((__m128i *) &dest[0 * 16], d0);
                len -= BLOCK_SIZE;
                src += BLOCK_SIZE;
                dest += BLOCK_SIZE;

            }
        }
    }
    // Process trailing bytes
    while (len > 0) {
        unsigned char v = *src;
        if (!ctr_pc_process_byte(&v, buf_pos, ctr, initialCTR, ctrMast, ctrAtEnd, IV_le, roundKeys, num_rounds,
                                     partialBlock)) {
            return false;
        }
        *dest = v;
        src++;
        dest++;
        len--;
    }
    *written = (size_t) (dest - destStart);
    return true;
}

#endif
