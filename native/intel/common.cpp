
#include "common.h"
#include <wmmintrin.h>
#include <memory.h>

inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32 (temp2, 0xff);
    temp3 = _mm_slli_si128 (temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);

    memset(&temp2, 0, sizeof(__m128i));
    memset(&temp3, 0, sizeof(__m128i));
    return temp1;
}

inline void KEY_192_ASSIST(__m128i *temp1, __m128i *temp2, __m128i *temp3) {
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32 (*temp2, 0x55);
    temp4 = _mm_slli_si128 (*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
    *temp2 = _mm_shuffle_epi32(*temp1, 0xff);
    temp4 = _mm_slli_si128 (*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, *temp2);
}

inline void KEY_256_ASSIST_1(__m128i *temp1, __m128i *temp2) {
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
    temp4 = _mm_slli_si128 (*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
}

inline void KEY_256_ASSIST_2(__m128i *temp1, __m128i *temp3) {
    __m128i temp2, temp4;
    temp4 = _mm_aeskeygenassist_si128 (*temp1, 0x0);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128 (*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, temp2);
}

void init_256(__m128i *rk, unsigned char *uk, bool enc) {
    __m128i temp1, temp2, temp3;

    temp1 = _mm_loadu_si128((__m128i *) uk);
    temp3 = _mm_loadu_si128((__m128i *) (uk + 16));
    rk[0] = temp1;
    rk[1] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x01);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[2] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    rk[3] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x02);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[4] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    rk[5] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x04);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[6] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    rk[7] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x08);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[8] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    rk[9] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x10);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[10] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    rk[11] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x20);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[12] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    rk[13] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x40);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[14] = temp1;

    if (!enc) {
        rk[1] = _mm_aesimc_si128(rk[1]);
        rk[2] = _mm_aesimc_si128(rk[2]);
        rk[3] = _mm_aesimc_si128(rk[3]);
        rk[4] = _mm_aesimc_si128(rk[4]);
        rk[5] = _mm_aesimc_si128(rk[5]);
        rk[6] = _mm_aesimc_si128(rk[6]);
        rk[7] = _mm_aesimc_si128(rk[7]);
        rk[8] = _mm_aesimc_si128(rk[8]);
        rk[9] = _mm_aesimc_si128(rk[9]);
        rk[10] = _mm_aesimc_si128(rk[10]);
        rk[11] = _mm_aesimc_si128(rk[11]);
        rk[12] = _mm_aesimc_si128(rk[12]);
        rk[13] = _mm_aesimc_si128(rk[13]);
    }

    memset(&temp1, 0, sizeof(__m128i));
    memset(&temp2, 0, sizeof(__m128i));
    memset(&temp3, 0, sizeof(__m128i));
}

void init_192(__m128i *rk, unsigned char *uk, bool enc) {
    __m128i temp1, temp2, temp3, temp4;

    temp1 = _mm_loadu_si128((__m128i *) uk);
    temp3 = _mm_loadu_si128((__m128i *) (uk + 16));
    rk[0] = temp1;
    rk[1] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x1);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);


    rk[1] = (__m128i) _mm_shuffle_pd((__m128d) rk[1],
                                     (__m128d) temp1, 0);
    rk[2] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x2);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    rk[3] = temp1;
    rk[4] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x4);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);

    rk[4] = (__m128i) _mm_shuffle_pd((__m128d) rk[4],
                                     (__m128d) temp1, 0);
    rk[5] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


    rk[4] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(rk[4]),
                                            _mm_castsi128_pd(temp1), 0));
    rk[5] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 1));


    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x8);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    rk[6] = temp1;
    rk[7] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x10);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);


    rk[7] = (__m128i) _mm_shuffle_pd((__m128d) rk[7],
                                     (__m128d) temp1, 0);
    rk[8] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x20);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    rk[9] = temp1;
    rk[10] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x40);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);


    rk[10] = (__m128i) _mm_shuffle_pd((__m128d) rk[10],
                                      (__m128d) temp1, 0);
    rk[11] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x80);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    rk[12] = temp1;


    if (!enc) {
        rk[1] = _mm_aesimc_si128(rk[1]);
        rk[2] = _mm_aesimc_si128(rk[2]);
        rk[3] = _mm_aesimc_si128(rk[3]);
        rk[4] = _mm_aesimc_si128(rk[4]);
        rk[5] = _mm_aesimc_si128(rk[5]);
        rk[6] = _mm_aesimc_si128(rk[6]);
        rk[7] = _mm_aesimc_si128(rk[7]);
        rk[8] = _mm_aesimc_si128(rk[8]);
        rk[9] = _mm_aesimc_si128(rk[9]);
        rk[10] = _mm_aesimc_si128(rk[10]);
        rk[11] = _mm_aesimc_si128(rk[11]);
    }

    memset(&temp1, 0, sizeof(__m128i));
    memset(&temp2, 0, sizeof(__m128i));
    memset(&temp3, 0, sizeof(__m128i));
    memset(&temp4, 0, sizeof(__m128i));
}

void init_128(__m128i *rk, unsigned char *uk, bool enc) {
    __m128i temp1;
    __m128i temp2;

    temp1 = _mm_loadu_si128((__m128i *) uk);
    rk[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[10] = temp1;

    if (!enc) {
        rk[1] = _mm_aesimc_si128(rk[1]);
        rk[2] = _mm_aesimc_si128(rk[2]);
        rk[3] = _mm_aesimc_si128(rk[3]);
        rk[4] = _mm_aesimc_si128(rk[4]);
        rk[5] = _mm_aesimc_si128(rk[5]);
        rk[6] = _mm_aesimc_si128(rk[6]);
        rk[7] = _mm_aesimc_si128(rk[7]);
        rk[8] = _mm_aesimc_si128(rk[8]);
        rk[9] = _mm_aesimc_si128(rk[9]);
    }
    memset(&temp1, 0, sizeof(__m128i));
    memset(&temp2, 0, sizeof(__m128i));
}



