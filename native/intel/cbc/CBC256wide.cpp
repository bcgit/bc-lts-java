//
// Created by 25/7/2022.
//


#include "CBC256wide.h"
#include "../../macro.h"
#include <cstring>
#include <iostream>
#include <immintrin.h>


namespace intel {
    namespace cbc {


        CBC256wide::CBC256wide() : CBCLike() {
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
            roundKeys = new __m256i[15];
            memset(roundKeys, 0, 15 * sizeof(__m256i));
            encrypting = false;
        }

        CBC256wide::~CBC256wide() {
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
            memset(roundKeys, 0, 15 * sizeof(__m256i));
            delete[] roundKeys;
        }

        void CBC256wide::init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) {
            feedback = _mm_loadu_si128((__m128i *) (iv));
            initialFeedback = feedback;
            initKey(key, keylen);
        }

        void CBC256wide::reset() {
            feedback = initialFeedback;
        }

        uint32_t CBC256wide::getMultiBlockSize() {
            return CBC_BLOCK_SIZE * 2;
        }


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


        void CBC256wide::initKey(unsigned char *key, size_t len) {

            abortNull(key);

            memset(roundKeys, 0, 15 * sizeof(__m256i));
            auto *rk = (__m128i *) (roundKeys);

            if (len == 16) {
                __m128i temp1;
                __m128i temp2;


                temp1 = _mm_loadu_si128((__m128i *) key);
                rk[1] = rk[0] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x1);
                temp1 = AES_128_ASSIST(temp1, temp2);
                rk[2] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x2);
                temp1 = AES_128_ASSIST(temp1, temp2);
                rk[4] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x4);
                temp1 = AES_128_ASSIST(temp1, temp2);
                rk[6] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x8);
                temp1 = AES_128_ASSIST(temp1, temp2);
                rk[8] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x10);
                temp1 = AES_128_ASSIST(temp1, temp2);
                rk[10] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x20);
                temp1 = AES_128_ASSIST(temp1, temp2);
                rk[12] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x40);
                temp1 = AES_128_ASSIST(temp1, temp2);
                rk[14] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x80);
                temp1 = AES_128_ASSIST(temp1, temp2);
                rk[16] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x1b);
                temp1 = AES_128_ASSIST(temp1, temp2);
                rk[18] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x36);
                temp1 = AES_128_ASSIST(temp1, temp2);
                rk[21] = rk[20] = temp1;


                if (!encrypting) {
                    rk[3] = rk[2] = _mm_aesimc_si128(rk[2]);
                    rk[5] = rk[4] = _mm_aesimc_si128(rk[4]);
                    rk[7] = rk[6] = _mm_aesimc_si128(rk[6]);
                    rk[9] = rk[8] = _mm_aesimc_si128(rk[8]);
                    rk[11] = rk[10] = _mm_aesimc_si128(rk[10]);
                    rk[13] = rk[12] = _mm_aesimc_si128(rk[12]);
                    rk[15] = rk[14] = _mm_aesimc_si128(rk[14]);
                    rk[17] = rk[16] = _mm_aesimc_si128(rk[16]);
                    rk[19] = rk[18] = _mm_aesimc_si128(rk[18]);

                }
                memset(&temp1, 0, sizeof(__m128i));
                memset(&temp2, 0, sizeof(__m128i));
                return;
            } else if (len == 24) {
                __m128i temp1, temp2, temp3, temp4;

                temp1 = _mm_loadu_si128((__m128i *) key);
                temp3 = _mm_loadu_si128((__m128i *) (key + 16));
                rk[1] = rk[0] = temp1;
                rk[3] = rk[2] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x1);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);


                rk[2] = (__m128i) _mm_shuffle_pd((__m128d) rk[2],
                                                 (__m128d) temp1, 0);
                rk[4] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x2);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                rk[6] = temp1;
                rk[8] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x4);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);

                rk[8] = (__m128i) _mm_shuffle_pd((__m128d) rk[8],
                                                 (__m128d) temp1, 0);
                rk[10] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


                rk[8] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(rk[8]),
                                                        _mm_castsi128_pd(temp1), 0));
                rk[10] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 1));


                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x8);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                rk[12] = temp1;
                rk[14] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x10);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);


                rk[14] = (__m128i) _mm_shuffle_pd((__m128d) rk[14],
                                                  (__m128d) temp1, 0);
                rk[16] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x20);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                rk[18] = temp1;
                rk[20] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x40);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);


                rk[20] = (__m128i) _mm_shuffle_pd((__m128d) rk[20],
                                                  (__m128d) temp1, 0);
                rk[22] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x80);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                rk[25] = rk[24] = temp1;

                if (!encrypting) {
                    rk[3] = rk[2] = _mm_aesimc_si128(rk[2]);
                    rk[5] = rk[4] = _mm_aesimc_si128(rk[4]);
                    rk[7] = rk[6] = _mm_aesimc_si128(rk[6]);
                    rk[9] = rk[8] = _mm_aesimc_si128(rk[8]);
                    rk[11] = rk[10] = _mm_aesimc_si128(rk[10]);
                    rk[13] = rk[12] = _mm_aesimc_si128(rk[12]);
                    rk[15] = rk[14] = _mm_aesimc_si128(rk[14]);
                    rk[17] = rk[16] = _mm_aesimc_si128(rk[16]);
                    rk[19] = rk[18] = _mm_aesimc_si128(rk[18]);
                    rk[21] = rk[20] = _mm_aesimc_si128(rk[20]);
                    rk[23] = rk[22] = _mm_aesimc_si128(rk[22]);
                }


                memset(&temp1, 0, sizeof(__m128i));
                memset(&temp2, 0, sizeof(__m128i));
                memset(&temp3, 0, sizeof(__m128i));
                memset(&temp4, 0, sizeof(__m128i));

                return;
            } else if (len == 32) {

                __m128i temp1, temp2, temp3;

                temp1 = _mm_loadu_si128((__m128i *) key);
                temp3 = _mm_loadu_si128((__m128i *) (key + 16));
                rk[1] = rk[0] = temp1;
                rk[2] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x01);
                KEY_256_ASSIST_1(&temp1, &temp2);
                rk[4] = temp1;
                KEY_256_ASSIST_2(&temp1, &temp3);
                rk[6] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x02);
                KEY_256_ASSIST_1(&temp1, &temp2);
                rk[8] = temp1;
                KEY_256_ASSIST_2(&temp1, &temp3);
                rk[10] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x04);
                KEY_256_ASSIST_1(&temp1, &temp2);
                rk[12] = temp1;
                KEY_256_ASSIST_2(&temp1, &temp3);
                rk[14] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x08);
                KEY_256_ASSIST_1(&temp1, &temp2);
                rk[16] = temp1;
                KEY_256_ASSIST_2(&temp1, &temp3);
                rk[18] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x10);
                KEY_256_ASSIST_1(&temp1, &temp2);
                rk[20] = temp1;
                KEY_256_ASSIST_2(&temp1, &temp3);
                rk[22] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x20);
                KEY_256_ASSIST_1(&temp1, &temp2);
                rk[24] = temp1;
                KEY_256_ASSIST_2(&temp1, &temp3);
                rk[26] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x40);
                KEY_256_ASSIST_1(&temp1, &temp2);
                rk[29] = rk[28] = temp1;

                if (!encrypting) {
                    rk[3] = rk[2] = _mm_aesimc_si128(rk[2]);
                    rk[5] = rk[4] = _mm_aesimc_si128(rk[4]);
                    rk[7] = rk[6] = _mm_aesimc_si128(rk[6]);
                    rk[9] = rk[8] = _mm_aesimc_si128(rk[8]);
                    rk[11] = rk[10] = _mm_aesimc_si128(rk[10]);
                    rk[13] = rk[12] = _mm_aesimc_si128(rk[12]);
                    rk[15] = rk[14] = _mm_aesimc_si128(rk[14]);
                    rk[17] = rk[16] = _mm_aesimc_si128(rk[16]);
                    rk[19] = rk[18] = _mm_aesimc_si128(rk[18]);
                    rk[21] = rk[20] = _mm_aesimc_si128(rk[20]);
                    rk[23] = rk[22] = _mm_aesimc_si128(rk[22]);
                    rk[25] = rk[24] = _mm_aesimc_si128(rk[24]);
                    rk[27] = rk[26] = _mm_aesimc_si128(rk[26]);
                }

                memset(&temp1, 0, sizeof(__m128i));
                memset(&temp2, 0, sizeof(__m128i));
                memset(&temp3, 0, sizeof(__m128i));
                return;
            }


            abortIf(true,
                    "Invalid key size supplied to lowest level of api, must only be 16, 24 or 32 bytes. aborting");

        }


    }


}



