//
// Created by 25/7/2022.
//


#include "CBC128wide.h"
#include "../../macro.h"
#include <cstring>
#include <iostream>
#include <immintrin.h>


namespace intel {
    namespace cbc {


        CBC128wide::CBC128wide(): CBCLike() {
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
            roundKeys = new __m128i[15];
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            encrypting = false;
        }

        CBC128wide::~CBC128wide() {
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            delete[] roundKeys;
        }

        void CBC128wide::init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) {
            feedback = _mm_loadu_si128((__m128i *) (iv));
            initialFeedback = feedback;
            initKey(key, keylen);
        }

        void CBC128wide::reset() {
            feedback = initialFeedback;
        }

        uint32_t CBC128wide::getMultiBlockSize() {
            return CBC_BLOCK_SIZE;
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


        void CBC128wide::initKey(unsigned char *key, size_t len) {

            abortNull(key);
            memset(roundKeys, 0, 15 * sizeof(__m128i));

            if (len == 16) {
                __m128i temp1;
                __m128i temp2;

                temp1 = _mm_loadu_si128((__m128i *) key);
                roundKeys[0] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x1);
                temp1 = AES_128_ASSIST(temp1, temp2);
                roundKeys[1] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x2);
                temp1 = AES_128_ASSIST(temp1, temp2);
                roundKeys[2] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x4);
                temp1 = AES_128_ASSIST(temp1, temp2);
                roundKeys[3] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x8);
                temp1 = AES_128_ASSIST(temp1, temp2);
                roundKeys[4] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x10);
                temp1 = AES_128_ASSIST(temp1, temp2);
                roundKeys[5] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x20);
                temp1 = AES_128_ASSIST(temp1, temp2);
                roundKeys[6] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x40);
                temp1 = AES_128_ASSIST(temp1, temp2);
                roundKeys[7] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x80);
                temp1 = AES_128_ASSIST(temp1, temp2);
                roundKeys[8] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x1b);
                temp1 = AES_128_ASSIST(temp1, temp2);
                roundKeys[9] = temp1;
                temp2 = _mm_aeskeygenassist_si128 (temp1, 0x36);
                temp1 = AES_128_ASSIST(temp1, temp2);
                roundKeys[10] = temp1;

                if (!encrypting) {
                    roundKeys[1] = _mm_aesimc_si128(roundKeys[1]);
                    roundKeys[2] = _mm_aesimc_si128(roundKeys[2]);
                    roundKeys[3] = _mm_aesimc_si128(roundKeys[3]);
                    roundKeys[4] = _mm_aesimc_si128(roundKeys[4]);
                    roundKeys[5] = _mm_aesimc_si128(roundKeys[5]);
                    roundKeys[6] = _mm_aesimc_si128(roundKeys[6]);
                    roundKeys[7] = _mm_aesimc_si128(roundKeys[7]);
                    roundKeys[8] = _mm_aesimc_si128(roundKeys[8]);
                    roundKeys[9] = _mm_aesimc_si128(roundKeys[9]);

                }
                memset(&temp1, 0, sizeof(__m128i));
                memset(&temp2, 0, sizeof(__m128i));
                return;
            } else if (len == 24) {
                __m128i temp1, temp2, temp3, temp4;

                temp1 = _mm_loadu_si128((__m128i *) key);
                temp3 = _mm_loadu_si128((__m128i *) (key + 16));
                roundKeys[0] = temp1;
                roundKeys[1] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x1);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);


                roundKeys[1] = (__m128i) _mm_shuffle_pd((__m128d) roundKeys[1],
                                                        (__m128d) temp1, 0);
                roundKeys[2] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x2);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                roundKeys[3] = temp1;
                roundKeys[4] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x4);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);

                roundKeys[4] = (__m128i) _mm_shuffle_pd((__m128d) roundKeys[4],
                                                        (__m128d) temp1, 0);
                roundKeys[5] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


                roundKeys[4] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(roundKeys[4]),
                                                               _mm_castsi128_pd(temp1), 0));
                roundKeys[5] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 1));


                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x8);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                roundKeys[6] = temp1;
                roundKeys[7] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x10);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);


                roundKeys[7] = (__m128i) _mm_shuffle_pd((__m128d) roundKeys[7],
                                                        (__m128d) temp1, 0);
                roundKeys[8] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x20);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                roundKeys[9] = temp1;
                roundKeys[10] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x40);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);


                roundKeys[10] = (__m128i) _mm_shuffle_pd((__m128d) roundKeys[10],
                                                         (__m128d) temp1, 0);
                roundKeys[11] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x80);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                roundKeys[12] = temp1;

                if (!encrypting) {
                    roundKeys[1] = _mm_aesimc_si128(roundKeys[1]);
                    roundKeys[2] = _mm_aesimc_si128(roundKeys[2]);
                    roundKeys[3] = _mm_aesimc_si128(roundKeys[3]);
                    roundKeys[4] = _mm_aesimc_si128(roundKeys[4]);
                    roundKeys[5] = _mm_aesimc_si128(roundKeys[5]);
                    roundKeys[6] = _mm_aesimc_si128(roundKeys[6]);
                    roundKeys[7] = _mm_aesimc_si128(roundKeys[7]);
                    roundKeys[8] = _mm_aesimc_si128(roundKeys[8]);
                    roundKeys[9] = _mm_aesimc_si128(roundKeys[9]);
                    roundKeys[10] = _mm_aesimc_si128(roundKeys[10]);
                    roundKeys[11] = _mm_aesimc_si128(roundKeys[11]);
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
                roundKeys[0] = temp1;
                roundKeys[1] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x01);
                KEY_256_ASSIST_1(&temp1, &temp2);
                roundKeys[2] = temp1;
                KEY_256_ASSIST_2(&temp1, &temp3);
                roundKeys[3] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x02);
                KEY_256_ASSIST_1(&temp1, &temp2);
                roundKeys[4] = temp1;
                KEY_256_ASSIST_2(&temp1, &temp3);
                roundKeys[5] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x04);
                KEY_256_ASSIST_1(&temp1, &temp2);
                roundKeys[6] = temp1;
                KEY_256_ASSIST_2(&temp1, &temp3);
                roundKeys[7] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x08);
                KEY_256_ASSIST_1(&temp1, &temp2);
                roundKeys[8] = temp1;
                KEY_256_ASSIST_2(&temp1, &temp3);
                roundKeys[9] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x10);
                KEY_256_ASSIST_1(&temp1, &temp2);
                roundKeys[10] = temp1;
                KEY_256_ASSIST_2(&temp1, &temp3);
                roundKeys[11] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x20);
                KEY_256_ASSIST_1(&temp1, &temp2);
                roundKeys[12] = temp1;
                KEY_256_ASSIST_2(&temp1, &temp3);
                roundKeys[13] = temp3;
                temp2 = _mm_aeskeygenassist_si128 (temp3, 0x40);
                KEY_256_ASSIST_1(&temp1, &temp2);
                roundKeys[14] = temp1;

                if (!encrypting) {
                    roundKeys[1] = _mm_aesimc_si128(roundKeys[1]);
                    roundKeys[2] = _mm_aesimc_si128(roundKeys[2]);
                    roundKeys[3] = _mm_aesimc_si128(roundKeys[3]);
                    roundKeys[4] = _mm_aesimc_si128(roundKeys[4]);
                    roundKeys[5] = _mm_aesimc_si128(roundKeys[5]);
                    roundKeys[6] = _mm_aesimc_si128(roundKeys[6]);
                    roundKeys[7] = _mm_aesimc_si128(roundKeys[7]);
                    roundKeys[8] = _mm_aesimc_si128(roundKeys[8]);
                    roundKeys[9] = _mm_aesimc_si128(roundKeys[9]);
                    roundKeys[10] = _mm_aesimc_si128(roundKeys[10]);
                    roundKeys[11] = _mm_aesimc_si128(roundKeys[11]);
                    roundKeys[12] = _mm_aesimc_si128(roundKeys[12]);
                    roundKeys[13] = _mm_aesimc_si128(roundKeys[13]);

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


