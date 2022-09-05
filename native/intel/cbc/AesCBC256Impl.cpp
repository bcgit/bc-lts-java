//
// Created  on 7/6/2022.
//

#include <emmintrin.h>
#include <wmmintrin.h>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include "AesCBC.h"
#include "CBC.h"


namespace intel {
    namespace cbc {


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


        //
        // AES CBC 128 Encryption
        //

        AesCBC256Enc::AesCBC256Enc() : CBC() {

        }

        AesCBC256Enc::~AesCBC256Enc() = default;


        void AesCBC256Enc::init(unsigned char *key) {
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

            memset(&temp1, 0, sizeof(__m128i));
            memset(&temp2, 0, sizeof(__m128i));
            memset(&temp3, 0, sizeof(__m128i));
        }

        void AesCBC256Enc::xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) {
            auto tmp = _mm_xor_si128(data, feedback);
            tmp = _mm_xor_si128(tmp, roundKeys[0]);

            tmp = _mm_aesenc_si128(tmp, roundKeys[1]);
            tmp = _mm_aesenc_si128(tmp, roundKeys[2]);
            tmp = _mm_aesenc_si128(tmp, roundKeys[3]);
            tmp = _mm_aesenc_si128(tmp, roundKeys[4]);
            tmp = _mm_aesenc_si128(tmp, roundKeys[5]);
            tmp = _mm_aesenc_si128(tmp, roundKeys[6]);
            tmp = _mm_aesenc_si128(tmp, roundKeys[7]);
            tmp = _mm_aesenc_si128(tmp, roundKeys[8]);
            tmp = _mm_aesenc_si128(tmp, roundKeys[9]);
            tmp = _mm_aesenc_si128(tmp, roundKeys[10]);
            tmp = _mm_aesenc_si128(tmp, roundKeys[11]);
            tmp = _mm_aesenc_si128(tmp, roundKeys[12]);
            tmp = _mm_aesenc_si128(tmp, roundKeys[13]);

            result = _mm_aesenclast_si128(tmp, roundKeys[14]);
            feedback = result;
        }

        //
        // AES CBC 128 Decryption
        //
        AesCBC256Dec::AesCBC256Dec() : CBC() {

        }

        AesCBC256Dec::~AesCBC256Dec() = default;


        void AesCBC256Dec::init(unsigned char *key) {
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

            memset(&temp1, 0, sizeof(__m128i));
            memset(&temp2, 0, sizeof(__m128i));
            memset(&temp3, 0, sizeof(__m128i));
        }

        void AesCBC256Dec::xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) {
            auto tmp = _mm_xor_si128(data, roundKeys[14]);

            tmp = _mm_aesdec_si128(tmp, roundKeys[13]);
            tmp = _mm_aesdec_si128(tmp, roundKeys[12]);
            tmp = _mm_aesdec_si128(tmp, roundKeys[11]);
            tmp = _mm_aesdec_si128(tmp, roundKeys[10]);
            tmp = _mm_aesdec_si128(tmp, roundKeys[9]);
            tmp = _mm_aesdec_si128(tmp, roundKeys[8]);
            tmp = _mm_aesdec_si128(tmp, roundKeys[7]);
            tmp = _mm_aesdec_si128(tmp, roundKeys[6]);
            tmp = _mm_aesdec_si128(tmp, roundKeys[5]);
            tmp = _mm_aesdec_si128(tmp, roundKeys[4]);
            tmp = _mm_aesdec_si128(tmp, roundKeys[3]);
            tmp = _mm_aesdec_si128(tmp, roundKeys[2]);
            tmp = _mm_aesdec_si128(tmp, roundKeys[1]);

            tmp = _mm_aesdeclast_si128(tmp, roundKeys[0]);
            result = _mm_xor_si128(tmp, feedback);
            feedback = data;
        }


    }
}


