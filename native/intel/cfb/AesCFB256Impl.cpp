//
// Created  on 7/6/2022.
//

#include <emmintrin.h>
#include <wmmintrin.h>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include "AesCFB.h"
#include "cfb.h"


namespace intel {
    namespace cfb {


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
        // AES CFB 128 Encryption
        //

        AesCFB256Enc::AesCFB256Enc() : CFB() {

        }

        AesCFB256Enc::~AesCFB256Enc() = default;


        void AesCFB256Enc::init(unsigned char *key) {
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


        void AesCFB256Enc::encryptBlock(__m128i in, __m128i &out) {
            auto tmp = _mm_xor_si128(in, roundKeys[0]);
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
            out = _mm_aesenclast_si128(tmp, roundKeys[14]);
        }
    }
}


