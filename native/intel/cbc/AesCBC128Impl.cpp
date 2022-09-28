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


        //
        // AES CBC 128 Encryption
        //

        AesCBC128Enc::AesCBC128Enc() : CBC() {

        }

        AesCBC128Enc::~AesCBC128Enc() = default;


        void AesCBC128Enc::init(unsigned char *key) {
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
        }

        void AesCBC128Enc::xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) {
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

            result = _mm_aesenclast_si128(tmp, roundKeys[10]);
            feedback = result;
        }

        //
        // AES CBC 128 Decryption
        //
        AesCBC128Dec::AesCBC128Dec() : CBC() {

        }

        AesCBC128Dec::~AesCBC128Dec() = default;


        void AesCBC128Dec::init(unsigned char *key) {
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


            roundKeys[1] = _mm_aesimc_si128(roundKeys[1]);
            roundKeys[2] = _mm_aesimc_si128(roundKeys[2]);
            roundKeys[3] = _mm_aesimc_si128(roundKeys[3]);
            roundKeys[4] = _mm_aesimc_si128(roundKeys[4]);
            roundKeys[5] = _mm_aesimc_si128(roundKeys[5]);
            roundKeys[6] = _mm_aesimc_si128(roundKeys[6]);
            roundKeys[7] = _mm_aesimc_si128(roundKeys[7]);
            roundKeys[8] = _mm_aesimc_si128(roundKeys[8]);
            roundKeys[9] = _mm_aesimc_si128(roundKeys[9]);

            memset(&temp1, 0, sizeof(__m128i));
            memset(&temp2, 0, sizeof(__m128i));
        }

        void AesCBC128Dec::xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) {
            auto tmp = _mm_xor_si128(data, roundKeys[10]);
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


