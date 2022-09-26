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
        // AES CFB 128 Encryption
        //

        AesCFB128Enc::AesCFB128Enc() : CFB() {

        }

        AesCFB128Enc::~AesCFB128Enc() = default;


        void AesCFB128Enc::init(unsigned char *key) {
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


        void AesCFB128Enc::encryptBlock(__m128i in, __m128i &out) {

            auto tmp = in;
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
            out = _mm_aesenclast_si128(tmp, roundKeys[10]);
        }





    }
}


