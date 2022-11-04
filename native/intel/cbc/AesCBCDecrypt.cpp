//
// Created  on 7/6/2022.
//

#include <emmintrin.h>
#include <wmmintrin.h>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include "AesCBCNarrow.h"
#include "CBC128wide.h"


namespace intel {
    namespace cbc {


        //
        // AES CBC 128 Decryption
        //
        AesCBC128Dec::AesCBC128Dec() : CBC128wide() {

        }

        AesCBC128Dec::~AesCBC128Dec() = default;

        size_t AesCBC128Dec::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;

            for (int t = 0; t < blocks; t++) {

                auto data = _mm_loadu_si128((__m128i *) in);
                __m128i tmp = _mm_xor_si128(data, roundKeys[10]);
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

                //result = _mm_xor_si128(tmp, feedback);
                _mm_storeu_si128((__m128i *) out, _mm_xor_si128(tmp, feedback));
                feedback = data;

                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
            }

            return (size_t)(out - outStart);
        }



        //
        // AES CBC 128 Decryption
        //
        AesCBC192Dec::AesCBC192Dec() : CBC128wide() {

        }

        AesCBC192Dec::~AesCBC192Dec() = default;


        size_t AesCBC192Dec::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;

            for (uint32_t t = 0; t < blocks; t++) {

                auto data = _mm_loadu_si128((__m128i *) in);
                __m128i tmp = _mm_xor_si128(data, roundKeys[12]);
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

                //result = _mm_xor_si128(tmp, feedback);
                _mm_storeu_si128((__m128i *) out, _mm_xor_si128(tmp, feedback));
                feedback = data;

                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
            }

            return (size_t)(out - outStart);
        }




        //
        // AES CBC 256 Decryption
        //
        AesCBC256Dec::AesCBC256Dec() : CBC128wide() {

        }

        AesCBC256Dec::~AesCBC256Dec() = default;


        size_t AesCBC256Dec::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;

            for (uint32_t t = 0; t < blocks; t++) {

                auto data = _mm_loadu_si128((__m128i *) in);
                __m128i tmp = _mm_xor_si128(data, roundKeys[14]);
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

                //result = _mm_xor_si128(tmp, feedback);
                _mm_storeu_si128((__m128i *) out, _mm_xor_si128(tmp, feedback));
                feedback = data;

                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
            }

            return (size_t)(out - outStart);
        }


    }
}


