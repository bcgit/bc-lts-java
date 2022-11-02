
//
// AES CBC 128 Encryption
//

#include <emmintrin.h>
#include <wmmintrin.h>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include "AesCBCNarrow.h"
#include "CBCNarrow.h"

namespace intel {
    namespace cbc {

        /*
         * CBC Encryption is always one block wide because of the need
         * to use ciphertext as feedback.
         */

        //
        // AES CBC 128 Encryption
        //

        AesCBC128Enc::AesCBC128Enc() : CBCNarrow() {
            encrypting = true;
        }

        AesCBC128Enc::~AesCBC128Enc() = default;

        size_t AesCBC128Enc::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;

            __m128i data;

            for (uint32_t t = 0; t < blocks; t++) {

                data = _mm_loadu_si128((__m128i *) in);
                data = _mm_xor_si128(data, feedback);
                data = _mm_xor_si128(data, roundKeys[0]);
                data = _mm_aesenc_si128(data, roundKeys[1]);
                data = _mm_aesenc_si128(data, roundKeys[2]);
                data = _mm_aesenc_si128(data, roundKeys[3]);
                data = _mm_aesenc_si128(data, roundKeys[4]);
                data = _mm_aesenc_si128(data, roundKeys[5]);
                data = _mm_aesenc_si128(data, roundKeys[6]);
                data = _mm_aesenc_si128(data, roundKeys[7]);
                data = _mm_aesenc_si128(data, roundKeys[8]);
                data = _mm_aesenc_si128(data, roundKeys[9]);
                data = _mm_aesenclast_si128(data, roundKeys[10]);
                feedback = data;
                _mm_storeu_si128((__m128i *) out, data);

                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
            }

            return (size_t)(out - outStart);
        }



        AesCBC192Enc::AesCBC192Enc() : CBCNarrow() {
            encrypting = true;
        }

        AesCBC192Enc::~AesCBC192Enc() = default;

        size_t AesCBC192Enc::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;

            __m128i data;

            for (uint32_t t = 0; t < blocks; t++) {

                data = _mm_loadu_si128((__m128i *) in);
                data = _mm_xor_si128(data, feedback);
                data = _mm_xor_si128(data, roundKeys[0]);
                data = _mm_aesenc_si128(data, roundKeys[1]);
                data = _mm_aesenc_si128(data, roundKeys[2]);
                data = _mm_aesenc_si128(data, roundKeys[3]);
                data = _mm_aesenc_si128(data, roundKeys[4]);
                data = _mm_aesenc_si128(data, roundKeys[5]);
                data = _mm_aesenc_si128(data, roundKeys[6]);
                data = _mm_aesenc_si128(data, roundKeys[7]);
                data = _mm_aesenc_si128(data, roundKeys[8]);
                data = _mm_aesenc_si128(data, roundKeys[9]);
                data = _mm_aesenc_si128(data, roundKeys[10]);
                data = _mm_aesenc_si128(data, roundKeys[11]);
                data = _mm_aesenclast_si128(data, roundKeys[12]);
                feedback = data;
                _mm_storeu_si128((__m128i *) out, data);

                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
            }

            return  (size_t) (out - outStart);
        }


        //
        // AES CBC 256 Encryption
        //

        AesCBC256Enc::AesCBC256Enc() : CBCNarrow() {
            encrypting = true;
        }

        AesCBC256Enc::~AesCBC256Enc() = default;

        size_t AesCBC256Enc::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;

            __m128i data;

            for (uint32_t t = 0; t < blocks; t++) {

                data = _mm_loadu_si128((__m128i *) in);
                data = _mm_xor_si128(data, feedback);
                data = _mm_xor_si128(data, roundKeys[0]);
                data = _mm_aesenc_si128(data, roundKeys[1]);
                data = _mm_aesenc_si128(data, roundKeys[2]);
                data = _mm_aesenc_si128(data, roundKeys[3]);
                data = _mm_aesenc_si128(data, roundKeys[4]);
                data = _mm_aesenc_si128(data, roundKeys[5]);
                data = _mm_aesenc_si128(data, roundKeys[6]);
                data = _mm_aesenc_si128(data, roundKeys[7]);
                data = _mm_aesenc_si128(data, roundKeys[8]);
                data = _mm_aesenc_si128(data, roundKeys[9]);
                data = _mm_aesenc_si128(data, roundKeys[10]);
                data = _mm_aesenc_si128(data, roundKeys[11]);
                data = _mm_aesenc_si128(data, roundKeys[12]);
                data = _mm_aesenc_si128(data, roundKeys[13]);
                data = _mm_aesenclast_si128(data, roundKeys[14]);
                feedback = data;
                _mm_storeu_si128((__m128i *) out, data);

                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
            }

            return (size_t)(out - outStart);
        }


    }
}