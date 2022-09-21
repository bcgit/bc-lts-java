//
// Created by MEGAN WOODS on 20/9/2022.
//

#include "cfb.h"
#include <cstring>
#include <iostream>

namespace intel {
    namespace cfb {


        CFB::CFB() {
            roundKeys = new __m128i[15];
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
            byteCount = 0;
        }

        CFB::~CFB() {
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            delete[] roundKeys;
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
        }

        void CFB::init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) {

            byteCount = 0;
            feedback = _mm_loadu_si128((__m128i *) (iv));
            initialFeedback = feedback;

            // key was not null so set up transformation.
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            init(key);

        }

        void CFB::reset() {
            feedback = initialFeedback;
        }


        size_t CFB::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;

            for (int t = 0; t < blocks; t++) {

                auto data = _mm_loadu_si128((__m128i *) in);
                auto result = _mm_setzero_si128();

                xform(data, roundKeys, result, feedback);

                _mm_storeu_si128((__m128i *) out, result);

                in += CFB_BLOCK_SIZE;
                out += CFB_BLOCK_SIZE;
            }

            return out - outStart;
        }

    }
}
