
#include "CFB128Wide.h"
#include <cstring>
#include <iostream>
#include <jni_md.h>
#include "../common.h"

namespace intel {
    namespace cfb {


        CFB128Wide::CFB128Wide() {
            roundKeys = new __m128i[15];
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
            byteCount = 0;
        }

        CFB128Wide::~CFB128Wide() {
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            delete[] roundKeys;
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
        }

        void CFB128Wide::init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) {
            byteCount = 0;
            feedback = _mm_loadu_si128((__m128i *) (iv));
            initialFeedback = feedback;


            memset(roundKeys, 0, 15 * sizeof(__m128i));

            switch (keylen) {
                case 16:
                    init_128(roundKeys, key, true);
                    break;
                case 24:
                    init_192(roundKeys, key, true);
                    break;
                case 32:
                    init_256(roundKeys, key, true);
                    break;
                default:
                    std::cerr << "invalid key size at lowest level of cfb api" << std::endl;
                    abort();
            }

        }

        void CFB128Wide::reset() {
            feedback = initialFeedback;
            byteCount = 0;
        }


    }
}
