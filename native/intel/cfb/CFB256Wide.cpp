
#include "CFB256Wide.h"
#include <cstring>
#include <iostream>
#include "../common.h"

namespace intel {
    namespace cfb {


        CFB256Wide::CFB256Wide() {
            roundKeys256 = new __m256i[15];
            memset(roundKeys256, 0, 15 * sizeof(__m256i));
            roundKeys128 = new __m128i[15];
            memset(roundKeys128, 0, 15 * sizeof(__m128i));
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
            byteCount = 0;
        }

        CFB256Wide::~CFB256Wide() {
            memset(roundKeys256, 0, 15 * sizeof(__m256i));
            delete[] roundKeys256;
            memset(roundKeys128, 0, 15 * sizeof(__m128i));
            delete[] roundKeys128;
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
        }

        void
        CFB256Wide::init(unsigned char *key, unsigned long keylen, unsigned char *iv,
                         unsigned long ivlen) {
            byteCount = 0;
            initialFeedback = _mm_loadu_si128((__m128i *) (iv));
            feedback = initialFeedback;

            memset(roundKeys256, 0, 15 * sizeof(__m256i));
            memset(roundKeys128, 0, sizeof(__m128i) * 15);

            switch (keylen) {
                case 16:
                    init_128(roundKeys128, key, true);
                    break;
                case 24:
                    init_192(roundKeys128, key, true);
                    break;
                case 32:
                    init_256(roundKeys128, key, true);
                    break;
                default:
                    std::cerr << "invalid key size at lowest level of cfb api" << std::endl;
                    abort();
            }

            for (int t = 0; t < 15; t++) {
                roundKeys256[t] = _mm256_set_m128i(roundKeys128[t], roundKeys128[t]);
            }
        }

        void CFB256Wide::reset() {
            feedback = initialFeedback;
            byteCount = 0;
        }

    }
}
