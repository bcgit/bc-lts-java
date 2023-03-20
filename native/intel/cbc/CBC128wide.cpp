//
// Created by 25/7/2022.
//


#include "CBC128wide.h"
#include "../../macro.h"
#include "../common.h"
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
            feedback = _mm_loadu_si128((__m128i * )(iv));
            initialFeedback = feedback;

            switch (keylen) {
                case 16:
                    init_128(roundKeys,key, encrypting);
                    break;
                case 24:
                    init_192(roundKeys,key, encrypting);
                    break;
                case 32:
                    init_256(roundKeys,key, encrypting);
                    break;
                default:
                    std::cerr << "Invalid key size passed to lowest level of CBC128wide" << __FUNCTION__ << std::flush
                              << std::endl;
                    abort();
            }
        }

        void CBC128wide::reset() {
            feedback = initialFeedback;
        }

        uint32_t CBC128wide::getMultiBlockSize() {
            return CBC_BLOCK_SIZE_4;
        }

    }


}


