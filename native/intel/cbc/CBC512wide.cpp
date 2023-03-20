//
// Created by 25/7/2022.
//


#include <immintrin.h>
#include "CBC512wide.h"
#include "../../macro.h"
#include <cstring>
#include <iostream>
#include "../common.h"


namespace intel {
    namespace cbc {


        CBC512wide::CBC512wide() : CBCLike() {
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
            roundKeys = new __m128i[15];
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            feedbackCtrl = _mm512_set_epi64(5, 4, 3, 2, 1, 0, 9, 8);

        }

        CBC512wide::~CBC512wide() {
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            delete[] roundKeys;
        }

        void CBC512wide::init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) {
            feedback = _mm_loadu_si128((__m128i * )(iv));
            initialFeedback = feedback;

            switch (keylen) {
                case 16:
                    init_128(roundKeys,key, false);
                    break;
                case 24:
                    init_192(roundKeys,key, false);
                    break;
                case 32:
                    init_256(roundKeys,key, false);
                    break;
                default:
                    std::cerr << "Invalid key size passed to lowest level of CBC512wide" << __FUNCTION__ << std::flush
                              << std::endl;
                    abort();
            }

        }

        void CBC512wide::reset() {
            feedback = initialFeedback;
        }

        uint32_t CBC512wide::getMultiBlockSize() {
            return CBC_BLOCK_SIZE * 16;
        }


    }


}



