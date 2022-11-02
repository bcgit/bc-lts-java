//
// Created by 25/7/2022.
//

#include <stdexcept>
#include <cstring>
#include <iostream>
#include "CBCNarrow.h"
#include "AesCBCNarrow.h"
#include "../../debug.h"


namespace intel {
    namespace cbc {


        CBCNarrow::CBCNarrow():CBCLike() {
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
        }

        CBCNarrow::~CBCNarrow() {
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
        }

        void CBCNarrow::init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) {
            feedback = _mm_loadu_si128((__m128i *) (iv));
            initialFeedback = feedback;
            initKey(key, keylen);
        }

        void CBCNarrow::reset() {
            feedback = initialFeedback;
        }

        uint32_t CBCNarrow::getMultiBlockSize() {
            return CBC_BLOCK_SIZE;
        }


    }


}


