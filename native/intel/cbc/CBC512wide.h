//
// Created  on 7/6/2022.
//

#ifndef BCFIPS_0_0_CBC512wide_H
#define BCFIPS_0_0_CBC512wide_H


#include <emmintrin.h>
#include <wmmintrin.h>
#include <jni_md.h>
#include <immintrin.h>
#include "CBCLike.h"


namespace intel {
    namespace cbc {


        class CBC512wide: protected CBCLike {

        protected:
            __m128i feedback;
            __m128i initialFeedback;
            __m512i *roundKeys;
            bool encrypting;
            __m512i feedbackCtrl;


        public:



            CBC512wide();

            ~CBC512wide() override;

             void init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) override;

            void reset() override;

            uint32_t getMultiBlockSize() override;

//            size_t processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) override = 0;


        };




    }
}

#endif //BCFIPS_0_0_AESCBC_H
