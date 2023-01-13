//
// Created  on 7/6/2022.
//

#ifndef BCFIPS_0_0_CBC256wide_H
#define BCFIPS_0_0_CBC256wide_H


#include <emmintrin.h>
#include <wmmintrin.h>
#include <jni_md.h>
#include <immintrin.h>
#include "CBC128wide.h"


namespace intel {
    namespace cbc {


        class CBC256wide: protected CBCLike {
        private:
            CBC256wide & operator=(CBC256wide const&);

        protected:
            __m128i feedback;
            __m128i initialFeedback;
            __m256i *roundKeys;
            bool encrypting;


            void initKey(unsigned char *key, size_t len);

        public:

            CBC256wide(const CBC256wide &) = delete;

            CBC256wide();

            ~CBC256wide() override;

             void init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) override;

            void reset() override;

            uint32_t getMultiBlockSize() override;

//            size_t processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) override = 0;


        };




    }
}

#endif //BCFIPS_0_0_AESCBC_H
