//
// Created  on 7/6/2022.
//

#ifndef BCFIPS_0_0_CBC512wide_H
#define BCFIPS_0_0_CBC512wide_H


#include <immintrin.h>
#include <jni_md.h>
#include "CBCLike.h"


namespace intel {
    namespace cbc {


        class CBC512wide: protected CBCLike {

        private:
            CBC512wide & operator=(CBC512wide const&);


        protected:
            __m128i feedback;
            __m128i initialFeedback;
            __m512i *roundKeys;
            __m512i feedbackCtrl;


        public:

            CBC512wide(const CBC512wide &) = delete;

            CBC512wide();

            ~CBC512wide() override;

             void init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) override;

            void reset() override;

            uint32_t getMultiBlockSize() override;


        };




    }
}

#endif //BCFIPS_0_0_CBC512wide_H
