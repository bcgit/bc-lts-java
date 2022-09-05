//
// Created  on 7/6/2022.
//

#ifndef BCFIPS_0_0_AESCBC_H
#define BCFIPS_0_0_AESCBC_H


#include <emmintrin.h>
#include <wmmintrin.h>
#include <jni_md.h>
#include "CBC.h"


namespace intel {
    namespace cbc {


        class AesCBC128Enc : public CBC {
        private:

            void init(unsigned char *key) override;

            void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) override;

        public:
            AesCBC128Enc();

            ~AesCBC128Enc() override;
        };

        class AesCBC128Dec : public CBC {
        private:

            void init(unsigned char *key) override;

            void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) override;

        public:
            AesCBC128Dec();

            ~AesCBC128Dec() override;
        };


        class AesCBC192Enc : public CBC {
        private:

            void init(unsigned char *key) override;

            void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) override;

        public:
            AesCBC192Enc();

            ~AesCBC192Enc() override;
        };

        class AesCBC192Dec : public CBC {
        private:

            void init(unsigned char *key) override;

            void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) override;

        public:
            AesCBC192Dec();

            ~AesCBC192Dec() override;
        };

        class AesCBC256Enc : public CBC {
        private:

            void init(unsigned char *key) override;

            void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) override;

        public:
            AesCBC256Enc();

            ~AesCBC256Enc() override;
        };

        class AesCBC256Dec : public CBC {
        private:

            void init(unsigned char *key) override;

            void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) override;

        public:
            AesCBC256Dec();

            ~AesCBC256Dec() override;
        };

    }
}

#endif //BCFIPS_0_0_AESCBC_H
