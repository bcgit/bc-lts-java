

#include "cfb.h"

#ifndef BCN_AESCFB_H
#define BCN_AESCFB_H

#endif //BCN_AESCFB_H


namespace intel {
    namespace cfb {


        class AesCFB128Enc : public CFB {
        private:

            void init(unsigned char *key) override;

            void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) override;

        public:
            AesCFB128Enc();

            ~AesCFB128Enc() override;
        };

        class AesCFB128Dec : public CFB {
        private:

            void init(unsigned char *key) override;

            void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) override;

        public:
            AesCFB128Dec();

            ~AesCFB128Dec() override;
        };


        class AesCFB192Enc : public CFB {
        private:

            void init(unsigned char *key) override;

            void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) override;

        public:
            AesCFB192Enc();

            ~AesCFB192Enc() override;
        };

        class AesCFB192Dec : public CFB {
        private:

            void init(unsigned char *key) override;

            void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) override;

        public:
            AesCFB192Dec();

            ~AesCFB192Dec() override;
        };

        class AesCFB256Enc : public CFB {
        private:

            void init(unsigned char *key) override;

            void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) override;

        public:
            AesCFB256Enc();

            ~AesCFB256Enc() override;
        };

        class AesCFB256Dec : public CFB {
        private:

            void init(unsigned char *key) override;

            void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) override;

        public:
            AesCFB256Dec();

            ~AesCFB256Dec() override;
        };

    }
}