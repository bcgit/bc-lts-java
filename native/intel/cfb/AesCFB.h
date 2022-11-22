

#include "cfb.h"

#ifndef BCN_AESCFB_H
#define BCN_AESCFB_H

#endif //BCN_AESCFB_H


namespace intel {
    namespace cfb {


        class AesCFB128Enc : public CFB {
        private:

            void init(unsigned char *key) override;

            void encryptBlock(__m128i in, __m128i &out) override;


        public:
            AesCFB128Enc();

            ~AesCFB128Enc() override;
        };

        class AesCFB192Enc : public CFB {
        private:

            void init(unsigned char *key) override;

            void encryptBlock(__m128i in, __m128i &out) override;


        public:
            AesCFB192Enc();

            ~AesCFB192Enc() override;
        };


        class AesCFB256Enc : public CFB {
        private:

            void init(unsigned char *key) override;

            void encryptBlock(__m128i in, __m128i &out) override;


        public:
            AesCFB256Enc();

            ~AesCFB256Enc() override;
        };


    }
}