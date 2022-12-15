

#include "CFB256Wide.h"

#ifndef BCN_AESCFB_H
#define BCN_AESCFB_H

#endif //BCN_AESCFB_H


namespace intel {
    namespace cfb {


        class AesCFB128DecVaes : public CFB256Wide {
        protected:


            void encryptBlock256(__m256i in, __m256i &out) override;
            void encryptBlock128(__m128i in, __m128i &out) override;

        public:
            AesCFB128DecVaes();

            ~AesCFB128DecVaes() override;

            size_t processBytes(unsigned char *src, size_t len, unsigned char *dest) override;

            unsigned char processByte(unsigned char in) override;

        };

        class AesCFB192DecVaes : public AesCFB128DecVaes {
        protected:


            void encryptBlock256(__m256i in, __m256i &out) override;

        public:
            AesCFB192DecVaes();
            ~AesCFB192DecVaes() override;

        };

        class AesCFB256DecVaes : public AesCFB128DecVaes {
        protected:


            void encryptBlock256(__m256i in, __m256i &out) override;
        public:
            AesCFB256DecVaes();
            ~AesCFB256DecVaes() override;

        };

    }
}