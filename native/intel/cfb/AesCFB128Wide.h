

#include "CFB128Wide.h"

#ifndef BCN_AESCFB_H
#define BCN_AESCFB_H

#endif //BCN_AESCFB_H


namespace intel {
    namespace cfb {


        class AesCFB128Dec : public CFB128Wide {
        protected:


            void encryptBlock(__m128i in, __m128i &out) override;


        public:
            AesCFB128Dec();

            ~AesCFB128Dec() override;

            size_t processBytes(unsigned char *src, size_t len, unsigned char *dest) override;

            unsigned char processByte(unsigned char in) override;

        };

        class AesCFB192Dec : public AesCFB128Dec {
        protected:


            void encryptBlock(__m128i in, __m128i &out) override;

        public:
            AesCFB192Dec();
            ~AesCFB192Dec() override;

        };

        class AesCFB256Dec : public AesCFB128Dec {
        protected:


            void encryptBlock(__m128i in, __m128i &out) override;
        public:
            AesCFB256Dec();
            ~AesCFB256Dec() override;

        };

        //
        // Encryption
        //



        class AesCFB128Enc : public CFB128Wide {
        private:


            void encryptBlock(__m128i in, __m128i &out) override;


        public:
            AesCFB128Enc();

            ~AesCFB128Enc() override;

            size_t processBytes(unsigned char *src, size_t len, unsigned char *dest) override;

            unsigned char processByte(unsigned char in) override;

        };

        class AesCFB192Enc : public AesCFB128Enc {
        protected:


            void encryptBlock(__m128i in, __m128i &out) override;
        public:
            AesCFB192Enc();
            ~AesCFB192Enc() override;

        };


        class AesCFB256Enc : public AesCFB128Enc {
        protected:
            void encryptBlock(__m128i in, __m128i &out) override;

        public:
            AesCFB256Enc();
            ~AesCFB256Enc() override;
        };






    }
}