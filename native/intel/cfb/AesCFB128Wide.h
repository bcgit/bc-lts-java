

#include "CFB128Wide.h"

#ifndef BCN_AESCFB_H
#define BCN_AESCFB_H

#endif //BCN_AESCFB_H


namespace intel {
    namespace cfb {


        class AesCFB128Dec : public CFB128Wide {
        private:
            AesCFB128Dec & operator=(AesCFB128Dec const&);

        protected:


            void encryptBlock(__m128i in, __m128i &out) override;


        public:
            AesCFB128Dec(const AesCFB128Dec &) = delete;
            AesCFB128Dec();

            ~AesCFB128Dec() override;

            size_t processBytes(unsigned char *src, size_t len, unsigned char *dest) override;

            unsigned char processByte(unsigned char in) override;

        };

        class AesCFB192Dec : public AesCFB128Dec {
        private:
            AesCFB192Dec & operator=(AesCFB192Dec const&);

        protected:


            void encryptBlock(__m128i in, __m128i &out) override;

        public:
            AesCFB192Dec(const AesCFB192Dec &) = delete;
            AesCFB192Dec();
            ~AesCFB192Dec() override;

        };

        class AesCFB256Dec : public AesCFB128Dec {
        private:
            AesCFB256Dec & operator=(AesCFB256Dec const&);

        protected:
            void encryptBlock(__m128i in, __m128i &out) override;
        public:
            AesCFB256Dec(const AesCFB256Dec &) = delete;
            AesCFB256Dec();
            ~AesCFB256Dec() override;

        };

        //
        // Encryption
        //



        class AesCFB128Enc : public CFB128Wide {
        private:
            AesCFB128Enc & operator=(AesCFB128Enc const&);
            void encryptBlock(__m128i in, __m128i &out) override;


        public:
            AesCFB128Enc(const AesCFB128Enc &) = delete;
            AesCFB128Enc();

            ~AesCFB128Enc() override;

            size_t processBytes(unsigned char *src, size_t len, unsigned char *dest) override;

            unsigned char processByte(unsigned char in) override;

        };

        class AesCFB192Enc : public AesCFB128Enc {
        private:
            AesCFB192Enc & operator=(AesCFB192Enc const&);

        protected:
            void encryptBlock(__m128i in, __m128i &out) override;
        public:
            AesCFB192Enc(const AesCFB192Enc &) = delete;
            AesCFB192Enc();
            ~AesCFB192Enc() override;

        };


        class AesCFB256Enc : public AesCFB128Enc {
        private:
            AesCFB256Enc & operator=(AesCFB256Enc const&);
        protected:
            void encryptBlock(__m128i in, __m128i &out) override;

        public:
            AesCFB256Enc(const AesCFB256Enc &) = delete;
            AesCFB256Enc();
            ~AesCFB256Enc() override;
        };






    }
}