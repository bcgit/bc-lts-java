#ifndef BCN_CFB256Wide_H
#define BCN_CFB256Wide_H

#include <cstddef>
#include <cstdint>
#include <immintrin.h>
#include <jni_md.h>
#include "CFBLike.h"

#define CFB_BLOCK_SIZE 16
#define CFB_BLOCK_SIZE_2 32


namespace intel {

    namespace cfb {

        class CFB256Wide : public CFBLike {
        private:
            CFB256Wide & operator=(CFB256Wide const&);

        protected:
            __m256i *roundKeys256;
            __m128i *roundKeys128;
            __m128i feedback;
            __m128i initialFeedback;

            int byteCount;


            virtual void encryptBlock256(__m256i in, __m256i &out) = 0;
            virtual void encryptBlock128(__m128i in, __m128i &out) = 0;


        public:
            CFB256Wide(const CFB256Wide &) = delete;
            CFB256Wide();

            ~CFB256Wide() override;

            void
            init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) override;

            void reset() override;

            virtual size_t processBytes(unsigned char *src, size_t len, unsigned char *dest) override = 0;

            virtual unsigned char processByte(unsigned char in) override = 0;


        };

    }
}


#endif //BCN_CFB256Wide_H
