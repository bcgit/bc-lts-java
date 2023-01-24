#ifndef BCN_CFB128WIDE_H
#define BCN_CFB128WIDE_H

#include <immintrin.h>
#include <cstddef>
#include <cstdint>
#include <jni_md.h>
#include "CFBLike.h"

#define CFB_BLOCK_SIZE 16

namespace intel {

    namespace cfb {

        class CFB128Wide : public CFBLike {
        private:
            CFB128Wide & operator=(CFB128Wide const&);

        protected:
            __m128i *roundKeys;
            __m128i feedback;
            __m128i initialFeedback;
            int byteCount;



            virtual void encryptBlock(__m128i in, __m128i &out) = 0;



        public:

            CFB128Wide(const CFB128Wide &) = delete;

            CFB128Wide();

            ~CFB128Wide() override;

            void init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) override;

            void reset() override;

            size_t processBytes(unsigned char *src, size_t len, unsigned char *dest) override = 0;

            unsigned char processByte(unsigned char in) override = 0;


        };

    }
}


#endif //BCN_CFB128WIDE_H
