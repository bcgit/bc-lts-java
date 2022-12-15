#ifndef BCN_CFB128WIDE_H
#define BCN_CFB128WIDE_H

#include <cstddef>
#include <cstdint>
#include <emmintrin.h>
#include <jni_md.h>
#include "CFBLike.h"

#define CFB_BLOCK_SIZE 16

namespace intel {

    namespace cfb {

        class CFB128Wide : public CFBLike {
        protected:
            __m128i *roundKeys;
            __m128i feedback;
            __m128i initialFeedback;
            int byteCount;



            virtual void encryptBlock(__m128i in, __m128i &out) = 0;



        public:

            CFB128Wide();

            ~CFB128Wide() override;

            void init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) override;

            void reset();

            virtual size_t processBytes(unsigned char *src, size_t len, unsigned char *dest) override = 0;

            virtual unsigned char processByte(unsigned char in) override = 0;


        };

    }
}


#endif //BCN_CFB128WIDE_H
