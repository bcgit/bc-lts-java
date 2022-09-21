#ifndef BCN_CFB_H
#define BCN_CFB_H

#include <cstddef>
#include <cstdint>
#include <emmintrin.h>

#define CFB_BLOCK_SIZE 16

namespace intel {

    namespace cfb {

        class CFB {
        protected:
            __m128i *roundKeys;
            __m128i feedback;
            __m128i initialFeedback;

            int byteCount;

            virtual void init(unsigned char *key) = 0;

            virtual void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) = 0;


        public:

            CFB();

            virtual ~CFB();

            void init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen);

            void reset();

           virtual size_t processBlock(unsigned char *in, uint32_t blocks, unsigned char *out);

        };

    }
}


#endif //BCN_CFB_H
