//
// Created on 25/7/2022.
//

#ifndef BC_FIPS_CBC_H
#define BC_FIPS_CBC_H


#include <cstddef>
#include <cstdint>
#include <emmintrin.h>

#define CBC_BLOCK_SIZE 16

namespace intel {
    namespace cbc {

        class CBC {

        protected:
            __m128i *roundKeys;
            __m128i feedback;
            __m128i initialFeedback;

            virtual void init(unsigned char *key) = 0;

            virtual void xform(__m128i data, __m128i *pInt, __m128i &result, __m128i &feedback) = 0;

        public:

            static CBC *makeCBC(int keySize, bool direction);

            CBC();

            virtual ~CBC();

            void init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen);

            void reset();

            uint32_t getMultiBlockSize();

            size_t processBlock(unsigned char *in, uint32_t blocks, unsigned char *out);


        };

    }
}

#endif //BC_FIPS_CBC_H
