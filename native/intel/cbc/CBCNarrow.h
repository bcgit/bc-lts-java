//
// Created on 25/7/2022.
//

#ifndef BC_FIPS_CBC_H
#define BC_FIPS_CBC_H


#include <cstddef>
#include <cstdint>
#include <emmintrin.h>
#include "CBCLike.h"

#define CBC_BLOCK_SIZE 16

namespace intel {
    namespace cbc {

        class CBCNarrow: protected CBCLike {

        protected:
            __m128i feedback;
            __m128i initialFeedback;

        public:



            CBCNarrow();

            virtual ~CBCNarrow();

            void init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen);

            void reset();

            uint32_t getMultiBlockSize();

            virtual size_t processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) =0;


        };

    }
}

#endif //BC_FIPS_CBC_H
