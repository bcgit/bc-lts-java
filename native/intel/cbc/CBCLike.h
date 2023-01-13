
#ifndef BCN_CBCLIKE_H
#define BCN_CBCLIKE_H

#include <cstddef>
#include <cstdint>
#include <emmintrin.h>

#define CBC_BLOCK_SIZE 16
#define CBC_BLOCK_SIZE_2 32
#define CBC_BLOCK_SIZE_4 64

namespace intel {


    namespace cbc {
        class CBCLike {
        protected:


        public:

            CBCLike() = default;

            virtual ~CBCLike() = 0;

            virtual void init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) = 0;

            virtual void reset() = 0;

            virtual uint32_t getMultiBlockSize() = 0;

            virtual size_t processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) = 0;

        };
    }
}

#endif //BCN_CBCLIKE_H
