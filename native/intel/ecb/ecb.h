//
// Created on 22/7/2022.
//

#ifndef BC_FIPS_ECB_H
#define BC_FIPS_ECB_H

#include <cstddef>
#include <cstdint>
#include <emmintrin.h>

#define ECB_TYPE_AES 0
#define ECB_TYPE_AES_AVX 1
#define ECB_TYPE_VAES 2
#define ECB_TYPE_VAES_AVX512VL 3
#define ECB_TYPE_VAES_AVX512VF 4

#define ECB_BLOCK_SIZE 16

namespace intel {
    namespace ecb {

/**
 * Interface for all ECB variants.
 */
        class ECB {
        protected:
            __m128i *roundKeys;
        public:

            ECB();

            virtual ~ECB();

            virtual uint32_t getMultiBlockSize() = 0;

            virtual  void init(unsigned char *key) =0;
//            virtual void init(bool encryption, unsigned char *key, unsigned long key_len) = 0;

            virtual void reset() = 0;

            virtual size_t
            processBlocks(unsigned char *input, size_t in_start, size_t in_len, uint32_t blocks, unsigned char *output,
                          size_t out_start) = 0;
        };



    }
}

#endif //BC_FIPS_ECB_H
