//
// Created on 22/7/2022.
//

#ifndef BC_FIPS_ECB_H
#define BC_FIPS_ECB_H

#include <cstddef>
#include <cstdint>
#include <immintrin.h>


#define ECB_BLOCK_SIZE 16
#define ECB_BLOCK_SIZE_2 32
#define ECB_BLOCK_SIZE_4 64

namespace intel {
    namespace ecb {

/**
 * Interface for all ECB variants.
 */
        class ECB {

        public:

            ECB();

            virtual ~ECB() = 0;

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
