//
// Created on 25/7/2022.
//

#ifndef BC_FIPS_CBC128wide_H
#define BC_FIPS_CBC128wide_H


#include <cstddef>
#include <cstdint>
#include "CBCLike.h"



namespace intel {
    namespace cbc {

        class CBC128wide: protected CBCLike {

        private:
            CBC128wide & operator=(CBC128wide const&);

        protected:
            __m128i feedback;
            __m128i initialFeedback;
            __m128i *roundKeys;
            bool encrypting;


        public:

            CBC128wide(CBC128wide const &c) = delete;

            CBC128wide();

            ~CBC128wide() override;

            void init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) override;

            void reset() override;

            uint32_t getMultiBlockSize() override;

            size_t processBlocks(unsigned char *in, uint32_t blocks, unsigned char *out) override =0;


        };

    }
}

#endif //BC_FIPS_CBC_H
