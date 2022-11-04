//
// Created on 26/7/2022.
//

#ifndef BC_FIPS_GCM_H
#define BC_FIPS_GCM_H

#include "immintrin.h"

#include <cstdint>


namespace intel::gcm {

    static __m128i ONE = _mm_set_epi32(0, 1, 0, 0);


    class GCM {


    public:

        GCM();

        virtual ~GCM();

        virtual void reset(bool keepMac) = 0;

        virtual void init(bool encryption, unsigned char *key, size_t keyLen, unsigned char *nonce, size_t nonceLen,
                          unsigned char *initialText,
                          size_t initialTextLen, size_t macSizeBytes) = 0;


        virtual void processAADBytes(unsigned char *in, size_t inOff, size_t len) = 0;

        virtual size_t getMacLen() = 0;

        virtual void getMac(unsigned char *dest) = 0;

        virtual size_t getOutputSize(size_t len) = 0;

        virtual size_t getUpdateOutputSize(size_t len) = 0;

        virtual void processAADByte(unsigned char in) = 0;

        virtual size_t processByte(unsigned char in, unsigned char *out, size_t outputLen) = 0;

        virtual size_t
        processBytes(unsigned char *in, size_t inOff, size_t len, unsigned char *out, int outOff, size_t outputLen) = 0;

        virtual size_t doFinal(unsigned char *output, size_t outOff, size_t outLen) = 0;

        virtual void setBlocksRemainingDown(int64_t down) = 0;

    };
}


#endif //BC_FIPS_GCM_H
