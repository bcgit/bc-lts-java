//
// Created on 12/14/22.
//



#ifndef BCN_CFBLIKE_H
#define BCN_CFBLIKE_H


#include <cstddef>

namespace intel {

    namespace cfb {

        class CFBLike {


        public:

            CFBLike() = default;

            virtual ~CFBLike() = 0;

            virtual void
            init(unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) = 0;

            virtual void reset() = 0;

            virtual size_t processBytes(unsigned char *src, size_t len, unsigned char *dest) = 0;

            virtual unsigned char processByte(unsigned char in) = 0;

        };
    }
}

#endif //BCN_CFBLIKE_H
