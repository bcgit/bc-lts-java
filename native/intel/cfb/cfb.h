#ifndef BCN_CFB_H
#define BCN_CFB_H

#include <cstddef>
#include <cstdint>
#include <emmintrin.h>
#include <jni_md.h>

#define CFB_BLOCK_SIZE 16

namespace intel {

    namespace cfb {

        class CFB {
        protected:
            __m128i *roundKeys;
            __m128i feedback;
            __m128i initialFeedback;
            int byteCount;
            bool encryption;

            virtual void init(unsigned char *key) = 0;

            virtual void encryptBlock(__m128i in, __m128i &out) = 0;


        public:

            CFB();

            virtual ~CFB();

            void
            init(bool encryption, unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen);

            void reset();

            size_t processBytes(unsigned char *src, size_t len, unsigned char *dest);

            jbyte processByte(unsigned char in);


        };

    }
}


#endif //BCN_CFB_H
