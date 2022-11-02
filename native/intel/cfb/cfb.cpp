
#include "cfb.h"
#include <cstring>
#include <iostream>
#include <jni_md.h>

namespace intel {
    namespace cfb {


        CFB::CFB() {
            roundKeys = new __m128i[15];
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
            byteCount = 0;
            encryption = false;
        }

        CFB::~CFB() {
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            delete[] roundKeys;
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
        }

        void
        CFB::init(bool encryption, unsigned char *key, unsigned long keylen, unsigned char *iv, unsigned long ivlen) {
            byteCount = 0;
            feedback = _mm_loadu_si128((__m128i *) (iv));
            initialFeedback = feedback;
            this->encryption = encryption;

            memset(roundKeys, 0, 15 * sizeof(__m128i));
            init(key);

        }

        void CFB::reset() {
            feedback = initialFeedback;
        }


        size_t CFB::processBytes(unsigned char *src, size_t len, unsigned char *dest) {


            unsigned char *end = src + len;
            unsigned char *destStart = dest;

            for (auto ptr = src; ptr < end;) {

                if (byteCount == 0) {
                    encryptBlock(feedback, feedback);
                }

                if (byteCount >= 0 && end - ptr < CFB_BLOCK_SIZE) {
                    *dest = ((unsigned char *) &feedback)[byteCount] ^ *ptr;
                    ((unsigned char *) &feedback)[byteCount] = *dest;
                    byteCount++;
                    dest++;
                    ptr++;
                    if (byteCount == CFB_BLOCK_SIZE) {
                        byteCount = 0;
                    }
                } else {
                    if (encryption) {
                        auto data = _mm_loadu_si128((__m128i *) ptr);
                        feedback = _mm_xor_si128(data, feedback);
                        _mm_storeu_si128((__m128i *) dest, feedback);
                    } else {
                        auto data = _mm_loadu_si128((__m128i *) ptr);
                        feedback = _mm_xor_si128(data, feedback);
                        _mm_storeu_si128((__m128i *) dest, feedback);
                        feedback = data;
                    }

                    dest += CFB_BLOCK_SIZE;
                    ptr += CFB_BLOCK_SIZE;
                }
            }
            return (size_t) (dest - destStart);
        }

        jbyte CFB::processByte(unsigned char in) {

            if (byteCount == 0) {
                encryptBlock(feedback, feedback);
            }
            unsigned char out = ((unsigned char *) &feedback)[byteCount] ^ in;

            if (encryption) {
                ((unsigned char *) &feedback)[byteCount] = out;
            } else {
                ((unsigned char *) &feedback)[byteCount] = in;
            }
            byteCount++;
            if (byteCount == CFB_BLOCK_SIZE) {
                byteCount = 0;
            }
            return (jbyte)out;
        }

    }
}
