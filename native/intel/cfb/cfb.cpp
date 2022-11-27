
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

            auto *fb = (unsigned char *) (&feedback);

            // TODO use separate instance of class that does either decryption or encryption
            if (encryption) {
                for (auto ptr = src; ptr < end;) {

                    if (byteCount == 0) {
                        encryptBlock(feedback, feedback);
                    }

                    if (byteCount >= 0 || end - ptr < CFB_BLOCK_SIZE) {
                        *dest = fb[byteCount] ^ *ptr;
                        fb[byteCount++] = *dest;
                        dest++;
                        ptr++;
                        if (byteCount == CFB_BLOCK_SIZE) {
                            byteCount = 0;
                        }
                    } else {

                        auto data = _mm_loadu_si128((__m128i *) ptr);
                        feedback = _mm_xor_si128(data, feedback);
                        _mm_storeu_si128((__m128i *) dest, feedback);

                        dest += CFB_BLOCK_SIZE;
                        ptr += CFB_BLOCK_SIZE;
                    }
                }
            } else {
                for (auto ptr = src; ptr < end;) {

                    if (byteCount == 0) {
                        encryptBlock(feedback, feedback);
                    }

                    if (byteCount >= 0 || end - ptr < CFB_BLOCK_SIZE) {

                        *dest = *ptr ^ fb[byteCount];
                        fb[byteCount++] = *ptr;
                        dest++;
                        ptr++;
                        if (byteCount == CFB_BLOCK_SIZE) {
                            byteCount = 0;
                        }
                    } else {

                        auto data = _mm_loadu_si128((__m128i *) ptr);
                        feedback = _mm_xor_si128(data, feedback);
                        _mm_storeu_si128((__m128i *) dest, feedback);
                        feedback = data;
                        dest += CFB_BLOCK_SIZE;
                        ptr += CFB_BLOCK_SIZE;
                    }
                }
            }

            return dest - destStart;
        }

        jbyte CFB::processByte(unsigned char in) {

            if (byteCount == 0) {
                encryptBlock(feedback, feedback);
            }

            auto *fb = (unsigned char *) (&feedback);

            unsigned char out;

            if (encryption) {
                out = fb[byteCount] ^ in;
                fb[byteCount++] = out;
            } else {
                out = fb[byteCount] ^ in;
                fb[byteCount++] = in;
            }

            if (byteCount == CFB_BLOCK_SIZE) {
                byteCount = 0;
            }
            return out;
        }

    }
}
