//
// Created  on 7/6/2022.
//

#include <immintrin.h>
#include <cstring>
#include "AesCFB256Wide.h"
#include "CFB256Wide.h"


namespace intel {
    namespace cfb {

        //
        // AES CFB128Wide 128 Encryption
        //

        AesCFB128DecVaes::AesCFB128DecVaes() : CFB256Wide() {

        }

        AesCFB128DecVaes::~AesCFB128DecVaes() = default;


        void AesCFB128DecVaes::encryptBlock128(__m128i in, __m128i &out) {
            auto tmp = in;
            tmp = _mm_xor_si128(tmp, roundKeys128[0]);
            tmp = _mm_aesenc_si128(tmp, roundKeys128[1]);
            tmp = _mm_aesenc_si128(tmp, roundKeys128[2]);
            tmp = _mm_aesenc_si128(tmp, roundKeys128[3]);
            tmp = _mm_aesenc_si128(tmp, roundKeys128[4]);
            tmp = _mm_aesenc_si128(tmp, roundKeys128[5]);
            tmp = _mm_aesenc_si128(tmp, roundKeys128[6]);
            tmp = _mm_aesenc_si128(tmp, roundKeys128[7]);
            tmp = _mm_aesenc_si128(tmp, roundKeys128[8]);
            tmp = _mm_aesenc_si128(tmp, roundKeys128[9]);
            out = _mm_aesenclast_si128(tmp, roundKeys128[10]);
        }

        void AesCFB128DecVaes::encryptBlock256(__m256i in, __m256i &out) {
            auto tmp = in;

            tmp = _mm256_xor_si256(tmp, roundKeys256[0]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[1]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[2]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[3]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[4]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[5]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[6]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[7]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[8]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[9]);
            out = _mm256_aesenclast_epi128(tmp, roundKeys256[10]);
        }


        unsigned char AesCFB128DecVaes::processByte(unsigned char in) {
            if (byteCount == 0) {
                encryptBlock128(feedback, feedback);
            }

            auto *fb = (unsigned char *) (&feedback);

            unsigned char out = fb[byteCount] ^ in;
            fb[byteCount++] = in;

            if (byteCount == CFB_BLOCK_SIZE) {
                byteCount = 0;
            }
            return out;
        }

        size_t AesCFB128DecVaes::processBytes(unsigned char *src, size_t len, unsigned char *dest) {
            unsigned char *end = src + len;
            unsigned char *destStart = dest;
            auto *fb = (unsigned char *) (&feedback);

            auto *ptr = src;

            //
            // Deal with partial blocks, we need to round it back up to a full block, if possible.
            // There may have been a call to processByte at any time before passing in a byte array.
            //
            while (byteCount > 0) {
                if (byteCount == 0) {
                    encryptBlock128(feedback, feedback);
                }

                *dest = *ptr ^ fb[byteCount];
                fb[byteCount++] = *ptr;
                dest++;
                ptr++;
                len--;
                if (byteCount == CFB_BLOCK_SIZE) {
                    byteCount = 0;
                }
            }

            //
            // Process 256b double blocks
            // TODO expand to eight blocks, to better utilise CPU.
            while (len > CFB_BLOCK_SIZE_2) {
                __m256i cipherText1 = _mm256_loadu_si256((__m256i *) ptr);
                //
                // Create the first feedback block which is the old feedback and the first block of cipher text.
                //
                __m256i wideFeedback = _mm256_set_m128i(_mm256_extracti128_si256(cipherText1, 0), feedback);
                encryptBlock256(wideFeedback, wideFeedback);
                __m256i d = _mm256_xor_si256(cipherText1, wideFeedback);
                _mm256_storeu_si256((__m256i *) dest, d);
                ptr += CFB_BLOCK_SIZE_2;
                dest += CFB_BLOCK_SIZE_2;
                feedback = _mm256_extracti128_si256(cipherText1, 1);
                len -= CFB_BLOCK_SIZE_2;
            }

            //
            // Process remaining whole blocks
            //
            while (len > CFB_BLOCK_SIZE) {
                //
                // 128 bit blocks
                //
                encryptBlock128(feedback, feedback);
                auto data = _mm_loadu_si128((__m128i *) ptr);
                feedback = _mm_xor_si128(data, feedback);
                _mm_storeu_si128((__m128i *) dest, feedback);
                feedback = data;
                dest += CFB_BLOCK_SIZE;
                ptr += CFB_BLOCK_SIZE;
                len -= CFB_BLOCK_SIZE;
            }

            //
            // Deal with remaining unprocessed bytes.
            //
            while (len > 0) {
                if (byteCount == 0) {
                    encryptBlock128(feedback, feedback);
                }

                *dest = *ptr ^ fb[byteCount];
                fb[byteCount++] = *ptr;
                dest++;
                ptr++;
                len--;
                if (byteCount == CFB_BLOCK_SIZE) {
                    byteCount = 0;
                }
            }

            return (size_t) (dest - destStart);
        }

        void AesCFB192DecVaes::encryptBlock256(__m256i in, __m256i &out) {
            auto tmp = in;
            tmp = _mm256_xor_si256(tmp, roundKeys256[0]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[1]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[2]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[3]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[4]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[5]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[6]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[7]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[8]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[9]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[10]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[11]);
            out = _mm256_aesenclast_epi128(tmp, roundKeys256[12]);
        }

        void AesCFB256DecVaes::encryptBlock256(__m256i in, __m256i &out) {
            auto tmp = in;
            tmp = _mm256_xor_si256(tmp, roundKeys256[0]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[1]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[2]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[3]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[4]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[5]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[6]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[7]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[8]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[9]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[10]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[11]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[12]);
            tmp = _mm256_aesenc_epi128(tmp, roundKeys256[13]);
            out = _mm256_aesenclast_epi128(tmp, roundKeys256[14]);
        }

        AesCFB192DecVaes::AesCFB192DecVaes() : AesCFB128DecVaes() {};

        AesCFB192DecVaes::~AesCFB192DecVaes() = default;

        AesCFB256DecVaes::AesCFB256DecVaes() : AesCFB128DecVaes() {};

        AesCFB256DecVaes::~AesCFB256DecVaes() = default;
    }
}


