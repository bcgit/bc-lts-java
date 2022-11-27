//
//

#include "SHA256.h"
#include <immintrin.h>
#include <emmintrin.h>
#include <cstring>
#include <cstdint>
#include <tmmintrin.h>
#include <smmintrin.h>
#include <stdexcept>


namespace intel {
    namespace digest {

        __m128i endianSwap = _mm_set_epi8(
                12, 13, 14, 15,
                8, 9, 10, 11,
                4, 5, 6, 7,
                0, 1, 2, 3);

        Sha256::Sha256() {
            reset();
        }

        Sha256::~Sha256() {
            memset(buf, 0, BUF_SIZE_SHA256);
            _mm_store_si128(&s0, _mm_setzero_si128());
            _mm_store_si128(&s1, _mm_setzero_si128());
            memset(state, 0, 8 * sizeof(uint32_t));
        }

        void Sha256::update(unsigned char b) {
            buf[bufPtr++] = b;
            byteCount++;
            if (bufPtr == BUF_SIZE_SHA256) {
                hashBlock(buf);
                memset(buf, 0, BUF_SIZE_SHA256);
                bufPtr = 0;
            }
        }

        void Sha256::update(unsigned char *val, size_t offset, size_t len) {
            unsigned char *end = val + offset + len;
            unsigned char *start = val + offset;


            if (bufPtr != 0) {

                //
                // Round out buffer.
                //

                size_t rem = BUF_SIZE_SHA256 - bufPtr;
                size_t toCopy = len < rem ? len : rem;
                memcpy(buf + bufPtr, start, toCopy);
                bufPtr += toCopy;
                start += toCopy;
                byteCount += toCopy;

                if (bufPtr == BUF_SIZE_SHA256) {
                    hashBlock(buf);
                    memset(buf, 0, BUF_SIZE_SHA256);
                    bufPtr = 0;
                }

            }

            //
            // Directly process block
            //
            unsigned char *ptr;
            for (ptr = start; end - ptr >= BUF_SIZE_SHA256;) {
                hashBlock(ptr);
                ptr += BUF_SIZE_SHA256;
                byteCount += BUF_SIZE_SHA256;
            }


            //
            // Copy in any trailing bytes that do not fill a block.
            //
            if (end - ptr > 0) {
                size_t rem = BUF_SIZE_SHA256 - bufPtr;
                size_t toCopy = end - ptr < rem ? end - ptr : rem;
                memcpy(buf + bufPtr, ptr, toCopy);
                bufPtr += toCopy;
                byteCount += toCopy;
            }


        }

        void Sha256::digest(unsigned char *out, size_t outOff) {
            size_t bitLen = byteCount << 3;
            size_t padLen = bufPtr < 56 ? 56 - bufPtr : 64 + 56 - bufPtr;
            update((unsigned char *) padBlock, 0, padLen);
            processLength(bitLen);
            hashBlock(buf);


            __m128i tmp = _mm_shuffle_epi32(s0, 0x1B);       /* FEBA */
            s1 = _mm_shuffle_epi32(s1, 0xB1);    /* DCHG */
            s0 = _mm_blend_epi16(tmp, s1, 0xF0); /* DCBA */
            s1 = _mm_alignr_epi8(s1, tmp, 8);    /* ABEF */

            //
            // Save state
            //
            _mm_storeu_si128((__m128i *) &state[0], s0);
            _mm_storeu_si128((__m128i *) &state[4], s1);


            out += outOff;

            _mm_storeu_si128((__m128i *) out, _mm_shuffle_epi8(s0, endianSwap));
            _mm_storeu_si128((__m128i *) (out + 16), _mm_shuffle_epi8(s1, endianSwap));

            reset();
        }

        void Sha256::reset() {
            memset(buf, 0, BUF_SIZE_SHA256);
            bufPtr = 0;
            byteCount = 0;

            state[0] = 0x6a09e667;
            state[1] = 0xbb67ae85;
            state[2] = 0x3c6ef372;
            state[3] = 0xa54ff53a;
            state[4] = 0x510e527f;
            state[5] = 0x9b05688c;
            state[6] = 0x1f83d9ab;
            state[7] = 0x5be0cd19;


            __m128i tmp = _mm_loadu_si128((const __m128i *) &state[0]);
            s1 = _mm_loadu_si128((const __m128i *) &state[4]);

            tmp = _mm_shuffle_epi32(tmp, 0xB1);          /* CDAB */
            s1 = _mm_shuffle_epi32(s1, 0x1B);    /* EFGH */
            s0 = _mm_alignr_epi8(tmp, s1, 8);    /* ABEF */
            s1 = _mm_blend_epi16(s1, tmp, 0xF0); /* CDGH */

        }

        int Sha256::getDigestSize() {
            return SHA256_SIZE;
        }

        int Sha256::getByteLength() {
            return BUF_SIZE_SHA256;
        }

        void Sha256::hashBlock(unsigned char *block) {

            //
            // Adapted on code from Intel and Jeffrey Walton
            //

            __m128i abef_save = s0;
            __m128i cdgh_save = s1;

            __m128i msg;
            __m128i msgTmp0;
            __m128i msg1;
            __m128i msg2;
            __m128i msg3;
            __m128i tmp;


            msg = _mm_loadu_si128((const __m128i *) (block));
            msgTmp0 = _mm_shuffle_epi8(msg, mask);
            msg = _mm_add_epi32(msgTmp0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);

            block += 16;


            msg1 = _mm_loadu_si128((const __m128i *) (block));
            msg1 = _mm_shuffle_epi8(msg1, mask);
            msg = _mm_add_epi32(msg1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            msgTmp0 = _mm_sha256msg1_epu32(msgTmp0, msg1);

            block += 16;


            msg2 = _mm_loadu_si128((const __m128i *) (block));
            msg2 = _mm_shuffle_epi8(msg2, mask);
            msg = _mm_add_epi32(msg2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            block += 16;


            msg3 = _mm_loadu_si128((const __m128i *) (block));
            msg3 = _mm_shuffle_epi8(msg3, mask);
            msg = _mm_add_epi32(msg3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            tmp = _mm_alignr_epi8(msg3, msg2, 4);
            msgTmp0 = _mm_add_epi32(msgTmp0, tmp);
            msgTmp0 = _mm_sha256msg2_epu32(msgTmp0, msg3);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            msg = _mm_add_epi32(msgTmp0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            tmp = _mm_alignr_epi8(msgTmp0, msg3, 4);
            msg1 = _mm_add_epi32(msg1, tmp);
            msg1 = _mm_sha256msg2_epu32(msg1, msgTmp0);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            msg3 = _mm_sha256msg1_epu32(msg3, msgTmp0);

            msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            tmp = _mm_alignr_epi8(msg1, msgTmp0, 4);
            msg2 = _mm_add_epi32(msg2, tmp);
            msg2 = _mm_sha256msg2_epu32(msg2, msg1);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            msgTmp0 = _mm_sha256msg1_epu32(msgTmp0, msg1);

            msg = _mm_add_epi32(msg2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            tmp = _mm_alignr_epi8(msg2, msg1, 4);
            msg3 = _mm_add_epi32(msg3, tmp);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            tmp = _mm_alignr_epi8(msg3, msg2, 4);
            msgTmp0 = _mm_add_epi32(msgTmp0, tmp);
            msgTmp0 = _mm_sha256msg2_epu32(msgTmp0, msg3);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            msg = _mm_add_epi32(msgTmp0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            tmp = _mm_alignr_epi8(msgTmp0, msg3, 4);
            msg1 = _mm_add_epi32(msg1, tmp);
            msg1 = _mm_sha256msg2_epu32(msg1, msgTmp0);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            msg3 = _mm_sha256msg1_epu32(msg3, msgTmp0);

            msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            tmp = _mm_alignr_epi8(msg1, msgTmp0, 4);
            msg2 = _mm_add_epi32(msg2, tmp);
            msg2 = _mm_sha256msg2_epu32(msg2, msg1);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            msgTmp0 = _mm_sha256msg1_epu32(msgTmp0, msg1);

            msg = _mm_add_epi32(msg2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            tmp = _mm_alignr_epi8(msg2, msg1, 4);
            msg3 = _mm_add_epi32(msg3, tmp);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            tmp = _mm_alignr_epi8(msg3, msg2, 4);
            msgTmp0 = _mm_add_epi32(msgTmp0, tmp);
            msgTmp0 = _mm_sha256msg2_epu32(msgTmp0, msg3);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            msg = _mm_add_epi32(msgTmp0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            tmp = _mm_alignr_epi8(msgTmp0, msg3, 4);
            msg1 = _mm_add_epi32(msg1, tmp);
            msg1 = _mm_sha256msg2_epu32(msg1, msgTmp0);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            msg3 = _mm_sha256msg1_epu32(msg3, msgTmp0);

            msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            tmp = _mm_alignr_epi8(msg1, msgTmp0, 4);
            msg2 = _mm_add_epi32(msg2, tmp);
            msg2 = _mm_sha256msg2_epu32(msg2, msg1);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);

            msg = _mm_add_epi32(msg2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            tmp = _mm_alignr_epi8(msg2, msg1, 4);
            msg3 = _mm_add_epi32(msg3, tmp);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);

            msg = _mm_add_epi32(msg3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);

            s0 = _mm_add_epi32(s0, abef_save);
            s1 = _mm_add_epi32(s1, cdgh_save);

        }

        int Sha256::processLength(size_t length) {
            buf[63] = (unsigned char)(length & 0xFF);
            buf[62] = (unsigned char)((length >> 8) & 0xFF);
            buf[61] = (unsigned char)((length >> 16) & 0xFF);
            buf[60] = (unsigned char)((length >> 24) & 0xFF);
            buf[59] = (unsigned char)((length >> 32) & 0xFF);
            buf[58] = (unsigned char)((length >> 40) & 0xFF);
            buf[57] = (unsigned char)((length >> 48) & 0xFF);
            buf[56] = (unsigned char)((length >> 56) & 0xFF);
            return 8;
        }

        void Sha256::encodeState(unsigned char *rawStateBuffer, size_t &length) {

            length = sizeof(SHA256StateType);

            if (rawStateBuffer == nullptr) {
                //
                // Null buffer return after setting encoded length.
                //
                return;
            }

            auto *stateValues = reinterpret_cast<SHA256StateType *>(rawStateBuffer);
            stateValues->type = 1;
            stateValues->bufPtr = bufPtr;
            stateValues->byteCount = byteCount;
            stateValues->s0 = s0;
            stateValues->s1 = s1;
            memcpy(stateValues->buf, buf, BUF_SIZE_SHA256);
        }

        void Sha256::setState(unsigned char *rawState, size_t rawStateLen) {
            if (*rawState != 1) {
                throw std::runtime_error("encoded SHA256 state must start with 1");
            }

            if (rawStateLen != sizeof(SHA256StateType)) {
                throw std::runtime_error("rawStateLen does not equal sizeof native stateType");
            }

            auto *stateValues = reinterpret_cast<SHA256StateType *>(rawState);
            bufPtr = stateValues->bufPtr;
            byteCount = stateValues->byteCount;
            memcpy(buf, stateValues->buf, BUF_SIZE_SHA256);
            s0 = stateValues->s0;
            s1 = stateValues->s1;
        }

    }
}
