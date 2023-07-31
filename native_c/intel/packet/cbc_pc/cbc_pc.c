//
//
//

#include "cbc_pc.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../../common.h"

packet_err *
cbc_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *iv, uint8_t *p_in,
                      size_t inLen, uint8_t *p_out, size_t *outputLen) {
    __m128i roundKeys[15];
    __m128i chainblock;
    chainblock = _mm_loadu_si128((__m128i *) iv);
    uint32_t num_rounds = generate_key(encryption, key, roundKeys, keysize);
    if (encryption) {

    } else {

    }

    return NULL;
}


static inline void encrypt(__m128i *d0, const __m128i chainblock, __m128i *roundKeys, const int num_rounds) {
    *d0 = _mm_xor_si128(*d0, chainblock);
    *d0 = _mm_xor_si128(*d0, roundKeys[0]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[1]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[2]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[3]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[4]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[5]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[6]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[7]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[8]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[9]);
    *d0 = _mm_aesenclast_si128(*d0, roundKeys[10]);
    if (num_rounds == ROUNDS_192) {
        *d0 = _mm_aesenc_si128(*d0, roundKeys[11]);
        *d0 = _mm_aesenclast_si128(*d0, roundKeys[12]);
    } else if (num_rounds == ROUNDS_256) {
        *d0 = _mm_aesenc_si128(*d0, roundKeys[11]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[12]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[13]);
        *d0 = _mm_aesenclast_si128(*d0, roundKeys[14]);
    } else {
        assert(0);
    }
}


size_t cbc_encrypt(unsigned char *src, uint32_t blocks, unsigned char *dest, __m128i *chainblock, __m128i *roundKeys,
                   int num_rounds) {

    unsigned char *destStart = dest;
    __m128i d0;
    __m128i tmpCb = *chainblock;
    while (blocks > 0) {
        d0 = _mm_loadu_si128((__m128i *) src);
        encrypt(&d0, tmpCb, roundKeys, num_rounds);
        _mm_storeu_si128((__m128i *) dest, d0);
        blocks--;
        src += BLOCK_SIZE;
        dest += BLOCK_SIZE;
        tmpCb = d0;
    }

    *chainblock = tmpCb;

    return (size_t) (dest - destStart);
}




