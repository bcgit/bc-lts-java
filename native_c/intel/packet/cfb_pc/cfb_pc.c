
#include <assert.h>
#include <memory.h>
#include "cfb_pc.h"
#include "../../common.h"

packet_err *
cfb_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *iv, size_t ivLen, uint8_t *p_in,
                      size_t inLen, uint8_t *p_out, size_t *outputLen) {
    __m128i roundKeys[15];
    __m128i mask = _mm_setzero_si128();
    __m128i feedback = _mm_loadu_si128((__m128i *) iv);
    uint32_t buf_index = 0;
    uint32_t num_rounds = generate_key(true, key, roundKeys, keysize);
    if (encryption) {
        *outputLen = cfb_pc_encrypt(p_in, inLen, p_out, roundKeys, &mask, &feedback, &buf_index, num_rounds);
    } else {
        //
        // The decryption function for each variant is found in cfb128.c, cfb256.c, cfb512.c
        //
        *outputLen = cfb_pc_decrypt(p_in, inLen, p_out, roundKeys, &mask, &feedback, &buf_index, num_rounds);
    }
    return NULL;
}


static inline void
aes128w_cfb128_encrypt(__m128i *d, __m128i *feedback, __m128i *roundKeys, const uint32_t max_rounds) {

//
// Not possible to optimise CFB mode as the need to feedback ciphertexts forces
// serialisation.
//
    *feedback = _mm_xor_si128(*feedback, roundKeys[0]);
    *feedback = _mm_aesenc_si128(*feedback, roundKeys[1]);
    *feedback = _mm_aesenc_si128(*feedback, roundKeys[2]);
    *feedback = _mm_aesenc_si128(*feedback, roundKeys[3]);
    *feedback = _mm_aesenc_si128(*feedback, roundKeys[4]);
    *feedback = _mm_aesenc_si128(*feedback, roundKeys[5]);
    *feedback = _mm_aesenc_si128(*feedback, roundKeys[6]);
    *feedback = _mm_aesenc_si128(*feedback, roundKeys[7]);
    *feedback = _mm_aesenc_si128(*feedback, roundKeys[8]);
    *feedback = _mm_aesenc_si128(*feedback, roundKeys[9]);
    if (max_rounds == 10) {
        *feedback = _mm_aesenclast_si128(*feedback, roundKeys[10]);
    } else if (max_rounds == 12) {
        *feedback = _mm_aesenc_si128(*feedback, roundKeys[10]);
        *feedback = _mm_aesenc_si128(*feedback, roundKeys[11]);
        *feedback = _mm_aesenclast_si128(*feedback, roundKeys[12]);
    } else if (max_rounds == 14) {
        *feedback = _mm_aesenc_si128(*feedback, roundKeys[10]);
        *feedback = _mm_aesenc_si128(*feedback, roundKeys[11]);
        *feedback = _mm_aesenc_si128(*feedback, roundKeys[12]);
        *feedback = _mm_aesenc_si128(*feedback, roundKeys[13]);
        *feedback = _mm_aesenclast_si128(*feedback, roundKeys[14]);
    }
    *d = *feedback = _mm_xor_si128(*feedback, *d);
}


size_t
cfb_pc_encrypt(unsigned char *src, size_t len, unsigned char *dest, __m128i *roundKeys, __m128i *mask,
               __m128i *feedback,
               uint32_t *buf_index, uint32_t num_rounds) {
    unsigned char *destStart = dest;
//    while (buf_index > 0 && len > 0) {
//        *dest = cfb_pc_encrypt_byte(cfb, *src);
//        len--;
//        dest++;
//        src++;
//    }

    // Bulk round.
    while (len >= 16) {
        __m128i d0 = _mm_loadu_si128((__m128i *) src);
        aes128w_cfb128_encrypt(&d0, feedback, roundKeys, num_rounds);
        _mm_storeu_si128((__m128i *) dest, d0);
        dest += 16;
        src += 16;
        len -= 16;
    }

    //
    // load any trailing bytes into the buffer, the expectation is that
    // whatever is passed in has to be encrypted, ideally callers will
    // try and stick to the AES block size for as long as possible.
    //
    while (len > 0) {
        *dest = cfb_pc_encrypt_byte(*src, roundKeys, mask, feedback, buf_index, num_rounds);
        len--;
        dest++;
        src++;
    }

    return (size_t) (dest - destStart);

}

unsigned char
cfb_pc_encrypt_byte(unsigned char b, __m128i *roundKeys, __m128i *mask, __m128i *feedback, uint32_t *buf_index,
                    uint32_t num_rounds) {
    if (*buf_index == 0) {
        // We need to generate a new encrypted feedback block to xor into the data
        *mask = _mm_xor_si128(*feedback, roundKeys[0]);
        int j;
        for (j = 1; j < num_rounds; j++) {
            *mask = _mm_aesenc_si128(*mask, roundKeys[j]);
        }
        *mask = _mm_aesenclast_si128(*mask, roundKeys[j]);
    }
    //
    // incrementally mask becomes the last block of cipher text
    //
    unsigned char r = ((unsigned char *) mask)[*buf_index] ^= b;
    (*buf_index)++;
    if (*buf_index == BLOCK_SIZE) {
        *buf_index = 0;
        *feedback = *mask;
    }
    return r;
}


