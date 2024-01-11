
#include <assert.h>
#include <memory.h>
#include "cfb.h"
#include "../common.h"

cfb_ctx *cfb_create_ctx() {
    cfb_ctx *ctx = calloc(1, sizeof(cfb_ctx));
    assert(ctx != NULL);
    return ctx;
}

void cfb_free_ctx(cfb_ctx *ctx) {
    memzero(ctx, sizeof(cfb_ctx));
    free(ctx);
}

void cfb_reset(cfb_ctx *ctx) {
    ctx->feedback = ctx->initialFeedback;
    ctx->buf_index = 0;
    ctx->mask = _mm_setzero_si128();
}

void cfb_init(cfb_ctx *pCtx, unsigned char *key, unsigned char *iv) {
    assert(pCtx != NULL);
    memzero(pCtx->roundKeys, sizeof(__m128i) * 15);
    switch (pCtx->num_rounds) {
        case ROUNDS_128:
            init_128(pCtx->roundKeys, key, true);
            pCtx->initialFeedback = _mm_loadu_si128((__m128i *) iv);
            break;
        case ROUNDS_192:
            init_192(pCtx->roundKeys, key, true);
            pCtx->initialFeedback = _mm_loadu_si128((__m128i *) iv);
            break;
        case ROUNDS_256:
            init_256(pCtx->roundKeys, key, true);
            pCtx->initialFeedback = _mm_loadu_si128((__m128i *) iv);
            break;
        default:
            // it technically cannot hit here but if it does, we need to exit hard.
            assert(0);
    }

    cfb_reset(pCtx);

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


size_t cfb_encrypt(cfb_ctx *cfb, unsigned char *src, size_t len, unsigned char *dest) {
    unsigned char *destStart = dest;
    //
    // Round out buffer.
    //
    while (cfb->buf_index > 0 && len > 0) {
        *dest = cfb_encrypt_byte(cfb, *src);
        len--;
        dest++;
        src++;
    }


    // Bulk round.
    while (len >= 16) {
        __m128i d0 = _mm_loadu_si128((__m128i *) src);
        aes128w_cfb128_encrypt(&d0, &cfb->feedback, cfb->roundKeys, cfb->num_rounds);
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
        *dest = cfb_encrypt_byte(cfb, *src);
        len--;
        dest++;
        src++;
    }

    return (size_t) (dest - destStart);

}

unsigned char cfb_encrypt_byte(cfb_ctx *cfb, unsigned char b) {
    if (cfb->buf_index == 0) {

        // We need to generate a new encrypted feedback block to xor into the data
        cfb->mask = _mm_xor_si128(cfb->feedback, cfb->roundKeys[0]);
        int j;
        for (j = 1; j < cfb->num_rounds; j++) {
            cfb->mask = _mm_aesenc_si128(cfb->mask, cfb->roundKeys[j]);
        }
        cfb->mask = _mm_aesenclast_si128(cfb->mask, cfb->roundKeys[j]);
    }

    //
    // incrementally mask becomes the last block of cipher text
    //

    unsigned char r = ((unsigned char *) &cfb->mask)[cfb->buf_index] ^= b;

    cfb->buf_index++;
    if (cfb->buf_index == 16) {
        cfb->buf_index = 0;
        cfb->feedback = cfb->mask;
    }

    return r;


}


