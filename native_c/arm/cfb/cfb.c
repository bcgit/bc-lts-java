//
//

#include <assert.h>
#ifdef __APPLE__
#include <libc.h>
#else
#include <stdlib.h>
#include <memory.h>
#endif

#include "cfb.h"
#include "arm_neon.h"

cfb_ctx *cfb_create_ctx() {
    cfb_ctx *ctx = calloc(1, sizeof(cfb_ctx));
    assert(ctx != NULL);
    return ctx;
}

void cfb_free_ctx(cfb_ctx *ctx) {
    memzero(ctx,  sizeof(cfb_ctx));
    free(ctx);
}

void cfb_reset(cfb_ctx *ctx) {
    ctx->feedback = ctx->initialFeedback;
    ctx->buf_index = 0;
    ctx->mask = vdupq_n_u8(0);
}

void cfb_init(cfb_ctx *pCtx, unsigned char *key, unsigned char *iv) {
    assert(pCtx != NULL);

    // TODO refactor..

    switch (pCtx->num_rounds) {
        case ROUNDS_128:
            init_aes_key(&pCtx->key, key, 16, true);
            break;
        case ROUNDS_192:
            init_aes_key(&pCtx->key, key, 24, true);
            break;
        case ROUNDS_256:
            init_aes_key(&pCtx->key, key, 32, true);
            break;
        default:
            // it technically cannot hit here but if it does, we need to exit hard.
            assert(0);
    }

    pCtx->initialFeedback = vld1q_u8(iv);

    cfb_reset(pCtx);

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
        uint8x16_t d0 = vld1q_u8(src);
        uint8x16_t feedback = cfb->feedback;
        single_block(&cfb->key, feedback, &feedback);
        feedback = veorq_u8(feedback, d0);
        vst1q_u8(dest, feedback);
        cfb->feedback = feedback;
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
        single_block(&cfb->key, cfb->feedback, &cfb->mask);
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