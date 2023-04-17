//
//
//

#include "cbc.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../common.h"


cbc_ctx *cbc_create_ctx() {
    cbc_ctx *c = calloc(1, sizeof(cbc_ctx));
    assert(c != NULL);
    return c;
}

void cbc_free_ctx(cbc_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(cbc_ctx));
    free(ctx);
}

void cbc_reset(cbc_ctx *ctx) {
    assert(ctx != NULL);
    ctx->chainblock = ctx->initialChainblock;
}

void cbc_init(cbc_ctx *pCtx, unsigned char *key, unsigned char *iv) {
    assert(pCtx != NULL);
    memset(pCtx->roundKeys, 0, sizeof(__m128i) * 15);
    switch (pCtx->num_rounds) {
        case ROUNDS_128:
            init_128(pCtx->roundKeys, key, pCtx->encryption);
            pCtx->initialChainblock = _mm_loadu_si128((__m128i *) iv);
            pCtx->chainblock = pCtx->initialChainblock;
            break;
        case ROUNDS_192:
            init_192(pCtx->roundKeys, key, pCtx->encryption);
            pCtx->initialChainblock = _mm_loadu_si128((__m128i *) iv);
            pCtx->chainblock = pCtx->initialChainblock;
            break;
        case ROUNDS_256:
            init_256(pCtx->roundKeys, key, pCtx->encryption);
            pCtx->initialChainblock = _mm_loadu_si128((__m128i *) iv);
            pCtx->chainblock = pCtx->initialChainblock;
            break;
        default:
            // it technically cannot hit here but if it does, we need to exit hard.
            assert(0);
    }


}


static inline void encrypt(__m128i *d0, const __m128i chainblock, __m128i *roundKeys, const int num_rounds) {

    if (num_rounds == ROUNDS_128) {
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
    } else if (num_rounds == ROUNDS_192) {
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
        *d0 = _mm_aesenc_si128(*d0, roundKeys[10]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[11]);
        *d0 = _mm_aesenclast_si128(*d0, roundKeys[12]);
    } else if (num_rounds == ROUNDS_256) {
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
        *d0 = _mm_aesenc_si128(*d0, roundKeys[10]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[11]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[12]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[13]);
        *d0 = _mm_aesenclast_si128(*d0, roundKeys[14]);
    } else {
        assert(0);
    }
}


size_t cbc_encrypt(cbc_ctx *cbc, unsigned char *src, uint32_t blocks, unsigned char *dest) {
    assert(cbc != NULL);

    unsigned char *destStart = dest;
    __m128i d0;
    __m128i tmpCb = cbc->chainblock;
    while (blocks > 0) {
        d0 = _mm_loadu_si128((__m128i *) src);
        encrypt(&d0, tmpCb, cbc->roundKeys, cbc->num_rounds);
        _mm_storeu_si128((__m128i *) dest, d0);
        blocks--;
        src += CBC_BLOCK_SIZE;
        dest += CBC_BLOCK_SIZE;
        tmpCb = d0;
    }

    cbc->chainblock = tmpCb;

    return (size_t) (dest - destStart);
}




