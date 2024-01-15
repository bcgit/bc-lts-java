
#include <assert.h>
#ifdef __APPLE__
#include <libc.h>
#else
#include <stdlib.h>
#include <memory.h>
#endif
#include "cbc.h"
#include "../aes/aes_common_neon.h"


cbc_ctx *cbc_create_ctx() {
    cbc_ctx *c = calloc(1, sizeof(cbc_ctx));
    assert(c != NULL);
    return c;
}

void cbc_free_ctx(cbc_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    memzero(ctx, sizeof(cbc_ctx));
    free(ctx);
}

void cbc_reset(cbc_ctx *ctx) {
    assert(ctx != NULL);
    ctx->chain_block = ctx->initial_chain_block;
}

void cbc_init(cbc_ctx *pCtx, unsigned char *key, unsigned char *iv) {
    assert(pCtx != NULL);
    // TODO refactor CBC setup
    switch (pCtx->num_rounds) {
        case ROUNDS_128:
            init_aes_key(&pCtx->key, key, 16, pCtx->encryption);
            break;
        case ROUNDS_192:
            init_aes_key(&pCtx->key, key, 24, pCtx->encryption);
            break;
        case ROUNDS_256:
            init_aes_key(&pCtx->key, key, 32, pCtx->encryption);
            break;
        default:
            assert(0);
    }

    pCtx->initial_chain_block = vld1q_u8(iv);
    cbc_reset(pCtx);
}


static inline void
enc_blocks(const uint8x16_t *rk, uint8x16_t chain_block, uint8x16_t *d0,
           const size_t rounds) {


    *d0 = veorq_u8(*d0, chain_block);

    size_t r = 0;
    for (r = 0; r < rounds - 1; r++) {
        *d0 = vaeseq_u8(*d0, rk[r]);
        *d0 = vaesmcq_u8(*d0);
    }

    const uint8x16_t r0 = rk[r];
    *d0 = vaeseq_u8(*d0, r0);

    const uint8x16_t r1 = rk[r + 1];
    *d0 = veorq_u8(*d0, r1);
}


size_t cbc_encrypt(cbc_ctx *cbc, unsigned char *src, uint32_t blocks, unsigned char *dest) {
    assert(cbc != NULL);
    unsigned char *destStart = dest;
    uint8x16_t d0;
    uint8x16_t tmpCb = cbc->chain_block;
    while (blocks > 0) {
        d0 = vld1q_u8(src);
        enc_blocks(
                cbc->key.round_keys,
                tmpCb,
                &d0,
                cbc->num_rounds);
        vst1q_u8(dest, d0);
        blocks--;
        src += CBC_BLOCK_SIZE;
        dest += CBC_BLOCK_SIZE;
        tmpCb = d0;
    }

    cbc->chain_block = tmpCb;

    return (size_t) (dest - destStart);
}