//
//

#include <assert.h>
#include <string.h>
#include "ecb.h"
#include "../common.h"

ecb_ctx *ecb_create_ctx() {
    ecb_ctx *b = calloc(1, sizeof(ecb_ctx));
    assert(b != NULL);
    return b;
}

void ecb_free_ctx(ecb_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    memset(ctx,0, sizeof(ecb_ctx));
    free(ctx);
}

void ecb_reset(ecb_ctx *ctx) {
    // no action.
}

void ecb_init(ecb_ctx *pCtx, uint8_t *key) {
    assert(pCtx != NULL);
    memset(pCtx->roundKeys, 0, sizeof(__m128i)*15);
    switch (pCtx->num_rounds) {
        case ROUNDS_128:
            init_128(pCtx->roundKeys, key, pCtx->encryption);
            break;
        case ROUNDS_192:
            init_192(pCtx->roundKeys, key, pCtx->encryption);
            break;
        case ROUNDS_256:
            init_256(pCtx->roundKeys, key, pCtx->encryption);
            break;
        default:
            // it technically cannot hit here but if it does, we need to exit hard.
            assert(0);
    }

}