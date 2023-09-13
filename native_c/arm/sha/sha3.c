//
//

#include <stdlib.h>
#include <assert.h>
#include <memory.h>
#include "sha3.h"
#include <stdbool.h>
#include "../keccak/keccak.h"


static const uint64_t K[] = {
        0x0000000000000001UL, 0x0000000000008082UL,
        0x800000000000808aUL, 0x8000000080008000UL,
        0x000000000000808bUL, 0x0000000080000001UL,
        0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008aUL, 0x0000000000000088UL,
        0x0000000080008009UL, 0x000000008000000aUL,
        0x000000008000808bUL, 0x800000000000008bUL,
        0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL,
        0x000000000000800aUL, 0x800000008000000aUL,
        0x8000000080008081UL, 0x8000000000008080UL,
        0x0000000080000001UL, 0x8000000080008008UL
};


sha3_ctx *sha3_create_ctx(int bitLen) {
    assert(bitLen == 224 || bitLen == 256 || bitLen == 384 || bitLen == 512);
    sha3_ctx *ptr = calloc(1, sizeof(sha3_ctx));
    assert(ptr != NULL);
    ptr->bitLen = (uint32_t) bitLen;
    ptr->rate = 1600 - ((uint32_t) bitLen << 1);
    sha3_reset(ptr);
    return ptr;
}

void sha3_free_ctx(sha3_ctx *ctx) {
    memset(ctx, 0, sizeof(sha3_ctx));
    free(ctx);
}

void sha3_reset(sha3_ctx *ctx) {
    ctx->ident = SHA3_MAGIC;
    ctx->buf_index = 0;
    ctx->byteCount = 0;
    ctx->rate_bytes = ctx->rate >> 3;
    memset(ctx->state, 0, sizeof(uint64_t) * STATE_LEN);
    memset(ctx->buf, 0, BUF_SIZE_SHA3);
    ctx->squeezing = false;
}

void sha3_update_byte(sha3_ctx *ctx, uint8_t b) {
    assert(!ctx->squeezing);
    const size_t rateBytes = ctx->rate_bytes;
    ctx->buf[ctx->buf_index++] = b;
    ctx->byteCount++;
    if (ctx->buf_index == rateBytes) {
        keccak_absorb_buf((uint8x8_t *) ctx->state, ctx->buf, rateBytes, K);
        ctx->buf_index = 0;
    }
}

void sha3_update(sha3_ctx *ctx, uint8_t *input, size_t len) {
    assert(!ctx->squeezing);
    const size_t rateBytes = ctx->rate_bytes;
    const size_t remaining = rateBytes - ctx->buf_index;

    if (ctx->buf_index != 0) {
        const size_t toCopy = remaining > len ? len : remaining;
        memcpy(&ctx->buf[ctx->buf_index], input, toCopy);
        ctx->buf_index += toCopy;
        len -= toCopy;
        input += toCopy;
        if (ctx->buf_index == rateBytes) {
            keccak_absorb_buf((uint8x8_t *) ctx->state, ctx->buf, rateBytes, K);
            ctx->buf_index = 0;
        }
    }

    while (len >= rateBytes) {
        keccak_absorb_buf((uint8x8_t *) ctx->state, input, rateBytes, K);
        input += rateBytes;
        len -= rateBytes;
    }

    if (len > 0) {
        memcpy(ctx->buf, input, len);
        ctx->buf_index += len;
        if (ctx->buf_index == rateBytes) {
            keccak_absorb_buf((uint8x8_t *) ctx->state, ctx->buf, rateBytes, K);
            ctx->buf_index = 0;
        }
    }

    ctx->byteCount += len;
}

void sha3_digest(sha3_ctx *ctx, uint8_t *output) {
    ctx->squeezing = true;
    size_t rateBytes = ctx->rate_bytes;
    const size_t toClear = rateBytes - ctx->buf_index;

    // Padding will be set up inside the buffer so
    // we need to zero out any unused buffer first.
    // TODO add padding to state directly.
    memset(ctx->buf + ctx->buf_index, 0, toClear); // clear to end of buffer
    switch (ctx->bitLen) {
        case 224:
        case 256:
        case 384:
        case 512:
            ctx->buf[ctx->buf_index] = 0x06;
            break;

    }

    ctx->buf[rateBytes - 1] |= 128;

    uint8_t *p = ctx->buf;
    uint8x8_t tmp;
    uint8x8_t *state = (uint8x8_t *) ctx->state;
    for (int i = 0; i < rateBytes >> 3; i++) {
        tmp = vld1_u8(p);
        tmp = veor_u8(vld1_u8((void *) state), tmp); // eor into state
        vst1_u8((void *) state, tmp);
        state++;
        p += 8;
    }


    uint8x8_t *s = (uint8x8_t *) ctx->state;
    KF1600_StatePermute(ctx->state, K);

    memcpy(output, ctx->state, ctx->bitLen / 8);
}

uint32_t sha3_getSize(sha3_ctx *ctx) {
    return ctx->bitLen >> 3;
}

uint32_t sha3_getByteLen(sha3_ctx *ctx) {
    return ctx->rate >> 3;
}

bool sha3_restoreFullState(sha3_ctx *ctx, const uint8_t *oldState) {
    sha3_ctx newState;
    memcpy(&newState, oldState, sizeof(sha3_ctx));

    if (newState.ident != SHA3_MAGIC) {
        return false;
    }

    switch (newState.bitLen) {
        case 224:
        case 256:
        case 384:
        case 512:
            break;
        default:
            return false;
    }

    // Recalculate these
    newState.rate = 1600 - ((uint32_t) newState.bitLen << 1);
    newState.rate_bytes = newState.rate >> 3;

    if (newState.buf_index >= BUF_SIZE_SHA3) {
        return false;
    }

    *ctx = newState;

    return true;
}

size_t sha3_encodeFullState(const sha3_ctx *ctx, uint8_t *output) {
    memcpy(output, ctx, sizeof(sha3_ctx));
    return sizeof(sha3_ctx);
}