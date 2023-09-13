//
//

#include <stdlib.h>
#include <assert.h>
#include <memory.h>
#include "shake.h"
#include <stdbool.h>
#include <printf.h>
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


shake_ctx *shake_create_ctx(int bitLen) {
    assert(bitLen == 128 || bitLen == 256);
    shake_ctx *ptr = calloc(1, sizeof(shake_ctx));
    assert(ptr != NULL);
    ptr->bitLen = (uint32_t) bitLen;
    ptr->rate = 1600 - ((uint32_t) bitLen << 1);
    shake_reset(ptr);
    return ptr;
}

void shake_free_ctx(shake_ctx *ctx) {
    memset(ctx, 0, sizeof(shake_ctx));
    free(ctx);
}

void shake_reset(shake_ctx *ctx) {
    ctx->ident = SHAKE_MAGIC;
    ctx->buf_index = 0;
    ctx->byteCount = 0;
    ctx->rate_bytes = ctx->rate >> 3;
    memset(ctx->state, 0, sizeof(uint64_t) * STATE_LEN);
    memset(ctx->buf, 0, BUF_SIZE_SHAKE);
    ctx->squeezing = false;
}

void shake_update_byte(shake_ctx *ctx, uint8_t b) {
    assert(!ctx->squeezing);
    const size_t rateBytes = ctx->rate_bytes;
    ctx->buf[ctx->buf_index++] = b;
    ctx->byteCount++;
    if (ctx->buf_index == rateBytes) {
        keccak_absorb_buf((uint8x8_t *) ctx->state, ctx->buf, rateBytes, K);
        ctx->buf_index = 0;
    }
}

void shake_update(shake_ctx *ctx, uint8_t *input, size_t len) {
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

void shake_digest(shake_ctx *ctx, uint8_t *output, size_t len) {
    size_t rateBytes = ctx->rate_bytes;
    const size_t toClear = rateBytes - ctx->buf_index;

    // Padding will be set up inside the buffer so
    // we need to zero out any unused buffer first.
    // TODO add padding to state directly.
    memset(ctx->buf + ctx->buf_index, 0, toClear); // clear to end of buffer
    switch (ctx->bitLen) {
        case 128:
        case 256:
            ctx->buf[ctx->buf_index] = 0x1F;
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

    ctx->squeezing = true;
    KF1600_StatePermute(ctx->state, K);

    while (len >= ctx->rate_bytes) {
        memcpy(output, ctx->state, ctx->rate_bytes);
        KF1600_StatePermute(ctx->state, K);
        len -= ctx->rate_bytes;
        output += ctx->rate_bytes;
    }

    if (len > 0) {
        memcpy(output, ctx->state, len);
    }

}

uint32_t shake_getSize(shake_ctx *ctx) {
    return ctx->bitLen >> 2;
}

uint32_t shake_getByteLen(shake_ctx *ctx) {
    return ctx->rate >> 3;
}

bool shake_restoreFullState(shake_ctx *ctx, const uint8_t *oldState) {
    shake_ctx newState;
    memcpy(&newState, oldState, sizeof(shake_ctx));

    if (newState.ident != SHAKE_MAGIC) {
        return false;
    }

    switch (newState.bitLen) {
        case 128:
        case 255:
            break;
        default:
            return false;
    }

    // Recalculate these
    newState.rate = 1600 - ((uint32_t) newState.bitLen << 1);
    newState.rate_bytes = newState.rate >> 3;

    if (newState.buf_index >= BUF_SIZE_SHAKE) {
        return false;
    }

    *ctx = newState;

    return true;
}

size_t shake_encodeFullState(const shake_ctx *ctx, uint8_t *output) {
    memcpy(output, ctx, sizeof(shake_ctx));
    return sizeof(shake_ctx);
}