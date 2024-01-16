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
    ptr->rate_bytes = (1600 - ((uint32_t) bitLen << 1)) >> 3;
    ptr->ident = SHA3_MAGIC;
    sha3_reset(ptr);
    return ptr;
}

void sha3_free_ctx(sha3_ctx *ctx) {
    memzero(ctx,  sizeof(sha3_ctx));
    free(ctx);
}

void sha3_reset(sha3_ctx *ctx) {
    ctx->buf_u8_index = 0;
    memzero(ctx->state,  sizeof(uint64x2_t) * STATE_LEN);
    memzero(ctx->buf,  BUF_SIZE_SHA3);
    ctx->squeezing = false;
}

void sha3_update_byte(sha3_ctx *ctx, uint8_t b) {
    assert(!ctx->squeezing);
    const size_t rateBytes = ctx->rate_bytes;
    uint8_t *buf = (uint8_t *) ctx->buf;
    buf[ctx->buf_u8_index++] = b;

    if (ctx->buf_u8_index == rateBytes) {
        keccak_absorb_buf(ctx->state, buf, rateBytes, K);
        ctx->buf_u8_index = 0;
    }
}

void sha3_update(sha3_ctx *ctx, uint8_t *input, size_t len) {
    assert(!ctx->squeezing);
    const size_t rateBytes = ctx->rate_bytes;
    const size_t remaining = rateBytes - ctx->buf_u8_index;
    uint8_t *buf = (uint8_t *) ctx->buf;

    if (ctx->buf_u8_index != 0) {
        const size_t toCopy = remaining > len ? len : remaining;
        memcpy(&buf[ctx->buf_u8_index], input, toCopy);
        ctx->buf_u8_index += toCopy;
        len -= toCopy;
        input += toCopy;
        if (ctx->buf_u8_index == rateBytes) {
            keccak_absorb_buf(ctx->state, buf, rateBytes, K);
            ctx->buf_u8_index = 0;
        }
    }

    while (len >= rateBytes) {
        keccak_absorb_buf(ctx->state, input, rateBytes, K);
        input += rateBytes;
        len -= rateBytes;
    }

    if (len > 0) {
        memcpy(buf, input, len);
        ctx->buf_u8_index += len;
        if (ctx->buf_u8_index == rateBytes) {
            keccak_absorb_buf(ctx->state, buf, rateBytes, K);
            ctx->buf_u8_index = 0;
        }
    }


}

void sha3_digest(sha3_ctx *ctx, uint8_t *output) {

    uint8_t *buf = (uint8_t *) ctx->buf;

    ctx->squeezing = true;
    size_t rateBytes = ctx->rate_bytes;
    const size_t toClear = rateBytes - ctx->buf_u8_index;

    // Padding will be set up inside the buffer so
    // we need to zero out any unused buffer first.

    memzero(buf + ctx->buf_u8_index,  toClear); // clear to end of buffer
    switch (ctx->bitLen) {
        case 224:
        case 256:
        case 384:
        case 512:
            buf[ctx->buf_u8_index] = 0x06;
            break;
        default:
            assert(false);

    }

    buf[rateBytes - 1] |= 128;

    uint64_t *p = ctx->buf;
    uint64x2_t tmp;
    uint64x2_t *state = ctx->state;
    for (int i = 0; i < rateBytes >> 3; i++) {
        tmp = vsetq_lane_u64(*p, k_zero, 0);
        *state = veorq_u64(*state, tmp); // eor into state
        state++;
        p++;
    }


    KF1600_StatePermute(ctx->state, K);
    size_t len = ctx->bitLen >> 3;
    assert(len <= ctx->rate_bytes);

    int stateIndex = 0;
    // Partial
    while (len >= 8) {
        vst1_u8(output, (uint8x8_t) vgetq_lane_u64(ctx->state[stateIndex++], 0));
        output += 8;
        len -= 8;
    }

    if (len > 0) {
        assert(len < 8);
        // sub 64 bit
        memcpy(output, (uint8_t *)&ctx->state[stateIndex], len); // TODO BE endian issue
    }

}

uint32_t sha3_getSize(sha3_ctx *ctx) {
    return ctx->bitLen >> 3;
}

uint32_t sha3_getByteLen(sha3_ctx *ctx) {
    return (uint32_t)ctx->rate_bytes;
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
    newState.rate_bytes = (1600 - ((uint32_t) newState.bitLen << 1))>>3;

    if (newState.buf_u8_index >= BUF_SIZE_SHA3) {
        return false;
    }

    *ctx = newState;

    return true;
}

size_t sha3_encodeFullState(const sha3_ctx *ctx, uint8_t *output) {
    memcpy(output, ctx, sizeof(sha3_ctx));
    return sizeof(sha3_ctx);
}