//
//

#include <assert.h>
#include <stdlib.h>
#include <memory.h>
#include "sha256.h"

void hashBlock(sha256_ctx *ctx, uint8_t *block);


static const uint8_t padBlock[64] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint32_t K[] = {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

static inline int processLength(sha256_ctx *ctx, size_t length) {
    ctx->buf[63] = (uint8_t) (length & 0xFF);
    ctx->buf[62] = (uint8_t) ((length >> 8) & 0xFF);
    ctx->buf[61] = (uint8_t) ((length >> 16) & 0xFF);
    ctx->buf[60] = (uint8_t) ((length >> 24) & 0xFF);
    ctx->buf[59] = (uint8_t) ((length >> 32) & 0xFF);
    ctx->buf[58] = (uint8_t) ((length >> 40) & 0xFF);
    ctx->buf[57] = (uint8_t) ((length >> 48) & 0xFF);
    ctx->buf[56] = (uint8_t) ((length >> 56) & 0xFF);
    return 8;
}

sha256_ctx *sha256_create_ctx() {
    sha256_ctx *ptr = calloc(1, sizeof(sha256_ctx));
    assert(ptr != NULL);
    sha256_reset(ptr);
    return ptr;
}

void sha256_free_ctx(sha256_ctx *ctx) {
    memset(ctx, 0, sizeof(sha256_ctx));
    free(ctx);
}

void sha256_reset(sha256_ctx *ctx) {

    memset(ctx->buf, 0, BUF_SIZE_SHA256);
    ctx->ident = SHA256_MAGIC;
    ctx->buf_index = 0;
    ctx->byteCount = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;

    ctx->s0 = vld1q_u32(&ctx->state[0]);
    ctx->s1 = vld1q_u32(&ctx->state[4]);

}

void sha256_update(sha256_ctx *ctx, uint8_t *input, size_t len) {
    if (input == NULL || len == 0) {
        return;
    }

    uint8_t *end = input + len;

    if (ctx->buf_index != 0) {
        size_t rem = BUF_SIZE_SHA256 - ctx->buf_index;
        size_t toCopy = len < rem ? len : rem;
        memcpy(&ctx->buf[ctx->buf_index], input, toCopy);
        ctx->buf_index += toCopy;
        input += toCopy;
        ctx->byteCount += toCopy;

        if (ctx->buf_index == BUF_SIZE_SHA256) {
            hashBlock(ctx, ctx->buf);
            ctx->buf_index = 0;
        }
    }

    //
    // Directly process block
    //
    uint8_t *ptr = input;
    while (end - ptr >= BUF_SIZE_SHA256) {
        hashBlock(ctx, ptr);
        ptr += BUF_SIZE_SHA256;
        ctx->byteCount += BUF_SIZE_SHA256;
    }

    //
    // Copy in any trailing bytes that do not fill a block.
    //
    if (end - ptr > 0) {
        size_t rem = BUF_SIZE_SHA256 - ctx->buf_index;
        size_t toCopy = end - ptr < rem ? (size_t) (end - ptr) : rem;
        memcpy(&ctx->buf[ctx->buf_index], ptr, toCopy);
        ctx->buf_index += toCopy;
        ctx->byteCount += toCopy;
    }


}

void sha256_update_byte(sha256_ctx *ctx, uint8_t b) {
    ctx->buf[ctx->buf_index++] = b;
    ctx->byteCount++;
    if (ctx->buf_index == BUF_SIZE_SHA256) {
        hashBlock(ctx, ctx->buf);
        ctx->buf_index = 0;
    }
}

void sha256_digest(sha256_ctx *ctx, uint8_t *output) {
    size_t bitLen = ctx->byteCount << 3;
    size_t padLen = ctx->buf_index < 56 ? 56 - ctx->buf_index : 64 + 56 - ctx->buf_index;
    sha256_update(ctx, (uint8_t *) padBlock, padLen);
    processLength(ctx, bitLen);
    hashBlock(ctx, ctx->buf);


    //
    // Save state
    //
    vst1q_u32(&ctx->state[0], ctx->s0);
    vst1q_u32(&ctx->state[4], ctx->s1);


    vst1q_u32((uint32_t *) &output[0 * 16], vreinterpretq_u32_u8( vrev32q_u8(vreinterpretq_u8_u32( ctx->s0))));
    vst1q_u32((uint32_t *) &output[1 * 16], vreinterpretq_u32_u8( vrev32q_u8(vreinterpretq_u8_u32( ctx->s1))));


    sha256_reset(ctx);
}

uint32_t sha256_getSize(sha256_ctx *ctx) {
    return SHA256_SIZE;
}

uint32_t sha256_getByteLen(sha256_ctx *ctx) {
    return BUF_SIZE_SHA256;
}

bool sha256_restoreFullState(sha256_ctx *ctx, const uint8_t *oldState) {

    sha256_ctx newState;
    memcpy(&newState, oldState, sizeof(sha256_ctx));

    if (newState.ident != SHA256_MAGIC) {
        return false;
    }

    if (newState.buf_index >= BUF_SIZE_SHA256) {
        return false;
    }

    *ctx = newState;

    return true;
}

size_t sha256_encodeFullState(const sha256_ctx *ctx, uint8_t *output) {
    memcpy(output, ctx, sizeof(sha256_ctx));
    return sizeof(sha256_ctx);
}

void hashBlock(sha256_ctx *ctx, uint8_t *block) {
    //
    // Adapted on code from ARM and Jeffrey Walton
    //

    uint32x4_t s0, s1, abef_save, cdgh_save;
    uint32x4_t msg0, msg1, msg2, msg3;
    uint32x4_t tmp0, tmp1, tmp2;

    s0 = abef_save = ctx->s0;
    s1 = cdgh_save = ctx->s1;

    msg0 = vld1q_u32((uint32_t *) &block[0 * 16]);
    msg1 = vld1q_u32((uint32_t *) &block[1 * 16]);
    msg2 = vld1q_u32((uint32_t *) &block[2 * 16]);
    msg3 = vld1q_u32((uint32_t *) &block[3 * 16]);


    msg0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0)));
    msg1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1)));
    msg2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2)));
    msg3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3)));

    tmp0 = vaddq_u32(msg0, vld1q_u32(&K[0x00]));


    msg0 = vsha256su0q_u32(msg0, msg1);
    tmp2 = s0;
    tmp1 = vaddq_u32(msg1, vld1q_u32(&K[0x04]));
    s0 = vsha256hq_u32(s0, s1, tmp0);
    s1 = vsha256h2q_u32(s1, tmp2, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);


    msg1 = vsha256su0q_u32(msg1, msg2);
    tmp2 = s0;
    tmp0 = vaddq_u32(msg2, vld1q_u32(&K[0x08]));
    s0 = vsha256hq_u32(s0, s1, tmp1);
    s1 = vsha256h2q_u32(s1, tmp2, tmp1);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);


    msg2 = vsha256su0q_u32(msg2, msg3);
    tmp2 = s0;
    tmp1 = vaddq_u32(msg3, vld1q_u32(&K[0x0c]));
    s0 = vsha256hq_u32(s0, s1, tmp0);
    s1 = vsha256h2q_u32(s1, tmp2, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);


    msg3 = vsha256su0q_u32(msg3, msg0);
    tmp2 = s0;
    tmp0 = vaddq_u32(msg0, vld1q_u32(&K[0x10]));
    s0 = vsha256hq_u32(s0, s1, tmp1);
    s1 = vsha256h2q_u32(s1, tmp2, tmp1);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);


    msg0 = vsha256su0q_u32(msg0, msg1);
    tmp2 = s0;
    tmp1 = vaddq_u32(msg1, vld1q_u32(&K[0x14]));
    s0 = vsha256hq_u32(s0, s1, tmp0);
    s1 = vsha256h2q_u32(s1, tmp2, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);


    msg1 = vsha256su0q_u32(msg1, msg2);
    tmp2 = s0;
    tmp0 = vaddq_u32(msg2, vld1q_u32(&K[0x18]));
    s0 = vsha256hq_u32(s0, s1, tmp1);
    s1 = vsha256h2q_u32(s1, tmp2, tmp1);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);


    msg2 = vsha256su0q_u32(msg2, msg3);
    tmp2 = s0;
    tmp1 = vaddq_u32(msg3, vld1q_u32(&K[0x1c]));
    s0 = vsha256hq_u32(s0, s1, tmp0);
    s1 = vsha256h2q_u32(s1, tmp2, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);


    msg3 = vsha256su0q_u32(msg3, msg0);
    tmp2 = s0;
    tmp0 = vaddq_u32(msg0, vld1q_u32(&K[0x20]));
    s0 = vsha256hq_u32(s0, s1, tmp1);
    s1 = vsha256h2q_u32(s1, tmp2, tmp1);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);


    msg0 = vsha256su0q_u32(msg0, msg1);
    tmp2 = s0;
    tmp1 = vaddq_u32(msg1, vld1q_u32(&K[0x24]));
    s0 = vsha256hq_u32(s0, s1, tmp0);
    s1 = vsha256h2q_u32(s1, tmp2, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);


    msg1 = vsha256su0q_u32(msg1, msg2);
    tmp2 = s0;
    tmp0 = vaddq_u32(msg2, vld1q_u32(&K[0x28]));
    s0 = vsha256hq_u32(s0, s1, tmp1);
    s1 = vsha256h2q_u32(s1, tmp2, tmp1);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);


    msg2 = vsha256su0q_u32(msg2, msg3);
    tmp2 = s0;
    tmp1 = vaddq_u32(msg3, vld1q_u32(&K[0x2c]));
    s0 = vsha256hq_u32(s0, s1, tmp0);
    s1 = vsha256h2q_u32(s1, tmp2, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);


    msg3 = vsha256su0q_u32(msg3, msg0);
    tmp2 = s0;
    tmp0 = vaddq_u32(msg0, vld1q_u32(&K[0x30]));
    s0 = vsha256hq_u32(s0, s1, tmp1);
    s1 = vsha256h2q_u32(s1, tmp2, tmp1);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);


    tmp2 = s0;
    tmp1 = vaddq_u32(msg1, vld1q_u32(&K[0x34]));
    s0 = vsha256hq_u32(s0, s1, tmp0);
    s1 = vsha256h2q_u32(s1, tmp2, tmp0);


    tmp2 = s0;
    tmp0 = vaddq_u32(msg2, vld1q_u32(&K[0x38]));
    s0 = vsha256hq_u32(s0, s1, tmp1);
    s1 = vsha256h2q_u32(s1, tmp2, tmp1);


    tmp2 = s0;
    tmp1 = vaddq_u32(msg3, vld1q_u32(&K[0x3c]));
    s0 = vsha256hq_u32(s0, s1, tmp0);
    s1 = vsha256h2q_u32(s1, tmp2, tmp0);


    tmp2 = s0;
    s0 = vsha256hq_u32(s0, s1, tmp1);
    s1 = vsha256h2q_u32(s1, tmp2, tmp1);

    /* Combine state */
    ctx->s0 = vaddq_u32(s0, abef_save);
    ctx->s1 = vaddq_u32(s1, cdgh_save);

}