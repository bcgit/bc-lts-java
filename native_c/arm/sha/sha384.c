//
//

#include <assert.h>
#include <stdlib.h>
#include <memory.h>
#include "sha384.h"

void hashBlock384(sha384_ctx *ctx, uint8_t *block);


static const uint8_t padBlock[128] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00
};

static const uint64_t K[80] = {
        0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
        0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
        0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
        0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
        0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
        0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
        0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
        0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
        0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
        0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
        0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
        0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
        0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
        0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
        0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
        0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
        0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
        0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
        0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
        0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

static inline int processLength(sha384_ctx *ctx, uint64_t l, uint64_t h) {


    ctx->buf[127] = (uint8_t) (l & 0xFF);
    ctx->buf[126] = (uint8_t) ((l >> 8) & 0xFF);
    ctx->buf[125] = (uint8_t) ((l >> 16) & 0xFF);
    ctx->buf[124] = (uint8_t) ((l >> 24) & 0xFF);
    ctx->buf[123] = (uint8_t) ((l >> 32) & 0xFF);
    ctx->buf[122] = (uint8_t) ((l >> 40) & 0xFF);
    ctx->buf[121] = (uint8_t) ((l >> 48) & 0xFF);
    ctx->buf[120] = (uint8_t) ((l >> 56) & 0xFF);

    ctx->buf[119] = (uint8_t) (h & 0xFF);
    ctx->buf[118] = (uint8_t) ((h >> 8) & 0xFF);
    ctx->buf[117] = (uint8_t) ((h >> 16) & 0xFF);
    ctx->buf[116] = (uint8_t) ((h >> 24) & 0xFF);
    ctx->buf[115] = (uint8_t) ((h >> 32) & 0xFF);
    ctx->buf[114] = (uint8_t) ((h >> 40) & 0xFF);
    ctx->buf[113] = (uint8_t) ((h >> 48) & 0xFF);
    ctx->buf[112] = (uint8_t) ((h >> 56) & 0xFF);


    return 16;
}

sha384_ctx *sha384_create_ctx() {
    sha384_ctx *ptr = calloc(1, sizeof(sha384_ctx));
    assert(ptr != NULL);
    sha384_reset(ptr);
    return ptr;
}

void sha384_free_ctx(sha384_ctx *ctx) {
    memset(ctx, 0, sizeof(sha384_ctx));
    free(ctx);
}

void sha384_reset(sha384_ctx *ctx) {

    memset(ctx->buf, 0, BUF_SIZE_SHA384);
    ctx->ident = SHA384_MAGIC;
    ctx->buf_index = 0;
    ctx->byteCount1 = 0;
    ctx->byteCount2 = 0;
    ctx->state[0] = 0xcbbb9d5dc1059ed8L;
    ctx->state[1] = 0x629a292a367cd507L;
    ctx->state[2] = 0x9159015a3070dd17L;
    ctx->state[3] = 0x152fecd8f70e5939L;
    ctx->state[4] = 0x67332667ffc00b31L;
    ctx->state[5] = 0x8eb44a8768581511L;
    ctx->state[6] = 0xdb0c2e0d64f98fa7L;
    ctx->state[7] = 0x47b5481dbefa4fa4L;

    ctx->s0 = vld1q_u64(&ctx->state[0]);
    ctx->s1 = vld1q_u64(&ctx->state[2]);
    ctx->s2 = vld1q_u64(&ctx->state[4]);
    ctx->s3 = vld1q_u64(&ctx->state[6]);

}

void sha384_update(sha384_ctx *ctx, uint8_t *input, size_t len) {
    if (input == NULL || len == 0) {
        return;
    }

    uint8_t *end = input + len;

    if (ctx->buf_index != 0) {
        size_t rem = BUF_SIZE_SHA384 - ctx->buf_index;
        size_t toCopy = len < rem ? len : rem;
        memcpy(&ctx->buf[ctx->buf_index], input, toCopy);
        ctx->buf_index += toCopy;
        input += toCopy;
        ctx->byteCount1 += toCopy;
        if (ctx->byteCount1 < (uint64_t) toCopy) {
            ctx->byteCount2++;
        }


        if (ctx->buf_index == BUF_SIZE_SHA384) {
            hashBlock384(ctx, ctx->buf);
            ctx->buf_index = 0;
        }
    }

    //
    // Directly process block
    //
    uint8_t *ptr = input;
    while (end - ptr >= BUF_SIZE_SHA384) {
        hashBlock384(ctx, ptr);
        ptr += BUF_SIZE_SHA384;
        ctx->byteCount1 += BUF_SIZE_SHA384;
        if (ctx->byteCount1 < BUF_SIZE_SHA384) {
            ctx->byteCount2++;
        }
    }

    //
    // Copy in any trailing bytes that do not fill a block.
    //
    if (end - ptr > 0) {
        size_t rem = BUF_SIZE_SHA384 - ctx->buf_index;
        size_t toCopy = end - ptr < rem ? (size_t) (end - ptr) : rem;
        memcpy(&ctx->buf[ctx->buf_index], ptr, toCopy);
        ctx->buf_index += toCopy;
        ctx->byteCount1 += toCopy;
        if (ctx->byteCount1 < (uint64_t) toCopy) {
            ctx->byteCount2++;
        }
    }


}

void sha384_update_byte(sha384_ctx *ctx, uint8_t b) {
    ctx->buf[ctx->buf_index++] = b;
    ctx->byteCount1++;
    if (ctx->byteCount1 == 0) {
        ctx->byteCount2++;
    }
    if (ctx->buf_index == BUF_SIZE_SHA384) {
        hashBlock384(ctx, ctx->buf);
        ctx->buf_index = 0;
    }
}

void sha384_digest(sha384_ctx *ctx, uint8_t *output) {

    const uint64_t h = ctx->byteCount1 >> 61 | ctx->byteCount2 << 3;
    const uint64_t l = ctx->byteCount1 << 3;

    size_t padLen = ctx->buf_index < 112 ? 112 - ctx->buf_index : 128 + 112 - ctx->buf_index;
    sha384_update(ctx, (uint8_t *) padBlock, padLen);
    processLength(ctx, l, h);
    hashBlock384(ctx, ctx->buf);

    //
    // Save state
    //
    vst1q_u64(&ctx->state[0], ctx->s0);
    vst1q_u64(&ctx->state[2], ctx->s1);
    vst1q_u64(&ctx->state[4], ctx->s2);
    vst1q_u64(&ctx->state[6], ctx->s3);

    vst1q_u8((uint8_t *) &output[0 * 16], vrev64q_u8(vreinterpretq_u8_u64(ctx->s0)));
    vst1q_u8((uint8_t *) &output[1 * 16], vrev64q_u8(vreinterpretq_u8_u64(ctx->s1)));
    vst1q_u8((uint8_t *) &output[2 * 16], vrev64q_u8(vreinterpretq_u8_u64(ctx->s2)));

    sha384_reset(ctx);
}

uint32_t sha384_getSize(sha384_ctx *ctx) {
    return SHA384_SIZE;
}

uint32_t sha384_getByteLen(sha384_ctx *ctx) {
    return BUF_SIZE_SHA384;
}

bool sha384_restoreFullState(sha384_ctx *ctx, const uint8_t *oldState) {

    sha384_ctx newState;
    memcpy(&newState, oldState, sizeof(sha384_ctx));

    if (newState.ident != SHA384_MAGIC) {
        return false;
    }

    if (newState.buf_index >= BUF_SIZE_SHA384) {
        return false;
    }

    *ctx = newState;

    return true;
}

size_t sha384_encodeFullState(const sha384_ctx *ctx, uint8_t *output) {
    memcpy(output, ctx, sizeof(sha384_ctx));
    return sizeof(sha384_ctx);
}

void hashBlock384(sha384_ctx *ctx, uint8_t *block) {

    uint64x2_t ab_save, cd_save, ef_save, gh_save;
    uint64x2_t msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7;
    uint64x2_t tmp0, tmp1, tmp2;

    uint64x2_t s0 = ab_save = ctx->s0;
    uint64x2_t s1 = cd_save = ctx->s1;
    uint64x2_t s2 = ef_save = ctx->s2;
    uint64x2_t s3 = gh_save = ctx->s3;
    

    msg0 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(&block[0 * 16])));
    msg1 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(&block[1 * 16])));
    msg2 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(&block[2 * 16])));
    msg3 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(&block[3 * 16])));
    msg4 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(&block[4 * 16])));
    msg5 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(&block[5 * 16])));
    msg6 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(&block[6 * 16])));
    msg7 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(&block[7 * 16])));

    tmp0 = vaddq_u64(msg0, vld1q_u64(&K[0]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s3);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s2, s3, 1), vextq_u64(s1, s2, 1));
    s3 = vsha512h2q_u64(tmp2, s1, s0);
    s1 = vaddq_u64(s1, tmp2);

    tmp0 = vaddq_u64(msg1, vld1q_u64(&K[2]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s2);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s1, s2, 1), vextq_u64(s0, s1, 1));
    s2 = vsha512h2q_u64(tmp2, s0, s3);
    s0 = vaddq_u64(s0, tmp2);

    tmp0 = vaddq_u64(msg2, vld1q_u64(&K[4]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s1);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s0, s1, 1), vextq_u64(s3, s0, 1));
    s1 = vsha512h2q_u64(tmp2, s3, s2);
    s3 = vaddq_u64(s3, tmp2);

    tmp0 = vaddq_u64(msg3, vld1q_u64(&K[6]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s0);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s3, s0, 1), vextq_u64(s2, s3, 1));
    s0 = vsha512h2q_u64(tmp2, s2, s1);
    s2 = vaddq_u64(s2, tmp2);

    tmp0 = vaddq_u64(msg4, vld1q_u64(&K[8]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s3);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s2, s3, 1), vextq_u64(s1, s2, 1));
    s3 = vsha512h2q_u64(tmp2, s1, s0);
    s1 = vaddq_u64(s1, tmp2);

    tmp0 = vaddq_u64(msg5, vld1q_u64(&K[10]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s2);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s1, s2, 1), vextq_u64(s0, s1, 1));
    s2 = vsha512h2q_u64(tmp2, s0, s3);
    s0 = vaddq_u64(s0, tmp2);

    tmp0 = vaddq_u64(msg6, vld1q_u64(&K[12]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s1);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s0, s1, 1), vextq_u64(s3, s0, 1));
    s1 = vsha512h2q_u64(tmp2, s3, s2);
    s3 = vaddq_u64(s3, tmp2);

    tmp0 = vaddq_u64(msg7, vld1q_u64(&K[14]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s0);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s3, s0, 1), vextq_u64(s2, s3, 1));
    s0 = vsha512h2q_u64(tmp2, s2, s1);
    s2 = vaddq_u64(s2, tmp2);

    msg0 = vsha512su1q_u64(vsha512su0q_u64(msg0, msg1), msg7, vextq_u64(msg4, msg5, 1));
    tmp0 = vaddq_u64(msg0, vld1q_u64(&K[16]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s3);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s2, s3, 1), vextq_u64(s1, s2, 1));
    s3 = vsha512h2q_u64(tmp2, s1, s0);
    s1 = vaddq_u64(s1, tmp2);

    msg1 = vsha512su1q_u64(vsha512su0q_u64(msg1, msg2), msg0, vextq_u64(msg5, msg6, 1));
    tmp0 = vaddq_u64(msg1, vld1q_u64(&K[18]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s2);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s1, s2, 1), vextq_u64(s0, s1, 1));
    s2 = vsha512h2q_u64(tmp2, s0, s3);
    s0 = vaddq_u64(s0, tmp2);

    msg2 = vsha512su1q_u64(vsha512su0q_u64(msg2, msg3), msg1, vextq_u64(msg6, msg7, 1));
    tmp0 = vaddq_u64(msg2, vld1q_u64(&K[20]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s1);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s0, s1, 1), vextq_u64(s3, s0, 1));
    s1 = vsha512h2q_u64(tmp2, s3, s2);
    s3 = vaddq_u64(s3, tmp2);

    msg3 = vsha512su1q_u64(vsha512su0q_u64(msg3, msg4), msg2, vextq_u64(msg7, msg0, 1));
    tmp0 = vaddq_u64(msg3, vld1q_u64(&K[22]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s0);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s3, s0, 1), vextq_u64(s2, s3, 1));
    s0 = vsha512h2q_u64(tmp2, s2, s1);
    s2 = vaddq_u64(s2, tmp2);

    msg4 = vsha512su1q_u64(vsha512su0q_u64(msg4, msg5), msg3, vextq_u64(msg0, msg1, 1));
    tmp0 = vaddq_u64(msg4, vld1q_u64(&K[24]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s3);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s2, s3, 1), vextq_u64(s1, s2, 1));
    s3 = vsha512h2q_u64(tmp2, s1, s0);
    s1 = vaddq_u64(s1, tmp2);

    msg5 = vsha512su1q_u64(vsha512su0q_u64(msg5, msg6), msg4, vextq_u64(msg1, msg2, 1));
    tmp0 = vaddq_u64(msg5, vld1q_u64(&K[26]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s2);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s1, s2, 1), vextq_u64(s0, s1, 1));
    s2 = vsha512h2q_u64(tmp2, s0, s3);
    s0 = vaddq_u64(s0, tmp2);

    msg6 = vsha512su1q_u64(vsha512su0q_u64(msg6, msg7), msg5, vextq_u64(msg2, msg3, 1));
    tmp0 = vaddq_u64(msg6, vld1q_u64(&K[28]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s1);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s0, s1, 1), vextq_u64(s3, s0, 1));
    s1 = vsha512h2q_u64(tmp2, s3, s2);
    s3 = vaddq_u64(s3, tmp2);

    msg7 = vsha512su1q_u64(vsha512su0q_u64(msg7, msg0), msg6, vextq_u64(msg3, msg4, 1));
    tmp0 = vaddq_u64(msg7, vld1q_u64(&K[30]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s0);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s3, s0, 1), vextq_u64(s2, s3, 1));
    s0 = vsha512h2q_u64(tmp2, s2, s1);
    s2 = vaddq_u64(s2, tmp2);

    msg0 = vsha512su1q_u64(vsha512su0q_u64(msg0, msg1), msg7, vextq_u64(msg4, msg5, 1));
    tmp0 = vaddq_u64(msg0, vld1q_u64(&K[32]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s3);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s2, s3, 1), vextq_u64(s1, s2, 1));
    s3 = vsha512h2q_u64(tmp2, s1, s0);
    s1 = vaddq_u64(s1, tmp2);


    msg1 = vsha512su1q_u64(vsha512su0q_u64(msg1, msg2), msg0, vextq_u64(msg5, msg6, 1));
    tmp0 = vaddq_u64(msg1, vld1q_u64(&K[34]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s2);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s1, s2, 1), vextq_u64(s0, s1, 1));
    s2 = vsha512h2q_u64(tmp2, s0, s3);
    s0 = vaddq_u64(s0, tmp2);

    msg2 = vsha512su1q_u64(vsha512su0q_u64(msg2, msg3), msg1, vextq_u64(msg6, msg7, 1));
    tmp0 = vaddq_u64(msg2, vld1q_u64(&K[36]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s1);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s0, s1, 1), vextq_u64(s3, s0, 1));
    s1 = vsha512h2q_u64(tmp2, s3, s2);
    s3 = vaddq_u64(s3, tmp2);

    msg3 = vsha512su1q_u64(vsha512su0q_u64(msg3, msg4), msg2, vextq_u64(msg7, msg0, 1));
    tmp0 = vaddq_u64(msg3, vld1q_u64(&K[38]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s0);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s3, s0, 1), vextq_u64(s2, s3, 1));
    s0 = vsha512h2q_u64(tmp2, s2, s1);
    s2 = vaddq_u64(s2, tmp2);

    msg4 = vsha512su1q_u64(vsha512su0q_u64(msg4, msg5), msg3, vextq_u64(msg0, msg1, 1));
    tmp0 = vaddq_u64(msg4, vld1q_u64(&K[40]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s3);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s2, s3, 1), vextq_u64(s1, s2, 1));
    s3 = vsha512h2q_u64(tmp2, s1, s0);
    s1 = vaddq_u64(s1, tmp2);

    msg5 = vsha512su1q_u64(vsha512su0q_u64(msg5, msg6), msg4, vextq_u64(msg1, msg2, 1));
    tmp0 = vaddq_u64(msg5, vld1q_u64(&K[42]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s2);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s1, s2, 1), vextq_u64(s0, s1, 1));
    s2 = vsha512h2q_u64(tmp2, s0, s3);
    s0 = vaddq_u64(s0, tmp2);

    msg6 = vsha512su1q_u64(vsha512su0q_u64(msg6, msg7), msg5, vextq_u64(msg2, msg3, 1));
    tmp0 = vaddq_u64(msg6, vld1q_u64(&K[44]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s1);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s0, s1, 1), vextq_u64(s3, s0, 1));
    s1 = vsha512h2q_u64(tmp2, s3, s2);
    s3 = vaddq_u64(s3, tmp2);

    msg7 = vsha512su1q_u64(vsha512su0q_u64(msg7, msg0), msg6, vextq_u64(msg3, msg4, 1));
    tmp0 = vaddq_u64(msg7, vld1q_u64(&K[46]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s0);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s3, s0, 1), vextq_u64(s2, s3, 1));
    s0 = vsha512h2q_u64(tmp2, s2, s1);
    s2 = vaddq_u64(s2, tmp2);

    msg0 = vsha512su1q_u64(vsha512su0q_u64(msg0, msg1), msg7, vextq_u64(msg4, msg5, 1));
    tmp0 = vaddq_u64(msg0, vld1q_u64(&K[48]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s3);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s2, s3, 1), vextq_u64(s1, s2, 1));
    s3 = vsha512h2q_u64(tmp2, s1, s0);
    s1 = vaddq_u64(s1, tmp2);

    msg1 = vsha512su1q_u64(vsha512su0q_u64(msg1, msg2), msg0, vextq_u64(msg5, msg6, 1));
    tmp0 = vaddq_u64(msg1, vld1q_u64(&K[50]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s2);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s1, s2, 1), vextq_u64(s0, s1, 1));
    s2 = vsha512h2q_u64(tmp2, s0, s3);
    s0 = vaddq_u64(s0, tmp2);

    msg2 = vsha512su1q_u64(vsha512su0q_u64(msg2, msg3), msg1, vextq_u64(msg6, msg7, 1));
    tmp0 = vaddq_u64(msg2, vld1q_u64(&K[52]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s1);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s0, s1, 1), vextq_u64(s3, s0, 1));
    s1 = vsha512h2q_u64(tmp2, s3, s2);
    s3 = vaddq_u64(s3, tmp2);

    msg3 = vsha512su1q_u64(vsha512su0q_u64(msg3, msg4), msg2, vextq_u64(msg7, msg0, 1));
    tmp0 = vaddq_u64(msg3, vld1q_u64(&K[54]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s0);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s3, s0, 1), vextq_u64(s2, s3, 1));
    s0 = vsha512h2q_u64(tmp2, s2, s1);
    s2 = vaddq_u64(s2, tmp2);

    msg4 = vsha512su1q_u64(vsha512su0q_u64(msg4, msg5), msg3, vextq_u64(msg0, msg1, 1));
    tmp0 = vaddq_u64(msg4, vld1q_u64(&K[56]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s3);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s2, s3, 1), vextq_u64(s1, s2, 1));
    s3 = vsha512h2q_u64(tmp2, s1, s0);
    s1 = vaddq_u64(s1, tmp2);

    msg5 = vsha512su1q_u64(vsha512su0q_u64(msg5, msg6), msg4, vextq_u64(msg1, msg2, 1));
    tmp0 = vaddq_u64(msg5, vld1q_u64(&K[58]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s2);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s1, s2, 1), vextq_u64(s0, s1, 1));
    s2 = vsha512h2q_u64(tmp2, s0, s3);
    s0 = vaddq_u64(s0, tmp2);

    msg6 = vsha512su1q_u64(vsha512su0q_u64(msg6, msg7), msg5, vextq_u64(msg2, msg3, 1));
    tmp0 = vaddq_u64(msg6, vld1q_u64(&K[60]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s1);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s0, s1, 1), vextq_u64(s3, s0, 1));
    s1 = vsha512h2q_u64(tmp2, s3, s2);
    s3 = vaddq_u64(s3, tmp2);

    msg7 = vsha512su1q_u64(vsha512su0q_u64(msg7, msg0), msg6, vextq_u64(msg3, msg4, 1));
    tmp0 = vaddq_u64(msg7, vld1q_u64(&K[62]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s0);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s3, s0, 1), vextq_u64(s2, s3, 1));
    s0 = vsha512h2q_u64(tmp2, s2, s1);
    s2 = vaddq_u64(s2, tmp2);

    msg0 = vsha512su1q_u64(vsha512su0q_u64(msg0, msg1), msg7, vextq_u64(msg4, msg5, 1));
    tmp0 = vaddq_u64(msg0, vld1q_u64(&K[64]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s3);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s2, s3, 1), vextq_u64(s1, s2, 1));
    s3 = vsha512h2q_u64(tmp2, s1, s0);
    s1 = vaddq_u64(s1, tmp2);

    msg1 = vsha512su1q_u64(vsha512su0q_u64(msg1, msg2), msg0, vextq_u64(msg5, msg6, 1));
    tmp0 = vaddq_u64(msg1, vld1q_u64(&K[66]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s2);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s1, s2, 1), vextq_u64(s0, s1, 1));
    s2 = vsha512h2q_u64(tmp2, s0, s3);
    s0 = vaddq_u64(s0, tmp2);

    msg2 = vsha512su1q_u64(vsha512su0q_u64(msg2, msg3), msg1, vextq_u64(msg6, msg7, 1));
    tmp0 = vaddq_u64(msg2, vld1q_u64(&K[68]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s1);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s0, s1, 1), vextq_u64(s3, s0, 1));
    s1 = vsha512h2q_u64(tmp2, s3, s2);
    s3 = vaddq_u64(s3, tmp2);

    msg3 = vsha512su1q_u64(vsha512su0q_u64(msg3, msg4), msg2, vextq_u64(msg7, msg0, 1));
    tmp0 = vaddq_u64(msg3, vld1q_u64(&K[70]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s0);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s3, s0, 1), vextq_u64(s2, s3, 1));
    s0 = vsha512h2q_u64(tmp2, s2, s1);
    s2 = vaddq_u64(s2, tmp2);

    msg4 = vsha512su1q_u64(vsha512su0q_u64(msg4, msg5), msg3, vextq_u64(msg0, msg1, 1));
    tmp0 = vaddq_u64(msg4, vld1q_u64(&K[72]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s3);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s2, s3, 1), vextq_u64(s1, s2, 1));
    s3 = vsha512h2q_u64(tmp2, s1, s0);
    s1 = vaddq_u64(s1, tmp2);

    msg5 = vsha512su1q_u64(vsha512su0q_u64(msg5, msg6), msg4, vextq_u64(msg1, msg2, 1));
    tmp0 = vaddq_u64(msg5, vld1q_u64(&K[74]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s2);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s1, s2, 1), vextq_u64(s0, s1, 1));
    s2 = vsha512h2q_u64(tmp2, s0, s3);
    s0 = vaddq_u64(s0, tmp2);

    msg6 = vsha512su1q_u64(vsha512su0q_u64(msg6, msg7), msg5, vextq_u64(msg2, msg3, 1));
    tmp0 = vaddq_u64(msg6, vld1q_u64(&K[76]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s1);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s0, s1, 1), vextq_u64(s3, s0, 1));
    s1 = vsha512h2q_u64(tmp2, s3, s2);
    s3 = vaddq_u64(s3, tmp2);

    msg7 = vsha512su1q_u64(vsha512su0q_u64(msg7, msg0), msg6, vextq_u64(msg3, msg4, 1));
    tmp0 = vaddq_u64(msg7, vld1q_u64(&K[78]));
    tmp1 = vaddq_u64(vextq_u64(tmp0, tmp0, 1), s0);
    tmp2 = vsha512hq_u64(tmp1, vextq_u64(s3, s0, 1), vextq_u64(s2, s3, 1));
    s0 = vsha512h2q_u64(tmp2, s2, s1);
    s2 = vaddq_u64(s2, tmp2);

    ctx->s0 = s0 = vaddq_u64(s0, ab_save);
    ctx->s1 = s1 = vaddq_u64(s1, cd_save);
    ctx->s2 = s2 = vaddq_u64(s2, ef_save);
    ctx->s3 = s3 = vaddq_u64(s3, gh_save);
}