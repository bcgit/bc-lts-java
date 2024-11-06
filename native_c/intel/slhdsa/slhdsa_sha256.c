
#include <stdlib.h>
#include <assert.h>
#include <memory.h>
#include "slhdsa_sha256.h"



slhdsa_sha256 *slhdsa_sha256_create_ctx() {
    slhdsa_sha256 *ctx = calloc(1, sizeof(slhdsa_sha256));
    assert(ctx != NULL);
    slhdsa_sha256_reset(ctx);
    return ctx;
}

void slhdsa_sha256_free_ctx(slhdsa_sha256 *ctx) {
    memzero(ctx, sizeof(slhdsa_sha256));
    free(ctx);
}

void slhdsa_sha256_reset(slhdsa_sha256 *ctx) {
    sha256_reset(&ctx->msgMemo);
    sha256_reset(&ctx->sha256Memo);
    sha256_reset(&ctx->msgDigest);
    sha256_reset(&ctx->sha256Digest);
}

void slhdsa_sha256_init_memos(
        slhdsa_sha256 *ctx,
        uint8_t *seed,
        size_t seed_len,
        uint8_t *padding,
        size_t padding_len_1,
        size_t padding_len_2) {

    sha256_update(&ctx->msgDigest, seed, seed_len);
    sha256_update(&ctx->msgDigest, padding, padding_len_1);
    sha256_update(&ctx->sha256Digest, seed, seed_len);
    sha256_update(&ctx->sha256Digest, padding, padding_len_2);
    ctx->msgMemo = ctx->msgDigest;
    ctx->sha256Memo = ctx->sha256Digest;

    sha256_reset(&ctx->msgDigest);
    sha256_reset(&ctx->sha256Digest);
}


void slhdsa_sha256_sha256_digest(
        slhdsa_sha256 *ctx,
        uint8_t *out,
        uint8_t *in0, size_t in0_len,
        uint8_t *in1, size_t in1_len,
        uint8_t *in2, size_t in2_len,
        uint8_t *in3, size_t in3_len
) {
    sha256_update(&ctx->sha256Digest, in0, in0_len);
    sha256_update(&ctx->sha256Digest, in1, in1_len);
    sha256_update(&ctx->sha256Digest, in2, in2_len);
    sha256_update(&ctx->sha256Digest, in3, in3_len);

    sha256_digest(&ctx->sha256Digest, out);
}

void slhdsa_sha256_msgDigest_digest(
        slhdsa_sha256 *ctx,
        uint8_t *out,
        uint8_t *in0, size_t in0_len,
        uint8_t *in1, size_t in1_len,
        uint8_t *in2, size_t in2_len,
        uint8_t *in3, size_t in3_len,
        uint8_t *in4, size_t in4_len
) {
    sha256_update(&ctx->msgDigest, in0, in0_len);
    sha256_update(&ctx->msgDigest, in1, in1_len);
    sha256_update(&ctx->msgDigest, in2, in2_len);
    sha256_update(&ctx->msgDigest, in3, in3_len);
    sha256_update(&ctx->msgDigest, in4, in4_len);
    sha256_digest(&ctx->msgDigest, out);
}


void slhdsa_sha256_mgf256_mask(slhdsa_sha256 *ctx,
                           uint8_t *key, size_t key_len,
                           uint8_t *output,
                           uint8_t *in0, size_t in0_len,
                           uint8_t *in1, size_t in1_len,
                           uint8_t *in2, size_t in2_len,
                           uint8_t *in3, size_t in3_len) {


    const size_t seedCtrLen = key_len + 4;
    uint8_t seedCtr[seedCtrLen];
    size_t hbPtr = 0;
    uint32_t counter = 0;
    size_t toCopy = 0;
    int tgtIndex = 0;

    // Lists of sources and their length
    uint8_t *source[4] = {in0, in1, in2, in3};
    size_t sourceSize[4] = {in0_len, in1_len, in2_len, in3_len};

    sha256_ctx sha256Ctx;
    sha256_reset(&sha256Ctx);

    memcpy(&seedCtr, key, key_len);
    memset(&seedCtr[key_len], 0, 4);

    uint8_t hashBuf[32];

    sha256_update(&sha256Ctx, seedCtr, seedCtrLen);
    sha256_digest(&sha256Ctx, hashBuf);

    do {
        uint8_t *tgt = source[tgtIndex];
        size_t tgtRem = sourceSize[tgtIndex];

        do {
            if (hbPtr == 32) {
                counter++;
                seedCtr[key_len + 0] = (uint8_t) (counter >> 24) & 0xFF;
                seedCtr[key_len + 1] = (uint8_t) (counter >> 16) & 0xFF;
                seedCtr[key_len + 2] = (uint8_t) (counter >> 8) & 0xFF;
                seedCtr[key_len + 3] = (uint8_t) (counter) & 0xFF;
                hbPtr = 0;
                sha256_update(&sha256Ctx, seedCtr, seedCtrLen);
                sha256_digest(&sha256Ctx, hashBuf);
            }

            toCopy = tgtRem > 32 - hbPtr ? 32 - hbPtr : tgtRem;

            xor(output, &hashBuf[hbPtr], tgt, toCopy);
            hbPtr += toCopy;
            tgt += toCopy;
            tgtRem -= toCopy;
            output += toCopy;
        } while (tgtRem > 0);
        tgtIndex++;
    } while (tgtIndex < 4);

    memzero(seedCtr, seedCtrLen);
    memzero(&sha256Ctx, sizeof(sha256_ctx));

}

