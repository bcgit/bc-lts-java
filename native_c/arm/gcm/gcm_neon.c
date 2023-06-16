//
//
//

#include <libc.h>
#include "gcm.h"

gcm_err *process_block(gcm_ctx *ctx, uint8_t *in, uint8_t *out, size_t outputLen) {
    if (out == NULL) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        return make_gcm_error("out is null, output generated when no output was expected by caller", ILLEGAL_ARGUMENT);
    }


    if (ctx->blocksRemaining < 1) {
        return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
    }
    ctx->blocksRemaining -= 1;

    if (outputLen < BLOCK_SIZE) {
        return make_gcm_error("output len too short", OUTPUT_LENGTH);
    }

    int j;

    ctx->ctr1 = vaddq_u32(ctx->ctr1, one);
    uint8x16_t tmp1 = vrev64q_u8(ctx->ctr1);
    single_block(&ctx->aesKey, tmp1, &tmp1);


//    tmp1 = _mm_xor_si128(tmp1, ctx->roundKeys[0]);
//    for (j = 1; j < ctx->num_rounds - 1; j += 2) {
//        tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[j]);
//        tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[j + 1]);
//    }
//    tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[ctx->num_rounds - 1]);
//    tmp1 = _mm_aesenclast_si128(tmp1, ctx->roundKeys[ctx->num_rounds]);
//    __m128i in1 = _mm_loadu_si128((__m128i *) in);
//    tmp1 = _mm_xor_si128(tmp1, in1);
//    _mm_storeu_si128((__m128i *) (out), tmp1);
//    tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);

    uint8x16_t in1 = vld1q_u8(in);
    tmp1 = veorq_u8(tmp1, in1);
    vst1q_u8(out, tmp1);


    if (ctx->encryption) {
        ctx->X = veorq_u8(ctx->X, swap_endian(tmp1));
        //ctx->X = _mm_xor_si128(ctx->X, tmp1);
    } else {
        ctx->X = veorq_u8(ctx->X, swap_endian(in1));

        // ctx->X = _mm_xor_si128(ctx->X, _mm_shuffle_epi8(in1, *BSWAP_MASK));
    }
    ctx->X = gfmul(ctx->X, ctx->H);

    return NULL;

}

gcm_err *processFourBlocksEnc(gcm_ctx *ctx, uint8_t *in, uint8_t *out) {

    if (out == NULL) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        return make_gcm_error("out is null, output generated when no output was expected by caller", ILLEGAL_ARGUMENT);
    }


    if (ctx->blocksRemaining < 4) {
        return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
    }
    ctx->blocksRemaining -= 4;

    const uint8x16_t h4 = ctx->hashKeys[HASHKEY_0];
    const uint8x16_t h3 = ctx->hashKeys[(HASHKEY_0 - 1)];
    const uint8x16_t h2 = ctx->hashKeys[(HASHKEY_0 - 2)];
    const uint8x16_t h1 = ctx->hashKeys[(HASHKEY_0 - 3)];


    ctx->ctr1 = vaddq_u32(ctx->ctr1, one);
    uint8x16_t ctr2 = vaddq_u32(ctx->ctr1, one);
    uint8x16_t ctr3 = vaddq_u32(ctr2, one);
    uint8x16_t ctr4 = vaddq_u32(ctr3, one);

    uint8x16_t tmp1 = vrev64q_u8(ctx->ctr1);
    uint8x16_t tmp2 = vrev64q_u8(ctr2);
    uint8x16_t tmp3 = vrev64q_u8(ctr3);
    uint8x16_t tmp4 = vrev64q_u8(ctr4);

    quad_block(&ctx->aesKey, &tmp1, &tmp2, &tmp3, &tmp4);

    uint8x16_t in1 = vld1q_u8((&in[0 * 16]));
    uint8x16_t in2 = vld1q_u8((&in[1 * 16]));
    uint8x16_t in3 = vld1q_u8((&in[2 * 16]));
    uint8x16_t in4 = vld1q_u8((&in[3 * 16]));


    tmp1 = veorq_u8(tmp1, in1);
    tmp2 = veorq_u8(tmp2, in2);
    tmp3 = veorq_u8(tmp3, in3);
    tmp4 = veorq_u8(tmp4, in4);

    vst1q_u8(&out[0 * 16], tmp1);
    vst1q_u8(&out[1 * 16], tmp2);
    vst1q_u8(&out[2 * 16], tmp3);
    vst1q_u8(&out[3 * 16], tmp4);

    swap_endian_inplace(&tmp1);
    swap_endian_inplace(&tmp2);
    swap_endian_inplace(&tmp3);
    swap_endian_inplace(&tmp4);


    tmp1 = veorq_u8(tmp1, ctx->X);
    ctx->X = gfmul_multi_reduce(tmp1, tmp2, tmp3, tmp4,
                                h1, h2, h3, h4);

    ctx->ctr1 = ctr4;
    return NULL;
}


// Simple single block implementation
gcm_err *process_buffer_enc(gcm_ctx *ctx,
                            uint8_t *in,
                            size_t inlen,
                            uint8_t *out,
                            size_t outputLen,
                            size_t *read,
                            size_t *written) {

    *read = *written = 0;

    if (ctx->bufBlockIndex >0) {

        // Try round out the block

        size_t rem = ctx->bufBlockLen - ctx->bufBlockIndex;
        size_t toCopy = inlen < rem ? inlen : rem;
        memcpy(ctx->bufBlock + ctx->bufBlockIndex, in, toCopy);
        ctx->bufBlockIndex += toCopy;
        ctx->totalBytes += toCopy;
        in+= toCopy;
        inlen -= toCopy;

        if (ctx->bufBlockIndex == ctx->bufBlockLen) {
            gcm_err *err = process_block(ctx,in,out,outputLen);
            if (err != NULL) {
                return err;
            }
            *written += GCM_BLOCK_SIZE;
            out += GCM_BLOCK_SIZE;
            outputLen -= GCM_BLOCK_SIZE;
            ctx->totalBytes += GCM_BLOCK_SIZE;
            ctx->bufBlockIndex =0;
        }
    }


    while (ctx->bufBlockIndex == 0 && inlen >= GCM_BLOCK_SIZE && outputLen >= GCM_BLOCK_SIZE) {
        gcm_err *err = process_block(ctx,in,out,outputLen);
        if (err != NULL) {
            return err;
        }
        *written += GCM_BLOCK_SIZE;
        in += GCM_BLOCK_SIZE;
        out += GCM_BLOCK_SIZE;
        outputLen -= GCM_BLOCK_SIZE;
        ctx->totalBytes += GCM_BLOCK_SIZE;
    }




    return NULL;


}


gcm_err *process_buffer_dec(gcm_ctx *ctx,
                            uint8_t *in,
                            size_t inlen,
                            uint8_t *out,
                            size_t outputLen,
                            size_t *read,
                            size_t *written);


