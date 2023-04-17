//

//

#include "gcm.h"
#include <stddef.h>
#include <immintrin.h>
#include "gcmHash128.h"
#include <memory.h>
#include <assert.h>



bool areEqualCT(const uint8_t *left, const uint8_t *right, size_t len) {

    assert(left != NULL);
    assert(right != NULL);

    uint32_t nonEqual = 0;

    for (int i = 0; i != len; i++) {
        nonEqual |= (left[i] ^ right[i]);
    }

    return nonEqual == 0;
}


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
    ctx->ctr1 = _mm_add_epi32(ctx->ctr1, *ONE);
    __m128i tmp1 = _mm_shuffle_epi8(ctx->ctr1, *BSWAP_EPI64);


    tmp1 = _mm_xor_si128(tmp1, ctx->roundKeys[0]);
    for (j = 1; j < ctx->num_rounds - 1; j += 2) {
        tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[j]);
        tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[j + 1]);
    }
    tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[ctx->num_rounds - 1]);
    tmp1 = _mm_aesenclast_si128(tmp1, ctx->roundKeys[ctx->num_rounds]);
    __m128i in1 = _mm_loadu_si128((__m128i *) in);
    tmp1 = _mm_xor_si128(tmp1, in1);
    _mm_storeu_si128((__m128i *) (out), tmp1);
    tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);

    if (ctx->encryption) {
        ctx->X = _mm_xor_si128(ctx->X, tmp1);
    } else {
        ctx->X = _mm_xor_si128(ctx->X, _mm_shuffle_epi8(in1, *BSWAP_MASK));
    }
    gfmul(ctx->X, ctx->H, &ctx->X);

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

    const __m128i h4 = ctx->hashKeys[HASHKEY_0];
    const __m128i h3 = ctx->hashKeys[(HASHKEY_0 - 1)];
    const __m128i h2 = ctx->hashKeys[(HASHKEY_0 - 2)];
    const __m128i h1 = ctx->hashKeys[(HASHKEY_0 - 3)];

    const uint32_t rounds = ctx->num_rounds;

    ctx->ctr1 = _mm_add_epi32(ctx->ctr1, *ONE);
    __m128i ctr2 = _mm_add_epi32(ctx->ctr1, *ONE);
    __m128i ctr3 = _mm_add_epi32(ctr2, *ONE);
    __m128i ctr4 = _mm_add_epi32(ctr3, *ONE);

    __m128i tmp1 = _mm_shuffle_epi8(ctx->ctr1, *BSWAP_EPI64);
    __m128i tmp2 = _mm_shuffle_epi8(ctr2, *BSWAP_EPI64);
    __m128i tmp3 = _mm_shuffle_epi8(ctr3, *BSWAP_EPI64);
    __m128i tmp4 = _mm_shuffle_epi8(ctr4, *BSWAP_EPI64);

    __m128i rk = ctx->roundKeys[0];
    aes_xor(&tmp1, &tmp2, &tmp3, &tmp4, rk);

    __m128i in1 = _mm_loadu_si128(((__m128i *) &in[0 * 16]));
    __m128i in2 = _mm_loadu_si128(((__m128i *) &in[1 * 16]));
    __m128i in3 = _mm_loadu_si128(((__m128i *) &in[2 * 16]));
    __m128i in4 = _mm_loadu_si128(((__m128i *) &in[3 * 16]));

    int j;
    for (j = 1; j < rounds; j++) {
        aes_enc(&tmp1, &tmp2, &tmp3, &tmp4, ctx->roundKeys[j]);
    }

    aes_enc_last(&tmp1, &tmp2, &tmp3, &tmp4, ctx->roundKeys[j]);

    tmp1 = _mm_xor_si128(tmp1, in1);
    tmp2 = _mm_xor_si128(tmp2, in2);
    tmp3 = _mm_xor_si128(tmp3, in3);
    tmp4 = _mm_xor_si128(tmp4, in4);

    _mm_storeu_si128((__m128i *) &out[0 * 16], tmp1);
    _mm_storeu_si128((__m128i *) &out[1 * 16], tmp2);
    _mm_storeu_si128((__m128i *) &out[2 * 16], tmp3);
    _mm_storeu_si128((__m128i *) &out[3 * 16], tmp4);

    tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);
    tmp2 = _mm_shuffle_epi8(tmp2, *BSWAP_MASK);
    tmp3 = _mm_shuffle_epi8(tmp3, *BSWAP_MASK);
    tmp4 = _mm_shuffle_epi8(tmp4, *BSWAP_MASK);

    tmp1 = _mm_xor_si128(tmp1, ctx->X);
    gfmul_multi_reduce(tmp1, tmp2, tmp3, tmp4,
                       h1, h2, h3, h4,
                       &ctx->X);

    ctx->ctr1 = ctr4;
    return NULL;
}


gcm_err *process_buffer_enc(gcm_ctx *ctx,
                            uint8_t *in,
                            size_t inlen,
                            uint8_t *out,
                            size_t outputLen,
                            size_t *read,
                            size_t *written) {


    *read = *written = 0;


    if (ctx->encryption && ctx->bufBlockIndex == 0 && inlen >= FOUR_BLOCKS && outputLen >= FOUR_BLOCKS) {
        // Special case when nothing is buffered, and we have more than 4 blocks to process, and we are doing
        // encryption.

        // The hash is calculated on the cipher text so if we are going to interleave reduction and encryption
        // then the reduction is always going to be on the previous cipher texts.
        // Eg:
        // 1. Create initial cipher texts
        // 2. Create subsequent cipher texts supplying previous cipher texts for reduction.
        // 3. Loop back to 2 until input is consumed.
        // 4. Final trailing reduction
        //

        if (out == NULL) {
            //
            // Java api my supply a null output array if it expects no output, however
            // if output does occur then we need to catch that here.
            //
            return make_gcm_error("out is null, output generated when no output was expected by caller",
                                  ILLEGAL_ARGUMENT);

        }


        if (ctx->blocksRemaining < 4) {
            return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
        }
        ctx->blocksRemaining -= 4;


        // Hash keys are constant throughout.
        const __m128i h4 = ctx->hashKeys[HASHKEY_0];
        const __m128i h3 = ctx->hashKeys[(HASHKEY_0 - 1)];
        const __m128i h2 = ctx->hashKeys[(HASHKEY_0 - 2)];
        const __m128i h1 = ctx->hashKeys[(HASHKEY_0 - 3)];

        // Initial set of 16 blocks.
        __m128i id0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
        __m128i id1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);
        __m128i id2 = _mm_loadu_si128((__m128i *) &in[2 * 16]);
        __m128i id3 = _mm_loadu_si128((__m128i *) &in[3 * 16]);

        ctx->ctr1 = _mm_add_epi32(ctx->ctr1, *ONE);
        __m128i ctr2 = _mm_add_epi32(ctx->ctr1, *ONE);
        __m128i ctr3 = _mm_add_epi32(ctr2, *ONE);
        __m128i ctr4 = _mm_add_epi32(ctr3, *ONE);


        __m128i tmp1 = _mm_shuffle_epi8(ctx->ctr1, *BSWAP_EPI64);
        __m128i tmp2 = _mm_shuffle_epi8(ctr2, *BSWAP_EPI64);
        __m128i tmp3 = _mm_shuffle_epi8(ctr3, *BSWAP_EPI64);
        __m128i tmp4 = _mm_shuffle_epi8(ctr4, *BSWAP_EPI64);


        apply_aes_no_reduction(
                &id0, &id1, &id2, &id3,
                tmp1, tmp2, tmp3, tmp4,
                ctx->roundKeys, ctx->num_rounds
        );

        _mm_storeu_si128((__m128i *) &out[0 * 16], id0);
        _mm_storeu_si128((__m128i *) &out[1 * 16], id1);
        _mm_storeu_si128((__m128i *) &out[2 * 16], id2);
        _mm_storeu_si128((__m128i *) &out[3 * 16], id3);


        // id0..3 are the initial set of cipher texts but bit swapped

        id0 = _mm_shuffle_epi8(id0, *BSWAP_MASK);
        id1 = _mm_shuffle_epi8(id1, *BSWAP_MASK);
        id2 = _mm_shuffle_epi8(id2, *BSWAP_MASK);
        id3 = _mm_shuffle_epi8(id3, *BSWAP_MASK);


        *written += FOUR_BLOCKS;
        *read += FOUR_BLOCKS;
        ctx->totalBytes += FOUR_BLOCKS;
        inlen -= FOUR_BLOCKS;
        outputLen -= FOUR_BLOCKS;

        in += FOUR_BLOCKS;
        out += FOUR_BLOCKS;

        ctx->ctr1 = ctr4;

        while (inlen >= FOUR_BLOCKS && outputLen >= FOUR_BLOCKS) {


            if (ctx->blocksRemaining < 4) {
                return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            ctx->blocksRemaining -= 4;

            // Encrypt next set of 4 blocks passing the result of the last encryption for reduction.

            __m128i d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
            __m128i d1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);
            __m128i d2 = _mm_loadu_si128((__m128i *) &in[2 * 16]);
            __m128i d3 = _mm_loadu_si128((__m128i *) &in[3 * 16]);

            ctx->ctr1 = _mm_add_epi32(ctx->ctr1, *ONE);
            ctr2 = _mm_add_epi32(ctx->ctr1, *ONE);
            ctr3 = _mm_add_epi32(ctr2, *ONE);
            ctr4 = _mm_add_epi32(ctr3, *ONE);


            tmp1 = _mm_shuffle_epi8(ctx->ctr1, *BSWAP_EPI64);
            tmp2 = _mm_shuffle_epi8(ctr2, *BSWAP_EPI64);
            tmp3 = _mm_shuffle_epi8(ctr3, *BSWAP_EPI64);
            tmp4 = _mm_shuffle_epi8(ctr4, *BSWAP_EPI64);

            id0 = _mm_xor_si128(id0, ctx->X);
            apply_aes_with_reduction(&d0, &d1, &d2, &d3,
                                     id0, id1, id2, id3,
                                     h1, h2, h3, h4,
                                     tmp1, tmp2, tmp3, tmp4,
                                     ctx->roundKeys, &ctx->X, ctx->num_rounds);

            _mm_storeu_si128((__m128i *) &out[0 * 16], d0);
            _mm_storeu_si128((__m128i *) &out[1 * 16], d1);
            _mm_storeu_si128((__m128i *) &out[2 * 16], d2);
            _mm_storeu_si128((__m128i *) &out[3 * 16], d3);

            // id0..3 are now the last cipher texts but bit swapped

            id0 = _mm_shuffle_epi8(d0, *BSWAP_MASK);
            id1 = _mm_shuffle_epi8(d1, *BSWAP_MASK);
            id2 = _mm_shuffle_epi8(d2, *BSWAP_MASK);
            id3 = _mm_shuffle_epi8(d3, *BSWAP_MASK);

            *written += FOUR_BLOCKS;
            *read += FOUR_BLOCKS;
            ctx->totalBytes += FOUR_BLOCKS;
            inlen -= FOUR_BLOCKS;
            outputLen -= FOUR_BLOCKS;
            in += FOUR_BLOCKS;
            out += FOUR_BLOCKS;

            ctx->ctr1 = ctr4;
        }

        //
        // Do trailing reduction
        //

        id0 = _mm_xor_si128(id0, ctx->X);
        gfmul_multi_reduce(
                id0, id1, id2, id3,
                h1, h2, h3, h4,
                &ctx->X);

        // fall through to existing code that will buffer trailing blocks if necessary

    }


    size_t rem = ctx->bufBlockLen - ctx->bufBlockIndex;
    size_t toCopy = inlen < rem ? inlen : rem;
    memcpy(ctx->bufBlock + ctx->bufBlockIndex, in, toCopy);
    ctx->bufBlockIndex += toCopy;
    ctx->totalBytes += toCopy;

    if (ctx->bufBlockIndex == ctx->bufBlockLen) {
        if (outputLen < FOUR_BLOCKS) {
            return make_gcm_error("output len too short", OUTPUT_LENGTH);
        }
        gcm_err *err = processFourBlocksEnc(ctx, ctx->bufBlock, out);
        if (err != NULL) {
            return err;
        }
        ctx->bufBlockIndex -= FOUR_BLOCKS;
        *written += FOUR_BLOCKS;
    }

    *read += toCopy;


    return NULL;

}


gcm_err *processFourBlocks_dec(gcm_ctx *ctx, uint8_t *in, uint8_t *out) {

    if (out == NULL) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        return make_gcm_error("out is null, output generated when no output was expected by caller", ILLEGAL_ARGUMENT);

    }

    __m128i ctr2, ctr3, ctr4, tmp12, tmp34, tmp56, tmp78;

    // Hash keys are constant throughout.
    const __m128i h4 = ctx->hashKeys[HASHKEY_0];
    const __m128i h3 = ctx->hashKeys[(HASHKEY_0 - 1)];
    const __m128i h2 = ctx->hashKeys[(HASHKEY_0 - 2)];
    const __m128i h1 = ctx->hashKeys[(HASHKEY_0 - 3)];


    if (ctx->blocksRemaining < 4) {
        return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
    }
    ctx->blocksRemaining -= 4;

    ctx->ctr1 = _mm_add_epi32(ctx->ctr1, *ONE);
    ctr2 = _mm_add_epi32(ctx->ctr1, *ONE);
    ctr3 = _mm_add_epi32(ctr2, *ONE);
    ctr4 = _mm_add_epi32(ctr3, *ONE);

    tmp12 = _mm_shuffle_epi8(ctx->ctr1, *BSWAP_EPI64);
    tmp34 = _mm_shuffle_epi8(ctr2, *BSWAP_EPI64);
    tmp56 = _mm_shuffle_epi8(ctr3, *BSWAP_EPI64);
    tmp78 = _mm_shuffle_epi8(ctr4, *BSWAP_EPI64);


    __m128i in1 = _mm_loadu_si128(((__m128i *) &in[0 * 16]));
    __m128i in2 = _mm_loadu_si128(((__m128i *) &in[1 * 16]));
    __m128i in3 = _mm_loadu_si128(((__m128i *) &in[2 * 16]));
    __m128i in4 = _mm_loadu_si128(((__m128i *) &in[3 * 16]));


    apply_aes_with_reduction_dec(&in1, &in2, &in3, &in4,
                                 h1, h2, h3, h4,
                                 tmp12, tmp34, tmp56, tmp78,
                                 ctx->roundKeys, &ctx->X, ctx->num_rounds);


    _mm_storeu_si128((__m128i *) &out[0 * 16], in1);
    _mm_storeu_si128((__m128i *) &out[1 * 16], in2);
    _mm_storeu_si128((__m128i *) &out[2 * 16], in3);
    _mm_storeu_si128((__m128i *) &out[3 * 16], in4);


    ctx->ctr1 = ctr4;
    return NULL;
}


gcm_err *process_buffer_dec(gcm_ctx *ctx,
                            uint8_t *in,
                            size_t inlen,
                            uint8_t *out,
                            size_t outputLen,
                            size_t *read,
                            size_t *written) {

    *read = *written = 0;

    if (ctx->bufBlockIndex > 0 && ctx->bufBlockIndex + inlen >= ctx->bufBlockLen) {

        // We have 4 or more blocks with of data in the buffer.
        // Process them now and copy any residual back to the start of the buffer.
        if (ctx->bufBlockIndex >= FOUR_BLOCKS) {
            if (outputLen < FOUR_BLOCKS) {
                return make_gcm_error("output len too short", OUTPUT_LENGTH);
            }
            gcm_err *err = processFourBlocks_dec(ctx, ctx->bufBlock, out);
            if (err != NULL) {
                return err;
            }
            *written += FOUR_BLOCKS;
            outputLen -= FOUR_BLOCKS;
            out += FOUR_BLOCKS;

            //
            // Copy whatever bytes after the 4 blocks back to the start of the buffer.
            // Internal copy so read does not change.
            //

            size_t toCopy = ctx->bufBlockIndex - FOUR_BLOCKS;
            memcpy(ctx->bufBlock, ctx->bufBlock + ctx->bufBlockIndex, toCopy);
            ctx->bufBlockIndex = toCopy;
        }

        //
        // There may still data in the buffer but less than before, does
        // our condition for rounding the buffer out still exist with respect
        // to the available input?
        //
        if (ctx->bufBlockIndex > 0 && ctx->bufBlockIndex + inlen >= ctx->bufBlockLen) {
            size_t toCopy = FOUR_BLOCKS - ctx->bufBlockIndex;

            // Copy from the input what we need to round out the buffer.
            memcpy(ctx->bufBlock + ctx->bufBlockIndex, in, toCopy);
            if (outputLen < FOUR_BLOCKS) {
                return make_gcm_error("output len too short", OUTPUT_LENGTH);
            }
            gcm_err *err = processFourBlocks_dec(ctx, ctx->bufBlock, out);
            if (err != NULL) {
                return err;
            }
            ctx->bufBlockIndex = 0;
            *written += FOUR_BLOCKS;
            *read += toCopy;
            ctx->totalBytes += toCopy;
            outputLen -= FOUR_BLOCKS;
            in += toCopy;
            out += FOUR_BLOCKS;
        }
    }

    //
    // Bulk decryption.
    //
    if (ctx->bufBlockIndex == 0 && inlen >= ctx->bufBlockLen && outputLen >= FOUR_BLOCKS) {

        // Hash keys are constant throughout.
        const __m128i h4 = ctx->hashKeys[HASHKEY_0];
        const __m128i h3 = ctx->hashKeys[(HASHKEY_0 - 1)];
        const __m128i h2 = ctx->hashKeys[(HASHKEY_0 - 2)];
        const __m128i h1 = ctx->hashKeys[(HASHKEY_0 - 3)];

        __m128i d0, d1, d2, d3, tmp12, tmp34, tmp56, tmp78;

        while (inlen >= ctx->bufBlockLen && outputLen >= FOUR_BLOCKS) {


            if (ctx->blocksRemaining < 4) {
                return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            ctx->blocksRemaining -= 4;

            d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
            d1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);
            d2 = _mm_loadu_si128((__m128i *) &in[2 * 16]);
            d3 = _mm_loadu_si128((__m128i *) &in[3 * 16]);

            ctx->ctr1 = _mm_add_epi32(ctx->ctr1, *ONE);
            __m128i ctr2 = _mm_add_epi32(ctx->ctr1, *ONE);
            __m128i ctr3 = _mm_add_epi32(ctr2, *ONE);
            __m128i ctr4 = _mm_add_epi32(ctr3, *ONE);

            tmp12 = _mm_shuffle_epi8(ctx->ctr1, *BSWAP_EPI64);
            tmp34 = _mm_shuffle_epi8(ctr2, *BSWAP_EPI64);
            tmp56 = _mm_shuffle_epi8(ctr3, *BSWAP_EPI64);
            tmp78 = _mm_shuffle_epi8(ctr4, *BSWAP_EPI64);

            ctx->ctr1 = ctr4;


            apply_aes_with_reduction_dec(&d0, &d1, &d2, &d3,
                                         h1, h2, h3, h4,
                                         tmp12, tmp34, tmp56, tmp78,
                                         ctx->roundKeys, &ctx->X, ctx->num_rounds);

            _mm_storeu_si128((__m128i *) &out[0 * 16], d0);
            _mm_storeu_si128((__m128i *) &out[1 * 16], d1);
            _mm_storeu_si128((__m128i *) &out[2 * 16], d2);
            _mm_storeu_si128((__m128i *) &out[3 * 16], d3);

            // id0..3 are now the last cipher texts but bit swapped

            *written += FOUR_BLOCKS;
            *read += FOUR_BLOCKS;
            ctx->totalBytes += FOUR_BLOCKS;
            inlen -= FOUR_BLOCKS;
            outputLen -= FOUR_BLOCKS;
            in += FOUR_BLOCKS;
            out += FOUR_BLOCKS;
        } // while
    } else {


        if (ctx->bufBlockIndex == 0 && inlen >= ctx->bufBlockLen) {
            if (outputLen < FOUR_BLOCKS) {
                return make_gcm_error("output len too short", OUTPUT_LENGTH);
            }
            gcm_err *err = processFourBlocks_dec(ctx, in, out);
            if (err != NULL) {
                return err;
            }
            *written += FOUR_BLOCKS;
            *read += FOUR_BLOCKS;
            ctx->totalBytes += FOUR_BLOCKS;

        } else {

            size_t rem = ctx->bufBlockLen - ctx->bufBlockIndex;
            size_t toCopy = inlen < rem ? inlen : rem;
            memcpy(ctx->bufBlock + ctx->bufBlockIndex, in, toCopy);
            ctx->bufBlockIndex += toCopy;
            ctx->totalBytes += toCopy;

            if (ctx->bufBlockIndex == ctx->bufBlockLen) {
                if (outputLen < FOUR_BLOCKS) {
                    return make_gcm_error("output len too short", OUTPUT_LENGTH);
                }
                gcm_err *err = processFourBlocks_dec(ctx, ctx->bufBlock, out);
                if (err != NULL) {
                    return err;
                }

                if (ctx->macBlockLen == 16) {
                    _mm_storeu_si128((__m128i *) ctx->bufBlock,
                                     _mm_loadu_si128((__m128i *) (ctx->bufBlock + FOUR_BLOCKS)));
                } else {
                    memcpy(ctx->bufBlock, ctx->bufBlock + FOUR_BLOCKS, ctx->macBlockLen);
                }

                ctx->bufBlockIndex -= FOUR_BLOCKS;
                *written += FOUR_BLOCKS;
            }
            *read += toCopy;
        }
    }
    return NULL;
}


/**
 *
 * @param output
 * @param outLen
 * @param written
 * @return NULL if no error, else ptr to struct CALLER NEEDS TO FREE
 */
gcm_err *gcm_doFinal(gcm_ctx *ctx, unsigned char *output, size_t outLen, size_t *written) {
    *written = 0;


    if (ctx->totalBytes == 0) {
        gcm__initBytes(ctx);
    }


    unsigned char *start = output;
    unsigned char *outPtr = start;

    __m128i tmp1;

    size_t limit = ctx->bufBlockIndex;

    if (!ctx->encryption) {

        // We need at least a mac block, and
        if (ctx->macBlockLen > ctx->bufBlockIndex) {
            return make_gcm_error("cipher text too short", ILLEGAL_CIPHER_TEXT);
        }
        limit -= ctx->macBlockLen; // Limit of cipher text before tag.
        ctx->totalBytes -= ctx->macBlockLen;

        // decryption so output buffer cannot be less than limit.
        // bytes are to limit are the mac block (tag)
        if (outLen < limit) {
            return make_gcm_error("output buffer too small", OUTPUT_LENGTH);
        }
    } else {
        // encryption, output must take remaining buffer + mac block
        if (outLen < ctx->bufBlockIndex + ctx->macBlockLen) {
            return make_gcm_error("output buffer too small", OUTPUT_LENGTH);
        }
    }

    if (ctx->bufBlockIndex > 0) {

        //
        // As we process data in four block hunks, our doFinal needs
        // to clean up any:
        // 1. Whole remaining blocks.
        // 2. Any remaining bytes less than one block in length.
        //

        int t = 0;
        if (limit >= BLOCK_SIZE) {

            //
            // Process whole blocks.
            //

            for (; t < ((limit >> 4) << 4); t += BLOCK_SIZE) {
                gcm_err *err = process_block(ctx, &ctx->bufBlock[t], outPtr, outLen);
                if (err != NULL) {
                    return err;
                }
                outPtr += BLOCK_SIZE;
                outLen -= BLOCK_SIZE;
            }

        }


        if (limit % 16) {
            if (ctx->blocksRemaining < 1) {
                return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            ctx->blocksRemaining -= 1;

            ctx->ctr1 = _mm_add_epi32(ctx->ctr1, *ONE);
            tmp1 = _mm_shuffle_epi8(ctx->ctr1, *BSWAP_EPI64);

            tmp1 = _mm_xor_si128(tmp1, ctx->roundKeys[0]);
            for (int j = 1; j < ctx->num_rounds - 1; j += 2) {
                tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[j]);
                tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[j + 1]);
            }
            tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[ctx->num_rounds - 1]);
            tmp1 = _mm_aesenclast_si128(tmp1, ctx->roundKeys[ctx->num_rounds]);

            __m128i in1 = _mm_loadu_si128((__m128i *) &ctx->bufBlock[t]);

            tmp1 = _mm_xor_si128(tmp1, in1);
            ctx->last_block = tmp1;
            int j;
            for (j = 0; j < limit % 16; j++) {
                *outPtr = ((unsigned char *) &ctx->last_block)[j];
                outPtr++;
            }
            for (; j < BLOCK_SIZE; j++) {
                ((unsigned char *) &ctx->last_block)[j] = 0;
                ((unsigned char *) &in1)[j] = 0;
            }
            tmp1 = ctx->last_block;
            tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);

            if (ctx->encryption) {
                ctx->X = _mm_xor_si128(ctx->X, tmp1);
            } else {
                ctx->X = _mm_xor_si128(ctx->X, _mm_shuffle_epi8(in1, *BSWAP_MASK));
            }
            gfmul(ctx->X, ctx->H, &ctx->X);
        } // partial
    } // has data in buffer




    ctx->atLength += ctx->atBlockPos;

    //
    // Deal with additional associated text that was supplied after
    // the init or reset methods were called.
    //
    if (ctx->atLength > ctx->atLengthPre) {

        if (ctx->atBlockPos > 0) {
            //
            // finalise any outstanding associated data
            // that was less than the block size.
            //
            tmp1 = ctx->last_aad_block;
            tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);
            ctx->S_at = _mm_xor_si128(ctx->S_at, tmp1);
            gfmul(ctx->S_at, ctx->H, &ctx->S_at);
        }


        if (ctx->atLengthPre > 0) {
            ctx->S_at = _mm_xor_si128(ctx->S_at, ctx->S_atPre);
        }

        size_t c = ((ctx->totalBytes * 8) + 127) >> 7;
        __m128i H_c ;


        gcm_exponentiate(ctx->H,c,&H_c);


        gfmul(ctx->S_at, H_c, &ctx->S_at);

        ctx->X = _mm_xor_si128(ctx->X, ctx->S_at);
    } // extra ad




    tmp1 = _mm_insert_epi64(tmp1, (long long) ctx->totalBytes * 8, 0);
    tmp1 = _mm_insert_epi64(tmp1, (long long) ctx->atLength * 8, 1);

    unsigned char tmpTag[BLOCK_SIZE];

    ctx->X = _mm_xor_si128(ctx->X, tmp1);
    gfmul(ctx->X, ctx->H, &ctx->X);
    ctx->X = _mm_shuffle_epi8(ctx->X, *BSWAP_MASK);
    ctx->T = _mm_xor_si128(ctx->X, ctx->T);


    _mm_storeu_si128((__m128i *) tmpTag, ctx->T);

    // Copy into mac block
    memcpy(ctx->macBlock, tmpTag, ctx->macBlockLen);
    memset(tmpTag, 0, BLOCK_SIZE);


    if (ctx->encryption) {
        // Append to end of message
        memcpy(outPtr, ctx->macBlock, ctx->macBlockLen);
        outPtr += ctx->macBlockLen;
    } else {

        if (!areEqualCT(ctx->macBlock, ctx->bufBlock + limit, ctx->macBlockLen)) {
            return make_gcm_error("mac check in GCM failed", ILLEGAL_CIPHER_TEXT);
        }
    }

    gcm_reset(ctx, true);
    *written = (size_t) (outPtr - start);


    return NULL;
}

void gcm_variant_init(gcm_ctx *ctx) {
    // does nothing
}

