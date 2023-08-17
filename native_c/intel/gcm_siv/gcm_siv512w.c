//
//

#include <memory.h>
#include <assert.h>
#include <stdbool.h>
#include "gcm_siv.h"
#include "gcm_sivHash512.h"


bool areEqualCT(const uint8_t *left, const uint8_t *right, size_t len) {

    assert(left != NULL);
    assert(right != NULL);

    uint32_t nonEqual = 0;

    for (int i = 0; i != len; i++) {
        nonEqual |= (left[i] ^ right[i]);
    }

    return nonEqual == 0;
}


gcm_siv_err *process_block(gcm_siv_ctx *ctx, uint8_t *in, uint8_t *out, size_t outputLen) {
    if (out == NULL) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        return make_gcm_siv_error("out is null, output generated when no output was expected by caller", ILLEGAL_ARGUMENT);
    }


    if (ctx->blocksRemaining < 1) {
        return make_gcm_siv_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
    }
    ctx->blocksRemaining -= 1;


    if (outputLen < BLOCK_SIZE) {
        return make_gcm_siv_error("output len too short", OUTPUT_LENGTH);
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

/**
 * Decryption version.
 *
 * @param in the cipher text
 * @param out  the plain text
 */
gcm_siv_err *process16Blocks_dec(gcm_siv_ctx *ctx, uint8_t *in, uint8_t *out) {

    if (out == NULL) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        return make_gcm_siv_error("out is null, output generated when no output was expected by caller", ILLEGAL_ARGUMENT);
    }

    if (ctx->blocksRemaining < 16) {
        return make_gcm_siv_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
    }

    ctx->blocksRemaining -= 16;

    const uint32_t aes_round_max = ctx->num_rounds;
    const __m512i h4 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[12]);
    const __m512i h3 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[8]);
    const __m512i h2 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[4]);
    const __m512i h1 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[0]);

    __m512i ctr12, ctr34, ctr56, ctr78;
    spreadCtr(ctx->ctr1, &ctr12, &ctr34, &ctr56, &ctr78);

    __m512i ctr12s = _mm512_shuffle_epi8(ctr12, *BSWAP_EPI64_512);
    __m512i ctr34s = _mm512_shuffle_epi8(ctr34, *BSWAP_EPI64_512);
    __m512i ctr56s = _mm512_shuffle_epi8(ctr56, *BSWAP_EPI64_512);
    __m512i ctr78s = _mm512_shuffle_epi8(ctr78, *BSWAP_EPI64_512);


    //
    // ctr1 is used during doFinal, we need that 128b value before
    // incrementing.
    //
    ctx->ctr1 = _mm_add_epi32(ctx->ctr1, *SIXTEEN);

    // Load 16 blocks to decrypt
    __m512i in1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
    __m512i in2 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
    __m512i in3 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
    __m512i in4 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);


    apply_aes_with_reduction_dec(
            &in1, &in2, &in3, &in4,
            h1, h2, h3, h4,
            ctr12s, ctr34s, ctr56s, ctr78s,
            ctx->roundKeys, &ctx->X, aes_round_max);

    _mm512_storeu_si512((__m256i *) &out[0 * 64], in1);
    _mm512_storeu_si512((__m256i *) &out[1 * 64], in2);
    _mm512_storeu_si512((__m256i *) &out[2 * 64], in3);
    _mm512_storeu_si512((__m256i *) &out[3 * 64], in4);


    return NULL;
}

/**
 * Encryption version.
 * *
 * @param in the cipher text
 * @param out  the plain text
 */
gcm_siv_err *process16Blocks_enc(gcm_siv_ctx *ctx, uint8_t *in, uint8_t *out) {



    if (out == NULL) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        return make_gcm_siv_error("out is null, output generated when no output was expected by caller", ILLEGAL_ARGUMENT);
    }



    if (ctx->blocksRemaining < 16) {
        return make_gcm_siv_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
    }
    ctx->blocksRemaining -= 16;

    const uint32_t aes_round_max = ctx->num_rounds;
    const __m512i h4 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[12]);
    const __m512i h3 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[8]);
    const __m512i h2 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[4]);
    const __m512i h1 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[0]);


    __m512i ctr12, ctr34, ctr56, ctr78;
    spreadCtr(ctx->ctr1, &ctr12, &ctr34, &ctr56, &ctr78);


    __m512i tmp12 = _mm512_shuffle_epi8(ctr12, *BSWAP_EPI64_512);
    __m512i tmp34 = _mm512_shuffle_epi8(ctr34, *BSWAP_EPI64_512);
    __m512i tmp56 = _mm512_shuffle_epi8(ctr56, *BSWAP_EPI64_512);
    __m512i tmp78 = _mm512_shuffle_epi8(ctr78, *BSWAP_EPI64_512);


    //
    // ctr1 is used during doFinal, we need that 128b value before
    // incrementing.
    //
    ctx->ctr1 = _mm_add_epi32(ctx->ctr1,
                              *SIXTEEN);  //_mm256_extracti128_si256(ctr78, 1); //   _mm_add_epi32(ctr1, _mm_set_epi32(0, 4, 0, 0));


    __m512i inw1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
    __m512i inw2 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
    __m512i inw3 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
    __m512i inw4 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);


    tmp12 = _mm512_xor_si512(tmp12, _mm512_broadcast_i32x4(ctx->roundKeys[0]));
    tmp34 = _mm512_xor_si512(tmp34, _mm512_broadcast_i32x4(ctx->roundKeys[0]));
    tmp56 = _mm512_xor_si512(tmp56, _mm512_broadcast_i32x4(ctx->roundKeys[0]));
    tmp78 = _mm512_xor_si512(tmp78, _mm512_broadcast_i32x4(ctx->roundKeys[0]));

    uint32_t aes_round;


    for (aes_round = 1; aes_round < aes_round_max; aes_round++) {
        tmp12 = _mm512_aesenc_epi128(tmp12, _mm512_broadcast_i32x4(ctx->roundKeys[aes_round]));
        tmp34 = _mm512_aesenc_epi128(tmp34, _mm512_broadcast_i32x4(ctx->roundKeys[aes_round]));
        tmp56 = _mm512_aesenc_epi128(tmp56, _mm512_broadcast_i32x4(ctx->roundKeys[aes_round]));
        tmp78 = _mm512_aesenc_epi128(tmp78, _mm512_broadcast_i32x4(ctx->roundKeys[aes_round]));
    }


    tmp12 = _mm512_aesenclast_epi128(tmp12, _mm512_broadcast_i32x4(ctx->roundKeys[aes_round]));
    tmp34 = _mm512_aesenclast_epi128(tmp34, _mm512_broadcast_i32x4(ctx->roundKeys[aes_round]));
    tmp56 = _mm512_aesenclast_epi128(tmp56, _mm512_broadcast_i32x4(ctx->roundKeys[aes_round]));
    tmp78 = _mm512_aesenclast_epi128(tmp78, _mm512_broadcast_i32x4(ctx->roundKeys[aes_round]));


    tmp12 = _mm512_xor_si512(tmp12, inw1);
    tmp34 = _mm512_xor_si512(tmp34, inw2);
    tmp56 = _mm512_xor_si512(tmp56, inw3);
    tmp78 = _mm512_xor_si512(tmp78, inw4);

    _mm512_storeu_si512((__m256i *) &out[0 * 64], tmp12);
    _mm512_storeu_si512((__m256i *) &out[1 * 64], tmp34);
    _mm512_storeu_si512((__m256i *) &out[2 * 64], tmp56);
    _mm512_storeu_si512((__m256i *) &out[3 * 64], tmp78);


    tmp12 = _mm512_shuffle_epi8(tmp12, *BSWAP_MASK_512);
    tmp34 = _mm512_shuffle_epi8(tmp34, *BSWAP_MASK_512);
    tmp56 = _mm512_shuffle_epi8(tmp56, *BSWAP_MASK_512);
    tmp78 = _mm512_shuffle_epi8(tmp78, *BSWAP_MASK_512);

    tmp12 = _mm512_xor_si512(tmp12, _mm512_castsi128_si512(ctx->X));

    gfmul_multi_reduce(tmp12, tmp34, tmp56, tmp78, h1, h2, h3, h4, &ctx->X);


    return NULL;
}


gcm_siv_err *process_buffer_dec(gcm_siv_ctx *ctx,
                            uint8_t *in,
                            size_t inlen,
                            uint8_t *out,
                            size_t outputLen,
                            size_t *read,
                            size_t *written) {

    *read = *written = 0;

    if (ctx->bufBlockIndex > 0 && ctx->bufBlockIndex + inlen >= ctx->bufBlockLen) {

        // We have 16 or more blocks with of data in the buffer.
        // Process them now and copy any residual back to the start of the buffer.
        if (ctx->bufBlockIndex >= SIXTEEN_BLOCKS) {
            if (outputLen < SIXTEEN_BLOCKS) {
                return make_gcm_siv_error("output len too short", OUTPUT_LENGTH);
            }
            gcm_siv_err *err = process16Blocks_dec(ctx, ctx->bufBlock, out);
            if (err != NULL) {
                return err;
            }

            *written += SIXTEEN_BLOCKS;
            outputLen -= SIXTEEN_BLOCKS;
            out += SIXTEEN_BLOCKS;

            //
            // Copy whatever bytes after the 16 blocks back to the start of the buffer.
            // Internal copy so read does not change.
            //

            size_t toCopy = ctx->bufBlockIndex - SIXTEEN_BLOCKS;
            memcpy(ctx->bufBlock, ctx->bufBlock + ctx->bufBlockIndex, toCopy);
            ctx->bufBlockIndex = toCopy;
        }

        //
        // There may still data in the buffer but less than before, does
        // our condition for rounding the buffer out still exist with respect
        // to the available input?
        //
        if (ctx->bufBlockIndex > 0 && ctx->bufBlockIndex + inlen >= ctx->bufBlockLen) {
            size_t toCopy = SIXTEEN_BLOCKS - ctx->bufBlockIndex;

            // Copy from the input what we need to round out the buffer.
            memcpy(ctx->bufBlock + ctx->bufBlockIndex, in, toCopy);
            if (outputLen < SIXTEEN_BLOCKS) {
                return make_gcm_siv_error("output len too short", OUTPUT_LENGTH);
            }
            gcm_siv_err *err = process16Blocks_dec(ctx, ctx->bufBlock, out);
            if (err != NULL) {
                return err;
            }
            ctx->bufBlockIndex = 0;
            *written += SIXTEEN_BLOCKS;
            *read += toCopy;
            ctx->totalBytes += toCopy;
            outputLen -= SIXTEEN_BLOCKS;
            in += toCopy;
            out += SIXTEEN_BLOCKS;
        }
    }


    //
    // Bulk decryption.
    //
    if (ctx->bufBlockIndex == 0 && inlen >= ctx->bufBlockLen && outputLen >= SIXTEEN_BLOCKS) {

        // Hash keys are constant throughout.
        const __m512i h4 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[12]);
        const __m512i h3 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[8]);
        const __m512i h2 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[4]);
        const __m512i h1 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[0]);

        __m512i d0, d1, d2, d3, tmp12, tmp34, tmp56, tmp78;

        while (inlen >= ctx->bufBlockLen && outputLen >= SIXTEEN_BLOCKS) {


            if (ctx->blocksRemaining < 16) {
                return make_gcm_siv_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            ctx->blocksRemaining -= 16;

            // Encrypt next set of 16 blocks passing the result of the last encryption for reduction.

            d0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
            d1 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
            d2 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
            d3 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);

            __m512i ctr12, ctr34, ctr56, ctr78;
            spreadCtr(ctx->ctr1, &ctr12, &ctr34, &ctr56, &ctr78);


            tmp12 = _mm512_shuffle_epi8(ctr12, *BSWAP_EPI64_512);
            tmp34 = _mm512_shuffle_epi8(ctr34, *BSWAP_EPI64_512);
            tmp56 = _mm512_shuffle_epi8(ctr56, *BSWAP_EPI64_512);
            tmp78 = _mm512_shuffle_epi8(ctr78, *BSWAP_EPI64_512);

            ctx->ctr1 = _mm_add_epi32(ctx->ctr1, *SIXTEEN);


            apply_aes_with_reduction_dec(&d0, &d1, &d2, &d3,
                                         h1, h2, h3, h4,
                                         tmp12, tmp34, tmp56, tmp78,
                                         ctx->roundKeys, &ctx->X, ctx->num_rounds);

            _mm512_storeu_si512((__m512i *) &out[0 * 64], d0);
            _mm512_storeu_si512((__m512i *) &out[1 * 64], d1);
            _mm512_storeu_si512((__m512i *) &out[2 * 64], d2);
            _mm512_storeu_si512((__m512i *) &out[3 * 64], d3);

            // id0..3 are now the last cipher texts but bit swapped

            *written += SIXTEEN_BLOCKS;
            *read += SIXTEEN_BLOCKS;
            ctx->totalBytes += SIXTEEN_BLOCKS;
            inlen -= SIXTEEN_BLOCKS;
            outputLen -= SIXTEEN_BLOCKS;
            in += SIXTEEN_BLOCKS;
            out += SIXTEEN_BLOCKS;
        }
    } else {


        if (ctx->bufBlockIndex == 0 && inlen >= ctx->bufBlockLen) {
            if (outputLen < SIXTEEN_BLOCKS) {
                return make_gcm_siv_error("output len too short", OUTPUT_LENGTH);
            }
            process16Blocks_dec(ctx, in, out);
            *written += SIXTEEN_BLOCKS;
            *read += SIXTEEN_BLOCKS;
            ctx->totalBytes += SIXTEEN_BLOCKS;

        } else {
            size_t rem = ctx->bufBlockLen - ctx->bufBlockIndex;
            size_t toCopy = inlen < rem ? inlen : rem;
            memcpy(ctx->bufBlock + ctx->bufBlockIndex, in, toCopy);
            ctx->bufBlockIndex += toCopy;
            ctx->totalBytes += toCopy;

            if (ctx->bufBlockIndex == ctx->bufBlockLen) {
                if (outputLen < SIXTEEN_BLOCKS) {
                    return make_gcm_siv_error("output len too short", OUTPUT_LENGTH);
                }
                process16Blocks_dec(ctx, ctx->bufBlock, out);

                if (ctx->macBlockLen == 16) {
                    _mm_storeu_si128((__m128i *) ctx->bufBlock,
                                     _mm_loadu_si128((__m128i *) (ctx->bufBlock + SIXTEEN_BLOCKS)));
                } else {
                    memcpy(ctx->bufBlock, ctx->bufBlock + SIXTEEN_BLOCKS, ctx->macBlockLen);
                }

                ctx->bufBlockIndex -= SIXTEEN_BLOCKS;
                *written += SIXTEEN_BLOCKS;
            }
            *read += toCopy;
        }
    }

    return NULL;
}


gcm_siv_err *process_buffer_enc(gcm_siv_ctx *ctx,
                            unsigned char *in,
                            size_t inlen,
                            unsigned char *out,
                            size_t outputLen,
                            size_t *read,
                            size_t *written) {


    *read = *written = 0;

    if (ctx->encryption && ctx->bufBlockIndex == 0 && inlen > SIXTEEN_BLOCKS && outputLen > SIXTEEN_BLOCKS) {
        // Special case when nothing is buffered, and we have more than 16 blocks to process, and we are doing
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

            return make_gcm_siv_error("out is null, output generated when no output was expected by caller",
                                  ILLEGAL_ARGUMENT);
        }


        if (ctx->blocksRemaining < 16) {
            return make_gcm_siv_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
        }
        ctx->blocksRemaining -= 16;

        // Hash keys are constant throughout.
        const __m512i h4 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[12]);
        const __m512i h3 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[8]);
        const __m512i h2 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[4]);
        const __m512i h1 = _mm512_loadu_si512((__m512i *) &ctx->hashKeys[0]);

        // Initial set of 16 blocks.
        __m512i id0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        __m512i id1 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
        __m512i id2 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
        __m512i id3 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);

        __m512i ctr12, ctr34, ctr56, ctr78;
        spreadCtr(ctx->ctr1, &ctr12, &ctr34, &ctr56, &ctr78);


        __m512i tmp12 = _mm512_shuffle_epi8(ctr12, *BSWAP_EPI64_512);
        __m512i tmp34 = _mm512_shuffle_epi8(ctr34, *BSWAP_EPI64_512);
        __m512i tmp56 = _mm512_shuffle_epi8(ctr56, *BSWAP_EPI64_512);
        __m512i tmp78 = _mm512_shuffle_epi8(ctr78, *BSWAP_EPI64_512);

        ctx->ctr1 = _mm_add_epi32(ctx->ctr1, *SIXTEEN);


        apply_aes_no_reduction(&id0, &id1, &id2, &id3, tmp12, tmp34, tmp56, tmp78, ctx->roundKeys, ctx->num_rounds);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], id0);
        _mm512_storeu_si512((__m512i *) &out[1 * 64], id1);
        _mm512_storeu_si512((__m512i *) &out[2 * 64], id2);
        _mm512_storeu_si512((__m512i *) &out[3 * 64], id3);


        // id0..3 are the initial set of cipher texts but bit swapped

        id0 = _mm512_shuffle_epi8(id0, *BSWAP_MASK_512);
        id1 = _mm512_shuffle_epi8(id1, *BSWAP_MASK_512);
        id2 = _mm512_shuffle_epi8(id2, *BSWAP_MASK_512);
        id3 = _mm512_shuffle_epi8(id3, *BSWAP_MASK_512);


        *written += SIXTEEN_BLOCKS;
        *read += SIXTEEN_BLOCKS;
        ctx->totalBytes += SIXTEEN_BLOCKS;
        inlen -= SIXTEEN_BLOCKS;
        outputLen -= SIXTEEN_BLOCKS;

        in += SIXTEEN_BLOCKS;
        out += SIXTEEN_BLOCKS;

        while (inlen >= SIXTEEN_BLOCKS && outputLen >= SIXTEEN_BLOCKS) {

            if (ctx->blocksRemaining < 16) {
                return make_gcm_siv_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            ctx->blocksRemaining -= 16;

            // Encrypt next set of 16 blocks passing the result of the last encryption for reduction.

            __m512i d0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
            __m512i d1 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
            __m512i d2 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
            __m512i d3 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);


            spreadCtr(ctx->ctr1, &ctr12, &ctr34, &ctr56, &ctr78);


            tmp12 = _mm512_shuffle_epi8(ctr12, *BSWAP_EPI64_512);
            tmp34 = _mm512_shuffle_epi8(ctr34, *BSWAP_EPI64_512);
            tmp56 = _mm512_shuffle_epi8(ctr56, *BSWAP_EPI64_512);
            tmp78 = _mm512_shuffle_epi8(ctr78, *BSWAP_EPI64_512);

            ctx->ctr1 = _mm_add_epi32(ctx->ctr1, *SIXTEEN);


            id0 = _mm512_xor_si512(id0, _mm512_castsi128_si512(ctx->X));
            apply_aes_with_reduction(&d0, &d1, &d2, &d3,
                                     &id0, &id1, &id2, &id3,
                                     h1, h2, h3, h4,
                                     tmp12, tmp34, tmp56, tmp78,
                                     ctx->roundKeys, &ctx->X, ctx->num_rounds);

            _mm512_storeu_si512((__m512i *) &out[0 * 64], d0);
            _mm512_storeu_si512((__m512i *) &out[1 * 64], d1);
            _mm512_storeu_si512((__m512i *) &out[2 * 64], d2);
            _mm512_storeu_si512((__m512i *) &out[3 * 64], d3);

            // id0..3 are now the last cipher texts but bit swapped

            id0 = _mm512_shuffle_epi8(d0, *BSWAP_MASK_512);
            id1 = _mm512_shuffle_epi8(d1, *BSWAP_MASK_512);
            id2 = _mm512_shuffle_epi8(d2, *BSWAP_MASK_512);
            id3 = _mm512_shuffle_epi8(d3, *BSWAP_MASK_512);

            *written += SIXTEEN_BLOCKS;
            *read += SIXTEEN_BLOCKS;
            ctx->totalBytes += SIXTEEN_BLOCKS;
            inlen -= SIXTEEN_BLOCKS;
            outputLen -= SIXTEEN_BLOCKS;
            in += SIXTEEN_BLOCKS;
            out += SIXTEEN_BLOCKS;

        }

        //
        // Do trailing reduction
        //

        id0 = _mm512_xor_si512(id0, _mm512_castsi128_si512(ctx->X));
        gfmul_multi_reduce(id0, id1, id2, id3, h1, h2, h3, h4, &ctx->X);

        // fall through to existing code that will buffer trailing blocks if necessary

    }


    if (ctx->bufBlockIndex == 0 && inlen >= ctx->bufBlockLen) {
        if (outputLen < SIXTEEN_BLOCKS) {
            return make_gcm_siv_error("output len too short", OUTPUT_LENGTH);
        }
        gcm_siv_err *err = process16Blocks_enc(ctx, in, out);
        if (err != NULL) {
            return err;
        }
        *written += SIXTEEN_BLOCKS;
        *read += SIXTEEN_BLOCKS;
        ctx->totalBytes += SIXTEEN_BLOCKS;

    } else {
        size_t rem = ctx->bufBlockLen - ctx->bufBlockIndex;
        const size_t toCopy = inlen < rem ? inlen : rem;

        memcpy(ctx->bufBlock + ctx->bufBlockIndex, in, toCopy);
        ctx->bufBlockIndex += toCopy;
        ctx->totalBytes += toCopy;

        if (ctx->bufBlockIndex == ctx->bufBlockLen) {
            if (outputLen < SIXTEEN_BLOCKS) {
                return make_gcm_siv_error("output len too short", OUTPUT_LENGTH);
            }
            gcm_siv_err *err = process16Blocks_enc(ctx, ctx->bufBlock, out);
            if (err != NULL) {
                return err;
            }
            ctx->bufBlockIndex -= SIXTEEN_BLOCKS;
            *written += SIXTEEN_BLOCKS;
        }
        *read += toCopy;
    }

    return NULL;

}

void gcm_siv_variant_init(gcm_siv_ctx *ctx) {


}

/**
 *
 * @param output
 * @param outLen
 * @param written
 * @return NULL if no error, else ptr to struct CALLER NEEDS TO FREE
 */
gcm_siv_err *gcm_siv_doFinal(gcm_siv_ctx *ctx, unsigned char *output, size_t outLen, size_t *written) {
    *written = 0;


    if (ctx->totalBytes == 0) {
        gcm_siv__initBytes(ctx);
    }


    unsigned char *start = output;
    unsigned char *outPtr = start;

    __m128i tmp1;

    size_t limit = ctx->bufBlockIndex;

    if (!ctx->encryption) {

        // We need at least a mac block, and
        if (ctx->macBlockLen > ctx->bufBlockIndex) {
            return make_gcm_siv_error("cipher text too short", ILLEGAL_CIPHER_TEXT);
        }
        limit -= ctx->macBlockLen; // Limit of cipher text before tag.
        ctx->totalBytes -= ctx->macBlockLen;

        // decryption so output buffer cannot be less than limit.
        // bytes are to limit are the mac block (tag)
        if (outLen < limit) {
            return make_gcm_siv_error("output buffer too small", OUTPUT_LENGTH);
        }
    } else {
        // encryption, output must take remaining buffer + mac block
        if (outLen < ctx->bufBlockIndex + ctx->macBlockLen) {
            return make_gcm_siv_error("output buffer too small", OUTPUT_LENGTH);
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
                gcm_siv_err *err = process_block(ctx, &ctx->bufBlock[t], outPtr, outLen);
                if (err != NULL) {
                    return err;
                }
                outPtr += BLOCK_SIZE;
                outLen -= BLOCK_SIZE;
            }

        }



        if (limit % 16) {


            //
            // Check block count.
            //

            ctx->blocksRemaining -= 1;

            if (ctx->blocksRemaining < 0) {
                return make_gcm_siv_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }


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
        __m128i H_c;

        gcm_siv_exponentiate(ctx->H,c,&H_c);

        gfmul(ctx->S_at, H_c, &ctx->S_at);

        ctx->X = _mm_xor_si128(ctx->X, ctx->S_at);
    } // extra ad




    tmp1 = _mm_insert_epi64(tmp1, (long long) ctx->totalBytes * 8, 0);
    tmp1 = _mm_insert_epi64(tmp1, (long long) ctx->atLength * 8, 1);

    ctx->X = _mm_xor_si128(ctx->X, tmp1);
    gfmul(ctx->X, ctx->H, &ctx->X);
    ctx->X = _mm_shuffle_epi8(ctx->X, *BSWAP_MASK);
    ctx->T = _mm_xor_si128(ctx->X, ctx->T);

    unsigned char tmpTag[BLOCK_SIZE];
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
            return make_gcm_siv_error("mac check in GCM failed", ILLEGAL_CIPHER_TEXT);
        }
    }

    gcm_siv_reset(ctx, true);
    *written = (size_t) (outPtr - start);


    return NULL;
}