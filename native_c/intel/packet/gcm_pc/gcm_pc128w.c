#include <stddef.h>
#include <immintrin.h>
#include "gcm_pc.h"
#include "gcm_pcHash128.h"
#include <memory.h>


packet_err *gcm_pc_process_buffer_enc(
        uint8_t *in,
        size_t inlen,
        uint8_t *out,
        size_t outputLen,
        size_t *read,
        size_t *written,
        bool encryption,
        size_t *bufBlockIndex,
        int64_t *blocksRemaining,
        __m128i *hashKeys,
        __m128i *ctr1,
        __m128i *roundKeys,
        int num_rounds,
        size_t *totalBytes,
        __m128i *X,
        size_t bufBlockLen,
        uint8_t *bufBlock) {
    *read = *written = 0;
    if (encryption && *bufBlockIndex == 0 && inlen >= FOUR_BLOCKS && outputLen >= FOUR_BLOCKS) {
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
            return make_packet_error("out is null, output generated when no output was expected by caller",
                                     ILLEGAL_ARGUMENT);
        }
        if (*blocksRemaining < 4) {
            return make_packet_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
        }
        *blocksRemaining -= 4;
        // Hash keys are constant throughout.
        const __m128i h4 = hashKeys[HASHKEY_0];
        const __m128i h3 = hashKeys[(HASHKEY_0 - 1)];
        const __m128i h2 = hashKeys[(HASHKEY_0 - 2)];
        const __m128i h1 = hashKeys[(HASHKEY_0 - 3)];
        // Initial set of 4 blocks.
        __m128i id0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
        __m128i id1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);
        __m128i id2 = _mm_loadu_si128((__m128i *) &in[2 * 16]);
        __m128i id3 = _mm_loadu_si128((__m128i *) &in[3 * 16]);

        *ctr1 = _mm_add_epi32(*ctr1, *ONE);
        __m128i ctr2 = _mm_add_epi32(*ctr1, *ONE);
        __m128i ctr3 = _mm_add_epi32(ctr2, *ONE);
        __m128i ctr4 = _mm_add_epi32(ctr3, *ONE);

        __m128i tmp1 = _mm_shuffle_epi8(*ctr1, *BSWAP_EPI64);
        __m128i tmp2 = _mm_shuffle_epi8(ctr2, *BSWAP_EPI64);
        __m128i tmp3 = _mm_shuffle_epi8(ctr3, *BSWAP_EPI64);
        __m128i tmp4 = _mm_shuffle_epi8(ctr4, *BSWAP_EPI64);

        apply_aes_no_reduction(
                &id0, &id1, &id2, &id3,
                tmp1, tmp2, tmp3, tmp4,
                roundKeys, num_rounds
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
        *totalBytes += FOUR_BLOCKS;
        inlen -= FOUR_BLOCKS;
        outputLen -= FOUR_BLOCKS;

        in += FOUR_BLOCKS;
        out += FOUR_BLOCKS;

        *ctr1 = ctr4;

        while (inlen >= FOUR_BLOCKS && outputLen >= FOUR_BLOCKS) {
            if (*blocksRemaining < 4) {
                return make_packet_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            *blocksRemaining -= 4;
            // Encrypt next set of 4 blocks passing the result of the last encryption for reduction.
            __m128i d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
            __m128i d1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);
            __m128i d2 = _mm_loadu_si128((__m128i *) &in[2 * 16]);
            __m128i d3 = _mm_loadu_si128((__m128i *) &in[3 * 16]);

            *ctr1 = _mm_add_epi32(*ctr1, *ONE);
            ctr2 = _mm_add_epi32(*ctr1, *ONE);
            ctr3 = _mm_add_epi32(ctr2, *ONE);
            ctr4 = _mm_add_epi32(ctr3, *ONE);

            tmp1 = _mm_shuffle_epi8(*ctr1, *BSWAP_EPI64);
            tmp2 = _mm_shuffle_epi8(ctr2, *BSWAP_EPI64);
            tmp3 = _mm_shuffle_epi8(ctr3, *BSWAP_EPI64);
            tmp4 = _mm_shuffle_epi8(ctr4, *BSWAP_EPI64);

            id0 = _mm_xor_si128(id0, *X);
            apply_aes_with_reduction(&d0, &d1, &d2, &d3,
                                     id0, id1, id2, id3,
                                     h1, h2, h3, h4,
                                     tmp1, tmp2, tmp3, tmp4,
                                     roundKeys, X, num_rounds);

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
            *totalBytes += FOUR_BLOCKS;
            inlen -= FOUR_BLOCKS;
            outputLen -= FOUR_BLOCKS;
            in += FOUR_BLOCKS;
            out += FOUR_BLOCKS;
            *ctr1 = ctr4;
        }

        //
        // Do trailing reduction
        //

        id0 = _mm_xor_si128(id0, *X);
        gfmul_multi_reduce(
                id0, id1, id2, id3,
                h1, h2, h3, h4,
                X);

        // fall through to existing code that will buffer trailing blocks if necessary

    }


    size_t rem = bufBlockLen - *bufBlockIndex;
    size_t toCopy = inlen < rem ? inlen : rem;
    memcpy(bufBlock + *bufBlockIndex, in, toCopy);
    *bufBlockIndex += toCopy;
    *totalBytes += toCopy;

    if (*bufBlockIndex == bufBlockLen) {
        if (outputLen < FOUR_BLOCKS) {
            return make_packet_error("output len too short", OUTPUT_LENGTH);
        }
        if (out == NULL) {
            //
            // Java api my supply a null output array if it expects no output, however
            // if output does occur then we need to catch that here.
            //
            return make_packet_error("out is null, output generated when no output was expected by caller",
                                     ILLEGAL_ARGUMENT);
        }


        if (*blocksRemaining < 4) {
            return make_packet_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
        }
        *blocksRemaining -= 4;

        const __m128i h4 = hashKeys[HASHKEY_0];
        const __m128i h3 = hashKeys[(HASHKEY_0 - 1)];
        const __m128i h2 = hashKeys[(HASHKEY_0 - 2)];
        const __m128i h1 = hashKeys[(HASHKEY_0 - 3)];

        const int rounds = num_rounds;

        *ctr1 = _mm_add_epi32(*ctr1, *ONE);
        __m128i ctr2 = _mm_add_epi32(*ctr1, *ONE);
        __m128i ctr3 = _mm_add_epi32(ctr2, *ONE);
        __m128i ctr4 = _mm_add_epi32(ctr3, *ONE);

        __m128i tmp1 = _mm_shuffle_epi8(*ctr1, *BSWAP_EPI64);
        __m128i tmp2 = _mm_shuffle_epi8(ctr2, *BSWAP_EPI64);
        __m128i tmp3 = _mm_shuffle_epi8(ctr3, *BSWAP_EPI64);
        __m128i tmp4 = _mm_shuffle_epi8(ctr4, *BSWAP_EPI64);

        __m128i rk = roundKeys[0];
        aes_xor(&tmp1, &tmp2, &tmp3, &tmp4, rk);

        __m128i in1 = _mm_loadu_si128(((__m128i *) &in[0 * 16]));
        __m128i in2 = _mm_loadu_si128(((__m128i *) &in[1 * 16]));
        __m128i in3 = _mm_loadu_si128(((__m128i *) &in[2 * 16]));
        __m128i in4 = _mm_loadu_si128(((__m128i *) &in[3 * 16]));

        int j;
        for (j = 1; j < rounds; j++) {
            aes_enc(&tmp1, &tmp2, &tmp3, &tmp4, roundKeys[j]);
        }

        aes_enc_last(&tmp1, &tmp2, &tmp3, &tmp4, roundKeys[j]);

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

        tmp1 = _mm_xor_si128(tmp1, *X);
        gfmul_multi_reduce(tmp1, tmp2, tmp3, tmp4,
                           h1, h2, h3, h4,
                           X);

        *ctr1 = ctr4;
        *bufBlockIndex -= FOUR_BLOCKS;
        *written += FOUR_BLOCKS;
    }
    *read += toCopy;
    return NULL;

}


packet_err *gcm_pc_processFourBlocks_dec(uint8_t *in, uint8_t *out, int64_t *blocksRemaining, __m128i *hashKeys,
                                  const int num_rounds, __m128i *ctr1, __m128i *roundKeys, __m128i *X) {

    if (out == NULL) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        return make_packet_error("out is null, output generated when no output was expected by caller",
                                 ILLEGAL_ARGUMENT);

    }

    __m128i ctr2, ctr3, ctr4, tmp12, tmp34, tmp56, tmp78;

    // Hash keys are constant throughout.
    const __m128i h4 = hashKeys[HASHKEY_0];
    const __m128i h3 = hashKeys[(HASHKEY_0 - 1)];
    const __m128i h2 = hashKeys[(HASHKEY_0 - 2)];
    const __m128i h1 = hashKeys[(HASHKEY_0 - 3)];


    if (*blocksRemaining < 4) {
        return make_packet_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
    }
    *blocksRemaining -= 4;

    *ctr1 = _mm_add_epi32(*ctr1, *ONE);
    ctr2 = _mm_add_epi32(*ctr1, *ONE);
    ctr3 = _mm_add_epi32(ctr2, *ONE);
    ctr4 = _mm_add_epi32(ctr3, *ONE);

    tmp12 = _mm_shuffle_epi8(*ctr1, *BSWAP_EPI64);
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
                                 roundKeys, X, num_rounds);

    _mm_storeu_si128((__m128i *) &out[0 * 16], in1);
    _mm_storeu_si128((__m128i *) &out[1 * 16], in2);
    _mm_storeu_si128((__m128i *) &out[2 * 16], in3);
    _mm_storeu_si128((__m128i *) &out[3 * 16], in4);

    *ctr1 = ctr4;
    return NULL;
}


packet_err *gcm_pc_process_buffer_dec(uint8_t *in, size_t inlen, uint8_t *out, size_t outputLen, size_t *read,
                               size_t *written, size_t *bufBlockIndex, int64_t *blocksRemaining, __m128i *hashKeys,
                               __m128i *ctr1, __m128i *roundKeys, int num_rounds, size_t *totalBytes, __m128i *X,
                               size_t bufBlockLen, uint8_t *bufBlock, size_t macBlockLen) {

    *read = *written = 0;

    if (*bufBlockIndex > 0 && *bufBlockIndex + inlen >= bufBlockLen) {

        // We have 4 or more blocks with of data in the buffer.
        // Process them now and copy any residual back to the start of the buffer.
        if (*bufBlockIndex >= FOUR_BLOCKS) {
            if (outputLen < FOUR_BLOCKS) {
                return make_packet_error("output len too short", OUTPUT_LENGTH);
            }
            packet_err *err = gcm_pc_processFourBlocks_dec(bufBlock, out, blocksRemaining, hashKeys,
                                                    num_rounds, ctr1, roundKeys, X);
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

            size_t toCopy = *bufBlockIndex - FOUR_BLOCKS;
            memcpy(bufBlock, bufBlock + *bufBlockIndex, toCopy);
            *bufBlockIndex = toCopy;
        }

        //
        // There may still data in the buffer but less than before, does
        // our condition for rounding the buffer out still exist with respect
        // to the available input?
        //
        if (*bufBlockIndex > 0 && *bufBlockIndex + inlen >= bufBlockLen) {
            size_t toCopy = FOUR_BLOCKS - *bufBlockIndex;

            // Copy from the input what we need to round out the buffer.
            memcpy(bufBlock + *bufBlockIndex, in, toCopy);
            if (outputLen < FOUR_BLOCKS) {
                return make_packet_error("output len too short", OUTPUT_LENGTH);
            }
            packet_err *err = gcm_pc_processFourBlocks_dec(bufBlock, out, blocksRemaining, hashKeys,
                                                    num_rounds, ctr1, roundKeys, X);
            if (err != NULL) {
                return err;
            }
            *bufBlockIndex = 0;
            *written += FOUR_BLOCKS;
            *read += toCopy;
            *totalBytes += toCopy;
            outputLen -= FOUR_BLOCKS;
            in += toCopy;
            out += FOUR_BLOCKS;
        }
    }

    //
    // Bulk decryption.
    //
    if (*bufBlockIndex == 0 && inlen >= bufBlockLen && outputLen >= FOUR_BLOCKS) {

        // Hash keys are constant throughout.
        const __m128i h4 = hashKeys[HASHKEY_0];
        const __m128i h3 = hashKeys[(HASHKEY_0 - 1)];
        const __m128i h2 = hashKeys[(HASHKEY_0 - 2)];
        const __m128i h1 = hashKeys[(HASHKEY_0 - 3)];

        __m128i d0, d1, d2, d3, tmp12, tmp34, tmp56, tmp78;

        while (inlen >= bufBlockLen && outputLen >= FOUR_BLOCKS) {


            if (*blocksRemaining < 4) {
                return make_packet_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            *blocksRemaining -= 4;

            d0 = _mm_loadu_si128((__m128i *) &in[0 * 16]);
            d1 = _mm_loadu_si128((__m128i *) &in[1 * 16]);
            d2 = _mm_loadu_si128((__m128i *) &in[2 * 16]);
            d3 = _mm_loadu_si128((__m128i *) &in[3 * 16]);

            *ctr1 = _mm_add_epi32(*ctr1, *ONE);
            __m128i ctr2 = _mm_add_epi32(*ctr1, *ONE);
            __m128i ctr3 = _mm_add_epi32(ctr2, *ONE);
            __m128i ctr4 = _mm_add_epi32(ctr3, *ONE);

            tmp12 = _mm_shuffle_epi8(*ctr1, *BSWAP_EPI64);
            tmp34 = _mm_shuffle_epi8(ctr2, *BSWAP_EPI64);
            tmp56 = _mm_shuffle_epi8(ctr3, *BSWAP_EPI64);
            tmp78 = _mm_shuffle_epi8(ctr4, *BSWAP_EPI64);

            *ctr1 = ctr4;


            apply_aes_with_reduction_dec(&d0, &d1, &d2, &d3,
                                         h1, h2, h3, h4,
                                         tmp12, tmp34, tmp56, tmp78,
                                         roundKeys, X, num_rounds);

            _mm_storeu_si128((__m128i *) &out[0 * 16], d0);
            _mm_storeu_si128((__m128i *) &out[1 * 16], d1);
            _mm_storeu_si128((__m128i *) &out[2 * 16], d2);
            _mm_storeu_si128((__m128i *) &out[3 * 16], d3);

            // id0..3 are now the last cipher texts but bit swapped

            *written += FOUR_BLOCKS;
            *read += FOUR_BLOCKS;
            *totalBytes += FOUR_BLOCKS;
            inlen -= FOUR_BLOCKS;
            outputLen -= FOUR_BLOCKS;
            in += FOUR_BLOCKS;
            out += FOUR_BLOCKS;
        } // while
    } else {


        if (*bufBlockIndex == 0 && inlen >= bufBlockLen) {
            if (outputLen < FOUR_BLOCKS) {
                return make_packet_error("output len too short", OUTPUT_LENGTH);
            }
            packet_err *err = gcm_pc_processFourBlocks_dec(in, out, blocksRemaining, hashKeys,
                                                    num_rounds, ctr1, roundKeys, X);
            if (err != NULL) {
                return err;
            }
            *written += FOUR_BLOCKS;
            *read += FOUR_BLOCKS;
            *totalBytes += FOUR_BLOCKS;

        } else {

            size_t rem = bufBlockLen - *bufBlockIndex;
            size_t toCopy = inlen < rem ? inlen : rem;
            memcpy(bufBlock + *bufBlockIndex, in, toCopy);
            *bufBlockIndex += toCopy;
            *totalBytes += toCopy;

            if (*bufBlockIndex == bufBlockLen) {
                if (outputLen < FOUR_BLOCKS) {
                    return make_packet_error("output len too short", OUTPUT_LENGTH);
                }
                packet_err *err = gcm_pc_processFourBlocks_dec(bufBlock, out, blocksRemaining, hashKeys,
                                                        num_rounds, ctr1, roundKeys, X);
                if (err != NULL) {
                    return err;
                }

                if (macBlockLen == 16) {
                    _mm_storeu_si128((__m128i *) bufBlock,
                                     _mm_loadu_si128((__m128i *) (bufBlock + FOUR_BLOCKS)));
                } else {
                    memcpy(bufBlock, bufBlock + FOUR_BLOCKS, macBlockLen);
                }

                *bufBlockIndex -= FOUR_BLOCKS;
                *written += FOUR_BLOCKS;
            }
            *read += toCopy;
        }
    }
    return NULL;
}


