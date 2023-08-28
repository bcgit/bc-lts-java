//
//

#include <memory.h>
#include <stdbool.h>
#include "gcm_pc.h"
#include "gcm_pcHash512.h"


/**
 * Decryption version.
 *
 * @param in the cipher text
 * @param out  the plain text
 */
packet_err *
gcm_pc_process16Blocks_dec(uint8_t *in, uint8_t *out, int64_t *blocksRemaining, const int num_rounds, __m128i *hashKeys,
                    __m128i *ctr1, __m128i *roundKeys, __m128i *X) {

    if (out == NULL) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        return make_packet_error("out is null, output generated when no output was expected by caller",
                                 ILLEGAL_ARGUMENT);
    }

    if (*blocksRemaining < 16) {
        return make_packet_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
    }

    *blocksRemaining -= 16;

    const int aes_round_max = num_rounds;
    const __m512i h4 = _mm512_loadu_si512((__m512i *) &hashKeys[12]);
    const __m512i h3 = _mm512_loadu_si512((__m512i *) &hashKeys[8]);
    const __m512i h2 = _mm512_loadu_si512((__m512i *) &hashKeys[4]);
    const __m512i h1 = _mm512_loadu_si512((__m512i *) &hashKeys[0]);

    __m512i ctr12, ctr34, ctr56, ctr78;
    spreadCtr(*ctr1, &ctr12, &ctr34, &ctr56, &ctr78);

    __m512i ctr12s = _mm512_shuffle_epi8(ctr12, *BSWAP_EPI64_512);
    __m512i ctr34s = _mm512_shuffle_epi8(ctr34, *BSWAP_EPI64_512);
    __m512i ctr56s = _mm512_shuffle_epi8(ctr56, *BSWAP_EPI64_512);
    __m512i ctr78s = _mm512_shuffle_epi8(ctr78, *BSWAP_EPI64_512);


    //
    // ctr1 is used during doFinal, we need that 128b value before
    // incrementing.
    //
    *ctr1 = _mm_add_epi32(*ctr1, *SIXTEEN);

    // Load 16 blocks to decrypt
    __m512i in1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
    __m512i in2 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
    __m512i in3 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
    __m512i in4 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);


    apply_aes_with_reduction_dec(
            &in1, &in2, &in3, &in4,
            h1, h2, h3, h4,
            ctr12s, ctr34s, ctr56s, ctr78s,
            roundKeys, X, aes_round_max);

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
packet_err *
gcm_pc_process16Blocks_enc(uint8_t *in, uint8_t *out, int64_t *blocksRemaining, const int num_rounds, __m128i *hashKeys,
                    __m128i *ctr1, __m128i *roundKeys, __m128i *X) {
    if (out == NULL) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        return make_packet_error("out is null, output generated when no output was expected by caller",
                                 ILLEGAL_ARGUMENT);
    }

    if (*blocksRemaining < 16) {
        return make_packet_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
    }
    *blocksRemaining -= 16;

    const int aes_round_max = num_rounds;
    const __m512i h4 = _mm512_loadu_si512((__m512i *) &hashKeys[12]);
    const __m512i h3 = _mm512_loadu_si512((__m512i *) &hashKeys[8]);
    const __m512i h2 = _mm512_loadu_si512((__m512i *) &hashKeys[4]);
    const __m512i h1 = _mm512_loadu_si512((__m512i *) &hashKeys[0]);

    __m512i ctr12, ctr34, ctr56, ctr78;
    spreadCtr(*ctr1, &ctr12, &ctr34, &ctr56, &ctr78);

    __m512i tmp12 = _mm512_shuffle_epi8(ctr12, *BSWAP_EPI64_512);
    __m512i tmp34 = _mm512_shuffle_epi8(ctr34, *BSWAP_EPI64_512);
    __m512i tmp56 = _mm512_shuffle_epi8(ctr56, *BSWAP_EPI64_512);
    __m512i tmp78 = _mm512_shuffle_epi8(ctr78, *BSWAP_EPI64_512);

    //
    // ctr1 is used during doFinal, we need that 128b value before
    // incrementing.
    //
    *ctr1 = _mm_add_epi32(*ctr1,
                          *SIXTEEN);  //_mm256_extracti128_si256(ctr78, 1); //   _mm_add_epi32(ctr1, _mm_set_epi32(0, 4, 0, 0));


    __m512i inw1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
    __m512i inw2 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
    __m512i inw3 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
    __m512i inw4 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);


    tmp12 = _mm512_xor_si512(tmp12, _mm512_broadcast_i32x4(roundKeys[0]));
    tmp34 = _mm512_xor_si512(tmp34, _mm512_broadcast_i32x4(roundKeys[0]));
    tmp56 = _mm512_xor_si512(tmp56, _mm512_broadcast_i32x4(roundKeys[0]));
    tmp78 = _mm512_xor_si512(tmp78, _mm512_broadcast_i32x4(roundKeys[0]));

    uint32_t aes_round;


    for (aes_round = 1; aes_round < aes_round_max; aes_round++) {
        tmp12 = _mm512_aesenc_epi128(tmp12, _mm512_broadcast_i32x4(roundKeys[aes_round]));
        tmp34 = _mm512_aesenc_epi128(tmp34, _mm512_broadcast_i32x4(roundKeys[aes_round]));
        tmp56 = _mm512_aesenc_epi128(tmp56, _mm512_broadcast_i32x4(roundKeys[aes_round]));
        tmp78 = _mm512_aesenc_epi128(tmp78, _mm512_broadcast_i32x4(roundKeys[aes_round]));
    }


    tmp12 = _mm512_aesenclast_epi128(tmp12, _mm512_broadcast_i32x4(roundKeys[aes_round]));
    tmp34 = _mm512_aesenclast_epi128(tmp34, _mm512_broadcast_i32x4(roundKeys[aes_round]));
    tmp56 = _mm512_aesenclast_epi128(tmp56, _mm512_broadcast_i32x4(roundKeys[aes_round]));
    tmp78 = _mm512_aesenclast_epi128(tmp78, _mm512_broadcast_i32x4(roundKeys[aes_round]));


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

    tmp12 = _mm512_xor_si512(tmp12, _mm512_castsi128_si512(*X));

    gfmul_multi_reduce(tmp12, tmp34, tmp56, tmp78, h1, h2, h3, h4, X);

    return NULL;
}


packet_err *gcm_pc_process_buffer_dec(uint8_t *in, size_t inlen, uint8_t *out, size_t outputLen, size_t *read, size_t *written,
                               size_t *bufBlockIndex, int64_t *blocksRemaining, __m128i *hashKeys, __m128i *ctr1,
                               __m128i *roundKeys, int num_rounds, size_t *totalBytes, __m128i *X,
                               size_t bufBlockLen, uint8_t *bufBlock, size_t macBlockLen) {

    *read = *written = 0;

    if (*bufBlockIndex > 0 && *bufBlockIndex + inlen >= bufBlockLen) {

        // We have 16 or more blocks with of data in the buffer.
        // Process them now and copy any residual back to the start of the buffer.
        if (*bufBlockIndex >= SIXTEEN_BLOCKS) {
            if (outputLen < SIXTEEN_BLOCKS) {
                return make_packet_error("output len too short", OUTPUT_LENGTH);
            }
            packet_err *err = gcm_pc_process16Blocks_dec(bufBlock, out, blocksRemaining, num_rounds, hashKeys,
                                                  ctr1, roundKeys, X);
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

            size_t toCopy = *bufBlockIndex - SIXTEEN_BLOCKS;
            memcpy(bufBlock, bufBlock + *bufBlockIndex, toCopy);
            *bufBlockIndex = toCopy;
        }

        //
        // There may still data in the buffer but less than before, does
        // our condition for rounding the buffer out still exist with respect
        // to the available input?
        //
        if (*bufBlockIndex > 0 && *bufBlockIndex + inlen >= bufBlockLen) {
            size_t toCopy = SIXTEEN_BLOCKS - *bufBlockIndex;

            // Copy from the input what we need to round out the buffer.
            memcpy(bufBlock + *bufBlockIndex, in, toCopy);
            if (outputLen < SIXTEEN_BLOCKS) {
                return make_packet_error("output len too short", OUTPUT_LENGTH);
            }
            packet_err *err = gcm_pc_process16Blocks_dec(bufBlock, out, blocksRemaining, num_rounds, hashKeys,
                                                  ctr1, roundKeys, X);
            if (err != NULL) {
                return err;
            }
            *bufBlockIndex = 0;
            *written += SIXTEEN_BLOCKS;
            *read += toCopy;
            *totalBytes += toCopy;
            outputLen -= SIXTEEN_BLOCKS;
            in += toCopy;
            out += SIXTEEN_BLOCKS;
        }
    }


    //
    // Bulk decryption.
    //
    if (*bufBlockIndex == 0 && inlen >= bufBlockLen && outputLen >= SIXTEEN_BLOCKS) {

        // Hash keys are constant throughout.
        const __m512i h4 = _mm512_loadu_si512((__m512i *) &hashKeys[12]);
        const __m512i h3 = _mm512_loadu_si512((__m512i *) &hashKeys[8]);
        const __m512i h2 = _mm512_loadu_si512((__m512i *) &hashKeys[4]);
        const __m512i h1 = _mm512_loadu_si512((__m512i *) &hashKeys[0]);

        __m512i d0, d1, d2, d3, tmp12, tmp34, tmp56, tmp78;

        while (inlen >= bufBlockLen && outputLen >= SIXTEEN_BLOCKS) {


            if (*blocksRemaining < 16) {
                return make_packet_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            *blocksRemaining -= 16;

            // Encrypt next set of 16 blocks passing the result of the last encryption for reduction.

            d0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
            d1 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
            d2 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
            d3 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);

            __m512i ctr12, ctr34, ctr56, ctr78;
            spreadCtr(*ctr1, &ctr12, &ctr34, &ctr56, &ctr78);


            tmp12 = _mm512_shuffle_epi8(ctr12, *BSWAP_EPI64_512);
            tmp34 = _mm512_shuffle_epi8(ctr34, *BSWAP_EPI64_512);
            tmp56 = _mm512_shuffle_epi8(ctr56, *BSWAP_EPI64_512);
            tmp78 = _mm512_shuffle_epi8(ctr78, *BSWAP_EPI64_512);

            *ctr1 = _mm_add_epi32(*ctr1, *SIXTEEN);


            apply_aes_with_reduction_dec(&d0, &d1, &d2, &d3,
                                         h1, h2, h3, h4,
                                         tmp12, tmp34, tmp56, tmp78,
                                         roundKeys, X, num_rounds);

            _mm512_storeu_si512((__m512i *) &out[0 * 64], d0);
            _mm512_storeu_si512((__m512i *) &out[1 * 64], d1);
            _mm512_storeu_si512((__m512i *) &out[2 * 64], d2);
            _mm512_storeu_si512((__m512i *) &out[3 * 64], d3);

            // id0..3 are now the last cipher texts but bit swapped

            *written += SIXTEEN_BLOCKS;
            *read += SIXTEEN_BLOCKS;
            *totalBytes += SIXTEEN_BLOCKS;
            inlen -= SIXTEEN_BLOCKS;
            outputLen -= SIXTEEN_BLOCKS;
            in += SIXTEEN_BLOCKS;
            out += SIXTEEN_BLOCKS;
        }
    } else {


        if (*bufBlockIndex == 0 && inlen >= bufBlockLen) {
            if (outputLen < SIXTEEN_BLOCKS) {
                return make_packet_error("output len too short", OUTPUT_LENGTH);
            }
            gcm_pc_process16Blocks_dec(in, out, blocksRemaining, num_rounds, hashKeys,
                                ctr1, roundKeys, X);
            *written += SIXTEEN_BLOCKS;
            *read += SIXTEEN_BLOCKS;
            *totalBytes += SIXTEEN_BLOCKS;

        } else {
            size_t rem = bufBlockLen - *bufBlockIndex;
            size_t toCopy = inlen < rem ? inlen : rem;
            memcpy(bufBlock + *bufBlockIndex, in, toCopy);
            *bufBlockIndex += toCopy;
            *totalBytes += toCopy;

            if (*bufBlockIndex == bufBlockLen) {
                if (outputLen < SIXTEEN_BLOCKS) {
                    return make_packet_error("output len too short", OUTPUT_LENGTH);
                }
                gcm_pc_process16Blocks_dec(bufBlock, out, blocksRemaining, num_rounds, hashKeys,
                                    ctr1, roundKeys, X);

                if (macBlockLen == 16) {
                    _mm_storeu_si128((__m128i *) bufBlock,
                                     _mm_loadu_si128((__m128i *) (bufBlock + SIXTEEN_BLOCKS)));
                } else {
                    memcpy(bufBlock, bufBlock + SIXTEEN_BLOCKS, macBlockLen);
                }

                *bufBlockIndex -= SIXTEEN_BLOCKS;
                *written += SIXTEEN_BLOCKS;
            }
            *read += toCopy;
        }
    }

    return NULL;
}


packet_err *
gcm_pc_process_buffer_enc(unsigned char *in, size_t inlen, unsigned char *out, size_t outputLen, size_t *read,
                   size_t *written, bool encryption, size_t *bufBlockIndex, int64_t *blocksRemaining, __m128i *hashKeys,
                   __m128i *ctr1, __m128i *roundKeys, int num_rounds, size_t *totalBytes, __m128i *X,
                   size_t bufBlockLen, uint8_t *bufBlock) {


    *read = *written = 0;

    if (encryption && *bufBlockIndex == 0 && inlen > SIXTEEN_BLOCKS && outputLen > SIXTEEN_BLOCKS) {
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

            return make_packet_error("out is null, output generated when no output was expected by caller",
                                     ILLEGAL_ARGUMENT);
        }


        if (*blocksRemaining < 16) {
            return make_packet_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
        }
        *blocksRemaining -= 16;

        // Hash keys are constant throughout.
        const __m512i h4 = _mm512_loadu_si512((__m512i *) &hashKeys[12]);
        const __m512i h3 = _mm512_loadu_si512((__m512i *) &hashKeys[8]);
        const __m512i h2 = _mm512_loadu_si512((__m512i *) &hashKeys[4]);
        const __m512i h1 = _mm512_loadu_si512((__m512i *) &hashKeys[0]);

        // Initial set of 16 blocks.
        __m512i id0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        __m512i id1 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
        __m512i id2 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
        __m512i id3 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);

        __m512i ctr12, ctr34, ctr56, ctr78;
        spreadCtr(*ctr1, &ctr12, &ctr34, &ctr56, &ctr78);


        __m512i tmp12 = _mm512_shuffle_epi8(ctr12, *BSWAP_EPI64_512);
        __m512i tmp34 = _mm512_shuffle_epi8(ctr34, *BSWAP_EPI64_512);
        __m512i tmp56 = _mm512_shuffle_epi8(ctr56, *BSWAP_EPI64_512);
        __m512i tmp78 = _mm512_shuffle_epi8(ctr78, *BSWAP_EPI64_512);

        *ctr1 = _mm_add_epi32(*ctr1, *SIXTEEN);


        apply_aes_no_reduction(&id0, &id1, &id2, &id3, tmp12, tmp34, tmp56, tmp78, roundKeys, num_rounds);

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
        *totalBytes += SIXTEEN_BLOCKS;
        inlen -= SIXTEEN_BLOCKS;
        outputLen -= SIXTEEN_BLOCKS;

        in += SIXTEEN_BLOCKS;
        out += SIXTEEN_BLOCKS;

        while (inlen >= SIXTEEN_BLOCKS && outputLen >= SIXTEEN_BLOCKS) {

            if (*blocksRemaining < 16) {
                return make_packet_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            *blocksRemaining -= 16;

            // Encrypt next set of 16 blocks passing the result of the last encryption for reduction.

            __m512i d0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
            __m512i d1 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
            __m512i d2 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
            __m512i d3 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);


            spreadCtr(*ctr1, &ctr12, &ctr34, &ctr56, &ctr78);


            tmp12 = _mm512_shuffle_epi8(ctr12, *BSWAP_EPI64_512);
            tmp34 = _mm512_shuffle_epi8(ctr34, *BSWAP_EPI64_512);
            tmp56 = _mm512_shuffle_epi8(ctr56, *BSWAP_EPI64_512);
            tmp78 = _mm512_shuffle_epi8(ctr78, *BSWAP_EPI64_512);

            *ctr1 = _mm_add_epi32(*ctr1, *SIXTEEN);


            id0 = _mm512_xor_si512(id0, _mm512_castsi128_si512(*X));
            apply_aes_with_reduction(&d0, &d1, &d2, &d3,
                                     &id0, &id1, &id2, &id3,
                                     h1, h2, h3, h4,
                                     tmp12, tmp34, tmp56, tmp78,
                                     roundKeys, X, num_rounds);

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
            *totalBytes += SIXTEEN_BLOCKS;
            inlen -= SIXTEEN_BLOCKS;
            outputLen -= SIXTEEN_BLOCKS;
            in += SIXTEEN_BLOCKS;
            out += SIXTEEN_BLOCKS;

        }

        //
        // Do trailing reduction
        //

        id0 = _mm512_xor_si512(id0, _mm512_castsi128_si512(*X));
        gfmul_multi_reduce(id0, id1, id2, id3, h1, h2, h3, h4, X);

        // fall through to existing code that will buffer trailing blocks if necessary

    }


    if (*bufBlockIndex == 0 && inlen >= bufBlockLen) {
        if (outputLen < SIXTEEN_BLOCKS) {
            return make_packet_error("output len too short", OUTPUT_LENGTH);
        }
        packet_err *err = gcm_pc_process16Blocks_enc(in, out, blocksRemaining, num_rounds, hashKeys,
                                              ctr1, roundKeys, X);
        if (err != NULL) {
            return err;
        }
        *written += SIXTEEN_BLOCKS;
        *read += SIXTEEN_BLOCKS;
        *totalBytes += SIXTEEN_BLOCKS;

    } else {
        size_t rem = bufBlockLen - *bufBlockIndex;
        const size_t toCopy = inlen < rem ? inlen : rem;

        memcpy(bufBlock + *bufBlockIndex, in, toCopy);
        *bufBlockIndex += toCopy;
        *totalBytes += toCopy;

        if (*bufBlockIndex == bufBlockLen) {
            if (outputLen < SIXTEEN_BLOCKS) {
                return make_packet_error("output len too short", OUTPUT_LENGTH);
            }
            packet_err *err = gcm_pc_process16Blocks_enc(bufBlock, out, blocksRemaining, num_rounds, hashKeys,
                                                  ctr1, roundKeys, X);
            if (err != NULL) {
                return err;
            }
            *bufBlockIndex -= SIXTEEN_BLOCKS;
            *written += SIXTEEN_BLOCKS;
        }
        *read += toCopy;
    }

    return NULL;

}

