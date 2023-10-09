
#include <immintrin.h>
#include <assert.h>
#include "gcm_pc.h"
#include <stdlib.h>
#include "gcm_pcHash128.h"
#include <memory.h>


packet_err *
gcm_pc_process_packet(bool encryption, uint8_t *key, size_t keyLen, uint8_t *nonce, size_t nonceLen, size_t macBlockLen,
                      uint8_t *initAD, size_t initADLen, uint8_t *input, size_t inLen, uint8_t *output,
                      size_t *outputLen) {
    __m128i roundKeys[15];
    int64_t blocksRemaining;
    __m128i X;
    __m128i ctr1;
    int num_rounds;
    // mac block
    uint8_t macBlock[MAC_BLOCK_LEN];
    uint32_t atBlockPos = 0;
    size_t atLengthPre;
    __m128i H, Y, T, S_at, S_atPre, last_aad_block;
    // bufBlock -- used for bytewise accumulation
    uint8_t bufBlock[BUF_BLK_SIZE];
    size_t bufBlockLen;
    size_t bufBlockIndex;
    __m128i last_block;
    size_t totalBytes;
    size_t atLength;
    __m128i initialX;
    __m128i initialY;
    __m128i initialT;
    __m128i initialH;
    __m128i hashKeys[HASHKEY_LEN];
    atLength = 0;
    totalBytes = 0;
    atLengthPre = 0;
    last_aad_block = _mm_setzero_si128(); // holds partial block of associated text.
    last_block = _mm_setzero_si128();

    // Zero out mac block
    memset(macBlock, 0, MAC_BLOCK_LEN);

    assert(macBlockLen <= MAC_BLOCK_LEN);

    memset(bufBlock, 0, BUF_BLK_SIZE);
    bufBlockIndex = 0;

#ifdef BC_VAESF
    bufBlockLen = encryption ? SIXTEEN_BLOCKS : (SIXTEEN_BLOCKS + macBlockLen);
#else
    bufBlockLen = encryption ? FOUR_BLOCKS : (FOUR_BLOCKS + macBlockLen);
#endif
    num_rounds = generate_key(true, key, roundKeys, keyLen);

    S_at = _mm_setzero_si128();
    S_atPre = _mm_setzero_si128();

    X = _mm_setzero_si128();
    Y = _mm_setzero_si128();
    T = _mm_setzero_si128();
    H = _mm_setzero_si128();

    __m128i tmp1, tmp2;

    if (nonceLen == 12) {
        //
        // Copy supplied nonce into 16 byte buffer to avoid potential for overrun
        // when loading nonce via _mm_loadu_si128;
        //

        uint8_t nonceBuf[16];
        memset(nonceBuf, 0, 16);
        memcpy(nonceBuf, nonce, nonceLen);
        Y = _mm_loadu_si128((__m128i *) nonceBuf);
        memset(nonceBuf, 0, 16);

        Y = _mm_insert_epi32(Y, 0x1000000, 3);

        tmp1 = _mm_xor_si128(X, roundKeys[0]);
        tmp2 = _mm_xor_si128(Y, roundKeys[0]);
        for (int j = 1; j < num_rounds - 1; j += 2) {
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j]);
            tmp2 = _mm_aesenc_si128(tmp2, roundKeys[j]);
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j + 1]);
            tmp2 = _mm_aesenc_si128(tmp2, roundKeys[j + 1]);
        }

        tmp1 = _mm_aesenc_si128(tmp1, roundKeys[num_rounds - 1]);
        tmp2 = _mm_aesenc_si128(tmp2, roundKeys[num_rounds - 1]);

        H = _mm_aesenclast_si128(tmp1, roundKeys[num_rounds]);
        T = _mm_aesenclast_si128(tmp2, roundKeys[num_rounds]);
        H = _mm_shuffle_epi8(H, *BSWAP_MASK);
    } else {
        tmp1 = _mm_xor_si128(X, roundKeys[0]);
        int j;
        for (j = 1; j < num_rounds; j++) {
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j]);
        }
        H = _mm_aesenclast_si128(tmp1, roundKeys[num_rounds]);
        H = _mm_shuffle_epi8(H, *BSWAP_MASK);
        Y = _mm_xor_si128(Y, Y); // ?
        int i;
        for (i = 0; i < nonceLen / 16; i++) {
            tmp1 = _mm_loadu_si128(&((__m128i *) nonce)[i]);
            tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);
            Y = _mm_xor_si128(Y, tmp1);
            gfmul(Y, H, &Y);
        }
        if (nonceLen % 16) {
            for (j = 0; j < nonceLen % 16; j++) {
                ((uint8_t *) &last_block)[j] = nonce[i * 16 + j];
            }
            tmp1 = last_block;
            tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);
            Y = _mm_xor_si128(Y, tmp1);
            gfmul(Y, H, &Y);
        }
        tmp1 = _mm_insert_epi64(tmp1, (long long) nonceLen * 8, 0);
        tmp1 = _mm_insert_epi64(tmp1, 0, 1);

        Y = _mm_xor_si128(Y, tmp1);
        gfmul(Y, H, &Y);
        Y = _mm_shuffle_epi8(Y, *BSWAP_MASK);
        // E(K,Y0)

        tmp1 = _mm_xor_si128(Y, roundKeys[0]);
        for (j = 1; j < num_rounds; j++) {
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j]);
        }
        T = _mm_aesenclast_si128(tmp1, roundKeys[num_rounds]);
    }

    //
    // Capture initial state.
    //
    initialX = X;
    initialY = Y;
    initialT = T;
    initialH = H;

    //
    // Process any initial associated data.
    //
    if (initAD != NULL) {
        //gcm_process_aad_bytes(ctx, initAD, initADLen);
        while (initADLen >= GCM_BLOCK_SIZE) {
            last_aad_block = _mm_loadu_si128((__m128i *) initAD);
            last_aad_block = _mm_shuffle_epi8(last_aad_block, *BSWAP_MASK);
            S_at = _mm_xor_si128(S_at, last_aad_block);
            gfmul(S_at, H, &S_at);
            last_aad_block = _mm_setzero_si128();

            initAD += GCM_BLOCK_SIZE;
            atLength += GCM_BLOCK_SIZE;
            initADLen -= GCM_BLOCK_SIZE;
        }
        while (initADLen > 0) {
//            gcm_process_aad_byte(ctx, *initAD);
            ((uint8_t *) &last_aad_block)[atBlockPos++] = *initAD;
            if (atBlockPos == GCM_BLOCK_SIZE) {
                // _gcm_processAadBlock(&last_aad_block,&S_at,&H);
                last_aad_block = _mm_shuffle_epi8(last_aad_block, *BSWAP_MASK);
                S_at = _mm_xor_si128(S_at, last_aad_block);
                gfmul(S_at, H, &S_at);
                last_aad_block = _mm_setzero_si128();
                atBlockPos = 0;
                atLength += GCM_BLOCK_SIZE;
            }
            initADLen--;
            initAD++;
        }
    }

    last_block = _mm_setzero_si128();

    //
    // Counter is pre incremented in processBlock and processFourBlocks
    //

    ctr1 = _mm_shuffle_epi8(Y, *BSWAP_EPI64);

    blocksRemaining = BLOCKS_REMAINING_INIT;



    // Expand hash keys, key number varies with variant see gcm.h
    hashKeys[HASHKEY_0] = H;
    for (int t = HASHKEY_1; t >= 0; t--) {
        gfmul(hashKeys[t + 1], H, &tmp1);
        hashKeys[t] = tmp1;
    }


    size_t rd = 0;
    size_t wr = 0;

    packet_err *err = NULL;

    unsigned char *start = input;
    unsigned char *end = start + inLen;
    unsigned char *outPtr = output;
    unsigned char *outStart = outPtr;

    if (encryption) {
        for (unsigned char *readPos = start; readPos < end;) {
            err = gcm_pc_process_buffer_enc(readPos, inLen, outPtr, (size_t) outputLen, &rd, &wr, encryption,
                                            &bufBlockIndex,
                                            &blocksRemaining, hashKeys, &ctr1, roundKeys, num_rounds, &totalBytes, &X,
                                            bufBlockLen, bufBlock);
            if (err != NULL) {
                break;
            }
            readPos += rd;
            inLen -= rd;
            outPtr += wr;
        }
    } else {
        for (unsigned char *readPos = start; readPos < end;) {
            err = gcm_pc_process_buffer_dec(readPos, inLen, outPtr, (size_t) outputLen, &rd, &wr, &bufBlockIndex,
                                            &blocksRemaining, hashKeys, &ctr1, roundKeys, num_rounds, &totalBytes, &X,
                                            bufBlockLen, bufBlock, macBlockLen);
            if (err != NULL) {
                break;
            }
            readPos += rd;
            inLen -= rd;
            outPtr += wr;
        }
    }

    *outputLen = (size_t) (outPtr - outStart);

    if (totalBytes == 0) {
        if (atLength > 0) {
            S_atPre = S_at;
            atLengthPre = atLength;
        }

        if (atBlockPos > 0) {
            __m128i tmp = _mm_shuffle_epi8(last_aad_block, *BSWAP_MASK);
            S_atPre = _mm_xor_si128(S_atPre, tmp);
            gfmul(S_atPre, H, &S_atPre);
            atLengthPre += atBlockPos;
        }

        if (atLengthPre > 0) {
            X = S_atPre;
        }
    }


    size_t limit = bufBlockIndex;

    if (!encryption) {

        // We need at least a mac block, and
        if (macBlockLen > bufBlockIndex) {
            return make_packet_error("cipher text too short", ILLEGAL_CIPHER_TEXT);
        }
        limit -= macBlockLen; // Limit of cipher text before tag.
        totalBytes -= macBlockLen;

        // decryption so output buffer cannot be less than limit.
        // bytes are to limit are the mac block (tag)
//        if (*outputLen < limit) {
//            return make_packet_error("output buffer too small", OUTPUT_LENGTH);
//        }
    } else {
        // encryption, output must take remaining buffer + mac block
//        if (*outputLen < bufBlockIndex + macBlockLen) {
//            return make_packet_error("output buffer too small", OUTPUT_LENGTH);
//        }
    }

    if (bufBlockIndex > 0) {

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
                //process_block(ctx, &ctx->bufBlock[t], outPtr, outLen);
                //uint8_t *in, uint8_t *out, size_t outputLen
                if (blocksRemaining < 1) {
                    return make_packet_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
                }
                blocksRemaining -= 1;

//                if (*outputLen < BLOCK_SIZE) {
//                    return make_packet_error("output len too short", OUTPUT_LENGTH);
//                }

                int j;
                ctr1 = _mm_add_epi32(ctr1, *ONE);
                __m128i tmp3 = _mm_shuffle_epi8(ctr1, *BSWAP_EPI64);


                tmp3 = _mm_xor_si128(tmp3, roundKeys[0]);
                for (j = 1; j < num_rounds - 1; j += 2) {
                    tmp3 = _mm_aesenc_si128(tmp3, roundKeys[j]);
                    tmp3 = _mm_aesenc_si128(tmp3, roundKeys[j + 1]);
                }
                tmp3 = _mm_aesenc_si128(tmp3, roundKeys[num_rounds - 1]);
                tmp3 = _mm_aesenclast_si128(tmp3, roundKeys[num_rounds]);
                __m128i in1 = _mm_loadu_si128((__m128i *) (bufBlock + t));
                tmp3 = _mm_xor_si128(tmp3, in1);
                _mm_storeu_si128((__m128i *) (outPtr), tmp3);
                tmp3 = _mm_shuffle_epi8(tmp3, *BSWAP_MASK);

                if (encryption) {
                    X = _mm_xor_si128(X, tmp3);
                } else {
                    X = _mm_xor_si128(X, _mm_shuffle_epi8(in1, *BSWAP_MASK));
                }
                gfmul(X, H, &X);
                outPtr += BLOCK_SIZE;
                *outputLen += BLOCK_SIZE;
            }

        }


        if (limit % 16) {
            if (blocksRemaining < 1) {
                return make_packet_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            blocksRemaining -= 1;

            ctr1 = _mm_add_epi32(ctr1, *ONE);
            tmp1 = _mm_shuffle_epi8(ctr1, *BSWAP_EPI64);

            tmp1 = _mm_xor_si128(tmp1, roundKeys[0]);
            for (int j = 1; j < num_rounds - 1; j += 2) {
                tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j]);
                tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j + 1]);
            }
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[num_rounds - 1]);
            tmp1 = _mm_aesenclast_si128(tmp1, roundKeys[num_rounds]);

            __m128i in1 = _mm_loadu_si128((__m128i *) &bufBlock[t]);

            tmp1 = _mm_xor_si128(tmp1, in1);
            last_block = tmp1;
            int j;
            for (j = 0; j < limit % 16; j++) {
                *outPtr = ((unsigned char *) &last_block)[j];
                outPtr++;
                (*outputLen)++;
            }
            for (; j < BLOCK_SIZE; j++) {
                ((unsigned char *) &last_block)[j] = 0;
                ((unsigned char *) &in1)[j] = 0;
            }
            tmp1 = last_block;
            tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);

            if (encryption) {
                X = _mm_xor_si128(X, tmp1);
            } else {
                X = _mm_xor_si128(X, _mm_shuffle_epi8(in1, *BSWAP_MASK));
            }
            gfmul(X, H, &X);
        } // partial
    } // has data in buffer




    atLength += atBlockPos;

    //
    // Deal with additional associated text that was supplied after
    // the init or reset methods were called.
    //
    if (atLength > atLengthPre) {

        if (atBlockPos > 0) {
            //
            // finalise any outstanding associated data
            // that was less than the block size.
            //
            tmp1 = last_aad_block;
            tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);
            S_at = _mm_xor_si128(S_at, tmp1);
            gfmul(S_at, H, &S_at);
        }


        if (atLengthPre > 0) {
            S_at = _mm_xor_si128(S_at, S_atPre);
        }

        size_t c = ((totalBytes * 8) + 127) >> 7;
        __m128i H_c;


        gcm_pc_exponentiate(H, c, &H_c);


        gfmul(S_at, H_c, &S_at);

        X = _mm_xor_si128(X, S_at);
    } // extra ad




    tmp1 = _mm_insert_epi64(tmp1, (long long) totalBytes * 8, 0);
    tmp1 = _mm_insert_epi64(tmp1, (long long) atLength * 8, 1);

    unsigned char tmpTag[BLOCK_SIZE];

    X = _mm_xor_si128(X, tmp1);
    gfmul(X, H, &X);
    X = _mm_shuffle_epi8(X, *BSWAP_MASK);
    T = _mm_xor_si128(X, T);


    _mm_storeu_si128((__m128i *) tmpTag, T);

    // Copy into mac block
    memcpy(macBlock, tmpTag, macBlockLen);
    memset(tmpTag, 0, BLOCK_SIZE);


    if (encryption) {
        // Append to end of message
        memcpy(outPtr, macBlock, macBlockLen);
        outPtr += macBlockLen;
        *outputLen += macBlockLen;
    } else {

        if (!tag_verification(macBlock, bufBlock + limit, macBlockLen)) {
            memset(output, 0, *outputLen);
            return make_packet_error("mac check in GCM failed", ILLEGAL_CIPHER_TEXT);
        }
    }

    atLength = 0;
    totalBytes = 0;
    bufBlockIndex = 0;
    atBlockPos = 0;
    atLengthPre = 0;
    last_aad_block = _mm_setzero_si128();
    last_block = _mm_setzero_si128();
    S_atPre = _mm_setzero_si128();
    S_at = _mm_setzero_si128();

    memset(bufBlock, 0, BUF_BLK_SIZE);
    X = initialX;
    Y = initialY;
    T = initialT;
    H = initialH;


    last_block = _mm_setzero_si128();
    ctr1 = _mm_shuffle_epi8(Y, *BSWAP_EPI64);

    blocksRemaining = BLOCKS_REMAINING_INIT;

    return err;
}


void gcm_pc_exponentiate(__m128i H, uint64_t pow, __m128i *output) {

    __m128i y = _mm_set_epi32(-2147483648, 0, 0, 0);

    if (pow > 0) {
        __m128i x = H;
        do {
            if ((pow & 1L) != 0) {
                gfmul(x, y, &y);
            }
            gfmul(x, x, &x);
            pow >>= 1;
        } while (pow > 0);
    }

    *output = y;
}
