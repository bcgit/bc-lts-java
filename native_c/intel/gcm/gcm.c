//
//

#include <immintrin.h>
#include <assert.h>
#include "gcm.h"
#include <stdlib.h>
#include "gcmHash128.h"
#include <memory.h>
#include <stdio.h>
#include "../common.h"




gcm_err *make_gcm_error(const char *msg, int type) {
    gcm_err *err = calloc(1, sizeof(gcm_err));
    err->msg = msg;
    err->type = type;
    return err;
}

void gcm_err_free(gcm_err *err) {
    if (err != NULL) {
        free(err);
    }
}

gcm_ctx *gcm_create_ctx() {
    gcm_ctx *ctx = calloc(1, sizeof(gcm_ctx));
    return ctx;
}

void gcm_free(gcm_ctx *ctx) {
    if (ctx->initAD != NULL) {
        memzero(ctx->initAD, ctx->initADLen);
        free(ctx->initAD);
    }

    memzero(ctx, sizeof(gcm_ctx));
    free(ctx);
}

void gcm_reset(gcm_ctx *ctx, bool keepMac) {
    ctx->atLength = 0;
    ctx->totalBytes = 0;
    ctx->bufBlockIndex = 0;
    ctx->atBlockPos = 0;
    ctx->atLengthPre = 0;
    ctx->last_aad_block = _mm_setzero_si128();
    ctx->last_block = _mm_setzero_si128();
    ctx->S_atPre = _mm_setzero_si128();
    ctx->S_at = _mm_setzero_si128();

    memzero(ctx->bufBlock, BUF_BLK_SIZE);


    if (!keepMac) {
        memzero(ctx->macBlock, 16);
    }

    ctx->X = ctx->initialX;
    ctx->Y = ctx->initialY;
    ctx->T = ctx->initialT;
    ctx->H = ctx->initialH;


    if (ctx->initAD != NULL) {
        gcm_process_aad_bytes(ctx, ctx->initAD, ctx->initADLen);
    }

    ctx->last_block = _mm_setzero_si128();
    ctx->ctr1 = _mm_shuffle_epi8(ctx->Y, *BSWAP_EPI64);

    ctx->blocksRemaining = BLOCKS_REMAINING_INIT;

    gcm_variant_init(ctx);

}


size_t gcm_getMac(gcm_ctx *ctx, uint8_t *destination) {
    if (destination == NULL) {
        return ctx->macBlockLen;
    }
    memcpy(destination, ctx->macBlock, ctx->macBlockLen);
    return ctx->macBlockLen;
}

void gcm__initBytes(gcm_ctx *ctx) {

    if (ctx->atLength > 0) {
        ctx->S_atPre = ctx->S_at;
        ctx->atLengthPre = ctx->atLength;
    }

    if (ctx->atBlockPos > 0) {
        __m128i tmp = _mm_shuffle_epi8(ctx->last_aad_block, *BSWAP_MASK);
        ctx->S_atPre = _mm_xor_si128(ctx->S_atPre, tmp);
        gfmul(ctx->S_atPre, ctx->H, &ctx->S_atPre);
        ctx->atLengthPre += ctx->atBlockPos;
    }

    if (ctx->atLengthPre > 0) {
        ctx->X = ctx->S_atPre;
    }
}


void gcm_process_aad_byte(gcm_ctx *ctx, uint8_t in) {
    ((uint8_t *) &ctx->last_aad_block)[ctx->atBlockPos++] = in;
    if (ctx->atBlockPos == GCM_BLOCK_SIZE) {
        // _gcm_processAadBlock(&last_aad_block,&S_at,&H);
        ctx->last_aad_block = _mm_shuffle_epi8(ctx->last_aad_block, *BSWAP_MASK);
        ctx->S_at = _mm_xor_si128(ctx->S_at, ctx->last_aad_block);
        gfmul(ctx->S_at, ctx->H, &ctx->S_at);
        ctx->last_aad_block = _mm_setzero_si128();
        ctx->atBlockPos = 0;
        ctx->atLength += GCM_BLOCK_SIZE;
    }
}


void gcm_process_aad_bytes(gcm_ctx *ctx, uint8_t *aad, size_t len) {
    // Fill if it needs filling
    if (ctx->atBlockPos > 0) {
        while (ctx->atBlockPos != 0 && len > 0) {
            gcm_process_aad_byte(ctx, *aad);
            len--;
            aad++;
        }
    }

    while (len >= GCM_BLOCK_SIZE) {
        ctx->last_aad_block = _mm_loadu_si128((__m128i *) aad);
        ctx->last_aad_block = _mm_shuffle_epi8(ctx->last_aad_block, *BSWAP_MASK);
        ctx->S_at = _mm_xor_si128(ctx->S_at, ctx->last_aad_block);
        gfmul(ctx->S_at, ctx->H, &ctx->S_at);
        ctx->last_aad_block = _mm_setzero_si128();

        aad += GCM_BLOCK_SIZE;
        ctx->atLength += GCM_BLOCK_SIZE;
        len -= GCM_BLOCK_SIZE;
    }

    while (len > 0) {
        gcm_process_aad_byte(ctx, *aad);
        len--;
        aad++;
    }
}

/**
 *
 * @param encryption
 * @param key
 * @param keyLen
 * @param nonce
 * @param nonceLen
 * @return NULL if no error, other ptr to struct CALLER NEEDS TO FREE
 */
gcm_err *gcm_init(
        gcm_ctx *ctx,
        bool encryption,
        uint8_t *key,
        size_t keyLen,
        uint8_t *nonce,
        size_t nonceLen,
        uint8_t *initialText,
        size_t initialTextLen,
        uint32_t macBlockLenBits) {


    ctx->encryption = encryption;
    ctx->atLength = 0;
    ctx->totalBytes = 0;
    ctx->atBlockPos = 0;
    ctx->atLengthPre = 0;
    ctx->last_aad_block = _mm_setzero_si128(); // holds partial block of associated text.
    ctx->last_block = _mm_setzero_si128();


    // We had old initial text drop it here.
    if (ctx->initAD != NULL) {
        memzero(ctx->initAD, ctx->initADLen);
        free(ctx->initAD);
        ctx->initAD = NULL;
        ctx->initADLen = 0;
    }

    if (initialText != NULL) {

        //
        // We keep a copy so that if the instances is reset it can be returned to
        // the same state it was before the first data is processed.
        //

        ctx->initAD = malloc(initialTextLen);
        ctx->initADLen = initialTextLen;
        memcpy(ctx->initAD, initialText, initialTextLen);
    }

    // Zero out mac block
    memzero(ctx->macBlock, MAC_BLOCK_LEN);


    //
    // Setup new mac block len
    //
    ctx->macBlockLen = macBlockLenBits / 8;
    assert(ctx->macBlockLen <= MAC_BLOCK_LEN);

    memzero(ctx->bufBlock, BUF_BLK_SIZE);
    ctx->bufBlockIndex = 0;

#ifdef BC_VAESF
    ctx->bufBlockLen = encryption ? SIXTEEN_BLOCKS : (SIXTEEN_BLOCKS + ctx->macBlockLen);
#else
    ctx->bufBlockLen = encryption ? FOUR_BLOCKS : (FOUR_BLOCKS + ctx->macBlockLen);
#endif

    memzero(ctx->roundKeys, 15 * sizeof(__m128i));
    switch (keyLen) {
        case 16:
            ctx->num_rounds = 10;
            init_128(ctx->roundKeys, key, true);
            break;

        case 24:
            ctx->num_rounds = 12;
            init_192(ctx->roundKeys, key, true);
            break;

        case 32:
            ctx->num_rounds = 14;
            init_256(ctx->roundKeys, key, true);
            break;

        default:
            return make_gcm_error("invalid key len", ILLEGAL_ARGUMENT);
    }


    ctx->S_at = _mm_setzero_si128();
    ctx->S_atPre = _mm_setzero_si128();

    ctx->X = _mm_setzero_si128();
    ctx->Y = _mm_setzero_si128();
    ctx->T = _mm_setzero_si128();
    ctx->H = _mm_setzero_si128();

    __m128i tmp1, tmp2;

    if (nonceLen == 12) {
        //
        // Copy supplied nonce into 16 byte buffer to avoid potential for overrun
        // when loading nonce via _mm_loadu_si128;
        //

        uint8_t nonceBuf[16];
        memzero(nonceBuf, 16);
        memcpy(nonceBuf, nonce, nonceLen);
        ctx->Y = _mm_loadu_si128((__m128i *) nonceBuf);
        memzero(nonceBuf, 16);

        ctx->Y = _mm_insert_epi32(ctx->Y, 0x1000000, 3);

        tmp1 = _mm_xor_si128(ctx->X, ctx->roundKeys[0]);
        tmp2 = _mm_xor_si128(ctx->Y, ctx->roundKeys[0]);
        for (int j = 1; j < ctx->num_rounds - 1; j += 2) {
            tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[j]);
            tmp2 = _mm_aesenc_si128(tmp2, ctx->roundKeys[j]);
            tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[j + 1]);
            tmp2 = _mm_aesenc_si128(tmp2, ctx->roundKeys[j + 1]);
        }

        tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[ctx->num_rounds - 1]);
        tmp2 = _mm_aesenc_si128(tmp2, ctx->roundKeys[ctx->num_rounds - 1]);

        ctx->H = _mm_aesenclast_si128(tmp1, ctx->roundKeys[ctx->num_rounds]);
        ctx->T = _mm_aesenclast_si128(tmp2, ctx->roundKeys[ctx->num_rounds]);
        ctx->H = _mm_shuffle_epi8(ctx->H, *BSWAP_MASK);
    } else {
        tmp1 = _mm_xor_si128(ctx->X, ctx->roundKeys[0]);
        int j;
        for (j = 1; j < ctx->num_rounds; j++) {
            tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[j]);
        }
        ctx->H = _mm_aesenclast_si128(tmp1, ctx->roundKeys[ctx->num_rounds]);
        ctx->H = _mm_shuffle_epi8(ctx->H, *BSWAP_MASK);
        ctx->Y = _mm_xor_si128(ctx->Y, ctx->Y); // ?
        int i;
        for (i = 0; i < nonceLen / 16; i++) {
            tmp1 = _mm_loadu_si128(&((__m128i *) nonce)[i]);
            tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);
            ctx->Y = _mm_xor_si128(ctx->Y, tmp1);
            gfmul(ctx->Y, ctx->H, &ctx->Y);
        }
        if (nonceLen % 16) {
            for (j = 0; j < nonceLen % 16; j++) {
                ((uint8_t *) &ctx->last_block)[j] = nonce[i * 16 + j];
            }
            tmp1 = ctx->last_block;
            tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);
            ctx->Y = _mm_xor_si128(ctx->Y, tmp1);
            gfmul(ctx->Y, ctx->H, &ctx->Y);
        }
        tmp1 = _mm_insert_epi64(tmp1, (long long) nonceLen * 8, 0);
        tmp1 = _mm_insert_epi64(tmp1, 0, 1);

        ctx->Y = _mm_xor_si128(ctx->Y, tmp1);
        gfmul(ctx->Y, ctx->H, &ctx->Y);
        ctx->Y = _mm_shuffle_epi8(ctx->Y, *BSWAP_MASK);
        // E(K,Y0)

        tmp1 = _mm_xor_si128(ctx->Y, ctx->roundKeys[0]);
        for (j = 1; j < ctx->num_rounds; j++) {
            tmp1 = _mm_aesenc_si128(tmp1, ctx->roundKeys[j]);
        }
        ctx->T = _mm_aesenclast_si128(tmp1, ctx->roundKeys[ctx->num_rounds]);
    }

    //
    // Capture initial state.
    //
    ctx->initialX = ctx->X;
    ctx->initialY = ctx->Y;
    ctx->initialT = ctx->T;
    ctx->initialH = ctx->H;

    //
    // Process any initial associated data.
    //
    if (ctx->initAD != NULL) {
        gcm_process_aad_bytes(ctx, ctx->initAD, ctx->initADLen);
    }

    ctx->last_block = _mm_setzero_si128();

    //
    // Counter is pre incremented in processBlock and processFourBlocks
    //

    ctx->ctr1 = _mm_shuffle_epi8(ctx->Y, *BSWAP_EPI64);

    ctx->blocksRemaining = BLOCKS_REMAINING_INIT;



    // Expand hash keys, key number varies with variant see gcm.h
    ctx->hashKeys[HASHKEY_0] = ctx->H;
    for (int t = HASHKEY_1; t >= 0; t--) {
        gfmul(ctx->hashKeys[t + 1], ctx->H, &tmp1);
        ctx->hashKeys[t] = tmp1;
    }

    gcm_variant_init(ctx);

    return NULL;// All good
}


size_t gcm_get_output_size(gcm_ctx *ctx, size_t len) {
    size_t totalData = len + ctx->bufBlockIndex;
    if (ctx->encryption) {
        return totalData + ctx->macBlockLen;
    }
    return totalData < ctx->macBlockLen ? 0 : totalData - ctx->macBlockLen;
}

size_t gcm_get_update_output_size(gcm_ctx *ctx, size_t len) {

    size_t totalData = len + ctx->bufBlockIndex;
    if (!ctx->encryption) {
        if (totalData < ctx->bufBlockLen) {
            return 0;
        }
        totalData -= ctx->macBlockLen;
    }




#ifdef BC_VAESF
    return totalData - totalData % SIXTEEN_BLOCKS;
#else
    return totalData - totalData % FOUR_BLOCKS;
#endif

}


/**
 *
 * @return NULL if no error, else ptr to struct CALLER NEEDS TO FREE
 */
gcm_err *gcm_process_byte(gcm_ctx *ctx, uint8_t byte, uint8_t *output, size_t outputLen, size_t *written) {
    if (ctx->totalBytes == 0) {
        gcm__initBytes(ctx);
    }

    size_t read = 0;

    if (ctx->encryption) {
        return process_buffer_enc(ctx, &byte, 1, output, outputLen, &read, written);
    }

    return process_buffer_dec(ctx, &byte, 1, output, outputLen, &read, written);

}

/**
 *
 * @param ctx
 * @param input
 * @param len
 * @param output
 * @return NULL if no error, else ptr to struct CALLER NEEDS TO FREE
 */
gcm_err *gcm_process_bytes(gcm_ctx *ctx, uint8_t *input, size_t len, unsigned char *output, size_t outputLen,
                           size_t *written) {


    if (ctx->totalBytes == 0 && len >0) {
        gcm__initBytes(ctx);
    }

    size_t rd = 0;
    size_t wr = 0;

    gcm_err *err = NULL;

    unsigned char *start = input;
    unsigned char *end = start + len;
    unsigned char *outPtr = output;
    unsigned char *outStart = outPtr;

    if (ctx->encryption) {
        for (unsigned char *readPos = start; readPos < end;) {
            err = process_buffer_enc(ctx, readPos, len, outPtr, outputLen, &rd, &wr);
            if (err != NULL) {
                break;
            }
            readPos += rd;
            len -= rd;
            outPtr += wr;
            outputLen -= wr;
        }
    } else {
        for (unsigned char *readPos = start; readPos < end;) {
            err = process_buffer_dec(ctx, readPos, len, outPtr, outputLen, &rd, &wr);
            if (err != NULL) {
                break;
            }
            readPos += rd;
            len -= rd;
            outPtr += wr;
            outputLen -= wr;
        }
    }

    *written = (size_t) (outPtr - outStart);
    return err;
}

void gcm_exponentiate(__m128i H, uint64_t pow, __m128i *output) {

    __m128i y = _mm_set_epi32(-2147483648, 0, 0, 0);

    if (pow > 0)
    {
        __m128i x = H;
        do
        {
            if ((pow & 1L) != 0)
            {
                gfmul(x, y, &y);
            }
            gfmul(x, x, &x);
            pow >>= 1;
        }
        while (pow > 0);
    }

    *output = y;
}
