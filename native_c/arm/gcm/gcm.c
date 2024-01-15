//
//

#include <stdlib.h>
#include <memory.h>

#ifdef __APPLE__

#include <libc.h>

#endif

#include <assert.h>
#include "gcm.h"
#include "gcm_hash.h"
//#include "../debug_neon.h"


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
        memzero(ctx->initAD,  ctx->initADLen);
        free(ctx->initAD);
    }

    memzero(ctx,  sizeof(gcm_ctx));
    free(ctx);
}

void gcm_reset(gcm_ctx *ctx, bool keepMac) {


    ctx->atLength = 0;
    ctx->totalBytes = 0;
    ctx->bufBlockIndex = 0;
    ctx->atBlockPos = 0;
    ctx->atLengthPre = 0;
    ctx->last_aad_block = vdupq_n_u8(0);
    ctx->last_block = vdupq_n_u8(0);
    ctx->S_atPre = vdupq_n_u8(0);
    ctx->S_at = vdupq_n_u8(0);

    memzero(ctx->bufBlock,  BUF_BLK_SIZE);


    if (!keepMac) {
        memzero(ctx->macBlock,  16);
    }

    ctx->X = ctx->initialX;
    ctx->Y = ctx->initialY;
    ctx->T = ctx->initialT;
    ctx->H = ctx->initialH;


    if (ctx->initAD != NULL) {
        gcm_process_aad_bytes(ctx, ctx->initAD, ctx->initADLen);
    }


    //    ctx->ctr1 = _mm_shuffle_epi8(ctx->Y, *BSWAP_EPI64);
    ctx->ctr1 = vreinterpretq_u32_u8( vrev64q_u8(ctx->Y));
    ctx->ctr1 = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(ctx->ctr1), vreinterpretq_u8_u32(ctx->ctr1), 8));

    ctx->blocksRemaining = BLOCKS_REMAINING_INIT;

//    gcm_variant_init(ctx);

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
        uint8x16_t tmp = vrev64q_u8(ctx->last_aad_block);//  _mm_shuffle_epi8(ctx->last_aad_block, *BSWAP_MASK);
        tmp = vextq_u8(tmp, tmp, 8);

        ctx->S_atPre = veorq_u8(ctx->S_atPre, tmp);
        ctx->S_atPre = gfmul(ctx->S_atPre, ctx->H);
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

        // For little endian, swap byte order
        ctx->last_aad_block = vrev64q_u8(ctx->last_aad_block);
        ctx->last_aad_block = vextq_u8(ctx->last_aad_block, ctx->last_aad_block, 8);

        ctx->S_at = veorq_u8(ctx->S_at, ctx->last_aad_block);
        ctx->S_at = gfmul(ctx->S_at, ctx->H);
        ctx->last_aad_block = vdupq_n_u8(0);
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
        ctx->last_aad_block = vld1q_u8(aad);

        // For little endian, swap byte order
        ctx->last_aad_block = vrev64q_u8(ctx->last_aad_block);
        ctx->last_aad_block = vextq_u8(ctx->last_aad_block, ctx->last_aad_block, 8);
        ctx->S_at = veorq_u8(ctx->S_at, ctx->last_aad_block);
        ctx->S_at = gfmul(ctx->S_at, ctx->H);
        ctx->last_aad_block = vdupq_n_u8(0);

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

static const uint8x16_t insert_32 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

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

    clear_aes_key(&ctx->aesKey);
    init_aes_key(&ctx->aesKey, key, keyLen, true);
    ctx->encryption = encryption;


    ctx->atLength = 0;
    ctx->totalBytes = 0;
    ctx->atBlockPos = 0;
    ctx->atLengthPre = 0;
    ctx->last_aad_block = vdupq_n_u8(0); // holds partial block of associated text.
    ctx->last_block = vdupq_n_u8(0);

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
    memzero(ctx->macBlock,  MAC_BLOCK_LEN);

    //
    // Setup new mac block len
    //
    ctx->macBlockLen = macBlockLenBits / 8;
    assert(ctx->macBlockLen <= MAC_BLOCK_LEN);

    memzero(ctx->bufBlock,  BUF_BLK_SIZE);
    ctx->bufBlockIndex = 0;

    // TODO change for multi-block
    ctx->bufBlockLen = encryption ? FOUR_BLOCKS : (FOUR_BLOCKS + ctx->macBlockLen);

    ctx->S_at = vdupq_n_u8(0);
    ctx->S_atPre = vdupq_n_u8(0);

    ctx->X = vdupq_n_u8(0);
    ctx->Y = vdupq_n_u8(0);
    ctx->T = vdupq_n_u8(0);
    ctx->H = vdupq_n_u8(0);

    uint8x16_t tmp1, tmp2;

    if (nonceLen == 12) {
        //
        // Copy supplied nonce into 16 byte buffer to avoid potential for overrun
        // when loading nonce via vld1q_u8;
        //
        uint8_t nonceBuf[16];
        memset(nonceBuf, 0, 16);
        memcpy(nonceBuf, nonce, nonceLen);
        ctx->Y = vld1q_u8(nonceBuf);
        memzero(nonceBuf,  16);
        ctx->Y = vorrq_u8(ctx->Y, insert_32);

        dual_block(&ctx->aesKey, ctx->X, ctx->Y, &ctx->H, &ctx->T);

        // swap endian -le only.
//        ctx->H = vrev64q_u8(ctx->H);
//        ctx->H = vextq_u8(ctx->H, ctx->H, 8);
        swap_endian_inplace(&ctx->H);
    } else {
        single_block(&ctx->aesKey, ctx->X, &ctx->H);
        // swap endian -le only.
        swap_endian_inplace(&ctx->H);
//        ctx->H = vrev64q_u8(ctx->H);
//        ctx->H = vextq_u8(ctx->H, ctx->H, 8);


        ctx->Y = veorq_u8(ctx->Y, ctx->Y);

        int i;
        for (i = 0; i < nonceLen / 16; i++) {
            tmp1 = vld1q_u8(&nonce[i * 16]);
            swap_endian_inplace(&tmp1);

//            tmp1 = vrev64q_u8(tmp1);
//            tmp1 = vextq_u8(tmp1, tmp1, 8);
            ctx->Y = veorq_u8(ctx->Y, tmp1);
            ctx->Y = gfmul(ctx->Y, ctx->H);
        }


        if (nonceLen % 16) {
            for (int j = 0; j < nonceLen % 16; j++) {
                ((uint8_t *) &ctx->last_block)[j] = nonce[i * 16 + j];
            }
            tmp1 = ctx->last_block;
            swap_endian_inplace(&tmp1); //  tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);

            ctx->Y = veorq_u8(ctx->Y, tmp1);
            ctx->Y = gfmul(ctx->Y, ctx->H);
        }

        //        tmp1 = _mm_insert_epi64(tmp1, (long long) nonceLen * 8, 0);
        const uint32x4_t nlen = {(uint32_t) nonceLen * 8, 0, 0,
                                 0}; // TODO look for intrinsic that can set u32 into a single lane
        tmp1 = vreinterpretq_u8_u32(nlen);

//        tmp1 = _mm_insert_epi64(tmp1, 0, 1);

        ctx->Y = veorq_u8(ctx->Y, tmp1);
        ctx->Y = gfmul(ctx->Y, ctx->H);
        swap_endian_inplace(&ctx->Y);
//        ctx->Y = _mm_xor_si128(ctx->Y, tmp1);
//        gfmul(ctx->Y, ctx->H, &ctx->Y);
//        ctx->Y = _mm_shuffle_epi8(ctx->Y, *BSWAP_MASK);
        // E(K,Y0)

        single_block(&ctx->aesKey, ctx->Y, &ctx->T);


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

    ctx->last_block = vdupq_n_u8(0);

    // BSWAP_EPI64 = vrev64q_u8(tmp1);

    ctx->ctr1 = vreinterpretq_u32_u8(vrev64q_u8(ctx->Y));
    ctx->blocksRemaining = BLOCKS_REMAINING_INIT;

    ctx->hashKeys[HASHKEY_0] = ctx->H;
    for (int t = HASHKEY_1; t >= 0; t--) {
        ctx->hashKeys[t] = gfmul(ctx->hashKeys[t + 1], ctx->H);
    }


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
    return totalData - totalData % FOUR_BLOCKS;
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


    if (ctx->totalBytes == 0 && len > 0) {
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