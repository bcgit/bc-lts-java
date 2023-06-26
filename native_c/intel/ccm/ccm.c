//
//


#include <assert.h>
#include "ccm.h"
#include <stdlib.h>
#include <memory.h>
#include "../common.h"


ccm_err *make_ccm_error(const char *msg, int type) {
    ccm_err *err = calloc(1, sizeof(ccm_err));
    assert(err != NULL);
    err->msg = msg;
    err->type = type;
    return err;
}

void ccm_err_free(ccm_err *err) {
    if (err != NULL) {
        free(err);
    }
}


ccm_ctx *ccm_create_ctx() {
    ccm_ctx *ctx = calloc(1, sizeof(ccm_ctx));
    assert(ctx != NULL);
    return ctx;
}

void ccm_free(ccm_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    //     Free if we have initial AD.
    if (ctx->initAD != NULL) {
        memset(ctx->initAD, 0, ctx->initADLen);
        free(ctx->initAD);
    }
//     Zero context
    memset(ctx, 0, sizeof(ccm_ctx));
    free(ctx);
}

void ccm_reset(ccm_ctx *ctx, bool keepMac) {
    if (ctx->aad != NULL) {
        ctx->aadLen = 0;
        ctx->aad = NULL;
    }
    memset(ctx->buf, 0, BLOCK_SIZE);
    ctx->buf_ptr = 0;
    ctx->chainblock = ctx->initialChainblock;
    ctx->partialBlock = _mm_setzero_si128();
    ctx->buf_pos = 0;
    ctx->ctr = ctx->initialCTR;
    ctx->ctrAtEnd = false;
    if (!keepMac) {
        // Zero out mac block
        memset(ctx->macBlock, 0, MAC_BLOCK_LEN);
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
ccm_err *ccm_init(
        ccm_ctx *ctx,
        bool encryption,
        uint8_t *key,
        size_t keyLen,
        uint8_t *nonce,
        size_t nonceLen,
        uint8_t *initialText,
        size_t initialTextLen,
        uint32_t macBlockLenBits) {
    //
    // All assertions of correctness need to be done by this call.
    //
    ctx->encryption = encryption;
    ctx->nonceLen = nonceLen;
    memset(ctx->nonce, 0, BLOCK_SIZE);
    memcpy(ctx->nonce, nonce, nonceLen);
    ctx->macBlockLenInBytes = macBlockLenBits;
    ctx->q = 15 - nonceLen;

    memset(ctx->roundKeys, 0, sizeof(__m128i) * 15);
    switch (keyLen) {
        case 16:
            ctx->num_rounds = ROUNDS_128;
            init_128(ctx->roundKeys, key, true);
            break;
        case 24:
            ctx->num_rounds = ROUNDS_192;
            init_192(ctx->roundKeys, key, true);
            break;
        case 32:
            ctx->num_rounds = ROUNDS_256;
            init_256(ctx->roundKeys, key, true);
            break;
        default:
            assert(0);
    }
    ctx->initialChainblock = _mm_setzero_si128();//_mm_loadu_si128((__m128i *) ctx->macBlock);
    ctx->chainblock = ctx->initialChainblock;

    memset(ctx->buf, 0, BLOCK_SIZE);

    ctx->buf_ptr = 0;
    ctx->macLen = macBlockLenBits;
    memset(ctx->macBlock, 0, BLOCK_SIZE);
    ctx->macBlock[0] = (ctx->q - 1) & 0x7;
    memcpy(ctx->macBlock + 1, ctx->nonce, ctx->nonceLen);
    ctx->ctrMask = 0xFFFFFFFFFFFFFFFF;
    ctx->IV_le = _mm_loadu_si128((__m128i *) ctx->macBlock);
    ctx->IV_le = _mm_shuffle_epi8(ctx->IV_le, *SWAP_ENDIAN_128);
    ctx->ctr = (uint64_t) _mm_extract_epi64(ctx->IV_le, 0);
    ctx->initialCTR = ctx->ctr;
    ctx->IV_le = _mm_and_si128(ctx->IV_le, _mm_set_epi64x(-1, 0));
    // We had old initial text drop it here.
    if (ctx->initAD != NULL) {
        memset(ctx->initAD, 0, (size_t) ctx->initADLen);
        free(ctx->initAD);
        ctx->initAD = NULL;
        ctx->initADLen = 0;
    }
    if (ctx->aad != NULL) {
        ctx->aad = NULL;
        ctx->aadLen = 0;
    }
    if (initialText != NULL) {
        //
        // We keep a copy as it is needed to calculate the mac
        // the same state it was before the first data is processed.
        //
        ctx->initAD = malloc(initialTextLen * sizeof(uint8_t));
        assert(ctx->initAD != NULL);
        ctx->initADLen = initialTextLen;
        memcpy(ctx->initAD, initialText, initialTextLen);
    }
    // Zero out mac block
    memset(ctx->macBlock, 0, MAC_BLOCK_LEN);
    return NULL;// All good
}


size_t ccm_get_output_size(ccm_ctx *ctx, size_t len) {
    if (ctx->encryption) {
        return len + ctx->macBlockLenInBytes;
    }
    return len < ctx->macBlockLenInBytes ? 0 : len - ctx->macBlockLenInBytes;
}

ccm_err *processPacket(ccm_ctx *ctx, uint8_t *in, size_t len, uint8_t *out, size_t *output_len) {
    if (ctx->q < 4) {
        int limitLen = 1 << (ctx->q << 3);
        if (len >= limitLen) {
            return make_ccm_error("CCM packet too large for choice of q", ILLEGAL_STATE);
        }
    }
    size_t written = 0;
    if (ctx->encryption) {
        calculateMac(ctx, in, len);
        ccm_ctr_process_bytes(ctx, ctx->macBlock, BLOCK_SIZE, ctx->macBlock, &written);
        ccm_ctr_process_bytes(ctx, in, len, out, &written);
        memcpy(out + written, ctx->macBlock, ctx->macBlockLenInBytes);
        *output_len = len + ctx->macBlockLenInBytes;
    } else {
        if (len < ctx->macBlockLenInBytes) {
            return make_ccm_error("ciphertext too short", ILLEGAL_CIPHER_TEXT);
        }
        size_t outputLen = len - ctx->macBlockLenInBytes;
        uint8_t tmp[BLOCK_SIZE] = {0};
        memcpy(ctx->macBlock, in + outputLen, ctx->macBlockLenInBytes);
        memset(ctx->macBlock + ctx->macBlockLenInBytes, 0, (BLOCK_SIZE - ctx->macBlockLenInBytes));
        ccm_ctr_process_bytes(ctx, ctx->macBlock, BLOCK_SIZE, tmp, &written);
        ccm_ctr_process_bytes(ctx, in, outputLen, out, &written);
        calculateMac(ctx, out, outputLen);
        uint8_t nonEqual = 0;
        for (int i = 0; i < ctx->macBlockLenInBytes; i++) {
            nonEqual |= (ctx->macBlock[i] ^ tmp[i]);
        }
        memset(tmp, 0, BLOCK_SIZE);
        //"mac check in CCM failed"
        if (nonEqual) {
            return make_ccm_error("mac check in CCM failed", ILLEGAL_CIPHER_TEXT);
        }
        *output_len = outputLen;
    }
    return NULL;
}


void calculateMac(ccm_ctx *ctx, uint8_t *input, size_t len) {
    size_t textLength = ctx->initADLen + ctx->aadLen;
    if (textLength) {
        ctx->buf[0] |= 0x40;
    }
    ctx->buf[0] |= ((((ctx->macBlockLenInBytes - 2) >> 1) & 0x7) << 3) | (((15 - ctx->nonceLen) - 1) & 0x7);
    memcpy(ctx->buf + 1, ctx->nonce, ctx->nonceLen);
    size_t count = 1;
    size_t q = len;
    while (q > 0) {
        ctx->buf[BLOCK_SIZE - count++] = (uint8_t) (q & 0xFF);
        q >>= 8;
    }
    cbcencrypt(ctx, ctx->buf, 1, ctx->macBlock);
    if (textLength) {
        if (textLength < TEXT_LENGTH_UPPER_BOUND) {
            ctx->buf[0] = (uint8_t) (textLength >> 8);
            ctx->buf[1] = (uint8_t) (textLength);
            ctx->buf_ptr = 2;
        } else {
            ctx->buf[0] = 0xff;
            ctx->buf[1] = 0xfe;
            ctx->buf[2] = (uint8_t) (textLength >> 24);
            ctx->buf[3] = (uint8_t) (textLength >> 16);
            ctx->buf[4] = (uint8_t) (textLength >> 8);
            ctx->buf[5] = (uint8_t) (textLength);
            ctx->buf_ptr = 6;
        }
        if (ctx->initAD != NULL) {
            cbcmac_update(ctx, ctx->initAD, ctx->initADLen);
        }
        if (ctx->aad != NULL) {
            cbcmac_update(ctx, ctx->aad, ctx->aadLen);
        }
        memset(ctx->buf + ctx->buf_ptr, 0, (BLOCK_SIZE - ctx->buf_ptr));
        cbcencrypt(ctx, ctx->buf, 1, ctx->macBlock);
        ctx->buf_ptr = 0;
    }
    cbcmac_update(ctx, input, len);
    if (ctx->buf_ptr) {
        memset(ctx->buf + ctx->buf_ptr, 0, BLOCK_SIZE - ctx->buf_ptr);
        cbcencrypt(ctx, ctx->buf, 1, ctx->macBlock);
    }
    memset(ctx->macBlock + ctx->macBlockLenInBytes, 0, BLOCK_SIZE - ctx->macBlockLenInBytes);
}

size_t ccm_getMac(ccm_ctx *ctx, uint8_t *destination) {
    memcpy(destination, ctx->macBlock, ctx->macBlockLenInBytes);
    return ctx->macBlockLenInBytes;
}

void ccm_process_aad_bytes(ccm_ctx *ctx, uint8_t *in, size_t len) {
    if (in != NULL) {
        ctx->aadLen = len;
        ctx->aad = in;
    }
}

static inline void encrypt(__m128i *d0, const __m128i chainblock, __m128i *roundKeys, const uint32_t num_rounds) {
    *d0 = _mm_xor_si128(*d0, chainblock);
    *d0 = _mm_xor_si128(*d0, roundKeys[0]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[1]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[2]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[3]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[4]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[5]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[6]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[7]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[8]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[9]);
    if (num_rounds == ROUNDS_128) {
        *d0 = _mm_aesenclast_si128(*d0, roundKeys[10]);
    } else if (num_rounds == ROUNDS_192) {
        *d0 = _mm_aesenc_si128(*d0, roundKeys[10]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[11]);
        *d0 = _mm_aesenclast_si128(*d0, roundKeys[12]);
    } else if (num_rounds == ROUNDS_256) {
        *d0 = _mm_aesenc_si128(*d0, roundKeys[10]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[11]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[12]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[13]);
        *d0 = _mm_aesenclast_si128(*d0, roundKeys[14]);
    } else {
        assert(0);
    }
}


size_t cbcencrypt(ccm_ctx *ctx, unsigned char *src, uint32_t blocks, unsigned char *dest) {
//    assert(ctx != NULL);
    unsigned char *destStart = dest;
    __m128i d0;
    __m128i tmpCb = ctx->chainblock;
    while (blocks > 0) {
        d0 = _mm_loadu_si128((__m128i *) src);
        encrypt(&d0, tmpCb, ctx->roundKeys, ctx->num_rounds);
        _mm_storeu_si128((__m128i *) dest, d0);
        blocks--;
        src += BLOCK_SIZE;
        dest += BLOCK_SIZE;
        tmpCb = d0;
    }
    ctx->chainblock = tmpCb;
    return (size_t) (dest - destStart);
}

void cbcmac_update(ccm_ctx *ctx, uint8_t *src, size_t len) {
    size_t gapLen = BLOCK_SIZE - ctx->buf_ptr;
    if (len > gapLen) {
        memcpy(ctx->buf + ctx->buf_ptr, src, gapLen);
        cbcencrypt(ctx, ctx->buf, 1, ctx->macBlock);
        ctx->buf_ptr = 0;
        len -= gapLen;
        src += gapLen;
        while (len > BLOCK_SIZE) {
            cbcencrypt(ctx, src, 1, ctx->macBlock);
            len -= BLOCK_SIZE;
            src += BLOCK_SIZE;
        }
    }
    if (len) {
        memcpy(ctx->buf + ctx->buf_ptr, src, len);
        ctx->buf_ptr += len;
    }
}

void ccm_generate_partial_block(ccm_ctx *pCtr) {
    __m128i c = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (long long) pCtr->ctr));
    __m128i j = _mm_shuffle_epi8(c, *SWAP_ENDIAN_128);
    c = _mm_xor_si128(j, pCtr->roundKeys[0]);
    int r;
    for (r = 1; r < pCtr->num_rounds; r++) {
        c = _mm_aesenc_si128(c, pCtr->roundKeys[r]);
    }
    pCtr->partialBlock = _mm_aesenclast_si128(c, pCtr->roundKeys[r]);
}

bool ccm_incCtr(ccm_ctx *pCtr, uint64_t magnitude) {
    uint64_t blockIndex = (pCtr->ctr - pCtr->initialCTR) & pCtr->ctrMask;
    uint64_t lastBlockIndex = pCtr->ctrMask;
    if (pCtr->ctrAtEnd || magnitude - 1 > lastBlockIndex - blockIndex) {
        return false;
    }
    pCtr->ctrAtEnd = magnitude > lastBlockIndex - blockIndex;
    pCtr->ctr += magnitude;
    pCtr->ctr &= pCtr->ctrMask;
    return true;
}

bool ccm_ctr_process_byte(ccm_ctx *ctx, unsigned char *io) {
    if (ctx->buf_pos == 0) {
        if (ctx->ctrAtEnd) {
            return false;
        }
        ccm_generate_partial_block(ctx);
        *io = ((unsigned char *) &ctx->partialBlock)[ctx->buf_pos++] ^ *io;
        return true;
    }
    *io = ((unsigned char *) &ctx->partialBlock)[ctx->buf_pos++] ^ *io;
    if (ctx->buf_pos == CTR_BLOCK_SIZE) {
        ctx->buf_pos = 0;
        return ccm_incCtr(ctx, 1);
    }
    return true;
}


