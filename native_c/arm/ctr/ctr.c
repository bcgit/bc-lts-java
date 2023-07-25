//
//
//

#include "ctr.h"


#include <assert.h>
#include <memory.h>

ctr_ctx *ctr_create_ctx() {
    ctr_ctx *ctx = calloc(1, sizeof(ctr_ctx));
    assert(ctx != NULL);
    return ctx;
}

void ctr_free_ctx(ctr_ctx *ctx) {
    memset(ctx, 0, sizeof(ctr_ctx));
    free(ctx);
}

void ctr_reset(ctr_ctx *ctx) {
    ctx->partialBlock = vdupq_n_u8(0);
    ctx->buf_pos = 0;
    ctx->ctr = ctx->initialCTR;
    ctx->ctrAtEnd = false;
}


int64_t ctr_get_position(ctr_ctx *pCtr) {
    return (int64_t) ((pCtr->ctr * 16) + pCtr->buf_pos);
}


void ctr_init(ctr_ctx *pCtx, unsigned char *key, size_t keyLen, unsigned char *iv, size_t ivLen) {

    assert(pCtx != NULL);

    if (keyLen != 0) {

        //
        // This mode supports key replacement, jni layer must check for previous initialisation.
        //

        assert(key != NULL);

        init_aes_key(&pCtx->key, key, keyLen, true);

    }


    switch (ivLen) {
        case 16:
        case 8:
            pCtx->ctrMask = 0xFFFFFFFFFFFFFFFF;
            break;
        case 15:
            pCtx->ctrMask = 0xFF;
            break;
        case 14:
            pCtx->ctrMask = 0xFFFF;
            break;
        case 13:
            pCtx->ctrMask = 0xFFFFFF;
            break;
        case 12:
            pCtx->ctrMask = 0xFFFFFFFF;
            break;
        case 11:
            pCtx->ctrMask = 0xFFFFFFFFFF;
            break;
        case 10:
            pCtx->ctrMask = 0xFFFFFFFFFFFF;
            break;
        case 9:
            pCtx->ctrMask = 0xFFFFFFFFFFFFFF;
            break;
        default:
            assert(0);

    }


    if (ivLen < 16) {
        pCtx->IV_le = vdupq_n_u8(0);
        for (int t = 0; t < ivLen; t++) {
            ((unsigned char *) &pCtx->IV_le)[15 - t] = iv[t]; // endian
        }

        pCtx->initialCTR = 0;
    } else {
        //
        // Users know what they are getting into.
        //
        pCtx->IV_le = vld1q_u8(iv);
        swap_endian_inplace(&pCtx->IV_le); //  pCtx->IV_le = _mm_shuffle_epi8(pCtx->IV_le, *SWAP_ENDIAN_128);

        pCtx->ctr = (uint64_t) vget_low_u64(
                vreinterpretq_u64_u8(pCtx->IV_le)); //uint64_t) _mm_extract_epi64(pCtx->IV_le, 0);
        pCtx->initialCTR = pCtx->ctr;

        pCtx->IV_le = vandq_u8(pCtx->IV_le, minus_one);//   _mm_and_si128(pCtx->IV_le, _mm_set_epi64x(-1, 0));
    }
    ctr_reset(pCtx);

}


bool ctr_shift_counter(ctr_ctx *pCtr, uint64_t magnitude, bool positive) {
    if (magnitude == 0) {
        return true;
    }
    uint64_t blockIndex = (pCtr->ctr - pCtr->initialCTR) & pCtr->ctrMask;
    if (positive) {
        uint64_t lastBlockIndex = pCtr->ctrMask;
        if (pCtr->ctrAtEnd || magnitude - 1 > lastBlockIndex - blockIndex) {
            return false;
        }
        pCtr->ctrAtEnd = magnitude > lastBlockIndex - blockIndex;
        pCtr->ctr += magnitude;
    } else {
        if (pCtr->ctrAtEnd) {
            if (magnitude - 1 > pCtr->ctrMask) {
                return false;
            }
        } else {
            if (magnitude > blockIndex) {
                return false;
            }
        }

        pCtr->ctr -= magnitude;
        pCtr->ctrAtEnd = false;
    }
    pCtr->ctr &= pCtr->ctrMask;

    return true;
}


void ctr_generate_partial_block(ctr_ctx *pCtr) {

    uint8x16_t c = veorq_u8(pCtr->IV_le,
                            vreinterpretq_u8_u64(
                                    vsetq_lane_u64(pCtr->ctr, vreinterpretq_u64_u8(vdupq_n_u8(0)), 0)));

    //  __m128i c = _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (long long) pCtr->ctr));
    uint8x16_t j = swap_endian(c);

    single_block(&pCtr->key, j, &pCtr->partialBlock);

//    __m128i j = _mm_shuffle_epi8(c, *SWAP_ENDIAN_128);
//    c = _mm_xor_si128(j, pCtr->roundKeys[0]);
//    int r;
//    for (r = 1; r < pCtr->num_rounds; r++) {
//        c = _mm_aesenc_si128(c, pCtr->roundKeys[r]);
//    }
//    pCtr->partialBlock = _mm_aesenclast_si128(c, pCtr->roundKeys[r]);
}

bool ctr_skip(ctr_ctx *pCtr, int64_t numberOfBytes) {

    uint64_t delta = (uint64_t) (labs(numberOfBytes));
    uint64_t blocksDelta = delta / CTR_BLOCK_SIZE;
    int bytesDelta = (int) (delta % CTR_BLOCK_SIZE);


    if (numberOfBytes < 0) {

        // New buf_pos value
        int ptr = (int) pCtr->buf_pos - (int) bytesDelta;

        if (ptr < 0) {
            pCtr->buf_pos = (uint32_t) (CTR_BLOCK_SIZE + ptr); // ptr is negative here
            if (!ctr_shift_counter(pCtr, 1, false)) {
                return false;
            }

        } else {
            // No need for buffer or ctr adjustment.
            pCtr->buf_pos = (uint32_t) ptr;
        }
        if (blocksDelta != 0 && !ctr_shift_counter(pCtr, blocksDelta, false)) {
            return false;
        }


    } else {

        uint32_t bpos = pCtr->buf_pos + (uint32_t) bytesDelta;


        // If we overflow the buffer then we need to
        // add an extra block and reset the buf_pos down one unit of blocksize.
        if (bpos >= CTR_BLOCK_SIZE) {
            bpos -= CTR_BLOCK_SIZE;
            if (!ctr_shift_counter(pCtr, 1, true)) {
                return false;
            }
        }
        if (blocksDelta != 0 && !ctr_shift_counter(pCtr, blocksDelta, true)) {
            return false;
        }

        if (pCtr->ctrAtEnd && bpos != 0) {
            return false;
        }

        pCtr->buf_pos = bpos;
    }


    ctr_generate_partial_block(pCtr);

    return true;
}


bool ctr_seekTo(ctr_ctx *pCtr, int64_t position) {
    if (position < 0) {
        return false;
    }

    if (pCtr->ctrMask != 0xFFFFFFFFFFFFFFFF && position > (pCtr->ctrMask + 1) * 16) {
        return false;
    }

    ctr_reset(pCtr);

    return ctr_skip(pCtr, position);
}

bool ctr_incCtr(ctr_ctx *pCtr, uint64_t delta) {
    return ctr_shift_counter(pCtr, delta, true);
}

bool ctr_process_byte(ctr_ctx *pCtx, unsigned char *io) {
    if (pCtx->buf_pos == 0) {
        if (!ctr_check(pCtx)) {
            return false;
        }
        ctr_generate_partial_block(pCtx);
        *io = ((unsigned char *) &pCtx->partialBlock)[pCtx->buf_pos++] ^ *io;
        return true;
    }

    *io = ((unsigned char *) &pCtx->partialBlock)[pCtx->buf_pos++] ^ *io;


    if (pCtx->buf_pos == CTR_BLOCK_SIZE) {
        pCtx->buf_pos = 0;
        return ctr_incCtr(pCtx, 1);
    }
    return true;
}

bool ctr_check(ctr_ctx *ctr) {
    return !ctr->ctrAtEnd;
}