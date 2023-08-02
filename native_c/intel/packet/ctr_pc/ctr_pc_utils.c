#include "ctr_pc_utils.h"

bool ctr_pc_incCtr(uint64_t magnitude, uint64_t *ctr, uint64_t initialCTR, uint64_t ctrMask, bool *ctrAtEnd) {
    uint64_t blockIndex = (*ctr - initialCTR) & ctrMask;
    uint64_t lastBlockIndex = ctrMask;
    if (*ctrAtEnd || magnitude - 1 > lastBlockIndex - blockIndex) {
        return false;
    }
    *ctrAtEnd = magnitude > lastBlockIndex - blockIndex;
    *ctr += magnitude;
    *ctr &= ctrMask;
    return true;
}


void ctr_pc_generate_partial_block(__m128i *IV_le, uint64_t ctr, __m128i *roundKeys, uint32_t num_rounds,
                                   __m128i *partialBlock) {
    __m128i c = _mm_xor_si128(*IV_le, _mm_set_epi64x(0, (long long) ctr));
    __m128i j = _mm_shuffle_epi8(c, *SWAP_ENDIAN_128);
    c = _mm_xor_si128(j, roundKeys[0]);
    int r;
    for (r = 1; r < num_rounds; r++) {
        c = _mm_aesenc_si128(c, roundKeys[r]);
    }
    *partialBlock = _mm_aesenclast_si128(c, roundKeys[r]);
}

bool ctr_pc_process_byte(unsigned char *io, uint32_t *buf_pos, uint64_t *ctr, uint64_t initialCTR, uint64_t ctrMask,
                             bool *ctrAtEnd, __m128i *IV_le, __m128i *roundKeys, uint32_t num_rounds,
                             __m128i *partialBlock) {
    if (*buf_pos == 0) {
        if (*ctrAtEnd) {
            return false;
        }
        ctr_pc_generate_partial_block(IV_le, *ctr, roundKeys, num_rounds, partialBlock);
        *io = ((unsigned char *) partialBlock)[(*buf_pos)++] ^ *io;
        return true;
    }
    *io = ((unsigned char *) partialBlock)[(*buf_pos)++] ^ *io;
    if (*buf_pos == BLOCK_SIZE) {
        *buf_pos = 0;
        return ctr_pc_incCtr(1, ctr, initialCTR, ctrMask, ctrAtEnd);
    }
    return true;
}
