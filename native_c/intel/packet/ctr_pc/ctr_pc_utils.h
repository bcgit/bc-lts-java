
#ifndef BC_LTS_C_CTR_PC_UTILS_H
#define BC_LTS_C_CTR_PC_UTILS_H
#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>
#include "../packet_utils.h"

bool ctr_pc_incCtr(uint64_t magnitude, uint64_t *ctr, uint64_t initialCTR, uint64_t ctrMask, bool *ctrAtEnd);

void ctr_pc_generate_partial_block(__m128i *IV_le, uint64_t ctr, __m128i *roundKeys, int num_rounds,
                                   __m128i *partialBlock);

bool ctr_pc_process_byte(unsigned char *io, uint32_t *buf_pos, uint64_t *ctr, uint64_t initialCTR, uint64_t ctrMask,
                             bool *ctrAtEnd, __m128i *IV_le, __m128i *roundKeys, int num_rounds,
                             __m128i *partialBlock);

bool ctr_pc_process_bytes(unsigned char *src, size_t len, unsigned char *dest, size_t *written, uint32_t *buf_pos,
                          uint64_t* ctr, uint64_t initialCTR, uint64_t ctrMast, bool* ctrAtEnd, __m128i* IV_le,
                          __m128i* roundKeys, int num_rounds, __m128i* partialBlock);



static const int8_t __attribute__ ((aligned(16))) _one[16] = {
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static __m128i *ONE = (__m128i *) _one;


static const int8_t __attribute__ ((aligned(16))) _two[16] = {
        2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static __m128i *TWO = (__m128i *) _two;


static const int8_t __attribute__ ((aligned(16))) _three[16] = {
        3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static __m128i *THREE = (__m128i *) _three;


static const int8_t __attribute__ ((aligned(16))) _four[16] = {
        4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static __m128i *FOUR = (__m128i *) _four;


static const int8_t __attribute__ ((aligned(16))) _five[16] = {
        5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static __m128i *FIVE = (__m128i *) _five;


static const int8_t __attribute__ ((aligned(16))) _six[16] = {
        6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static __m128i *SIX = (__m128i *) _six;

static const int8_t __attribute__ ((aligned(16))) _seven[16] = {
        7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static __m128i *SEVEN = (__m128i *) _seven;
#endif //BC_LTS_C_CTR_PC_UTILS_H
