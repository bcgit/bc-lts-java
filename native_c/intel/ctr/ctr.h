//
// Created by meganwoods on 3/20/23.
//

#ifndef BC_FIPS_C_CTR_H
#define BC_FIPS_C_CTR_H


#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>

#define CTR_BLOCK_SIZE 16

// matches java one
#define CTR_ERROR_MSG "Counter in CTR/SIC mode out of range."

typedef struct {
    __m128i roundKeys[15];
    uint64_t ctr;
    uint64_t initialCTR;
    __m128i IV_le;
    uint32_t buf_pos;
    __m128i partialBlock;
    uint32_t num_rounds;
    uint64_t ctrMask;
    bool ctrAtEnd;
} ctr_ctx;

ctr_ctx *ctr_create_ctx();

void ctr_free_ctx(ctr_ctx *ctx);

void ctr_reset(ctr_ctx *ctx);

void ctr_init(ctr_ctx *pCtx, unsigned char *key, size_t keyLen, unsigned char *iv, size_t ivLen);

bool ctr_shift_counter(ctr_ctx *pCtr, uint64_t magnitude, bool positive);

int64_t ctr_get_position(ctr_ctx *pCtr);

void ctr_generate_partial_block(ctr_ctx *pCtr);

bool ctr_skip(ctr_ctx *pCtr, int64_t numberOfBytes);

bool ctr_seekTo(ctr_ctx *pCtr, int64_t position);

bool ctr_incCtr(ctr_ctx *pCtr, uint64_t delta);

bool ctr_process_byte(ctr_ctx *pCtx, unsigned char *io);

bool ctr_process_bytes(ctr_ctx *ctr, unsigned char *src, size_t len, unsigned char *dest, size_t *written);

bool ctr_check(ctr_ctx *ctr);

static const int8_t __attribute__ ((aligned(16))) _swap_endian[16] = {
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
};

static const __m128i *SWAP_ENDIAN_128 = ((__m128i *) _swap_endian);

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


#endif //BC_FIPS_C_CFB_H




