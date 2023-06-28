//
//

#include <stdbool.h>
#include <stdint.h>
#include <immintrin.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef BC_FIPS_C_CCM_H
#define BC_FIPS_C_CCM_H

#define ILLEGAL_STATE 1
#define ILLEGAL_ARGUMENT 2
#define ILLEGAL_CIPHER_TEXT 3
#define OUTPUT_LENGTH 4
#define BLOCK_SIZE 16

#define TEXT_LENGTH_UPPER_BOUND ((1 << 16) - (1 << 8))
#define MAC_BLOCK_LEN 16
#define CTR_BLOCK_SIZE 16

typedef struct {
    const char *msg; // the message
    int type; // relates to exception needed on jvm side
} ccm_err;


ccm_err *make_ccm_error(const char *msg, int type);

void ccm_err_free(ccm_err *err);


typedef struct {
    __m128i roundKeys[15];
    bool encryption;
    uint8_t nonce[BLOCK_SIZE];
    size_t nonceLen;
    uint8_t *aad;
    size_t aadLen;
    // mac block
    uint8_t macBlock[MAC_BLOCK_LEN];
    size_t macBlockLenInBytes;
    uint8_t *initAD;
    size_t initADLen;
    size_t q;
    //cbcmac
    uint8_t buf[BLOCK_SIZE];
    size_t buf_ptr;
    size_t macLen;
    //cbc
    uint32_t num_rounds;
    __m128i initialChainblock;
    __m128i chainblock;
    //ctr
    uint64_t ctr;
    uint64_t initialCTR;
    __m128i IV_le;
    uint32_t buf_pos;
    __m128i partialBlock;
    uint64_t ctrMask;
    bool ctrAtEnd;
} ccm_ctx;


ccm_ctx *ccm_create_ctx();

void ccm_free(ccm_ctx *);

void ccm_reset(ccm_ctx *, bool keepMac);

size_t ccm_getMac(ccm_ctx *, uint8_t *destination);

size_t ccm_get_output_size(ccm_ctx *ctx, size_t len);

void ccm_process_aad_bytes(ccm_ctx *, uint8_t *aad, size_t len);

/**
 *
 * @param encryption
 * @param key
 * @param keyLen
 * @param nonce
 * @param nonceLen
 * @return NULL if no error, other ptr to struct CALLER NEEDS TO FREE
 */
ccm_err *ccm_init(ccm_ctx *ctx, bool encryption, uint8_t *key, size_t keyLen, uint8_t *nonce, size_t nonceLen,
                  uint8_t *intialText, size_t initialTextLen, uint32_t macBlockLenBytes);


ccm_err *processPacket(ccm_ctx *ctx, uint8_t *in, size_t to_process, uint8_t *out, size_t *output_len);

void calculateMac(ccm_ctx *ctx, uint8_t *input, size_t len);

void cbcmac_update(ccm_ctx *ctx, uint8_t *src, size_t len);

size_t cbcencrypt(ccm_ctx *ctx, unsigned char *src, uint32_t blocks, unsigned char *dest);

bool ccm_ctr_process_bytes(ccm_ctx *pCtr, unsigned char *src, size_t len, unsigned char *dest, size_t *written);

bool ccm_ctr_process_byte(ccm_ctx *ctx, unsigned char *io);

bool ccm_incCtr(ccm_ctx *pCtr, uint64_t magnitude);


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

#endif //BC_FIPS_C_CCM_H
