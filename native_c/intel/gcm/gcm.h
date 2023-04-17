//
//

#include <stdbool.h>
#include <stdint.h>
#include <immintrin.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef BC_FIPS_C_GCM_H
#define BC_FIPS_C_GCM_H


//
// Exponentiator
//

#define ILLEGAL_STATE 1
#define ILLEGAL_ARGUMENT 2
#define ILLEGAL_CIPHER_TEXT 3
#define OUTPUT_LENGTH 4


#define GCM_BLOCK_SIZE 16
#define BLOCK_SIZE 16
#define FOUR_BLOCKS 64
#define EIGHT_BLOCKS 128
#define SIXTEEN_BLOCKS 256

#define BLOCKS_REMAINING_INIT ((1L << 32) - 2L)
#define MAC_BLOCK_LEN 16


//#ifdef BC_AVX
//#define HASHKEY_1 2
//#define HASHKEY_0 3
//#define HASHKEY_LEN 4
//#else
#define HASHKEY_1 14
#define HASHKEY_0 15
#define HASHKEY_LEN 16
//#endif


typedef struct {
    const char *msg; // the message
    int type; // relates to exception needed on jvm side
} gcm_err;


gcm_err *make_gcm_error(const char *msg, int type);

void gcm_err_free(gcm_err *err);

#define BUF_BLK_SIZE (17 * 16) // 17 blocks because we need to hold the potential tag on decryption.

typedef struct {

    __m128i roundKeys[15];
    int64_t blocksRemaining;

    __m128i X;
    __m128i ctr1;
    uint32_t num_rounds;
    bool encryption;


    // mac block
    uint8_t macBlock[MAC_BLOCK_LEN];
    size_t macBlockLen;

    uint8_t *initAD;
    size_t initADLen;

    uint32_t atBlockPos;
    size_t atLengthPre;


    __m128i H, Y, T, S_at, S_atPre, last_aad_block;

    // AD

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

} gcm_ctx;


gcm_ctx *gcm_create_ctx();

void gcm_free(gcm_ctx *);

void gcm_reset(gcm_ctx *, bool keepMac);


/**
 *
 * @return NULL if no error, else ptr to struct CALLER NEEDS TO FREE
 */
gcm_err *gcm_process_byte(gcm_ctx *ctr, uint8_t byte, uint8_t *output, size_t outputLen, size_t *written);

/**
 *
 * @param ctx
 * @param input
 * @param len
 * @param output
 * @return NULL if no error, else ptr to struct CALLER NEEDS TO FREE
 */
gcm_err *
gcm_process_bytes(gcm_ctx *ctx, uint8_t *input, size_t len, uint8_t *output, size_t output_len, size_t *written);

/**
 *
 * @param output
 * @param outLen
 * @param written
 * @return NULL if no error, else ptr to struct CALLER NEEDS TO FREE
 */
gcm_err *gcm_doFinal(gcm_ctx *, uint8_t *output, size_t outLen, size_t *written);

/**
 * Call with NULL destination to get len.
 * @param destination destination to copy mac
 * @return the length
 */
size_t gcm_getMac(gcm_ctx *, uint8_t *destination);

size_t gcm_get_output_size(gcm_ctx *ctx, size_t len);

size_t gcm_get_update_output_size(gcm_ctx *ctx, size_t len);

void gcm_process_aad_byte(gcm_ctx *, uint8_t in);

void gcm_process_aad_bytes(gcm_ctx *, uint8_t *aad, size_t len);

void gcm__initBytes(gcm_ctx *ctx);


/**
 *
 * @param encryption
 * @param key
 * @param keyLen
 * @param nonce
 * @param nonceLen
 * @return NULL if no error, other ptr to struct CALLER NEEDS TO FREE
 */
gcm_err *gcm_init(gcm_ctx *ctx, bool encryption, uint8_t *key, size_t keyLen, uint8_t *nonce, size_t nonceLen,
                  uint8_t *intialText, size_t initialTextLen, uint32_t macBlockLenBits);


gcm_err *process_buffer_enc(gcm_ctx *ctx,
                            uint8_t *in,
                            size_t inlen,
                            uint8_t *out,
                            size_t outputLen,
                            size_t *read,
                            size_t *written);

gcm_err *process_buffer_dec(gcm_ctx *ctx,
                            uint8_t *in,
                            size_t inlen,
                            uint8_t *out,
                            size_t outputLen,
                            size_t *read,
                            size_t *written);


void gcm_variant_init(gcm_ctx *ctx);

void gcm_exponentiate(__m128i H, uint64_t pow, __m128i *output);

#endif //BC_FIPS_C_GCM_H
