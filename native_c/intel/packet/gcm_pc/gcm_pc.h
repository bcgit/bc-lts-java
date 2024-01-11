//
//

#include <stdbool.h>
#include <stdint.h>
#include <immintrin.h>
#include <stdlib.h>
#include <stdio.h>
#include "../packet_utils.h"


#ifndef BC_LTS_C_GCM_H
#define BC_LTS_C_GCM_H


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

packet_err *
gcm_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *iv, size_t ivsize, size_t macSize,
                      uint8_t *aad, size_t aadLen, uint8_t *p_in, size_t inLen, uint8_t *p_out, size_t *outputLen);

typedef struct {
    const char *msg; // the message
    int type; // relates to exception needed on jvm side
} gcm_err;



#define BUF_BLK_SIZE (17 * 16) // 17 blocks because we need to hold the potential tag on decryption.


packet_err *gcm_pc_process_buffer_enc(uint8_t *in, size_t inlen, uint8_t *out, size_t outputLen, size_t *read, size_t *written,
                               bool encryption, size_t *bufBlockIndex, int64_t *blocksRemaining, __m128i *hashKeys,
                               __m128i *ctr1, __m128i *roundKeys, int num_rounds, size_t *totalBytes, __m128i *X,
                               size_t bufBlockLen, uint8_t *bufBlock);


packet_err *gcm_pc_process_buffer_dec(uint8_t *in, size_t inlen, uint8_t *out, size_t outputLen, size_t *read,
                               size_t *written,  size_t *bufBlockIndex, int64_t *blocksRemaining,
                               __m128i *hashKeys, __m128i *ctr1, __m128i *roundKeys, int num_rounds,
                               size_t *totalBytes, __m128i *X, size_t bufBlockLen, uint8_t *bufBlock, size_t macBlockLen);

void gcm_pc_exponentiate(__m128i H, uint64_t pow, __m128i *output);

#endif //BC_FIPS_C_GCM_H
