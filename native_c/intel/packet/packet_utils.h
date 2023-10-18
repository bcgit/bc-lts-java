#ifndef BC_LTS_C_PACKET_UTILS_H
#define BC_LTS_C_PACKET_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <immintrin.h>
#include <stdlib.h>
#include <assert.h>
#include <memory.h>
#include "../common.h"

#define BLOCK_SIZE 16

typedef struct {
    const char *msg; // the message
    int type; // relates to exception needed on jvm side
} packet_err;


// Define error messages
// Reference: ExceptionMessage
#define EM_OUTPUT_LENGTH_NEGATIVE  "output len is negative"
#define EM_OUTPUT_LENGTH  "output buffer too short"
#define EM_OUTPUT_TOO_SHORT  "output buffer too short for offset + length"
#define EM_INPUT_LENGTH  "input buffer too short"
#define EM_INPUT_TOO_SHORT  "input buffer too short for offset + length"
#define EM_INPUT_NULL  "input was null"
#define EM_INPUT_OFFSET_NEGATIVE  "input offset is negative"
#define EM_OUTPUT_OFFSET_NEGATIVE  "output offset is negative"
#define EM_INPUT_LEN_NEGATIVE  "input len is negative"
#define EM_INPUT_SHORT  "input data too short"
#define EM_INVALID_LEN "len parameter invalid"
#define EM_AES_KEY_LENGTH  "Key length not 128/192/256 bits."
#define BLOCK_CIPHER_16_INPUT_LENGTH_INVALID  "input len not multiple of block size"
#define EM_CBC_IV_LENGTH  "initialisation vector must be the same length as block size"
#define EM_OUTPUT_NULL  "output was null"
#define EM_MACSIZE_INVALID  "invalid mac size"

//Error Type
#define ILLEGAL_STATE 1
#define ILLEGAL_ARGUMENT 2
#define ILLEGAL_CIPHER_TEXT 3
#define OUTPUT_LENGTH 4
//E1L=((0xe1000000L& 0xFFFFFFFFL) << 32)
#define E1L  (-2233785415175766016L)

typedef void (*encrypt_function)(__m128i *d0, __m128i *d1, __m128i *roundKeys);

static const int8_t __attribute__ ((aligned(16))) _swap_endian[16] = {
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
};
static const __m128i *SWAP_ENDIAN_128 = ((__m128i *) _swap_endian);

void packet_err_free(packet_err *err);

int get_aead_output_size(bool encryption, int len, int macSize);

int get_output_size(int len);

int generate_key(bool encryption, uint8_t *key, __m128i *roundKeys, size_t keyLen);

//int generateKey(bool encryption, uint8_t *key, __m128i *roundKeys, size_t keyLen, encrypt_function *fun);

packet_err *make_packet_error(const char *msg, int type);

size_t cbc_pc_encrypt(unsigned char *src, uint32_t blocks, unsigned char *dest, __m128i *chainblock, __m128i *roundKeys,
                      int num_rounds);

bool tag_verification(const uint8_t *left, const uint8_t *right, size_t len);

bool tag_verification_16(const uint8_t *left, const uint8_t *right);

//static inline void encrypt128(__m128i *d0, __m128i *d1, __m128i *roundKeys);
//
//static inline void encrypt192(__m128i *d0, __m128i *d1, __m128i *roundKeys);
//
//static inline void encrypt256(__m128i *d0, __m128i *d1, __m128i *roundKeys);

#endif //BC_LTS_C_PACKET_UTILS_H
