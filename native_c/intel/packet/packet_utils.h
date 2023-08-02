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
#define EM_OUTPUT_LENGTH  "output buffer too short"
#define EM_INPUT_LENGTH  "input buffer too short"
#define EM_INPUT_NULL  "input was null"
#define EM_INPUT_OFFSET_NEGATIVE  "input offset is negative"
#define EM_OUTPUT_OFFSET_NEGATIVE  "output offset is negative"
#define EM_LEN_NEGATIVE  "input len is negative"
#define EM_INPUT_SHORT  "data too short"
#define EM_AES_KEY_LENGTH  "Key length not 128/192/256 bits."
#define EM_AES_DECRYPTION_INPUT_LENGTH_INVALID  "the length of input should be times of 16."
#define EM_CBC_IV_LENGTH  "initialisation vector must be the same length as block size"
#define EM_OUTPUT_NULL  "output was null"
//Error Type
#define ILLEGAL_STATE 1
#define ILLEGAL_ARGUMENT 2
#define ILLEGAL_CIPHER_TEXT 3
#define OUTPUT_LENGTH 4

void packet_err_free(packet_err *err);

int get_aead_output_size(bool encryption, int len, int macSize);

int get_output_size(bool encryption, int len);

uint32_t generate_key(bool encryption, uint8_t *key, __m128i *roundKeys, size_t keyLen);

packet_err *make_packet_error(const char *msg, int type);

static inline void
packet_encrypt(__m128i *d0, const __m128i chainblock, __m128i *roundKeys, const uint32_t num_rounds);

size_t cbc_pc_encrypt(unsigned char *src, uint32_t blocks, unsigned char *dest, __m128i *chainblock, __m128i *roundKeys,
                      uint32_t num_rounds);


#endif //BC_LTS_C_PACKET_UTILS_H
