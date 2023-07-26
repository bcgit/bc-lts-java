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
#define EM_INPUT_OFFSET_NEGATIVE  "offset is negative"
#define EM_OUTPUT_OFFSET_NEGATIVE  "output offset is negative"
#define EM_LEN_NEGATIVE  "len is negative"
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

uint32_t generate_key(bool encryption, uint8_t* key, __m128i* roundKeys, size_t keyLen);

packet_err *make_packet_error(const char *msg, int type);


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
#endif //BC_LTS_C_PACKET_UTILS_H
