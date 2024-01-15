//
//

#ifndef BC_LTS_C_SHA512_H
#define BC_LTS_C_SHA512_H

#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>
#include <stdbool.h>
#include "../util/util.h"

#define BUF_SIZE_SHA512 128
#define SHA512_SIZE 64
#define SHA512_MAGIC 0x00020003

typedef struct {
    uint32_t ident;
    size_t buf_index;
    uint8_t buf[BUF_SIZE_SHA512];
    uint64_t byteCount1;
    uint64_t byteCount2;
    uint64_t state[8];
    uint64x2_t s0;
    uint64x2_t s1;
    uint64x2_t s2;
    uint64x2_t s3;
} sha512_ctx;


sha512_ctx * sha512_create_ctx();

void sha512_free_ctx(sha512_ctx *ctx);

void sha512_reset(sha512_ctx *ctx);

void sha512_update(sha512_ctx *ctx, uint8_t *input, size_t len);

void sha512_update_byte(sha512_ctx *ctx, uint8_t b);

void sha512_digest(sha512_ctx *ctx, uint8_t *output);

uint32_t sha512_getSize(sha512_ctx *ctx);
uint32_t sha512_getByteLen(sha512_ctx *ctx);

bool sha512_restoreFullState(sha512_ctx *ctx, const uint8_t *oldState);

size_t sha512_encodeFullState(const sha512_ctx *ctx, uint8_t *output);

static const int8_t __attribute__ ((aligned(16))) _endian_swap_sha512[16] = {
        3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12
};

static inline void swap_endian_inplace(uint8x16_t *in) {
    *in = vrev64q_u8(*in);
    *in = vextq_u8(*in, *in, 8);
}

static inline uint8x16_t swap_endian(uint8x16_t in) {
    in = vrev64q_u8(in);
    return vextq_u8(in, in, 8);
}





#endif //BC_LTS_C_SHA512_H
