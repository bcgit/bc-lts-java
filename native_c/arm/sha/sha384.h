//
//

#ifndef BC_LTS_C_SHA384_H
#define BC_LTS_C_SHA384_H

#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>
#include <stdbool.h>

#define BUF_SIZE_SHA384 128
#define SHA384_SIZE 48
#define SHA384_MAGIC 0x00020004

typedef struct {
    uint32_t ident;
    size_t buf_index;
    uint8_t buf[BUF_SIZE_SHA384];
    uint64_t byteCount1;
    uint64_t byteCount2;
    uint64_t state[8];
    uint64x2_t s0;
    uint64x2_t s1;
    uint64x2_t s2;
    uint64x2_t s3;
} sha384_ctx;


sha384_ctx * sha384_create_ctx();

void sha384_free_ctx(sha384_ctx *ctx);

void sha384_reset(sha384_ctx *ctx);

void sha384_update(sha384_ctx *ctx, uint8_t *input, size_t len);

void sha384_update_byte(sha384_ctx *ctx, uint8_t b);

void sha384_digest(sha384_ctx *ctx, uint8_t *output);

uint32_t sha384_getSize(sha384_ctx *ctx);
uint32_t sha384_getByteLen(sha384_ctx *ctx);

bool sha384_restoreFullState(sha384_ctx *ctx, const uint8_t *oldState);

size_t sha384_encodeFullState(const sha384_ctx *ctx, uint8_t *output);

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





#endif //BC_LTS_C_SHA384_H
