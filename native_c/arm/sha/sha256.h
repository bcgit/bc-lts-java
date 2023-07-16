//
//

#ifndef BC_LTS_C_SHA256_H
#define BC_LTS_C_SHA256_H

#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>
#include <stdbool.h>

#define BUF_SIZE_SHA256 64
#define SHA256_SIZE 32
#define SHA256_MAGIC 0x00020001

typedef struct {
    uint32_t ident;
    size_t buf_index;
    uint8_t buf[BUF_SIZE_SHA256];
    uint64_t byteCount;
    uint32_t state[8];
    uint8x16_t s0;
    uint8x16_t s1;
} sha256_ctx;


sha256_ctx * sha256_create_ctx();

void sha256_free_ctx(sha256_ctx *ctx);

void sha256_reset(sha256_ctx *ctx);

void sha256_update(sha256_ctx *ctx, uint8_t *input, size_t len);

void sha256_update_byte(sha256_ctx *ctx, uint8_t b);

void sha256_digest(sha256_ctx *ctx, uint8_t *output);

uint32_t sha256_getSize(sha256_ctx *ctx);
uint32_t sha256_getByteLen(sha256_ctx *ctx);

bool sha256_restoreFullState(sha256_ctx *ctx, const uint8_t *oldState);

size_t sha256_encodeFullState(const sha256_ctx *ctx, uint8_t *output);

static const int8_t __attribute__ ((aligned(16))) _endian_swap_sha256[16] = {
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



#endif //BC_LTS_C_SHA256_H
