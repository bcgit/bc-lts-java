//
//

#ifndef BC_LTS_C_SHA3_H
#define BC_LTS_C_SHA3_H

#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>
#include <stdbool.h>

#define BUF_SIZE_SHA3 144
#define SHA3_MAGIC 0x00030000
#define STATE_LEN 25

typedef struct {
    uint32_t ident;
    uint32_t bitLen;
    uint32_t rate;
    size_t rate_bytes;
    size_t buf_index;
    uint8_t buf[BUF_SIZE_SHA3];
    uint64_t byteCount;
    uint64_t state[STATE_LEN];
    bool squeezing;
} sha3_ctx;


sha3_ctx * sha3_create_ctx(int bitLen);

void sha3_free_ctx(sha3_ctx *ctx);

void sha3_reset(sha3_ctx *ctx);

void sha3_update(sha3_ctx *ctx, uint8_t *input, size_t len);

void keccak_absorb_buf(sha3_ctx *ctx, uint8_t *buf,  size_t rateBytes);

void sha3_update_byte(sha3_ctx *ctx, uint8_t b);

void sha3_digest(sha3_ctx *ctx, uint8_t *output);

uint32_t sha3_getSize(sha3_ctx *ctx);
uint32_t sha3_getByteLen(sha3_ctx *ctx);

bool sha3_restoreFullState(sha3_ctx *ctx, const uint8_t *oldState);

size_t sha3_encodeFullState(const sha3_ctx *ctx, uint8_t *output);

static const int8_t __attribute__ ((aligned(16))) _endian_swap_sha224[16] = {
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

static inline void swap_u64(uint8x8_t *src) {
    *src = vrev64_u8( *src);
}


#endif //BC_LTS_C_SHA3_H
