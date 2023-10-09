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
    size_t buf_u8_index;
    uint64_t buf[BUF_SIZE_SHA3 / 8];
    uint64_t byteCount;
    uint64x2_t state[STATE_LEN];
    bool squeezing;
} sha3_ctx;


sha3_ctx * sha3_create_ctx(int bitLen);

void sha3_free_ctx(sha3_ctx *ctx);

void sha3_reset(sha3_ctx *ctx);

void sha3_update(sha3_ctx *ctx, uint8_t *input, size_t len);

void sha3_update_byte(sha3_ctx *ctx, uint8_t b);

void sha3_digest(sha3_ctx *ctx, uint8_t *output);

uint32_t sha3_getSize(sha3_ctx *ctx);

uint32_t sha3_getByteLen(sha3_ctx *ctx);

bool sha3_restoreFullState(sha3_ctx *ctx, const uint8_t *oldState);

size_t sha3_encodeFullState(const sha3_ctx *ctx, uint8_t *output);

#endif //BC_LTS_C_SHA3_H
