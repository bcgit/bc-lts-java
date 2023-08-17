//
//

#ifndef BC_FIPS_C_SHA224_H
#define BC_FIPS_C_SHA224_H
#include <immintrin.h>
#include <stdint.h>
#include <stdbool.h>

#define BUF_SIZE_SHA224 64
#define SHA224_SIZE 28
#define SHA224_MAGIC 0x00020001

typedef struct {
    uint32_t ident;
    size_t buf_index;
    uint8_t buf[BUF_SIZE_SHA224];
    uint64_t byteCount;
    uint32_t state[8];
    __m128i s0;
    __m128i s1;
} sha224_ctx;


sha224_ctx * sha224_create_ctx();

void sha224_free_ctx(sha224_ctx *ctx);

void sha224_reset(sha224_ctx *ctx);

void sha224_update(sha224_ctx *ctx, uint8_t *input, size_t len);

void sha224_update_byte(sha224_ctx *ctx, uint8_t b);

void sha224_digest(sha224_ctx *ctx, uint8_t *output);

uint32_t sha224_getSize(sha224_ctx *ctx);
uint32_t sha224_getByteLen(sha224_ctx *ctx);

bool sha224_restoreFullState(sha224_ctx *ctx, const uint8_t *oldState);

size_t sha224_encodeFullState(const sha224_ctx *ctx, uint8_t *output);

static const int8_t __attribute__ ((aligned(16))) _endian_swap_sha224[16] = {
        3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12
};

static const __m128i *SWAP_ENDIAN_SHA_224 = ((__m128i *) _endian_swap_sha224);



#endif //BC_FIPS_C_SHA224_H
