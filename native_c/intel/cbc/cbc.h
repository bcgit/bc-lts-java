//
//

#ifndef BC_FIPS_C_CBC_H
#define BC_FIPS_C_CBC_H

#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>

#define CBC_BLOCK_SIZE 16


typedef struct cbc_ctx {
    __m128i roundKeys[15];
    int num_rounds;
    bool encryption;
    __m128i initialChainblock;
    __m128i chainblock;
} cbc_ctx;

cbc_ctx * cbc_create_ctx();

void cbc_free_ctx(cbc_ctx * ctx);

void cbc_reset(cbc_ctx *ctx);

void cbc_init(cbc_ctx *pCtx, unsigned char *key, unsigned char *iv);

size_t cbc_encrypt(cbc_ctx *cbc, unsigned char *src, uint32_t blocks, unsigned char *dest);

size_t cbc_decrypt(cbc_ctx *cbc, unsigned char *src, uint32_t blocks, unsigned char *dest);

#endif //BC_FIPS_C_CBC_H
