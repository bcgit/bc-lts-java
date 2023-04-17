//
//

#ifndef BC_FIPS_ECB_H
#define BC_FIPS_ECB_H

#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>
#include "../../jniutil/bytearraycritical.h"

#define ECB_BLOCK_SIZE 16

typedef struct ecb_ctx {
   __m128i roundKeys[15];
   int num_rounds;
   bool encryption;
} ecb_ctx;

ecb_ctx * ecb_create_ctx();

void ecb_free_ctx(ecb_ctx * ctx);

void ecb_reset(ecb_ctx *ctx);

void ecb_init(ecb_ctx *pCtx, uint8_t *key);

size_t ecb_process_blocks(ecb_ctx *ctx, uint8_t *src, uint32_t blocks, uint8_t *dest);


#endif //BC_FIPS_ECB_H
