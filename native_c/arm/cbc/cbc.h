//
//

#ifndef BC_LTS_C_CBC_H
#define BC_LTS_C_CBC_H

#include <stdbool.h>
#include "arm_neon.h"
#include "../aes/aes_common_neon.h"

#define CBC_BLOCK_SIZE 16

typedef struct cbc_ctx {
    aes_key key;
    size_t num_rounds;
    bool encryption;
    uint8x16_t initial_chain_block;
    uint8x16_t chain_block;
} cbc_ctx;

cbc_ctx * cbc_create_ctx();

void cbc_free_ctx(cbc_ctx * ctx);

void cbc_reset(cbc_ctx *ctx);

void cbc_init(cbc_ctx *pCtx, unsigned char *key, unsigned char *iv);

size_t cbc_encrypt(cbc_ctx *cbc, unsigned char *src, uint32_t blocks, unsigned char *dest);

size_t cbc_decrypt(cbc_ctx *cbc, unsigned char *src, uint32_t blocks, unsigned char *dest);



#endif //BC_LTS_C_CBC_H
