//
//

#ifndef BC_FIPS_C_CFB_H
#define BC_FIPS_C_CFB_H

#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>

#define CFB_BLOCK_SIZE 16


typedef struct cfb_ctx {
    __m128i roundKeys[15];
    __m128i mask;
    __m128i initialFeedback;
    __m128i feedback;
    uint32_t buf_index;
    uint32_t num_rounds;
    bool encryption;

} cfb_ctx;

cfb_ctx *cfb_create_ctx();

void cfb_free_ctx(cfb_ctx *ctx);

void cfb_reset(cfb_ctx *ctx);

void cfb_init(cfb_ctx *pCtx, unsigned char *key, unsigned char *iv);

size_t cfb_encrypt(cfb_ctx *cfb, unsigned char *src, size_t len, unsigned char *dest);

unsigned char cfb_encrypt_byte(cfb_ctx *cfb, unsigned char b);

//
// Decrypt methods implementation vary depending on which of cfb128, cfb256 or cfb512.c files are imported.
//
size_t cfb_decrypt(cfb_ctx *cfb, unsigned char *src, size_t len, unsigned char *dest);

unsigned char cfb_decrypt_byte(cfb_ctx *cfbCtx, unsigned char b);


#endif //BC_FIPS_C_CFB_H
