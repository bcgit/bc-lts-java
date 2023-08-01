//
//

#ifndef BC_LTS_C_CFB_H
#define BC_LTS_C_CFB_H

#include "arm_neon.h"
#include "../aes/aes_common_neon.h"

#define CFB_BLOCK_SIZE 16

typedef struct cfb_ctx {
   aes_key key;
    uint8x16_t mask;
    uint8x16_t initialFeedback;
    uint8x16_t feedback;
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

/**
 * Process one block.
 * @param key
 * @param in1 input 1
 * @param out1 output block 1
 */
static inline void single_block(
        aes_key *key,
        uint8x16_t in1,
        uint8x16_t *out1
) {

    const size_t rounds = key->rounds;
    const uint8x16_t *rk = key->round_keys;
    if (key->encryption) {

        if (rounds == 10) {
            in1 = vaeseq_u8(in1, rk[0]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[1]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[2]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[3]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[4]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[5]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[6]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[7]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[8]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[9]);
            *out1 = veorq_u8(in1, rk[10]);
        } else if (rounds == 12) {
            in1 = vaeseq_u8(in1, rk[0]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[1]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[2]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[3]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[4]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[5]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[6]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[7]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[8]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[9]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[10]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[11]);
            *out1 = veorq_u8(in1, rk[12]);
        } else {
            in1 = vaeseq_u8(in1, rk[0]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[1]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[2]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[3]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[4]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[5]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[6]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[7]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[8]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[9]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[10]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[11]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[12]);
            in1 = vaesmcq_u8(in1);
            in1 = vaeseq_u8(in1, rk[13]);
            *out1 = veorq_u8(in1, rk[14]);
        }
    } else {

        //
        // Decryption
        //


        if (rounds == 10) {
            in1 = vaesdq_u8(in1, rk[0]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[1]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[2]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[3]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[4]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[5]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[6]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[7]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[8]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[9]);
            *out1 = veorq_u8(in1, rk[10]);

        } else if (rounds == 12) {
            in1 = vaesdq_u8(in1, rk[0]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[1]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[2]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[3]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[4]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[5]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[6]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[7]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[8]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[9]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[10]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[11]);
            *out1 = veorq_u8(in1, rk[12]);

        } else {
            in1 = vaesdq_u8(in1, rk[0]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[1]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[2]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[3]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[4]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[5]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[6]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[7]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[8]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[9]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[10]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[11]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[12]);
            in1 = vaesimcq_u8(in1);

            in1 = vaesdq_u8(in1, rk[13]);
            *out1 = veorq_u8(in1, rk[14]);

        }
    }
}

#endif //BC_LTS_C_CFB_H
