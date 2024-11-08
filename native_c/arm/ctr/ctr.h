//
//

#ifndef BC_LTS_C_CTR_H
#define BC_LTS_C_CTR_H

#define CTR_BLOCK_SIZE 16
#define CTR_ERROR_MSG "Counter in CTR/SIC mode out of range."

#include "arm_neon.h"
#include "stdbool.h"
#include "stdlib.h"
#include "../aes/aes_common_neon.h"

typedef struct {
    aes_key key;
    uint64_t ctr;
    uint64_t initialCTR;
    uint8x16_t IV_le;
    uint32_t buf_pos;
    uint8x16_t partialBlock;
    uint64_t ctrMask;
    bool ctrAtEnd;
} ctr_ctx;

ctr_ctx *ctr_create_ctx();

void ctr_free_ctx(ctr_ctx *ctx);

void ctr_reset(ctr_ctx *ctx);

void ctr_init(ctr_ctx *pCtx, unsigned char *key, size_t keyLen, unsigned char *iv, size_t ivLen);

bool ctr_shift_counter(ctr_ctx *pCtr, uint64_t magnitude, bool positive);

int64_t ctr_get_position(ctr_ctx *pCtr);

void ctr_generate_partial_block(ctr_ctx *pCtr);

bool ctr_skip(ctr_ctx *pCtr, int64_t numberOfBytes);

bool ctr_seekTo(ctr_ctx *pCtr, int64_t position);

bool ctr_incCtr(ctr_ctx *pCtr, uint64_t delta);

bool ctr_process_byte(ctr_ctx *pCtx, unsigned char *io);

bool ctr_process_bytes(ctr_ctx *ctr, unsigned char *src, size_t len, unsigned char *dest, size_t *written);

bool ctr_check(ctr_ctx *ctr);


static const uint8x16_t zero = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8x16_t one = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // endian
static const uint8x16_t two = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // endian
static const uint8x16_t three = {3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // endian

static const uint8x16_t minus_one = {0,0,0,0,0,0,0,0,255,255,255,255,255,255,255,255};

static inline void swap_endian_inplace(uint8x16_t *in) {
    *in = vrev64q_u8(*in);
    *in = vextq_u8(*in, *in, 8);
}

static inline uint8x16_t swap_endian(uint8x16_t in) {
    in = vrev64q_u8(in);
    return vextq_u8(in, in, 8);
}


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

#endif //BC_LTS_C_CTR_H
