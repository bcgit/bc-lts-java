//
//

#ifndef BC_LTS_C_CCM_H
#define BC_LTS_C_CCM_H

#include <stdlib.h>
#include "arm_neon.h"
#include "stdbool.h"
#include "../aes/aes_common_neon.h"

#define ILLEGAL_STATE 1
#define ILLEGAL_ARGUMENT 2
#define ILLEGAL_CIPHER_TEXT 3
#define OUTPUT_LENGTH 4
#define BLOCK_SIZE 16

#define TEXT_LENGTH_UPPER_BOUND ((1 << 16) - (1 << 8))
#define MAC_BLOCK_LEN 16
#define CTR_BLOCK_SIZE 16

static const uint8x16_t zero = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8x16_t one = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // endian
static const uint8x16_t two = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // endian
static const uint8x16_t three = {3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // endian
static const uint8x16_t minus_one = {0,0,0,0,0,0,0,0,255,255,255,255,255,255,255,255};



typedef struct {
    const char *msg; // the message
    int type; // relates to exception needed on jvm side
} ccm_err;


ccm_err *make_ccm_error(const char *msg, int type);

void ccm_err_free(ccm_err *err);


typedef struct {
    aes_key key;
    bool encryption;
    uint8_t nonce[BLOCK_SIZE];
    size_t nonceLen;
    // mac block
    uint8_t macBlock[MAC_BLOCK_LEN];
    size_t macBlockLenInBytes;
    uint8_t *initAD;
    size_t initADLen;
    size_t q;
    //cbcmac
    uint8_t buf[BLOCK_SIZE];
    size_t buf_ptr;
    size_t macLen;
    //cbc
    uint32_t num_rounds;
    uint8x16_t initialChainblock;
    uint8x16_t chainblock;
    //ctr
    uint64_t ctr;
    uint64_t initialCTR;
    uint8x16_t IV_le;
    uint32_t buf_pos;
    uint8x16_t partialBlock;
    uint64_t ctrMask;
    bool ctrAtEnd;
} ccm_ctx;


ccm_ctx *ccm_create_ctx();

void ccm_free(ccm_ctx *);

void ccm_reset(ccm_ctx *, bool keepMac);

size_t ccm_getMac(ccm_ctx *, uint8_t *destination);

size_t ccm_get_output_size(ccm_ctx *ctx, size_t len);



/**
 *
 * @param encryption
 * @param key
 * @param keyLen
 * @param nonce
 * @param nonceLen
 * @return NULL if no error, other ptr to struct CALLER NEEDS TO FREE
 */
ccm_err *ccm_init(ccm_ctx *ctx, bool encryption, uint8_t *key, size_t keyLen, uint8_t *nonce, size_t nonceLen,
                  uint8_t *intialText, size_t initialTextLen, uint32_t macBlockLenBytes);


ccm_err *process_packet(
        ccm_ctx *ref,
        uint8_t *in,
        size_t to_process,
        uint8_t *out,
        size_t *output_len,
        uint8_t *aad,
        size_t aad_len);

void calculateMac(ccm_ctx *ctx, uint8_t *input, size_t len, uint8_t *aad, size_t aad_len);

void cbcmac_update(ccm_ctx *ctx, uint8_t *src, size_t len);

size_t cbcencrypt(ccm_ctx *ctx, unsigned char *src, uint32_t blocks, unsigned char *dest);

bool ccm_ctr_process_bytes(ccm_ctx *pCtr, unsigned char *src, size_t len, unsigned char *dest, size_t *written);

bool ccm_ctr_process_byte(ccm_ctx *ctx, unsigned char *io);

bool ccm_incCtr(ccm_ctx *pCtr, uint64_t magnitude);



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



#endif //BC_LTS_C_CCM_H
