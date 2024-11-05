//
// Created by meganwoods on 11/5/24.
//

#ifndef BC_LTS_C_SLHDSA_SHA256_H
#define BC_LTS_C_SLHDSA_SHA256_H

#include "../sha/sha256.h"
#include "../util/xor.h"


typedef struct slhdsa_sha256 {
    sha256_ctx msgMemo;
    sha256_ctx sha256Memo;

    sha256_ctx msgDigest;
    sha256_ctx sha256Digest;

} slhdsa_sha256;

slhdsa_sha256 *slhdsa_sha256_create_ctx();

void slhdsa_sha256_free_ctx(slhdsa_sha256 *ctx);

void slhdsa_sha256_reset(slhdsa_sha256 *ctx);

void slhdsa_sha256_init_memos(
        slhdsa_sha256 *ctx,
        uint8_t *seed,
        size_t seed_len,
        uint8_t *padding,
        size_t padding_len_1,
        size_t padding_len_2);


void slhdsa_sha256_sha256_digest(
        slhdsa_sha256 *ctx,
        uint8_t *out,
        uint8_t *in0, size_t in0_len,
        uint8_t *in1, size_t in1_len,
        uint8_t *in2, size_t in2_len,
        uint8_t *in3, size_t in3_len
);

void slhdsa_sha256_msgDigest_digest(
        slhdsa_sha256 *ctx,
        uint8_t *out,
        uint8_t *in0, size_t in0_len,
        uint8_t *in1, size_t in1_len,
        uint8_t *in2, size_t in2_len,
        uint8_t *in3, size_t in3_len,
        uint8_t *in4, size_t in4_len
);

void slhdsa_sha256_mgf256_mask(slhdsa_sha256 *ctx,
                               uint8_t *key, size_t key_len,
                               uint8_t *output,
                               uint8_t *in0, size_t in0_len,
                               uint8_t *in1, size_t in1_len,
                               uint8_t *in2, size_t in2_len,
                               uint8_t *in3, size_t in3_len
);


#endif //BC_LTS_C_SLHDSA_SHA256_H
