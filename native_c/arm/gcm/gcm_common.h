#ifndef BC_LTS_C_GCM_COMMON_H
#define BC_LTS_C_GCM_COMMON_H

#include <stdbool.h>
#include <assert.h>
#include "arm_neon.h"

static const uint8x16_t zero = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8x16_t one = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}; // endian

static inline void swap_endian_inplace(uint8x16_t *in) {
    *in = vrev64q_u8(*in);
    *in = vextq_u8(*in, *in, 8);
}

static inline uint8x16_t swap_endian(uint8x16_t in) {
    in = vrev64q_u8(in);
    return vextq_u8(in, in, 8);
}

static inline bool areEqualCT(const uint8_t *left, const uint8_t *right, size_t len) {

    assert(left != NULL);
    assert(right != NULL);

    uint32_t nonEqual = 0;

    for (int i = 0; i != len; i++) {
        nonEqual |= (left[i] ^ right[i]);
    }

    return nonEqual == 0;
}


#endif