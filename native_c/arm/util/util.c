#include "util.h"
#include "arm_neon.h"

void memzero(void *const pnt, const size_t len) {
    //
    // Based on the libsodium utils sodium_memzero function.
    // https://github.com/jedisct1/libsodium/blob/master/src/libsodium/sodium/utils.c
    //
    volatile unsigned char *volatile pnt_ =
            (volatile unsigned char *volatile) pnt;

    size_t i = (size_t) 0U;

    const uint8x16_t zero128 = vdupq_n_u8(0);
    while (i + sizeof(uint8x16_t) <= len) {
        vst1q_u8((uint8_t *) &pnt_[i], zero128);
        i += sizeof(uint8x16_t);
    }

    while (i < len) {
        pnt_[i++] = 0U;
    }
}
