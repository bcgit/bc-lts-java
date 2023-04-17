
#include "common.h"
#include <immintrin.h>
#include <memory.h>
#include <stdbool.h>

void init_256(__m128i *rk, uint8_t *uk, bool enc) {
    _schedule_256(uk, rk);
    if (!enc) {
        _inv_256(rk);
    }
}

void init_192(__m128i *rk, uint8_t *uk, bool enc) {
    // Why? The key scheduler loads two 128 bit vectors, so we need to ensure
    // we have memory we can safely load from.
    uint8_t key[32] = {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0};
    memcpy(key, uk, 24);
    _schedule_192(key, rk);
    memset(key, 0, 24);

    if (!enc) {
        _inv_192(rk);
    }
}

void init_128(__m128i *rk, uint8_t *uk, bool enc) {
    _schedule_128(uk, rk);
    if (!enc) {
        _inv_128(rk);
    }
}




