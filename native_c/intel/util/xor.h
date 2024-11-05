

#ifndef BC_LTS_C_XOR_H
#define BC_LTS_C_XOR_H

#include <stdint.h>
#include <stddef.h>
#include "emmintrin.h"


static inline void xor(uint8_t *dest, uint8_t *x, uint8_t *y, size_t len) {
    while (len >= 16) {
        _mm_storeu_si128((__m128i *) dest, _mm_xor_si128(_mm_loadu_si128((__m128i *)x), _mm_loadu_si128((__m128i *)y)));
        len -= 16;
        dest += 16;
        x += 16;
        y += 16;
    }

    while (len > 0) {
        *dest = *x ^ *y;
        len--;
        dest++;
        x++;
        y++;
    }
}


#endif //BC_LTS_C_XOR_H
