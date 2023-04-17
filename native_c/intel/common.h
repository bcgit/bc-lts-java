

#ifndef BCN_COMMON_H
#define BCN_COMMON_H

#include <immintrin.h>
#include <stdbool.h>
#include <stdint-gcc.h>

#define ROUNDS_128 10
#define ROUNDS_192 12
#define ROUNDS_256 14


void init_256(__m128i *rk, uint8_t *uk, bool enc);
void init_192(__m128i *rk, uint8_t *uk, bool enc);
void init_128(__m128i *rk, uint8_t *uk, bool enc);

extern void _schedule_128(uint8_t *key, __m128i *roundKeys);
extern void _schedule_192(uint8_t *key, __m128i *roundKeys);
extern void _schedule_256(uint8_t *key, __m128i *roundKeys);

extern void _inv_256(__m128i *roundKeys);
extern void _inv_192(__m128i *roundKeys);
extern void _inv_128(__m128i *roundKeys);

#endif //BCN_COMMON_H
