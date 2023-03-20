

#ifndef BCN_COMMON_H
#define BCN_COMMON_H

#include <immintrin.h>
#include <string>
#include "sstream"


void init_256(__m128i *rk, unsigned char *uk, bool enc);
void init_192(__m128i *rk, unsigned char *uk, bool enc);
void init_128(__m128i *rk, unsigned char *uk, bool enc);

#endif //BCN_COMMON_H
