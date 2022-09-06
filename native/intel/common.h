

#ifndef BCN_COMMON_H
#define BCN_COMMON_H

#include <wmmintrin.h>


void init_256(__m128i *rk, unsigned char *uk, bool enc);
void init_192(__m128i *rk, unsigned char *uk, bool enc);
void init_128(__m128i *rk, unsigned char *uk, bool enc);

#endif //BCN_COMMON_H
