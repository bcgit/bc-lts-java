//
//

#include <stdio.h>
#include "cmul.h"
#include "immintrin.h"

void cmul_acc(int64_t *x, int64_t *y, int64_t *z, size_t size) {
    size_t i = 0;

    if (size >= 2) {

        size_t limit = size - 2;

        while (i <= limit) {
            __m128i x01 = _mm_loadu_si128((__m128i *) &x[i]);
            size_t j = 0;
            while (j <= limit) {

                __m128i tmp1, z00, z01, z10, z11, z12, z23, tmp6, tmp7, tmp8;

                __m128i y01 = _mm_loadu_si128((__m128i *) &y[j]);

                z01 = _mm_clmulepi64_si128(x01, y01, 0x00); // Z01
                z12 = _mm_xor_si128(_mm_clmulepi64_si128(x01, y01, 0x01), _mm_clmulepi64_si128(x01, y01, 0x10));
                z23 = _mm_clmulepi64_si128(x01, y01, 0x11); // Z23

                z[i + j + 0] ^= _mm_extract_epi64(z01, 0);
                z[i + j + 1] ^= _mm_extract_epi64(z01, 1) ^ _mm_extract_epi64(z12, 0);
                z[i + j + 2] ^= _mm_extract_epi64(z23, 0) ^ _mm_extract_epi64(z12, 1);
                z[i + j + 3] ^= _mm_extract_epi64(z23, 1);

                j += 2;
            }
            i += 2;
        }

    }

    if (i < size) {
        __m128i Xi, Yi, Xj, Yj, Z;

        Xi = _mm_set_epi64x(0, x[i]);
        Yi = _mm_set_epi64x(0, y[i]);

        for (size_t j = 0; j < i; j++) {
            Xj = _mm_set_epi64x(0, x[j]);
            Yj = _mm_set_epi64x(0, y[j]);
            Z = _mm_xor_si128(_mm_clmulepi64_si128(Xi, Yj, 0x00), _mm_clmulepi64_si128(Yi, Xj, 0x00));
            z[i + j + 0] ^= _mm_extract_epi64(Z, 0);
            z[i + j + 1] ^= _mm_extract_epi64(Z, 1);
        }

        Z = _mm_clmulepi64_si128(Xi, Yi, 0x00);
        z[i + i + 0] ^= _mm_extract_epi64(Z, 0);
        z[i + i + 1] ^= _mm_extract_epi64(Z, 1);
    }

}