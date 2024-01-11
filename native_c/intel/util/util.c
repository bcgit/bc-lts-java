#include "util.h"
#include "immintrin.h"

void memzero(void *const pnt, const size_t len) {
    //
    // Based on the libsodium utils sodium_memzero function.
    // https://github.com/jedisct1/libsodium/blob/master/src/libsodium/sodium/utils.c
    //
    volatile unsigned char *volatile pnt_ =
            (volatile unsigned char *volatile) pnt;

    size_t i = (size_t) 0U;

#ifdef BC_VAESF
    const __m512i zero512 = _mm512_setzero_si512();
    while (i + sizeof(__m512i_u) <= len) {
        _mm512_storeu_si512((__m512i_u *) &pnt_[i], zero512);
        i += sizeof(__m512i_u);
    }

     const __m256i zero256 = _mm256_setzero_si256();
     if (i + sizeof(__m256i_u) <= len) {
        _mm256_storeu_si256((__m256i_u *) &pnt_[i], zero256);
        i += sizeof(__m256i_u);
    }

    const __m128i zero128 = _mm_setzero_si128();
    if (i + sizeof(__m128i_u) <= len) {
        _mm_storeu_si128((__m128i_u *) &pnt_[i], zero128);
        i += sizeof(__m128i_u);
    }
#elif defined(BC_VAES)
    const __m256i zero256 = _mm256_setzero_si256();
    while (i + sizeof(__m256i_u) <= len) {
        _mm256_storeu_si256((__m256i_u *) &pnt_[i], zero256);
        i += sizeof(__m256i_u);
    }

    const __m128i zero128 = _mm_setzero_si128();
    if (i + sizeof(__m128i_u) <= len) {
        _mm_storeu_si128((__m128i_u *) &pnt_[i], zero128);
        i += sizeof(__m128i_u);
    }
#else
    const __m128i zero128 = _mm_setzero_si128();
    while (i + sizeof(__m128i_u) <= len) {
        _mm_storeu_si128((__m128i_u *) &pnt_[i], zero128);
        i += sizeof(__m128i_u);
    }
#endif


    while (i < len) {
        pnt_[i++] = 0U;
    }
}
