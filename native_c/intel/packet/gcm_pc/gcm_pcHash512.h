//


#ifndef BC_FIPS_C_GCMHASH512_H
#define BC_FIPS_C_GCMHASH512_H

#include <immintrin.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>


static const int8_t __attribute__ ((aligned(16))) _one[16] = {
        00, 00, 00, 00, 00, 00, 00, 00, 01, 00, 00, 00, 00, 00, 00, 00
};

static const __m128i *ONE = ((__m128i *) _one);

static const int8_t __attribute__ ((aligned(16))) _bswap_epi64[16] = {
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8
};

static const __m128i *BSWAP_EPI64 = ((__m128i *) _bswap_epi64);


static const int8_t __attribute__ ((aligned(16))) _bswap_mask[16] = {
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
};

static const __m128i *BSWAP_MASK = ((__m128i *) _bswap_mask);


static const int8_t __attribute__ ((aligned(64))) _bswap_eip64_512[64] = {
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8
};

static const __m512i *BSWAP_EPI64_512 = ((__m512i *) _bswap_eip64_512);



static const int8_t __attribute__ ((aligned(64))) _bswap_mask_512[64] = {
        15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,
        15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,
        15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,
        15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
};

static const __m512i *BSWAP_MASK_512 = ((__m512i *) _bswap_mask_512);



static const int32_t __attribute__ ((aligned(64))) _four[4] = {
        0,0,4,0
};

static const __m128i * FOUR = ((__m128i*)_four);


static const int32_t __attribute__ ((aligned(64))) _eight[4] = {
        0,0,8,0
};

static const __m128i * EIGHT = ((__m128i*)_eight);


static const int32_t __attribute__ ((aligned(64))) _twelve[4] = {
        0,0,12,0
};

static const __m128i * TWELVE = ((__m128i*)_twelve);

static const int32_t __attribute__ ((aligned(64))) _sixteen[4] = {
        0,0,16,0
};

static const __m128i * SIXTEEN = ((__m128i*)_sixteen);


static const int32_t __attribute__ ((aligned(64))) _inc16[16] = {
        0,0,16,0,0,0,16,0,0,0,16,0,0,0,16,0
};

static const __m512i * INC16 = ((__m512i*)_inc16);


static const int32_t __attribute__ ((aligned(64))) _inc4[16] = {
        0,0,4,0,0,0,4,0,0,0,4,0,0,0,4,0
};

static const __m512i * INC4 = ((__m512i*)_inc4);


static inline void spreadCtr(const __m128i ctr, __m512i *ctr12,__m512i *ctr34, __m512i *ctr56, __m512i *ctr78) {
    *ctr12 = _mm512_add_epi32(_mm512_broadcast_i32x4(ctr),
                                  _mm512_set_epi32(0, 4, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0));
    *ctr34 = _mm512_add_epi32(_mm512_broadcast_i32x4(ctr),
                                  _mm512_set_epi32(0, 8, 0, 0, 0, 7, 0, 0, 0, 6, 0, 0, 0, 5, 0, 0));
    *ctr56 = _mm512_add_epi32(_mm512_broadcast_i32x4(ctr),
                                  _mm512_set_epi32(0, 12, 0, 0, 0, 11, 0, 0, 0, 10, 0, 0, 0, 9, 0, 0));
    *ctr78 = _mm512_add_epi32(_mm512_broadcast_i32x4(ctr),
                                  _mm512_set_epi32(0, 16, 0, 0, 0, 15, 0, 0, 0, 14, 0, 0, 0, 13, 0, 0));
}


static inline void aes_xor(
        __m512i *d0, __m512i *d1, __m512i *d2, __m512i *d3,
        const __m128i rk) {
    const __m512i rkw = _mm512_broadcast_i32x4(rk);

    *d0 = _mm512_xor_si512(*d0, rkw);
    *d1 = _mm512_xor_si512(*d1, rkw);
    *d2 = _mm512_xor_si512(*d2, rkw);
    *d3 = _mm512_xor_si512(*d3, rkw);
}


static inline void aes_enc(
        __m512i *d0, __m512i *d1, __m512i *d2, __m512i *d3,
        const __m128i rk) {
    const __m512i rkw = _mm512_broadcast_i32x4(rk);
    *d0 = _mm512_aesenc_epi128(*d0, rkw);
    *d1 = _mm512_aesenc_epi128(*d1, rkw);
    *d2 = _mm512_aesenc_epi128(*d2, rkw);
    *d3 = _mm512_aesenc_epi128(*d3, rkw);
}

static inline void aes_enc_last(
        __m512i *d0, __m512i *d1, __m512i *d2, __m512i *d3,
        const __m128i rk) {
    const __m512i rkw = _mm512_broadcast_i32x4(rk);
    *d0 = _mm512_aesenclast_epi128(*d0, rkw);
    *d1 = _mm512_aesenclast_epi128(*d1, rkw);
    *d2 = _mm512_aesenclast_epi128(*d2, rkw);
    *d3 = _mm512_aesenclast_epi128(*d3, rkw);
}


static inline __m128i reduceWide(const __m512i GHw, const __m512i t1w) {
    __m256i ymm31 = _mm256_xor_si256(
            _mm512_extracti64x4_epi64(GHw, 1),
            _mm512_extracti64x4_epi64(GHw, 0));
    __m256i ymm30 = _mm256_xor_si256(
            _mm512_extracti64x4_epi64(t1w, 1),
            _mm512_extracti64x4_epi64(t1w, 0));

    __m128i xmm31 = _mm_xor_si128(
            _mm256_extracti128_si256(ymm31, 1),
            _mm256_extracti128_si256(ymm31, 0));
    __m128i xmm30 = _mm_xor_si128(
            _mm256_extracti128_si256(ymm30, 1),
            _mm256_extracti128_si256(ymm30, 0)); // T7

    __m128i t1 = xmm30;
    __m128i t2 = xmm31;

    __m128i tmp6 = _mm_srli_epi32(t2, 31);
    __m128i tmp7 = _mm_srli_epi32(t1, 31);
    t2 = _mm_slli_epi32(t2, 1);
    t1 = _mm_slli_epi32(t1, 1);

    __m128i tmp8 = _mm_srli_si128(tmp6, 12);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp6 = _mm_slli_si128(tmp6, 4);
    t2 = _mm_or_si128(t2, tmp6);
    t1 = _mm_or_si128(t1, tmp7);
    t1 = _mm_or_si128(t1, tmp8);

    //
    tmp6 = _mm_slli_epi32(t2, 31);
    tmp7 = _mm_slli_epi32(t2, 30);
    tmp8 = _mm_slli_epi32(t2, 25);

    tmp6 = _mm_xor_si128(tmp6, tmp7);
    tmp6 = _mm_xor_si128(tmp6, tmp8);
    tmp7 = _mm_srli_si128(tmp6, 4);
    tmp6 = _mm_slli_si128(tmp6, 12);
    t2 = _mm_xor_si128(t2, tmp6);

    __m128i tmp1 = _mm_srli_epi32(t2, 1);
    __m128i gh = _mm_srli_epi32(t2, 2);
    __m128i t3 = _mm_srli_epi32(t2, 7);
    tmp1 = _mm_xor_si128(tmp1, gh);
    tmp1 = _mm_xor_si128(tmp1, t3);
    tmp1 = _mm_xor_si128(tmp1, tmp7);

    t2 = _mm_xor_si128(t2, tmp1);
    t1 = _mm_xor_si128(t1, t2);

    return t1;
}

static inline void gfmul_512_reduce(__m512i GHw, __m512i HK, __m128i *res) {

    __m512i t1w, t2w, t3w;


    t1w = _mm512_clmulepi64_epi128(GHw, HK, 0x11);
    t2w = _mm512_clmulepi64_epi128(GHw, HK, 0x00);
    t3w = _mm512_clmulepi64_epi128(GHw, HK, 0x01);
    GHw = _mm512_clmulepi64_epi128(GHw, HK, 0x10);

    GHw = _mm512_xor_epi32(GHw, t3w);
    t3w = _mm512_bsrli_epi128(GHw, 8); // right 8 into T3
    GHw = _mm512_bslli_epi128(GHw, 8); // left 8 into GH
    t1w = _mm512_xor_epi32(t1w, t3w);
    GHw = _mm512_xor_epi32(GHw, t2w);


    *res = reduceWide(GHw, t1w);

}


static inline void gfmul_multi_reduce(
        const __m512i d0, const __m512i d1, const __m512i d2, const __m512i d3,
        const __m512i h0, const __m512i h1, const __m512i h2, const __m512i h3,
        __m128i *res) {



    __m512i high1, high2, low1, low2, med1, med2, tee1, tee2;
    __m512i high, low, med, tee;

    high1 = _mm512_clmulepi64_epi128(d3, h3, 0x11);
    low1 = _mm512_clmulepi64_epi128(d3, h3, 0x00);
    med1 = _mm512_clmulepi64_epi128(d3, h3, 0x01);
    tee1 = _mm512_clmulepi64_epi128(d3, h3, 0x10);

    high2 = _mm512_clmulepi64_epi128(d2, h2, 0x11);
    low2 = _mm512_clmulepi64_epi128(d2, h2, 0x00);
    med2 = _mm512_clmulepi64_epi128(d2, h2, 0x01);
    tee2 = _mm512_clmulepi64_epi128(d2, h2, 0x10);

    high = _mm512_xor_si512(high1, high2);
    low = _mm512_xor_si512(low1, low2);
    med = _mm512_xor_si512(med1, med2);
    tee = _mm512_xor_si512(tee1, tee2);

    high1 = _mm512_clmulepi64_epi128(d1, h1, 0x11);
    low1 = _mm512_clmulepi64_epi128(d1, h1, 0x00);
    med1 = _mm512_clmulepi64_epi128(d1, h1, 0x01);
    tee1 = _mm512_clmulepi64_epi128(d1, h1, 0x10);

    high2 = _mm512_clmulepi64_epi128(d0, h0, 0x11);
    low2 = _mm512_clmulepi64_epi128(d0, h0, 0x00);
    med2 = _mm512_clmulepi64_epi128(d0, h0, 0x01); //t3
    tee2 = _mm512_clmulepi64_epi128(d0, h0, 0x10);

    high = _mm512_ternarylogic_epi64(high, high1, high2, 0x96);
    low = _mm512_ternarylogic_epi64(low, low1, low2, 0x96);
    med = _mm512_ternarylogic_epi64(med, med1, med2, 0x96);
    tee = _mm512_ternarylogic_epi64(tee, tee1, tee2, 0x96);

    tee = _mm512_xor_epi32(tee, med);
    med = _mm512_bsrli_epi128(tee, 8);
    tee = _mm512_bslli_epi128(tee, 8);
    high = _mm512_xor_si512(high, med);
    tee = _mm512_xor_si512(tee, low);


    *res = reduceWide(tee, high);
}


static inline __m128i reduce(__m128i tee, __m128i high) {


    __m128i tmp6 = _mm_srli_epi32(tee, 31);
    __m128i tmp7 = _mm_srli_epi32(high, 31);
    tee = _mm_slli_epi32(tee, 1);
    high = _mm_slli_epi32(high, 1);

    __m128i tmp8 = _mm_srli_si128(tmp6, 12);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp6 = _mm_slli_si128(tmp6, 4);
    tee = _mm_or_si128(tee, tmp6);
    high = _mm_or_si128(high, tmp7);
    high = _mm_or_si128(high, tmp8);

    //
    tmp6 = _mm_slli_epi32(tee, 31);
    tmp7 = _mm_slli_epi32(tee, 30);
    tmp8 = _mm_slli_epi32(tee, 25);

    tmp6 = _mm_xor_si128(tmp6, tmp7);
    tmp6 = _mm_xor_si128(tmp6, tmp8);
    tmp7 = _mm_srli_si128(tmp6, 4);
    tmp6 = _mm_slli_si128(tmp6, 12);
    tee = _mm_xor_si128(tee, tmp6);

    __m128i tmp1 = _mm_srli_epi32(tee, 1);
    __m128i gh = _mm_srli_epi32(tee, 2);
    __m128i t3 = _mm_srli_epi32(tee, 7);
    tmp1 = _mm_xor_si128(tmp1, gh);
    tmp1 = _mm_xor_si128(tmp1, t3);
    tmp1 = _mm_xor_si128(tmp1, tmp7);

    tee = _mm_xor_si128(tee, tmp1);
    high = _mm_xor_si128(high, tee);


    return high;
}


/**
 * Apply encrypted counter to io0..3
 * @param io0 block 0
 * @param io1 block 1
 * @param io2 block 2
 * @param io3  block 3
 * @param ctr0s counter bit swapped 0
 * @param ctr1s counter bit swapped 1
 * @param ctr2s counter bit swapped 2
 * @param ctr3s counter bit swapped 3
 * @param num_rounds rounds
 */
static inline void apply_aes_no_reduction(
        __m512i *io0, __m512i *io1, __m512i *io2, __m512i *io3,
        __m512i ctr0s, __m512i ctr1s, __m512i ctr2s, __m512i ctr3s, __m128i *roundKeys,
        const int num_rounds) {


    int rounds;
    aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[0]);

    for (rounds = 1; rounds < num_rounds; rounds++) {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[rounds]);
    }

    aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[rounds]);

    *io0 = _mm512_xor_si512(ctr0s, *io0);
    *io1 = _mm512_xor_si512(ctr1s, *io1);
    *io2 = _mm512_xor_si512(ctr2s, *io2);
    *io3 = _mm512_xor_si512(ctr3s, *io3);
}


/**
 * Apply encrypted counter to io0..3 with interleaved reduction of i0..3
 *
 * @param io0 block 0
 * @param io1 block 1
 * @param io2 block 2
 * @param io3 block 3
 * @param i0 previous result block 0 bit swapped
 * @param i1 previous result block 1 bit swapped
 * @param i2 previous result block 2 bit swapped
 * @param i3 previous result block 3 bit swapped
 * @param h0 hash key 0
 * @param h1 hash key 1
 * @param h2 hash key 2
 * @param h3 hash key 3
 * @param ctr0s counter bit swapped 0
 * @param ctr1s counter bit swapped 1
 * @param ctr2s counter bit swapped 2
 * @param ctr3s counter bit swapped 3
 * @param roundKeys
 * @param num_rounds
 */
static inline void apply_aes_with_reduction(__m512i *io0, __m512i *io1, __m512i *io2, __m512i *io3,
                                     const __m512i *i0, const __m512i *i1, const __m512i *i2, const __m512i *i3,
                                     const __m512i h0, const __m512i h1, const __m512i h2, const __m512i h3,
                                     __m512i ctr0s, __m512i ctr1s, __m512i ctr2s, __m512i ctr3s, __m128i *roundKeys,
                                     __m128i *X, const int num_rounds) {

    __m512i high, med, low, tee, high1, med1, low1, tee1, high2, med2, low2, tee2;

    aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[0]);

    high1 = _mm512_clmulepi64_epi128(*i3, h3, 0x11);
    low1 = _mm512_clmulepi64_epi128(*i3, h3, 0x00);
    med1 = _mm512_clmulepi64_epi128(*i3, h3, 0x01);
    tee1 = _mm512_clmulepi64_epi128(*i3, h3, 0x10);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[1]);

    high2 = _mm512_clmulepi64_epi128(*i2, h2, 0x11);
    low2 = _mm512_clmulepi64_epi128(*i2, h2, 0x00);
    med2 = _mm512_clmulepi64_epi128(*i2, h2, 0x01);
    tee2 = _mm512_clmulepi64_epi128(*i2, h2, 0x10);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[2]);

    high = _mm512_xor_si512(high1, high2);
    low = _mm512_xor_si512(low1, low2);
    med = _mm512_xor_si512(med1, med2);
    tee = _mm512_xor_si512(tee1, tee2);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[3]);


    high1 = _mm512_clmulepi64_epi128(*i1, h1, 0x11);
    low1 = _mm512_clmulepi64_epi128(*i1, h1, 0x00);
    med1 = _mm512_clmulepi64_epi128(*i1, h1, 0x01);
    tee1 = _mm512_clmulepi64_epi128(*i1, h1, 0x10);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[4]);

    high2 = _mm512_clmulepi64_epi128(*i0, h0, 0x11);
    low2 = _mm512_clmulepi64_epi128(*i0, h0, 0x00);
    med2 = _mm512_clmulepi64_epi128(*i0, h0, 0x01);
    tee2 = _mm512_clmulepi64_epi128(*i0, h0, 0x10);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[5]);

    high = _mm512_ternarylogic_epi64(high, high1, high2, 0x96);
    low = _mm512_ternarylogic_epi64(low, low1, low2, 0x96);
    med = _mm512_ternarylogic_epi64(med, med1, med2, 0x96);
    tee = _mm512_ternarylogic_epi64(tee, tee1, tee2, 0x96);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[6]);

    tee = _mm512_xor_epi32(tee, med);
    med = _mm512_bsrli_epi128(tee, 8);
    tee = _mm512_bslli_epi128(tee, 8);
    high = _mm512_xor_si512(high, med);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[7]);

    tee = _mm512_xor_si512(tee, low);

    __m256i ymm31 = _mm256_xor_si256(
            _mm512_extracti64x4_epi64(tee, 1),
            _mm512_extracti64x4_epi64(tee, 0));
    __m256i ymm30 = _mm256_xor_si256(
            _mm512_extracti64x4_epi64(high, 1),
            _mm512_extracti64x4_epi64(high, 0));

    __m128i t2 = _mm_xor_si128(
            _mm256_extracti128_si256(ymm31, 1),
            _mm256_extracti128_si256(ymm31, 0));
    __m128i t1 = _mm_xor_si128(
            _mm256_extracti128_si256(ymm30, 1),
            _mm256_extracti128_si256(ymm30, 0)); // T7


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[8]);

    __m128i tmp6 = _mm_srli_epi32(t2, 31);
    __m128i tmp7 = _mm_srli_epi32(t1, 31);
    t2 = _mm_slli_epi32(t2, 1);
    t1 = _mm_slli_epi32(t1, 1);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[9]);

    __m128i tmp8 = _mm_srli_si128(tmp6, 12);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp6 = _mm_slli_si128(tmp6, 4);
    t2 = _mm_or_si128(t2, tmp6);


    if (num_rounds == 10) {
        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[10]);


        t1 = _mm_or_si128(t1, tmp7);
        t1 = _mm_or_si128(t1, tmp8);

        tmp6 = _mm_slli_epi32(t2, 31);
        tmp7 = _mm_slli_epi32(t2, 30);
        tmp8 = _mm_slli_epi32(t2, 25);

        tmp6 = _mm_xor_si128(tmp6, tmp7);
        tmp6 = _mm_xor_si128(tmp6, tmp8);
        tmp7 = _mm_srli_si128(tmp6, 4);
        tmp6 = _mm_slli_si128(tmp6, 12);
        t2 = _mm_xor_si128(t2, tmp6);

        __m128i tmp1 = _mm_srli_epi32(t2, 1);
        __m128i gh = _mm_srli_epi32(t2, 2);
        __m128i t3 = _mm_srli_epi32(t2, 7);
        tmp1 = _mm_xor_si128(tmp1, gh);
        tmp1 = _mm_xor_si128(tmp1, t3);
        tmp1 = _mm_xor_si128(tmp1, tmp7);

        t2 = _mm_xor_si128(t2, tmp1);
        *X = _mm_xor_si128(t1, t2);

    } else if (num_rounds == 12) {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[10]);

        t1 = _mm_or_si128(t1, tmp7);
        t1 = _mm_or_si128(t1, tmp8);

        tmp6 = _mm_slli_epi32(t2, 31);
        tmp7 = _mm_slli_epi32(t2, 30);
        tmp8 = _mm_slli_epi32(t2, 25);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[11]);

        tmp6 = _mm_xor_si128(tmp6, tmp7);
        tmp6 = _mm_xor_si128(tmp6, tmp8);
        tmp7 = _mm_srli_si128(tmp6, 4);
        tmp6 = _mm_slli_si128(tmp6, 12);
        t2 = _mm_xor_si128(t2, tmp6);

        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[12]);


        __m128i tmp1 = _mm_srli_epi32(t2, 1);
        __m128i gh = _mm_srli_epi32(t2, 2);
        __m128i t3 = _mm_srli_epi32(t2, 7);
        tmp1 = _mm_xor_si128(tmp1, gh);
        tmp1 = _mm_xor_si128(tmp1, t3);
        tmp1 = _mm_xor_si128(tmp1, tmp7);

        t2 = _mm_xor_si128(t2, tmp1);
        *X = _mm_xor_si128(t1, t2);


    } else {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[10]);

        t1 = _mm_or_si128(t1, tmp7);
        t1 = _mm_or_si128(t1, tmp8);

        tmp6 = _mm_slli_epi32(t2, 31);
        tmp7 = _mm_slli_epi32(t2, 30);


        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[11]);

        tmp8 = _mm_slli_epi32(t2, 25);
        tmp6 = _mm_xor_si128(tmp6, tmp7);
        tmp6 = _mm_xor_si128(tmp6, tmp8);
        tmp7 = _mm_srli_si128(tmp6, 4);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[12]);

        tmp6 = _mm_slli_si128(tmp6, 12);
        t2 = _mm_xor_si128(t2, tmp6);
        __m128i tmp1 = _mm_srli_epi32(t2, 1);
        __m128i gh = _mm_srli_epi32(t2, 2);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[13]);

        __m128i t3 = _mm_srli_epi32(t2, 7);
        tmp1 = _mm_xor_si128(tmp1, gh);
        tmp1 = _mm_xor_si128(tmp1, t3);
        tmp1 = _mm_xor_si128(tmp1, tmp7);

        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[14]);

        t2 = _mm_xor_si128(t2, tmp1);
        *X = _mm_xor_si128(t1, t2);


    }

    *io0 = _mm512_xor_si512(ctr0s, *io0);
    *io1 = _mm512_xor_si512(ctr1s, *io1);
    *io2 = _mm512_xor_si512(ctr2s, *io2);
    *io3 = _mm512_xor_si512(ctr3s, *io3);


}


static inline void apply_aes_with_reduction_dec(__m512i *io0, __m512i *io1, __m512i *io2, __m512i *io3,
                                         const __m512i h0, const __m512i h1, const __m512i h2, const __m512i h3,
                                         __m512i ctr0s, __m512i ctr1s, __m512i ctr2s, __m512i ctr3s, __m128i *roundKeys,
                                         __m128i *X, const int num_rounds) {

    __m512i high, med, low, tee, high1, med1, low1, tee1, high2, med2, low2, tee2, i0;

    aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[0]);



    i0 = _mm512_shuffle_epi8(*io3, *BSWAP_MASK_512);

    high1 = _mm512_clmulepi64_epi128(i0, h3, 0x11);
    low1 = _mm512_clmulepi64_epi128(i0, h3, 0x00);
    med1 = _mm512_clmulepi64_epi128(i0, h3, 0x01);
    tee1 = _mm512_clmulepi64_epi128(i0, h3, 0x10);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[1]);

    i0 = _mm512_shuffle_epi8(*io2, *BSWAP_MASK_512);
    high2 = _mm512_clmulepi64_epi128(i0, h2, 0x11);
    low2 = _mm512_clmulepi64_epi128(i0, h2, 0x00);
    med2 = _mm512_clmulepi64_epi128(i0, h2, 0x01);
    tee2 = _mm512_clmulepi64_epi128(i0, h2, 0x10);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[2]);

    high = _mm512_xor_si512(high1, high2);
    low = _mm512_xor_si512(low1, low2);
    med = _mm512_xor_si512(med1, med2);
    tee = _mm512_xor_si512(tee1, tee2);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[3]);


    i0 = _mm512_shuffle_epi8(*io1, *BSWAP_MASK_512);
    high1 = _mm512_clmulepi64_epi128(i0, h1, 0x11);
    low1 = _mm512_clmulepi64_epi128(i0, h1, 0x00);
    med1 = _mm512_clmulepi64_epi128(i0, h1, 0x01);
    tee1 = _mm512_clmulepi64_epi128(i0, h1, 0x10);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[4]);


    i0 = _mm512_xor_si512(_mm512_castsi128_si512(*X), _mm512_shuffle_epi8(*io0, *BSWAP_MASK_512));
    high2 = _mm512_clmulepi64_epi128(i0, h0, 0x11);
    low2 = _mm512_clmulepi64_epi128(i0, h0, 0x00);
    med2 = _mm512_clmulepi64_epi128(i0, h0, 0x01);
    tee2 = _mm512_clmulepi64_epi128(i0, h0, 0x10);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[5]);

    high = _mm512_ternarylogic_epi64(high, high1, high2, 0x96);
    low = _mm512_ternarylogic_epi64(low, low1, low2, 0x96);
    med = _mm512_ternarylogic_epi64(med, med1, med2, 0x96);
    tee = _mm512_ternarylogic_epi64(tee, tee1, tee2, 0x96);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[6]);

    tee = _mm512_xor_epi32(tee, med);
    med = _mm512_bsrli_epi128(tee, 8);
    tee = _mm512_bslli_epi128(tee, 8);
    high = _mm512_xor_si512(high, med);
    tee = _mm512_xor_si512(tee, low);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[7]);

    __m256i ymm31 = _mm256_xor_si256(
            _mm512_extracti64x4_epi64(tee, 1),
            _mm512_extracti64x4_epi64(tee, 0));
    __m256i ymm30 = _mm256_xor_si256(
            _mm512_extracti64x4_epi64(high, 1),
            _mm512_extracti64x4_epi64(high, 0));

    __m128i t2 = _mm_xor_si128(
            _mm256_extracti128_si256(ymm31, 1),
            _mm256_extracti128_si256(ymm31, 0));
    __m128i t1 = _mm_xor_si128(
            _mm256_extracti128_si256(ymm30, 1),
            _mm256_extracti128_si256(ymm30, 0)); // T7


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[8]);
    __m128i tmp6 = _mm_srli_epi32(t2, 31);
    __m128i tmp7 = _mm_srli_epi32(t1, 31);
    t2 = _mm_slli_epi32(t2, 1);
    t1 = _mm_slli_epi32(t1, 1);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[9]);

    __m128i tmp8 = _mm_srli_si128(tmp6, 12);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp6 = _mm_slli_si128(tmp6, 4);
    t2 = _mm_or_si128(t2, tmp6);
    t1 = _mm_or_si128(t1, tmp7);


    if (num_rounds == 10) {
        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[10]);

        t1 = _mm_or_si128(t1, tmp8);
        tmp6 = _mm_slli_epi32(t2, 31);
        tmp7 = _mm_slli_epi32(t2, 30);
        tmp8 = _mm_slli_epi32(t2, 25);

        tmp6 = _mm_xor_si128(tmp6, tmp7);
        tmp6 = _mm_xor_si128(tmp6, tmp8);
        tmp7 = _mm_srli_si128(tmp6, 4);
        tmp6 = _mm_slli_si128(tmp6, 12);
        t2 = _mm_xor_si128(t2, tmp6);

        __m128i tmp1 = _mm_srli_epi32(t2, 1);
        __m128i gh = _mm_srli_epi32(t2, 2);
        __m128i t3 = _mm_srli_epi32(t2, 7);
        tmp1 = _mm_xor_si128(tmp1, gh);
        tmp1 = _mm_xor_si128(tmp1, t3);
        tmp1 = _mm_xor_si128(tmp1, tmp7);

        t2 = _mm_xor_si128(t2, tmp1);
        *X = _mm_xor_si128(t1, t2);

    } else if (num_rounds == 12) {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[10]);

        t1 = _mm_or_si128(t1, tmp8);
        tmp6 = _mm_slli_epi32(t2, 31);
        tmp7 = _mm_slli_epi32(t2, 30);
        tmp8 = _mm_slli_epi32(t2, 25);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[11]);

        tmp6 = _mm_xor_si128(tmp6, tmp7);
        tmp6 = _mm_xor_si128(tmp6, tmp8);
        tmp7 = _mm_srli_si128(tmp6, 4);
        tmp6 = _mm_slli_si128(tmp6, 12);
        t2 = _mm_xor_si128(t2, tmp6);

        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[12]);

        __m128i tmp1 = _mm_srli_epi32(t2, 1);
        __m128i gh = _mm_srli_epi32(t2, 2);
        __m128i t3 = _mm_srli_epi32(t2, 7);
        tmp1 = _mm_xor_si128(tmp1, gh);
        tmp1 = _mm_xor_si128(tmp1, t3);
        tmp1 = _mm_xor_si128(tmp1, tmp7);

        t2 = _mm_xor_si128(t2, tmp1);
        *X = _mm_xor_si128(t1, t2);

    } else {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[10]);

        t1 = _mm_or_si128(t1, tmp8);
        tmp6 = _mm_slli_epi32(t2, 31);
        tmp7 = _mm_slli_epi32(t2, 30);
        tmp8 = _mm_slli_epi32(t2, 25);


        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[11]);

        tmp6 = _mm_xor_si128(tmp6, tmp7);
        tmp6 = _mm_xor_si128(tmp6, tmp8);
        tmp7 = _mm_srli_si128(tmp6, 4);
        tmp6 = _mm_slli_si128(tmp6, 12);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[12]);

        t2 = _mm_xor_si128(t2, tmp6);
        __m128i tmp1 = _mm_srli_epi32(t2, 1);
        __m128i gh = _mm_srli_epi32(t2, 2);
        __m128i t3 = _mm_srli_epi32(t2, 7);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[13]);

        tmp1 = _mm_xor_si128(tmp1, gh);
        tmp1 = _mm_xor_si128(tmp1, t3);
        tmp1 = _mm_xor_si128(tmp1, tmp7);
        t2 = _mm_xor_si128(t2, tmp1);

        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[14]);

        *X = _mm_xor_si128(t1, t2);
    }

    *io0 = _mm512_xor_si512(ctr0s, *io0);
    *io1 = _mm512_xor_si512(ctr1s, *io1);
    *io2 = _mm512_xor_si512(ctr2s, *io2);
    *io3 = _mm512_xor_si512(ctr3s, *io3);



}

static inline void gfmul(__m128i a, __m128i b, __m128i *res) {
    __m128i tmp1, t2, gh, t3, t1, tmp6, tmp7, tmp8;

    t1 = _mm_clmulepi64_si128(a, b, 0x11);
    t2 = _mm_clmulepi64_si128(a, b, 0x00);
    t3 = _mm_clmulepi64_si128(a, b, 0x01);
    gh = _mm_clmulepi64_si128(a, b, 0x10);


    gh = _mm_xor_si128(gh, t3);
    t3 = _mm_slli_si128(gh, 8);
    gh = _mm_srli_si128(gh, 8);
    t2 = _mm_xor_si128(t2, t3);
    t1 = _mm_xor_si128(t1, gh);  // t1 is the result.


    tmp6 = _mm_srli_epi32(t2, 31);
    tmp7 = _mm_srli_epi32(t1, 31);
    t2 = _mm_slli_epi32(t2, 1);
    t1 = _mm_slli_epi32(t1, 1);

    tmp8 = _mm_srli_si128(tmp6, 12);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp6 = _mm_slli_si128(tmp6, 4);
    t2 = _mm_or_si128(t2, tmp6);
    t1 = _mm_or_si128(t1, tmp7);
    t1 = _mm_or_si128(t1, tmp8);

    //
    tmp6 = _mm_slli_epi32(t2, 31);
    tmp7 = _mm_slli_epi32(t2, 30);
    tmp8 = _mm_slli_epi32(t2, 25);

    tmp6 = _mm_xor_si128(tmp6, tmp7);
    tmp6 = _mm_xor_si128(tmp6, tmp8);
    tmp7 = _mm_srli_si128(tmp6, 4);
    tmp6 = _mm_slli_si128(tmp6, 12);
    t2 = _mm_xor_si128(t2, tmp6);

    tmp1 = _mm_srli_epi32(t2, 1);
    gh = _mm_srli_epi32(t2, 2);
    t3 = _mm_srli_epi32(t2, 7);
    tmp1 = _mm_xor_si128(tmp1, gh);
    tmp1 = _mm_xor_si128(tmp1, t3);
    tmp1 = _mm_xor_si128(tmp1, tmp7);

    t2 = _mm_xor_si128(t2, tmp1);
    t1 = _mm_xor_si128(t1, t2);

    *res = t1;
}


#endif //BC_FIPS_C_GCMHASH512_H
