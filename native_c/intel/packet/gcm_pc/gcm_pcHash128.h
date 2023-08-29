//


#ifndef BC_FIPS_C_GCMHASH128_H
#define BC_FIPS_C_GCMHASH128_H

#include <immintrin.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>


static const int8_t __attribute__ ((aligned(16))) _one[16] = {
        00,00,00,00,00,00,00,00,01,00,00,00,00,00,00,00
};

static const __m128i *ONE = ((__m128i *) _one);

static const int8_t __attribute__ ((aligned(16))) _bswap_epi64[16] = {
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8
};

static const __m128i *BSWAP_EPI64 = ((__m128i *) _bswap_epi64);


static const int8_t __attribute__ ((aligned(16))) _bswap_mask[16] = {
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,0
};

static const __m128i *BSWAP_MASK = ((__m128i *) _bswap_mask);


static inline void aes_xor(
        __m128i *d0, __m128i *d1, __m128i *d2, __m128i *d3,
        const __m128i rk) {
    *d0 = _mm_xor_si128(*d0, rk);
    *d1 = _mm_xor_si128(*d1, rk);
    *d2 = _mm_xor_si128(*d2, rk);
    *d3 = _mm_xor_si128(*d3, rk);
}


static inline void aes_enc(
        __m128i *d0, __m128i *d1, __m128i *d2, __m128i *d3,
        const __m128i rk) {
    *d0 = _mm_aesenc_si128(*d0, rk);
    *d1 = _mm_aesenc_si128(*d1, rk);
    *d2 = _mm_aesenc_si128(*d2, rk);
    *d3 = _mm_aesenc_si128(*d3, rk);
}

static inline void aes_enc_last(
        __m128i *d0, __m128i *d1, __m128i *d2, __m128i *d3,
        const __m128i rk) {
    *d0 = _mm_aesenclast_si128(*d0, rk);
    *d1 = _mm_aesenclast_si128(*d1, rk);
    *d2 = _mm_aesenclast_si128(*d2, rk);
    *d3 = _mm_aesenclast_si128(*d3, rk);
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


static inline void gfmul_multi_reduce(
        const __m128i d0, const __m128i d1, const __m128i d2, const __m128i d3,
        const __m128i h0, const __m128i h1, const __m128i h2, const __m128i h3,
        __m128i *res) {

    __m128i high2, low2, med2, tee2;
    __m128i high, low, med, tee;

    high = _mm_clmulepi64_si128(d3, h3, 0x11);
    low = _mm_clmulepi64_si128(d3, h3, 0x00);
    med = _mm_clmulepi64_si128(d3, h3, 0x01);
    tee = _mm_clmulepi64_si128(d3, h3, 0x10);


    high2 = _mm_clmulepi64_si128(d2, h2, 0x11);
    low2 = _mm_clmulepi64_si128(d2, h2, 0x00);
    med2 = _mm_clmulepi64_si128(d2, h2, 0x01);
    tee2 = _mm_clmulepi64_si128(d2, h2, 0x10);

    high = _mm_xor_si128(high, high2);
    low = _mm_xor_si128(low, low2);
    med = _mm_xor_si128(med, med2);
    tee = _mm_xor_si128(tee, tee2);


    high2 = _mm_clmulepi64_si128(d1, h1, 0x11);
    low2 = _mm_clmulepi64_si128(d1, h1, 0x00);
    med2 = _mm_clmulepi64_si128(d1, h1, 0x01);
    tee2 = _mm_clmulepi64_si128(d1, h1, 0x10);

    high = _mm_xor_si128(high, high2);
    low = _mm_xor_si128(low, low2);
    med = _mm_xor_si128(med, med2);
    tee = _mm_xor_si128(tee, tee2);


    high2 = _mm_clmulepi64_si128(d0, h0, 0x11);
    low2 = _mm_clmulepi64_si128(d0, h0, 0x00);
    med2 = _mm_clmulepi64_si128(d0, h0, 0x01);
    tee2 = _mm_clmulepi64_si128(d0, h0, 0x10);

    high = _mm_xor_si128(high, high2);
    low = _mm_xor_si128(low, low2);
    med = _mm_xor_si128(med, med2);
    tee = _mm_xor_si128(tee, tee2);

    tee = _mm_xor_si128(tee, med);
    med = _mm_slli_si128(tee, 8);
    tee = _mm_srli_si128(tee, 8);
    low = _mm_xor_si128(low, med);
    high = _mm_xor_si128(high, tee);


    *res = reduce(low, high);

}


///**
// * xor X into A and mul reduce
// * @param a
// * @param hk hash keys in reverse order of exponentiation.
// * @param X result of last round of reduction
// */
//inline void xor_reduce(__m512i a, __m512i hk, __m128i &X) {
//    a = _mm512_xor_si512(a, _mm512_castsi128_si512(X));
//    gfmul_512_reduce(a, hk, X);
//}

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
        __m128i *io0, __m128i *io1, __m128i *io2, __m128i *io3,
        __m128i ctr0s, __m128i ctr1s, __m128i ctr2s, __m128i ctr3s, __m128i *roundKeys,
        const int num_rounds) {


    int rounds;
    aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[0]);

    for (rounds = 1; rounds < num_rounds; rounds++) {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[rounds]);
    }

    aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[rounds]);

    *io0 = _mm_xor_si128(ctr0s, *io0);
    *io1 = _mm_xor_si128(ctr1s, *io1);
    *io2 = _mm_xor_si128(ctr2s, *io2);
    *io3 = _mm_xor_si128(ctr3s, *io3);
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
static inline void apply_aes_with_reduction(__m128i *io0, __m128i *io1, __m128i *io2, __m128i *io3,
                                     const __m128i i0, const __m128i i1, const __m128i i2, const __m128i i3,
                                     const __m128i h0, const __m128i h1, const __m128i h2, const __m128i h3,
                                     __m128i ctr0s, __m128i ctr1s, __m128i ctr2s, __m128i ctr3s, __m128i *roundKeys,
                                     __m128i *X, const int num_rounds) {

    __m128i high, med, low, tee, high2, med2, low2, tee2;

    aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[0]);

    high = _mm_clmulepi64_si128(i3, h3, 0x11);
    low = _mm_clmulepi64_si128(i3, h3, 0x00);
    med = _mm_clmulepi64_si128(i3, h3, 0x01);
    tee = _mm_clmulepi64_si128(i3, h3, 0x10);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[1]);

    high2 = _mm_clmulepi64_si128(i2, h2, 0x11);
    low2 = _mm_clmulepi64_si128(i2, h2, 0x00);
    med2 = _mm_clmulepi64_si128(i2, h2, 0x01);
    tee2 = _mm_clmulepi64_si128(i2, h2, 0x10);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[2]);

    high = _mm_xor_si128(high, high2);
    low = _mm_xor_si128(low, low2);
    med = _mm_xor_si128(med, med2);
    tee = _mm_xor_si128(tee, tee2);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[3]);

    high2 = _mm_clmulepi64_si128(i1, h1, 0x11);
    low2 = _mm_clmulepi64_si128(i1, h1, 0x00);
    med2 = _mm_clmulepi64_si128(i1, h1, 0x01);
    tee2 = _mm_clmulepi64_si128(i1, h1, 0x10);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[4]);
    high = _mm_xor_si128(high, high2);
    low = _mm_xor_si128(low, low2);
    med = _mm_xor_si128(med, med2);
    tee = _mm_xor_si128(tee, tee2);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[5]);

    high2 = _mm_clmulepi64_si128(i0, h0, 0x11);
    low2 = _mm_clmulepi64_si128(i0, h0, 0x00);
    med2 = _mm_clmulepi64_si128(i0, h0, 0x01);
    tee2 = _mm_clmulepi64_si128(i0, h0, 0x10);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[6]);

    high = _mm_xor_si128(high, high2);
    low = _mm_xor_si128(low, low2);
    med = _mm_xor_si128(med, med2);
    tee = _mm_xor_si128(tee, tee2);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[7]);

    tee = _mm_xor_si128(tee, med);
    med = _mm_srli_si128(tee, 8);
    tee = _mm_slli_si128(tee, 8);
    high = _mm_xor_si128(high, med);
    tee = _mm_xor_si128(tee, low);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[8]);

    __m128i tmp6 = _mm_srli_epi32(tee, 31);
    __m128i tmp7 = _mm_srli_epi32(high, 31);
    tee = _mm_slli_epi32(tee, 1);
    high = _mm_slli_epi32(high, 1);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[9]);

    __m128i tmp8 = _mm_srli_si128(tmp6, 12);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp6 = _mm_slli_si128(tmp6, 4);
    tee = _mm_or_si128(tee, tmp6);


    if (num_rounds == 10) {
        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[10]);

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


    } else if (num_rounds == 12) {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[10]);

        high = _mm_or_si128(high, tmp7);
        high = _mm_or_si128(high, tmp8);
        tmp6 = _mm_slli_epi32(tee, 31);
        tmp7 = _mm_slli_epi32(tee, 30);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[11]);

        tmp8 = _mm_slli_epi32(tee, 25);
        tmp6 = _mm_xor_si128(tmp6, tmp7);
        tmp6 = _mm_xor_si128(tmp6, tmp8);
        tmp7 = _mm_srli_si128(tmp6, 4);

        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[12]);

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

    } else {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[10]);

        high = _mm_or_si128(high, tmp7);
        high = _mm_or_si128(high, tmp8);
        tmp6 = _mm_slli_epi32(tee, 31);
        tmp7 = _mm_slli_epi32(tee, 30);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[11]);

        tmp8 = _mm_slli_epi32(tee, 25);
        tmp6 = _mm_xor_si128(tmp6, tmp7);
        tmp6 = _mm_xor_si128(tmp6, tmp8);
        tmp7 = _mm_srli_si128(tmp6, 4);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[12]);

        tmp6 = _mm_slli_si128(tmp6, 12);
        tee = _mm_xor_si128(tee, tmp6);

        __m128i tmp1 = _mm_srli_epi32(tee, 1);
        __m128i gh = _mm_srli_epi32(tee, 2);


        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[13]);

        __m128i t3 = _mm_srli_epi32(tee, 7);
        tmp1 = _mm_xor_si128(tmp1, gh);
        tmp1 = _mm_xor_si128(tmp1, t3);
        tmp1 = _mm_xor_si128(tmp1, tmp7);

        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[14]);

        tee = _mm_xor_si128(tee, tmp1);
        high = _mm_xor_si128(high, tee);
    }

    *io0 = _mm_xor_si128(ctr0s, *io0);
    *io1 = _mm_xor_si128(ctr1s, *io1);
    *io2 = _mm_xor_si128(ctr2s, *io2);
    *io3 = _mm_xor_si128(ctr3s, *io3);

    *X = high;

}


/**
 * Decryption orientated with reduction being performed on the input values interleaved with mask generation.
 * @param io0 Input / Output 0
 * @param io1 Input / Output 1
 * @param io2 Input / Output 2
 * @param io3 Input / Output 3
 * @param h0 Exponential Hash Key 0
 * @param h1 Exponential Hash Key 1
 * @param h2 Exponential Hash Key 2
 * @param h3 Exponential Hash Key 3
 * @param ctr0s Counter 0
 * @param ctr1s Counter 1
 * @param ctr2s Counter 2
 * @param ctr3s Counter 3
 * @param roundKeys  Round Keys
 * @param X GHASH running value, that will be updated.
 * @param num_rounds  number of rounds
 */
static inline void apply_aes_with_reduction_dec(__m128i *io0, __m128i *io1, __m128i *io2, __m128i *io3,
                                         const __m128i h0, const __m128i h1, const __m128i h2, const __m128i h3,
                                         __m128i ctr0s, __m128i ctr1s, __m128i ctr2s, __m128i ctr3s, __m128i *roundKeys,
                                         __m128i *X, const int num_rounds) {

    __m128i high, med, low, tee, high1, med1, low1, tee1, high2, med2, low2, tee2, i0;

    aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[0]));

    i0 = _mm_shuffle_epi8(*io3, *BSWAP_MASK);

    high = _mm_clmulepi64_si128(i0, h3, 0x11);
    low = _mm_clmulepi64_si128(i0, h3, 0x00);
    med = _mm_clmulepi64_si128(i0, h3, 0x01);
    tee = _mm_clmulepi64_si128(i0, h3, 0x10);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[1]));

    i0 = _mm_shuffle_epi8(*io2, *BSWAP_MASK);
    high2 = _mm_clmulepi64_si128(i0, h2, 0x11);
    low2 = _mm_clmulepi64_si128(i0, h2, 0x00);
    med2 = _mm_clmulepi64_si128(i0, h2, 0x01);
    tee2 = _mm_clmulepi64_si128(i0, h2, 0x10);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[2]));

    high = _mm_xor_si128(high, high2);
    low = _mm_xor_si128(low, low2);
    med = _mm_xor_si128(med, med2);
    tee = _mm_xor_si128(tee, tee2);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[3]));


    i0 = _mm_shuffle_epi8(*io1, *BSWAP_MASK);
    high2 = _mm_clmulepi64_si128(i0, h1, 0x11);
    low2 = _mm_clmulepi64_si128(i0, h1, 0x00);
    med2 = _mm_clmulepi64_si128(i0, h1, 0x01);
    tee2 = _mm_clmulepi64_si128(i0, h1, 0x10);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[4]));

    high = _mm_xor_si128(high, high2);
    low = _mm_xor_si128(low, low2);
    med = _mm_xor_si128(med, med2);
    tee = _mm_xor_si128(tee, tee2);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[5]));


    i0 = _mm_xor_si128(*X, _mm_shuffle_epi8(*io0, *BSWAP_MASK));
    high2 = _mm_clmulepi64_si128(i0, h0, 0x11);
    low2 = _mm_clmulepi64_si128(i0, h0, 0x00);
    med2 = _mm_clmulepi64_si128(i0, h0, 0x01);
    tee2 = _mm_clmulepi64_si128(i0, h0, 0x10);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[6]));

    high = _mm_xor_si128(high, high2);
    low = _mm_xor_si128(low, low2);
    med = _mm_xor_si128(med, med2);
    tee = _mm_xor_si128(tee, tee2);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[7]));

    tee = _mm_xor_si128(tee, med);
    med = _mm_srli_si128(tee, 8);
    tee = _mm_slli_si128(tee, 8);
    high = _mm_xor_si128(high, med); // t1
    tee = _mm_xor_si128(tee, low); // t2



    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[8]));

    __m128i tmp6 = _mm_srli_epi32(tee, 31);
    __m128i tmp7 = _mm_srli_epi32(high, 31);
    tee = _mm_slli_epi32(tee, 1);
    high = _mm_slli_epi32(high, 1);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[9]));

    __m128i tmp8 = _mm_srli_si128(tmp6, 12);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp6 = _mm_slli_si128(tmp6, 4);
    tee = _mm_or_si128(tee, tmp6);
    high = _mm_or_si128(high, tmp7);
    high = _mm_or_si128(high, tmp8);

    if (num_rounds == 10) {
        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[10]));
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
    } else if (num_rounds == 12) {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[10]));
        tmp6 = _mm_slli_epi32(tee, 31);
        tmp7 = _mm_slli_epi32(tee, 30);
        tmp8 = _mm_slli_epi32(tee, 25);

        tmp6 = _mm_xor_si128(tmp6, tmp7);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[11]));
        tmp6 = _mm_xor_si128(tmp6, tmp8);
        tmp7 = _mm_srli_si128(tmp6, 4);
        tmp6 = _mm_slli_si128(tmp6, 12);
        tee = _mm_xor_si128(tee, tmp6);
        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[12]));
        __m128i tmp1 = _mm_srli_epi32(tee, 1);
        __m128i gh = _mm_srli_epi32(tee, 2);
        __m128i t3 = _mm_srli_epi32(tee, 7);
        tmp1 = _mm_xor_si128(tmp1, gh);
        tmp1 = _mm_xor_si128(tmp1, t3);
        tmp1 = _mm_xor_si128(tmp1, tmp7);

        tee = _mm_xor_si128(tee, tmp1);
        high = _mm_xor_si128(high, tee);

    } else {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[10]));
        tmp6 = _mm_slli_epi32(tee, 31);
        tmp7 = _mm_slli_epi32(tee, 30);
        tmp8 = _mm_slli_epi32(tee, 25);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[11]));
        tmp6 = _mm_xor_si128(tmp6, tmp7);
        tmp6 = _mm_xor_si128(tmp6, tmp8);
        tmp7 = _mm_srli_si128(tmp6, 4);
        tmp6 = _mm_slli_si128(tmp6, 12);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[12]));
        tee = _mm_xor_si128(tee, tmp6);
        __m128i tmp1 = _mm_srli_epi32(tee, 1);
        __m128i gh = _mm_srli_epi32(tee, 2);
        __m128i t3 = _mm_srli_epi32(tee, 7);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[13]));
        tmp1 = _mm_xor_si128(tmp1, gh);
        tmp1 = _mm_xor_si128(tmp1, t3);
        tmp1 = _mm_xor_si128(tmp1, tmp7);

        tee = _mm_xor_si128(tee, tmp1);
        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, (roundKeys[14]));
        high = _mm_xor_si128(high, tee);

    }

    *io0 = _mm_xor_si128(ctr0s, *io0);
    *io1 = _mm_xor_si128(ctr1s, *io1);
    *io2 = _mm_xor_si128(ctr2s, *io2);
    *io3 = _mm_xor_si128(ctr3s, *io3);

    *X = high;

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


#endif //BC_FIPS_C_GCMHASH128_H
