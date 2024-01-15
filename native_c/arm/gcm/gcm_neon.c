//
//
//

#ifdef __APPLE__

#include <libc.h>

#else
#include <stdlib.h>
#include <memory.h>
#endif

#include "gcm.h"
#include "gcm_hash.h"


static inline uint8x16_t reduce(uint32x4_t tee, uint32x4_t high) {
    uint32x4_t tmp6 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 31);
    uint32x4_t tmp7 = vsriq_n_u32(vreinterpretq_u32_u8(zero), high, 31);
    tee = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 1);
    high = vsliq_n_u32(vreinterpretq_u32_u8(zero), high, 1);


    uint32x4_t tmp8 = vreinterpretq_u32_u8( vextq_u8(vreinterpretq_u8_u32(tmp6), zero, 12));
    tmp7 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp7), 12));
    tmp6 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp6), 12));
    tee = vorrq_u32(tee, tmp6);
    high = vorrq_u32(high, tmp7);
    high = vorrq_u32(high, tmp8);

    tmp6 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 31);
    tmp7 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 30);
    tmp8 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 25);

    tmp6 = veorq_u32(tmp6, tmp7);
    tmp6 = veorq_u32(tmp6, tmp8);
    tmp7 = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tmp6), zero, 4));
    tmp6 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp6), 4));
    tee = veorq_u32(tee, tmp6);

    uint32x4_t tmp1 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 1);
    uint32x4_t gh = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 2);
    uint32x4_t t3 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 7);

    tmp1 = veorq_u32(tmp1, gh);
    tmp1 = veorq_u32(tmp1, t3);
    tmp1 = veorq_u32(tmp1, tmp7);

    tee = veorq_u32(tee, tmp1);
    return vreinterpretq_u8_u32( veorq_u32(high, tee));

}

uint8x16_t gfmul_multi_reduce(
        const poly64x2_t d0, const poly64x2_t d1, const poly64x2_t d2, const poly64x2_t d3,
        const poly64x2_t h0, const poly64x2_t h1, const poly64x2_t h2, const poly64x2_t h3) {

    uint32x4_t high2, low2, med2, tee2;
    uint32x4_t high, low, med, tee;

    high = vreinterpretq_u32_p128(vmull_high_p64(d3, h3));
    low = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(d3), (poly64_t) vget_low_p64(h3)));
    med = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(d3), (poly64_t) vget_low_p64(h3)));
    tee = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(d3), (poly64_t) vget_high_p64(h3)));


    high2 = vreinterpretq_u32_p128(vmull_high_p64(d2, h2));
    low2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(d2), (poly64_t) vget_low_p64(h2)));
    med2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(d2), (poly64_t) vget_low_p64(h2)));
    tee2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(d2), (poly64_t) vget_high_p64(h2)));

    high = veorq_u32(high, high2);
    low = veorq_u32(low, low2);
    med = veorq_u32(med, med2);
    tee = veorq_u32(tee, tee2);

    high2 = vreinterpretq_u32_p128(vmull_high_p64(d1, h1));
    low2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(d1), (poly64_t) vget_low_p64(h1)));
    med2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(d1), (poly64_t) vget_low_p64(h1)));
    tee2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(d1), (poly64_t) vget_high_p64(h1)));

    high = veorq_u32(high, high2);
    low = veorq_u32(low, low2);
    med = veorq_u32(med, med2);
    tee = veorq_u32(tee, tee2);

    high2 = vreinterpretq_u32_p128(vmull_high_p64(d0, h0));
    low2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(d0), (poly64_t) vget_low_p64(h0)));
    med2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(d0), (poly64_t) vget_low_p64(h0)));
    tee2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(d0), (poly64_t) vget_high_p64(h0)));

    high = veorq_u32(high, high2);
    low = veorq_u32(low, low2);
    med = veorq_u32(med, med2);
    tee = veorq_u32(tee, tee2);

    tee = veorq_u32(tee, med);
    med = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tee), 8)); //vget_low_p64(gh);
    tee = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tee), zero, 8)); //vget_low_p64(gh);
    low = veorq_u32(low, med);
    high = veorq_u32(high, tee);

    return reduce(low, high);


}


static inline void aes_xor(uint8x16_t *d0, uint8x16_t *d1, uint8x16_t *d2, uint8x16_t *d3, const uint8x16_t rk) {
    *d0 = veorq_u8(*d0, rk);
    *d1 = veorq_u8(*d1, rk);
    *d2 = veorq_u8(*d2, rk);
    *d3 = veorq_u8(*d3, rk);
}


static inline void aes_enc(uint8x16_t *d0, uint8x16_t *d1, uint8x16_t *d2, uint8x16_t *d3, const uint8x16_t rk) {
    *d0 = vaeseq_u8(*d0, rk);
    *d0 = vaesmcq_u8(*d0);
    *d1 = vaeseq_u8(*d1, rk);
    *d1 = vaesmcq_u8(*d1);
    *d2 = vaeseq_u8(*d2, rk);
    *d2 = vaesmcq_u8(*d2);
    *d3 = vaeseq_u8(*d3, rk);
    *d3 = vaesmcq_u8(*d3);
}

static inline void aes_enc_last(
        uint8x16_t *d0, uint8x16_t *d1, uint8x16_t *d2, uint8x16_t *d3,
        const uint8x16_t rk) {
    *d0 = vaeseq_u8(*d0, rk);
    *d1 = vaeseq_u8(*d1, rk);
    *d2 = vaeseq_u8(*d2, rk);
    *d3 = vaeseq_u8(*d3, rk);
}


static inline void apply_aes_no_reduction(
        uint8x16_t *io0, uint8x16_t *io1, uint8x16_t *io2, uint8x16_t *io3,
        uint8x16_t ctr0s, uint8x16_t ctr1s, uint8x16_t ctr2s, uint8x16_t ctr3s, uint8x16_t *roundKeys,
        const size_t num_rounds) {

    const uint8x16_t r0 = roundKeys[0];
    const uint8x16_t r1 = roundKeys[1];
    const uint8x16_t r2 = roundKeys[2];
    const uint8x16_t r3 = roundKeys[3];
    const uint8x16_t r4 = roundKeys[4];
    const uint8x16_t r5 = roundKeys[5];
    const uint8x16_t r6 = roundKeys[6];
    const uint8x16_t r7 = roundKeys[7];
    const uint8x16_t r8 = roundKeys[8];
    const uint8x16_t r9 = roundKeys[9];
    const uint8x16_t r10 = roundKeys[10];
    const uint8x16_t r11 = roundKeys[11];
    const uint8x16_t r12 = roundKeys[12];
    const uint8x16_t r13 = roundKeys[13];
    const uint8x16_t r14 = roundKeys[14];


    if (num_rounds == 10) {

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r0);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r1);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r2);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r3);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r4);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r5);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r6);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r7);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r8);
        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r9);
        aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r10);
    } else if (num_rounds == 12) {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r0);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r1);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r2);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r3);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r4);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r5);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r6);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r7);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r8);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r9);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r10);
        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r11);
        aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r12);
    } else {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r0);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r1);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r2);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r3);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r4);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r5);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r6);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r7);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r8);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r9);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r10);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r11);
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r12);
        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r13);
        aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r14);
    }

//    int r;
//    for (r = 0; r < num_rounds - 1; r++) {
//        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[r]);
//    }
//    aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[r++]);
//    aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, roundKeys[r]);

    *io0 = veorq_u8(ctr0s, *io0);
    *io1 = veorq_u8(ctr1s, *io1);
    *io2 = veorq_u8(ctr2s, *io2);
    *io3 = veorq_u8(ctr3s, *io3);
}

static inline void apply_aes_with_reduction(uint8x16_t *io0, uint8x16_t *io1, uint8x16_t *io2, uint8x16_t *io3,
                                            const poly64x2_t i0, const poly64x2_t i1, const poly64x2_t i2,
                                            const poly64x2_t i3,
                                            const poly64x2_t h0, const poly64x2_t h1, const poly64x2_t h2,
                                            const poly64x2_t h3,
                                            uint8x16_t ctr0s, uint8x16_t ctr1s, uint8x16_t ctr2s, uint8x16_t ctr3s,
                                            uint8x16_t *roundKeys,
                                            uint8x16_t *X, const size_t num_rounds) {


    uint32x4_t high, med, low, tee, high2, med2, low2, tee2;

    const uint8x16_t r0 = roundKeys[0];
    const uint8x16_t r1 = roundKeys[1];
    const uint8x16_t r2 = roundKeys[2];
    const uint8x16_t r3 = roundKeys[3];
    const uint8x16_t r4 = roundKeys[4];
    const uint8x16_t r5 = roundKeys[5];
    const uint8x16_t r6 = roundKeys[6];
    const uint8x16_t r7 = roundKeys[7];
    const uint8x16_t r8 = roundKeys[8];
    const uint8x16_t r9 = roundKeys[9];
    const uint8x16_t r10 = roundKeys[10];
    const uint8x16_t r11 = roundKeys[11];
    const uint8x16_t r12 = roundKeys[12];
    const uint8x16_t r13 = roundKeys[13];
    const uint8x16_t r14 = roundKeys[14];


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r0);

    high = vreinterpretq_u32_p128(vmull_high_p64(i3, h3));
    low = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i3), (poly64_t) vget_low_p64(h3)));
    med = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(i3), (poly64_t) vget_low_p64(h3)));
    tee = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i3), (poly64_t) vget_high_p64(h3)));


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r1);

    high2 = vreinterpretq_u32_p128(vmull_high_p64(i2, h2));
    low2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i2), (poly64_t) vget_low_p64(h2)));
    med2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(i2), (poly64_t) vget_low_p64(h2)));
    tee2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i2), (poly64_t) vget_high_p64(h2)));


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r2);

    high = veorq_u32(high, high2);
    low = veorq_u32(low, low2);
    med = veorq_u32(med, med2);
    tee = veorq_u32(tee, tee2);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r3);

    high2 = vreinterpretq_u32_p128(vmull_high_p64(i1, h1));
    low2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i1), (poly64_t) vget_low_p64(h1)));
    med2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(i1), (poly64_t) vget_low_p64(h1)));
    tee2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i1), (poly64_t) vget_high_p64(h1)));


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r4);

    high = veorq_u32(high, high2);
    low = veorq_u32(low, low2);
    med = veorq_u32(med, med2);
    tee = veorq_u32(tee, tee2);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r5);

    high2 = vreinterpretq_u32_p128(vmull_high_p64(i0, h0));
    low2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i0), (poly64_t) vget_low_p64(h0)));
    med2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(i0), (poly64_t) vget_low_p64(h0)));
    tee2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i0), (poly64_t) vget_high_p64(h0)));


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r6);

    high = veorq_u32(high, high2);
    low = veorq_u32(low, low2);
    med = veorq_u32(med, med2);
    tee = veorq_u32(tee, tee2);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r7);

    tee = veorq_u32(tee, med);
    med = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tee), 8)); //vget_low_p64(gh);
    tee = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tee), zero, 8)); //vget_low_p64(gh);
    low = veorq_u32(low, med);
    high = veorq_u32(high, tee);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r8);

    // reduce(low,high);

    uint32x4_t tmp6 = vsriq_n_u32(vreinterpretq_u32_u8(zero), low, 31);
    uint32x4_t tmp7 = vsriq_n_u32(vreinterpretq_u32_u8(zero), high, 31);
    tee = vsliq_n_u32(vreinterpretq_u32_u8(zero), low, 1);
    high = vsliq_n_u32(vreinterpretq_u32_u8(zero), high, 1);

    uint32x4_t tmp8 = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tmp6), zero, 12));
    tmp7 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp7), 12));
    tmp6 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp6), 12));
    tee = vorrq_u32(tee, tmp6);

    if (num_rounds == 10) {
        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r9);

        high = vorrq_u32(high, tmp7);
        high = vorrq_u32(high, tmp8);

        tmp6 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 31);
        tmp7 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 30);
        tmp8 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 25);

        aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r10);

        tmp6 = veorq_u32(tmp6, tmp7);
        tmp6 = veorq_u32(tmp6, tmp8);
        tmp7 = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tmp6), zero, 4));
        tmp6 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp6), 4));
        tee = veorq_u32(tee, tmp6);

        uint32x4_t tmp1 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 1);
        uint32x4_t gh = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 2);
        uint32x4_t t3 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 7);

        tmp1 = veorq_u32(tmp1, gh);
        tmp1 = veorq_u32(tmp1, t3);
        tmp1 = veorq_u32(tmp1, tmp7);

        tee = veorq_u32(tee, tmp1);
        high = veorq_u32(high, tee); // result

    } else if (num_rounds == 12) {

        high = vorrq_u32(high, tmp7);
        high = vorrq_u32(high, tmp8);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r9);

        tmp6 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 31);
        tmp7 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 30);
        tmp8 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 25);
        tmp6 = veorq_u32(tmp6, tmp7);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r10);

        tmp6 = veorq_u32(tmp6, tmp8);
        tmp7 = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tmp6), zero, 4));
        tmp6 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp6), 4));
        tee = veorq_u32(tee, tmp6);

        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r11);

        uint32x4_t tmp1 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 1);
        uint32x4_t gh = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 2);
        uint32x4_t t3 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 7);
        tmp1 = veorq_u32(tmp1, gh);


        aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r12);

        tmp1 = veorq_u32(tmp1, t3);
        tmp1 = veorq_u32(tmp1, tmp7);
        tee = veorq_u32(tee, tmp1);
        high = veorq_u32(high, tee); // result

    } else {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r9);

        high = vorrq_u32(high, tmp7);
        high = vorrq_u32(high, tmp8);
        tmp6 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 31);
        tmp7 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 30);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r10);

        tmp8 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 25);
        tmp6 = veorq_u32(tmp6, tmp7);
        tmp6 = veorq_u32(tmp6, tmp8);
        tmp7 = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tmp6), zero, 4));


        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r11);

        tmp6 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp6), 4));
        tee = veorq_u32(tee, tmp6);
        uint32x4_t tmp1 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 1);
        uint32x4_t gh = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 2);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r12);

        uint32x4_t t3 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 7);
        tmp1 = veorq_u32(tmp1, gh);
        tmp1 = veorq_u32(tmp1, t3);
        tmp1 = veorq_u32(tmp1, tmp7);

        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r13);

        tee = veorq_u32(tee, tmp1);
        high = veorq_u32(high, tee); // result

        aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r14);

    }


    *io0 = veorq_u8(ctr0s, *io0);
    *io1 = veorq_u8(ctr1s, *io1);
    *io2 = veorq_u8(ctr2s, *io2);
    *io3 = veorq_u8(ctr3s, *io3);

    *X = vreinterpretq_u8_u32(high);

}


static inline void apply_aes_with_reduction_dec(uint8x16_t *io0, uint8x16_t *io1, uint8x16_t *io2, uint8x16_t *io3,
                                                const poly64x2_t h0, const poly64x2_t h1, const poly64x2_t h2,
                                                const poly64x2_t h3,
                                                uint8x16_t ctr0s, uint8x16_t ctr1s, uint8x16_t ctr2s, uint8x16_t ctr3s,
                                                uint8x16_t *roundKeys,
                                                uint8x16_t *X, const size_t num_rounds) {


    uint32x4_t high, med, low, tee, high2, med2, low2, tee2;
    poly64x2_t i0;

    const uint8x16_t r0 = roundKeys[0];
    const uint8x16_t r1 = roundKeys[1];
    const uint8x16_t r2 = roundKeys[2];
    const uint8x16_t r3 = roundKeys[3];
    const uint8x16_t r4 = roundKeys[4];
    const uint8x16_t r5 = roundKeys[5];
    const uint8x16_t r6 = roundKeys[6];
    const uint8x16_t r7 = roundKeys[7];
    const uint8x16_t r8 = roundKeys[8];
    const uint8x16_t r9 = roundKeys[9];
    const uint8x16_t r10 = roundKeys[10];
    const uint8x16_t r11 = roundKeys[11];
    const uint8x16_t r12 = roundKeys[12];
    const uint8x16_t r13 = roundKeys[13];
    const uint8x16_t r14 = roundKeys[14];

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r0);

    i0 = vreinterpretq_p64_u8(swap_endian(*io3));

    high = vreinterpretq_u32_p128(vmull_high_p64(i0, h3));
    low = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i0), (poly64_t) vget_low_p64(h3)));
    med = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(i0), (poly64_t) vget_low_p64(h3)));
    tee = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i0), (poly64_t) vget_high_p64(h3)));


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r1);

    i0 = vreinterpretq_p64_u8(swap_endian(*io2));

    high2 = vreinterpretq_u32_p128(vmull_high_p64(i0, h2));
    low2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i0), (poly64_t) vget_low_p64(h2)));
    med2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(i0), (poly64_t) vget_low_p64(h2)));
    tee2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i0), (poly64_t) vget_high_p64(h2)));

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r2);


    high = veorq_u32(high, high2);
    low = veorq_u32(low, low2);
    med = veorq_u32(med, med2);
    tee = veorq_u32(tee, tee2);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r3);

    i0 = vreinterpretq_p64_u8(swap_endian(*io1));
    high2 = vreinterpretq_u32_p128(vmull_high_p64(i0, h1));
    low2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i0), (poly64_t) vget_low_p64(h1)));
    med2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(i0), (poly64_t) vget_low_p64(h1)));
    tee2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i0), (poly64_t) vget_high_p64(h1)));

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r4);

    high = veorq_u32(high, high2);
    low = veorq_u32(low, low2);
    med = veorq_u32(med, med2);
    tee = veorq_u32(tee, tee2);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r5);

    i0 = vreinterpretq_p64_u8(veorq_u8(*X, swap_endian(*io0)));
    high2 = vreinterpretq_u32_p128(vmull_high_p64(i0, h0));
    low2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i0), (poly64_t) vget_low_p64(h0)));
    med2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(i0), (poly64_t) vget_low_p64(h0)));
    tee2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(i0), (poly64_t) vget_high_p64(h0)));

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r6);

    high = veorq_u32(high, high2);
    low = veorq_u32(low, low2);
    med = veorq_u32(med, med2);
    tee = veorq_u32(tee, tee2);


    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r7);


    tee = veorq_u32(tee, med);
    med = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tee), 8)); //vget_low_p64(gh);
    tee = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tee), zero, 8)); //vget_low_p64(gh);
    low = veorq_u32(low, med);
    high = veorq_u32(high, tee);

    aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r8);


    uint32x4_t tmp6 = vsriq_n_u32(vreinterpretq_u32_u8(zero), low, 31);
    uint32x4_t tmp7 = vsriq_n_u32(vreinterpretq_u32_u8(zero), high, 31);
    tee = vsliq_n_u32(vreinterpretq_u32_u8(zero), low, 1);
    high = vsliq_n_u32(vreinterpretq_u32_u8(zero), high, 1);


    uint32x4_t tmp8 = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tmp6), zero, 12));
    tmp7 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp7), 12));
    tmp6 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp6), 12));
    tee = vorrq_u32(tee, tmp6);

    high = vorrq_u32(high, tmp7);
    high = vorrq_u32(high, tmp8);

    if (num_rounds == 10) {

        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r9);

        tmp6 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 31);
        tmp7 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 30);
        tmp8 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 25);

        aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r10);

        tmp6 = veorq_u32(tmp6, tmp7);
        tmp6 = veorq_u32(tmp6, tmp8);
        tmp7 = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tmp6), zero, 4));
        tmp6 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp6), 4));
        tee = veorq_u32(tee, tmp6);

        uint32x4_t tmp1 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 1);
        uint32x4_t gh = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 2);
        uint32x4_t t3 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 7);

        tmp1 = veorq_u32(tmp1, gh);
        tmp1 = veorq_u32(tmp1, t3);
        tmp1 = veorq_u32(tmp1, tmp7);

        tee = veorq_u32(tee, tmp1);
        high = veorq_u32(high, tee); // result

    } else if (num_rounds == 12) {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r9);
        tmp6 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 31);
        tmp7 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 30);
        tmp8 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 25);
        tmp6 = veorq_u32(tmp6, tmp7);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r10);

        tmp6 = veorq_u32(tmp6, tmp8);
        tmp7 = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tmp6), zero, 4));
        tmp6 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp6), 4));
        tee = veorq_u32(tee, tmp6);

        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r11);

        uint32x4_t tmp1 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 1);
        uint32x4_t gh = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 2);
        uint32x4_t t3 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 7);
        tmp1 = veorq_u32(tmp1, gh);

        aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r12);

        tmp1 = veorq_u32(tmp1, t3);
        tmp1 = veorq_u32(tmp1, tmp7);

        tee = veorq_u32(tee, tmp1);
        high = veorq_u32(high, tee); // result

    } else {
        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r9);

        tmp6 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 31);
        tmp7 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 30);
        tmp8 = vsliq_n_u32(vreinterpretq_u32_u8(zero), tee, 25);

        tmp6 = veorq_u32(tmp6, tmp7);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r10);

        tmp6 = veorq_u32(tmp6, tmp8);
        tmp7 = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tmp6), zero, 4));
        tmp6 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp6), 4));
        tee = veorq_u32(tee, tmp6);


        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r11);


        uint32x4_t tmp1 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 1);
        uint32x4_t gh = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 2);
        uint32x4_t t3 = vsriq_n_u32(vreinterpretq_u32_u8(zero), tee, 7);

        tmp1 = veorq_u32(tmp1, gh);

        aes_enc(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r12);

        tmp1 = veorq_u32(tmp1, t3);
        tmp1 = veorq_u32(tmp1, tmp7);
        tee = veorq_u32(tee, tmp1);
        high = veorq_u32(high, tee); // result

        aes_enc_last(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r13);
        aes_xor(&ctr0s, &ctr1s, &ctr2s, &ctr3s, r14);
    }


    *io0 = veorq_u8(ctr0s, *io0);
    *io1 = veorq_u8(ctr1s, *io1);
    *io2 = veorq_u8(ctr2s, *io2);
    *io3 = veorq_u8(ctr3s, *io3);

    *X = vreinterpretq_u8_u32(high);


}

gcm_err *process_block(gcm_ctx *ctx, uint8_t *in, uint8_t *out, size_t outputLen) {
    if (out == NULL) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        return make_gcm_error("out is null, output generated when no output was expected by caller", ILLEGAL_ARGUMENT);
    }


    if (ctx->blocksRemaining < 1) {
        return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
    }
    ctx->blocksRemaining -= 1;

    if (outputLen < BLOCK_SIZE) {
        return make_gcm_error("output len too short", OUTPUT_LENGTH);
    }


    ctx->ctr1 = vaddq_u32(ctx->ctr1, vreinterpretq_u32_u8(one));
    uint8x16_t tmp1 = vrev64q_u8(vreinterpretq_u8_u32(ctx->ctr1));
    single_block(&ctx->aesKey, tmp1, &tmp1);


    uint8x16_t in1 = vld1q_u8(in);
    tmp1 = veorq_u8(tmp1, in1);
    vst1q_u8(out, tmp1);


    if (ctx->encryption) {
        ctx->X = veorq_u8(ctx->X, swap_endian(tmp1));
        //ctx->X = _mm_xor_si128(ctx->X, tmp1);
    } else {
        ctx->X = veorq_u8(ctx->X, swap_endian(in1));

        // ctx->X = _mm_xor_si128(ctx->X, _mm_shuffle_epi8(in1, *BSWAP_MASK));
    }
    ctx->X = gfmul(ctx->X, ctx->H);

    return NULL;

}

gcm_err *processFourBlocksEnc(gcm_ctx *ctx, uint8_t *in, uint8_t *out) {

    if (out == NULL) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        return make_gcm_error("out is null, output generated when no output was expected by caller", ILLEGAL_ARGUMENT);
    }


    if (ctx->blocksRemaining < 4) {
        return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
    }
    ctx->blocksRemaining -= 4;

    const poly64x2_t h4 = vreinterpretq_p64_u8(ctx->hashKeys[HASHKEY_0]);
    const poly64x2_t h3 = vreinterpretq_p64_u8(ctx->hashKeys[(HASHKEY_0 - 1)]);
    const poly64x2_t h2 = vreinterpretq_p64_u8(ctx->hashKeys[(HASHKEY_0 - 2)]);
    const poly64x2_t h1 = vreinterpretq_p64_u8(ctx->hashKeys[(HASHKEY_0 - 3)]);

    ctx->ctr1 = vaddq_u32(ctx->ctr1, vreinterpretq_u32_u8(one));
    uint32x4_t ctr2 = vaddq_u32(ctx->ctr1, vreinterpretq_u32_u8(one));
    uint32x4_t ctr3 = vaddq_u32(ctr2, vreinterpretq_u32_u8(one));
    uint32x4_t ctr4 = vaddq_u32(ctr3, vreinterpretq_u32_u8(one));

    uint8x16_t tmp1 = vrev64q_u8(vreinterpretq_u8_u32(ctx->ctr1));
    uint8x16_t tmp2 = vrev64q_u8(vreinterpretq_u8_u32(ctr2));
    uint8x16_t tmp3 = vrev64q_u8(vreinterpretq_u8_u32(ctr3));
    uint8x16_t tmp4 = vrev64q_u8(vreinterpretq_u8_u32(ctr4));

    quad_block(&ctx->aesKey, &tmp1, &tmp2, &tmp3, &tmp4);

    uint8x16_t in1 = vld1q_u8((&in[0 * 16]));
    uint8x16_t in2 = vld1q_u8((&in[1 * 16]));
    uint8x16_t in3 = vld1q_u8((&in[2 * 16]));
    uint8x16_t in4 = vld1q_u8((&in[3 * 16]));


    tmp1 = veorq_u8(tmp1, in1);
    tmp2 = veorq_u8(tmp2, in2);
    tmp3 = veorq_u8(tmp3, in3);
    tmp4 = veorq_u8(tmp4, in4);

    vst1q_u8(&out[0 * 16], tmp1);
    vst1q_u8(&out[1 * 16], tmp2);
    vst1q_u8(&out[2 * 16], tmp3);
    vst1q_u8(&out[3 * 16], tmp4);

    swap_endian_inplace(&tmp1);
    swap_endian_inplace(&tmp2);
    swap_endian_inplace(&tmp3);
    swap_endian_inplace(&tmp4);


    tmp1 = veorq_u8(tmp1, ctx->X);
    ctx->X = gfmul_multi_reduce(vreinterpretq_p64_u8(tmp1), vreinterpretq_p64_u8(tmp2), vreinterpretq_p64_u8(tmp3),
                                vreinterpretq_p64_u8(tmp4),
                                h1, h2, h3, h4);

    ctx->ctr1 = ctr4;
    return NULL;
}


// Simple single block implementation
gcm_err *process_buffer_enc(gcm_ctx *ctx,
                            uint8_t *in,
                            size_t inlen,
                            uint8_t *out,
                            size_t outputLen,
                            size_t *read,
                            size_t *written) {

    *read = *written = 0;
    const uint32x4_t one_u32v = vreinterpretq_u32_u8(one);

    if (ctx->encryption && ctx->bufBlockIndex == 0 && inlen >= FOUR_BLOCKS && outputLen >= FOUR_BLOCKS) {
        // Special case when nothing is buffered, and we have more than 4 blocks to process, and we are doing
        // encryption.

        // The hash is calculated on the cipher text so if we are going to interleave reduction and encryption
        // then the reduction is always going to be on the previous cipher texts.
        // Eg:
        // 1. Create initial cipher texts
        // 2. Create subsequent cipher texts supplying previous cipher texts for reduction.
        // 3. Loop back to 2 until input is consumed.
        // 4. Final trailing reduction
        //

        if (out == NULL) {
            //
            // Java api my supply a null output array if it expects no output, however
            // if output does occur then we need to catch that here.
            //
            return make_gcm_error("out is null, output generated when no output was expected by caller",
                                  ILLEGAL_ARGUMENT);

        }


        if (ctx->blocksRemaining < 4) {
            return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
        }
        ctx->blocksRemaining -= 4;


        // Hash keys are constant throughout.
        const poly64x2_t h4 = vreinterpretq_p64_u8(ctx->hashKeys[HASHKEY_0]);
        const poly64x2_t h3 = vreinterpretq_p64_u8(ctx->hashKeys[(HASHKEY_0 - 1)]);
        const poly64x2_t h2 = vreinterpretq_p64_u8(ctx->hashKeys[(HASHKEY_0 - 2)]);
        const poly64x2_t h1 = vreinterpretq_p64_u8(ctx->hashKeys[(HASHKEY_0 - 3)]);

        // Initial set of 4 blocks.
        uint8x16_t id0 = vld1q_u8(&in[0 * 16]);
        uint8x16_t id1 = vld1q_u8(&in[1 * 16]);
        uint8x16_t id2 = vld1q_u8(&in[2 * 16]);
        uint8x16_t id3 = vld1q_u8(&in[3 * 16]);

        ctx->ctr1 = vaddq_u32(ctx->ctr1, one_u32v);
        uint32x4_t ctr2 = vaddq_u32(ctx->ctr1, one_u32v);
        uint32x4_t ctr3 = vaddq_u32(ctr2, one_u32v);
        uint32x4_t ctr4 = vaddq_u32(ctr3, one_u32v);


        uint8x16_t tmp1 = vrev64q_u8(vreinterpretq_u8_u32(ctx->ctr1));//   _mm_shuffle_epi8(ctx->ctr1, *BSWAP_EPI64);
        uint8x16_t tmp2 = vrev64q_u8(vreinterpretq_u8_u32(ctr2));//  _mm_shuffle_epi8(ctr2, *BSWAP_EPI64);
        uint8x16_t tmp3 = vrev64q_u8(vreinterpretq_u8_u32(ctr3));// _mm_shuffle_epi8(ctr3, *BSWAP_EPI64);
        uint8x16_t tmp4 = vrev64q_u8(vreinterpretq_u8_u32(ctr4));// _mm_shuffle_epi8(ctr4, *BSWAP_EPI64);


        apply_aes_no_reduction(
                &id0, &id1, &id2, &id3,
                tmp1, tmp2, tmp3, tmp4,
                ctx->aesKey.round_keys, ctx->aesKey.rounds
        );

        vst1q_u8(&out[0 * 16], id0);
        vst1q_u8(&out[1 * 16], id1);
        vst1q_u8(&out[2 * 16], id2);
        vst1q_u8(&out[3 * 16], id3);


        // id0..3 are the initial set of cipher texts but bit swapped

        swap_endian_inplace(&id0);// = _mm_shuffle_epi8(id0, *BSWAP_MASK);
        swap_endian_inplace(&id1);// = _mm_shuffle_epi8(id1, *BSWAP_MASK);
        swap_endian_inplace(&id2);//id2 = _mm_shuffle_epi8(id2, *BSWAP_MASK);
        swap_endian_inplace(&id3);// id3 = _mm_shuffle_epi8(id3, *BSWAP_MASK);


        *written += FOUR_BLOCKS;
        *read += FOUR_BLOCKS;
        ctx->totalBytes += FOUR_BLOCKS;
        inlen -= FOUR_BLOCKS;
        outputLen -= FOUR_BLOCKS;

        in += FOUR_BLOCKS;
        out += FOUR_BLOCKS;

        ctx->ctr1 = ctr4;

        while (inlen >= FOUR_BLOCKS && outputLen >= FOUR_BLOCKS) {


            if (ctx->blocksRemaining < 4) {
                return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            ctx->blocksRemaining -= 4;

            // Encrypt next set of 4 blocks passing the result of the last encryption for reduction.

            uint8x16_t d0 = vld1q_u8(&in[0 * 16]);
            uint8x16_t d1 = vld1q_u8(&in[1 * 16]);
            uint8x16_t d2 = vld1q_u8(&in[2 * 16]);
            uint8x16_t d3 = vld1q_u8(&in[3 * 16]);


            ctx->ctr1 = vaddq_u32(ctx->ctr1, vreinterpretq_u32_u8(one));
            ctr2 = vaddq_u32(ctx->ctr1, vreinterpretq_u32_u8(one));
            ctr3 = vaddq_u32(ctr2, vreinterpretq_u32_u8(one));
            ctr4 = vaddq_u32(ctr3, vreinterpretq_u32_u8(one));


            tmp1 = vrev64q_u8(vreinterpretq_u8_u32(ctx->ctr1));
            tmp2 = vrev64q_u8(vreinterpretq_u8_u32(ctr2));
            tmp3 = vrev64q_u8(vreinterpretq_u8_u32(ctr3));
            tmp4 = vrev64q_u8(vreinterpretq_u8_u32(ctr4));

            id0 = veorq_u8(id0, ctx->X);
            apply_aes_with_reduction(&d0, &d1, &d2, &d3,
                                     vreinterpretq_p64_u8(id0), vreinterpretq_p64_u8(id1), vreinterpretq_p64_u8(id2),
                                     vreinterpretq_p64_u8(id3),
                                     h1, h2, h3, h4,
                                     tmp1, tmp2, tmp3, tmp4,
                                     ctx->aesKey.round_keys, &ctx->X, ctx->aesKey.rounds);

            vst1q_u8(&out[0 * 16], d0);
            vst1q_u8(&out[1 * 16], d1);
            vst1q_u8(&out[2 * 16], d2);
            vst1q_u8(&out[3 * 16], d3);

            // id0..3 are now the last cipher texts but bit swapped

            id0 = swap_endian(d0);// _mm_shuffle_epi8(d0, *BSWAP_MASK);
            id1 = swap_endian(d1);//_mm_shuffle_epi8(d1, *BSWAP_MASK);
            id2 = swap_endian(d2);//_mm_shuffle_epi8(d2, *BSWAP_MASK);
            id3 = swap_endian(d3);//_mm_shuffle_epi8(d3, *BSWAP_MASK);

            *written += FOUR_BLOCKS;
            *read += FOUR_BLOCKS;
            ctx->totalBytes += FOUR_BLOCKS;
            inlen -= FOUR_BLOCKS;
            outputLen -= FOUR_BLOCKS;
            in += FOUR_BLOCKS;
            out += FOUR_BLOCKS;

            ctx->ctr1 = ctr4;
        }

        //
        // Do trailing reduction
        //

        id0 = veorq_u8(id0, ctx->X);
        ctx->X = gfmul_multi_reduce(
                vreinterpretq_p64_u8(id0), vreinterpretq_p64_u8(id1), vreinterpretq_p64_u8(id2),
                vreinterpretq_p64_u8(id3),
                h1, h2, h3, h4);

        // fall through to existing code that will buffer trailing blocks if necessary

    }


    size_t rem = ctx->bufBlockLen - ctx->bufBlockIndex;
    size_t toCopy = inlen < rem ? inlen : rem;
    memcpy(ctx->bufBlock + ctx->bufBlockIndex, in, toCopy);
    ctx->bufBlockIndex += toCopy;
    ctx->totalBytes += toCopy;

    if (ctx->bufBlockIndex == ctx->bufBlockLen) {
        if (outputLen < FOUR_BLOCKS) {
            return make_gcm_error("output len too short", OUTPUT_LENGTH);
        }
        gcm_err *err = processFourBlocksEnc(ctx, ctx->bufBlock, out);
        if (err != NULL) {
            return err;
        }
        ctx->bufBlockIndex -= FOUR_BLOCKS;
        *written += FOUR_BLOCKS;
    }

    *read += toCopy;


    return NULL;


}


gcm_err *processFourBlocks_dec(gcm_ctx *ctx, uint8_t *in, uint8_t *out) {

    if (out == NULL) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        return make_gcm_error("out is null, output generated when no output was expected by caller", ILLEGAL_ARGUMENT);

    }

    uint8x16_t tmp12, tmp34, tmp56, tmp78;
    uint32x4_t ctr2, ctr3, ctr4;

    const uint32x4_t one_u32v = vreinterpretq_u32_u8(one);

    // Hash keys are constant throughout.
    const poly64x2_t h4 = vreinterpretq_p64_u8(ctx->hashKeys[HASHKEY_0]);
    const poly64x2_t h3 = vreinterpretq_p64_u8(ctx->hashKeys[(HASHKEY_0 - 1)]);
    const poly64x2_t h2 = vreinterpretq_p64_u8(ctx->hashKeys[(HASHKEY_0 - 2)]);
    const poly64x2_t h1 = vreinterpretq_p64_u8(ctx->hashKeys[(HASHKEY_0 - 3)]);


    if (ctx->blocksRemaining < 4) {
        return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
    }
    ctx->blocksRemaining -= 4;

    ctx->ctr1 = vaddq_u32(ctx->ctr1, one_u32v);
    ctr2 = vaddq_u32(ctx->ctr1, one_u32v);
    ctr3 = vaddq_u32(ctr2, one_u32v);
    ctr4 = vaddq_u32(ctr3, one_u32v);

    tmp12 = vrev64q_u8(vreinterpretq_u8_u32(ctx->ctr1));
    tmp34 = vrev64q_u8(vreinterpretq_u8_u32(ctr2));
    tmp56 = vrev64q_u8(vreinterpretq_u8_u32(ctr3));
    tmp78 = vrev64q_u8(vreinterpretq_u8_u32(ctr4));


    uint8x16_t in1 = vld1q_u8(&in[0 * 16]);
    uint8x16_t in2 = vld1q_u8(&in[1 * 16]);
    uint8x16_t in3 = vld1q_u8(&in[2 * 16]);
    uint8x16_t in4 = vld1q_u8(&in[3 * 16]);


    apply_aes_with_reduction_dec(&in1, &in2, &in3, &in4,
                                 h1, h2, h3, h4,
                                 tmp12, tmp34, tmp56, tmp78,
                                 ctx->aesKey.round_keys, &ctx->X, ctx->aesKey.rounds);


    vst1q_u8(&out[0 * 16], in1);
    vst1q_u8(&out[1 * 16], in2);
    vst1q_u8(&out[2 * 16], in3);
    vst1q_u8(&out[3 * 16], in4);


    ctx->ctr1 = ctr4;
    return NULL;
}


gcm_err *process_buffer_dec(gcm_ctx *ctx,
                            uint8_t *in,
                            size_t inlen,
                            uint8_t *out,
                            size_t outputLen,
                            size_t *read,
                            size_t *written) {


    *read = *written = 0;

    if (ctx->bufBlockIndex > 0 && ctx->bufBlockIndex + inlen >= ctx->bufBlockLen) {

        // We have 4 or more blocks with of data in the buffer.
        // Process them now and copy any residual back to the start of the buffer.
        if (ctx->bufBlockIndex >= FOUR_BLOCKS) {
            if (outputLen < FOUR_BLOCKS) {
                return make_gcm_error("output len too short", OUTPUT_LENGTH);
            }
            gcm_err *err = processFourBlocks_dec(ctx, ctx->bufBlock, out);
            if (err != NULL) {
                return err;
            }
            *written += FOUR_BLOCKS;
            outputLen -= FOUR_BLOCKS;
            out += FOUR_BLOCKS;

            //
            // Copy whatever bytes after the 4 blocks back to the start of the buffer.
            // Internal copy so read does not change.
            //

            size_t toCopy = ctx->bufBlockIndex - FOUR_BLOCKS;
            memcpy(ctx->bufBlock, ctx->bufBlock + ctx->bufBlockIndex, toCopy);
            ctx->bufBlockIndex = toCopy;
        }

        //
        // There may still data in the buffer but less than before, does
        // our condition for rounding the buffer out still exist with respect
        // to the available input?
        //
        if (ctx->bufBlockIndex > 0 && ctx->bufBlockIndex + inlen >= ctx->bufBlockLen) {
            size_t toCopy = FOUR_BLOCKS - ctx->bufBlockIndex;

            // Copy from the input what we need to round out the buffer.
            memcpy(ctx->bufBlock + ctx->bufBlockIndex, in, toCopy);
            if (outputLen < FOUR_BLOCKS) {
                return make_gcm_error("output len too short", OUTPUT_LENGTH);
            }
            gcm_err *err = processFourBlocks_dec(ctx, ctx->bufBlock, out);
            if (err != NULL) {
                return err;
            }
            ctx->bufBlockIndex = 0;
            *written += FOUR_BLOCKS;
            *read += toCopy;
            ctx->totalBytes += toCopy;
            outputLen -= FOUR_BLOCKS;
            in += toCopy;
            out += FOUR_BLOCKS;
        }
    }

    //
    // Bulk decryption.
    //
    if (ctx->bufBlockIndex == 0 && inlen >= ctx->bufBlockLen && outputLen >= FOUR_BLOCKS) {

        // Hash keys are constant throughout.
        const poly64x2_t h4 = vreinterpretq_p64_u8(ctx->hashKeys[HASHKEY_0]);
        const poly64x2_t h3 = vreinterpretq_p64_u8(ctx->hashKeys[(HASHKEY_0 - 1)]);
        const poly64x2_t h2 = vreinterpretq_p64_u8(ctx->hashKeys[(HASHKEY_0 - 2)]);
        const poly64x2_t h1 = vreinterpretq_p64_u8(ctx->hashKeys[(HASHKEY_0 - 3)]);

        const uint32x4_t one_u32v = vreinterpretq_u32_u8(one);

        uint8x16_t d0, d1, d2, d3, tmp12, tmp34, tmp56, tmp78;

        while (inlen >= ctx->bufBlockLen && outputLen >= FOUR_BLOCKS) {


            if (ctx->blocksRemaining < 4) {
                return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            ctx->blocksRemaining -= 4;

            d0 = vld1q_u8(&in[0 * 16]);
            d1 = vld1q_u8(&in[1 * 16]);
            d2 = vld1q_u8(&in[2 * 16]);
            d3 = vld1q_u8(&in[3 * 16]);

            ctx->ctr1 = vaddq_u32(ctx->ctr1, one_u32v);
            uint32x4_t ctr2 = vaddq_u32(ctx->ctr1, one_u32v);
            uint32x4_t ctr3 = vaddq_u32(ctr2, one_u32v);
            uint32x4_t ctr4 = vaddq_u32(ctr3, one_u32v);

            tmp12 = vrev64q_u8(vreinterpretq_u8_u32(ctx->ctr1));
            tmp34 = vrev64q_u8(vreinterpretq_u8_u32(ctr2));
            tmp56 = vrev64q_u8(vreinterpretq_u8_u32(ctr3));
            tmp78 = vrev64q_u8(vreinterpretq_u8_u32(ctr4));

            ctx->ctr1 = ctr4;


            apply_aes_with_reduction_dec(&d0, &d1, &d2, &d3,
                                         h1, h2, h3, h4,
                                         tmp12, tmp34, tmp56, tmp78,
                                         ctx->aesKey.round_keys, &ctx->X, ctx->aesKey.rounds);

            vst1q_u8(&out[0 * 16], d0);
            vst1q_u8(&out[1 * 16], d1);
            vst1q_u8(&out[2 * 16], d2);
            vst1q_u8(&out[3 * 16], d3);

            // id0..3 are now the last cipher texts but bit swapped

            *written += FOUR_BLOCKS;
            *read += FOUR_BLOCKS;
            ctx->totalBytes += FOUR_BLOCKS;
            inlen -= FOUR_BLOCKS;
            outputLen -= FOUR_BLOCKS;
            in += FOUR_BLOCKS;
            out += FOUR_BLOCKS;
        } // while
    } else {


        if (ctx->bufBlockIndex == 0 && inlen >= ctx->bufBlockLen) {
            if (outputLen < FOUR_BLOCKS) {
                return make_gcm_error("output len too short", OUTPUT_LENGTH);
            }
            gcm_err *err = processFourBlocks_dec(ctx, in, out);
            if (err != NULL) {
                return err;
            }
            *written += FOUR_BLOCKS;
            *read += FOUR_BLOCKS;
            ctx->totalBytes += FOUR_BLOCKS;

        } else {

            size_t rem = ctx->bufBlockLen - ctx->bufBlockIndex;
            size_t toCopy = inlen < rem ? inlen : rem;
            memcpy(ctx->bufBlock + ctx->bufBlockIndex, in, toCopy);
            ctx->bufBlockIndex += toCopy;
            ctx->totalBytes += toCopy;

            if (ctx->bufBlockIndex == ctx->bufBlockLen) {
                if (outputLen < FOUR_BLOCKS) {
                    return make_gcm_error("output len too short", OUTPUT_LENGTH);
                }
                gcm_err *err = processFourBlocks_dec(ctx, ctx->bufBlock, out);
                if (err != NULL) {
                    return err;
                }

                if (ctx->macBlockLen == 16) {
                    vst1q_u8(ctx->bufBlock,
                             vld1q_u8((ctx->bufBlock + FOUR_BLOCKS)));
                } else {
                    memcpy(ctx->bufBlock, ctx->bufBlock + FOUR_BLOCKS, ctx->macBlockLen);
                }

                ctx->bufBlockIndex -= FOUR_BLOCKS;
                *written += FOUR_BLOCKS;
            }
            *read += toCopy;
        }
    }
    return NULL;

}

void gcm_exponentiate(uint8x16_t H, uint64_t pow, uint8x16_t *output) {

    uint32x4_t y = {0, 0, 0, (uint32_t) -2147483648};

    if (pow > 0) {
        uint8x16_t x = H;
        do {
            if ((pow & 1L) != 0) {
                y = vreinterpretq_u32_u8(gfmul(x, vreinterpretq_u8_u32(y)));
            }
            x = gfmul(x, x);
            pow >>= 1;
        } while (pow > 0);
    }

    *output = vreinterpretq_u8_u32(y);
}

/**
 *
 * @param output
 * @param outLen
 * @param written
 * @return NULL if no error, else ptr to struct CALLER NEEDS TO FREE
 */
gcm_err *gcm_doFinal(gcm_ctx *ctx, unsigned char *output, size_t outLen, size_t *written) {
    *written = 0;


    if (ctx->totalBytes == 0) {
        gcm__initBytes(ctx);
    }


    unsigned char *start = output;
    unsigned char *outPtr = start;

    uint8x16_t tmp1;

    size_t limit = ctx->bufBlockIndex;

    if (!ctx->encryption) {

        // We need at least a mac block, and
        if (ctx->macBlockLen > ctx->bufBlockIndex) {
            return make_gcm_error("cipher text too short", ILLEGAL_CIPHER_TEXT);
        }
        limit -= ctx->macBlockLen; // Limit of cipher text before tag.
        ctx->totalBytes -= ctx->macBlockLen;

        // decryption so output buffer cannot be less than limit.
        // bytes are to limit are the mac block (tag)
        if (outLen < limit) {
            return make_gcm_error("output buffer too small", OUTPUT_LENGTH);
        }
    } else {
        // encryption, output must take remaining buffer + mac block
        if (outLen < ctx->bufBlockIndex + ctx->macBlockLen) {
            return make_gcm_error("output buffer too small", OUTPUT_LENGTH);
        }
    }

    if (ctx->bufBlockIndex > 0) {

        //
        // As we process data in four block hunks, our doFinal needs
        // to clean up any:
        // 1. Whole remaining blocks.
        // 2. Any remaining bytes less than one block in length.
        //

        int t = 0;
        if (limit >= BLOCK_SIZE) {

            //
            // Process whole blocks.
            //

            for (; t < ((limit >> 4) << 4); t += BLOCK_SIZE) {
                gcm_err *err = process_block(ctx, &ctx->bufBlock[t], outPtr, outLen);
                if (err != NULL) {
                    return err;
                }
                outPtr += BLOCK_SIZE;
                outLen -= BLOCK_SIZE;
            }

        }


        if (limit % 16) {
            if (ctx->blocksRemaining < 1) {
                return make_gcm_error("attempt to process too many blocks in GCM", ILLEGAL_ARGUMENT);
            }
            ctx->blocksRemaining -= 1;

            ctx->ctr1 = vaddq_u32(ctx->ctr1, vreinterpretq_u32_u8(one));
            tmp1 = vrev64q_u8(vreinterpretq_u8_u32(ctx->ctr1));

            single_block(&ctx->aesKey, tmp1, &tmp1);

            uint8x16_t in1 = vld1q_u8(&ctx->bufBlock[t]);

            tmp1 = veorq_u8(tmp1, in1);
            ctx->last_block = tmp1;
            int j;
            for (j = 0; j < limit % 16; j++) {
                *outPtr = ((unsigned char *) &ctx->last_block)[j];
                outPtr++;
            }
            for (; j < BLOCK_SIZE; j++) {
                ((unsigned char *) &ctx->last_block)[j] = 0;
                ((unsigned char *) &in1)[j] = 0;
            }
            tmp1 = ctx->last_block;
            swap_endian_inplace(&tmp1);//tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);


            if (ctx->encryption) {
                ctx->X = veorq_u8(ctx->X, tmp1);
            } else {
                ctx->X = veorq_u8(ctx->X, swap_endian(in1)); //_mm_shuffle_epi8(in1, *BSWAP_MASK));
            }
            ctx->X = gfmul(ctx->X, ctx->H);
        } // partial
    } // has data in buffer




    ctx->atLength += ctx->atBlockPos;

    //
    // Deal with additional associated text that was supplied after
    // the init or reset methods were called.
    //
    if (ctx->atLength > ctx->atLengthPre) {

        if (ctx->atBlockPos > 0) {
            //
            // finalise any outstanding associated data
            // that was less than the block size.
            //
            tmp1 = swap_endian(ctx->last_aad_block);
            // tmp1 = _mm_shuffle_epi8(tmp1, *BSWAP_MASK);
            ctx->S_at = veorq_u8(ctx->S_at, tmp1);
            ctx->S_at = gfmul(ctx->S_at, ctx->H);
        }


        if (ctx->atLengthPre > 0) {
            ctx->S_at = veorq_u8(ctx->S_at, ctx->S_atPre);
        }

        size_t c = ((ctx->totalBytes * 8) + 127) >> 7;
        uint8x16_t H_c;


        gcm_exponentiate(ctx->H, c, &H_c);


        ctx->S_at = gfmul(ctx->S_at, H_c);

        ctx->X = veorq_u8(ctx->X, ctx->S_at);
    } // extra ad



    uint64x2_t z = {ctx->totalBytes * 8, ctx->atLength * 8}; // endian
    tmp1 = vreinterpretq_u8_u64(z); // TODO find intrinsic


//    tmp1 = _mm_insert_epi64(tmp1, (long long) ctx->totalBytes * 8, 0);
//    tmp1 = _mm_insert_epi64(tmp1, (long long) ctx->atLength * 8, 1);

    unsigned char tmpTag[BLOCK_SIZE];


    ctx->X = veorq_u8(ctx->X, tmp1);
    ctx->X = gfmul(ctx->X, ctx->H);
    swap_endian_inplace(&ctx->X);
    ctx->T = veorq_u8(ctx->X, ctx->T);


    vst1q_u8(tmpTag, ctx->T);

    // Copy into mac block
    memcpy(ctx->macBlock, tmpTag, ctx->macBlockLen);
    memzero(tmpTag,  BLOCK_SIZE);


    if (ctx->encryption) {
        // Append to end of message
        memcpy(outPtr, ctx->macBlock, ctx->macBlockLen);
        outPtr += ctx->macBlockLen;
    } else {
        if (!areEqualCT(ctx->macBlock, ctx->bufBlock + limit, ctx->macBlockLen)) {
            return make_gcm_error("mac check in GCM failed", ILLEGAL_CIPHER_TEXT);
        }
    }

    gcm_reset(ctx, true);
    *written = (size_t) (outPtr - start);


    return NULL;
}


