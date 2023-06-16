//
//

#ifndef BC_LTS_C_GCM_HASH_H
#define BC_LTS_C_GCM_HASH_H

#include "arm_neon.h"

static const uint8x16_t zero = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8x16_t one = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // endian

static inline void swap_endian_inplace(uint8x16_t *in) {
    *in = vrev64q_u8(*in);
    *in = vextq_u8(*in, *in, 8);
}

static inline uint8x16_t swap_endian(uint8x16_t in) {
    in = vrev64q_u8(in);
    return vextq_u8(in, in, 8);
}

/**
 * Multiply a x b return result.
 * @param a
 * @param b
 * @return the result
 */
static inline uint8x16_t gfmul(uint8x16_t a, uint8x16_t b) {

    uint8x16_t t1 = (uint8x16_t) vmull_high_p64(a, b);
    uint8x16_t t2 = (uint8x16_t) vmull_p64(vget_low_p64(a), vget_low_p64(b));
    uint8x16_t t3 = (uint8x16_t) vmull_p64(vget_high_p64(a), vget_low_p64(b));
    uint8x16_t gh = (uint8x16_t) vmull_p64(vget_low_p64(a), vget_high_p64(b));


    gh = veorq_u8((uint8x16_t) gh, (uint8x16_t) t3);
    t3 = vextq_u8(zero, gh, 8); //vget_low_p64(gh);
    gh = vextq_u8(gh, zero, 8); //vget_low_p64(gh);
    t2 = veorq_u8(t2, t3);
    t1 = veorq_u8(t1, gh);


    uint32x4_t tmp6 = vsriq_n_u32(zero, t2, 31);
    uint32x4_t tmp7 = vsriq_n_u32(zero, t1, 31);
    t2 = vsliq_n_u32(zero, t2, 1);
    t1 = vsliq_n_u32(zero, t1, 1);


    uint32x4_t tmp8 = vextq_u8(tmp6, zero, 12);
    tmp7 = vextq_u8(zero, tmp7, 12);
    tmp6 = vextq_u8(zero, tmp6, 12);
    t2 = vorrq_u8(t2, tmp6);
    t1 = vorrq_u8(t1, tmp7);
    t1 = vorrq_u8(t1, tmp8);

    tmp6 = vsliq_n_u32(zero, t2, 31);
    tmp7 = vsliq_n_u32(zero, t2, 30);
    tmp8 = vsliq_n_u32(zero, t2, 25);

    tmp6 = veorq_u8(tmp6, tmp7);
    tmp6 = veorq_u8(tmp6, tmp8);
    tmp7 = vextq_u8(tmp6, zero, 4);
    tmp6 = vextq_u8(zero, tmp6, 4);
    t2 = veorq_u8(t2, tmp6);

    uint8x16_t tmp1 = vsriq_n_u32(zero, t2, 1);
    gh = vsriq_n_u32(zero, t2, 2);
    t3 = vsriq_n_u32(zero, t2, 7);

    tmp1 = veorq_u8(tmp1, gh);
    tmp1 = veorq_u8(tmp1, t3);
    tmp1 = veorq_u8(tmp1, tmp7);

    t2 = veorq_u8(t2, tmp1);
    return veorq_u8(t1, t2);

}

static inline uint8x16_t reduce(uint8x16_t tee, uint8x16_t high) {
    uint32x4_t tmp6 = vsriq_n_u32(zero, tee, 31);
    uint32x4_t tmp7 = vsriq_n_u32(zero, high, 31);
    tee = vsliq_n_u32(zero, tee, 1);
    high = vsliq_n_u32(zero, high, 1);


    uint32x4_t tmp8 = vextq_u8(tmp6, zero, 12);
    tmp7 = vextq_u8(zero, tmp7, 12);
    tmp6 = vextq_u8(zero, tmp6, 12);
    tee = vorrq_u8(tee, tmp6);
    high = vorrq_u8(high, tmp7);
    high = vorrq_u8(high, tmp8);

    tmp6 = vsliq_n_u32(zero, tee, 31);
    tmp7 = vsliq_n_u32(zero, tee, 30);
    tmp8 = vsliq_n_u32(zero, tee, 25);

    tmp6 = veorq_u8(tmp6, tmp7);
    tmp6 = veorq_u8(tmp6, tmp8);
    tmp7 = vextq_u8(tmp6, zero, 4);
    tmp6 = vextq_u8(zero, tmp6, 4);
    tee = veorq_u8(tee, tmp6);

    uint8x16_t tmp1 = vsriq_n_u32(zero, tee, 1);
    uint8x16_t gh = vsriq_n_u32(zero, tee, 2);
    uint8x16_t t3 = vsriq_n_u32(zero, tee, 7);

    tmp1 = veorq_u8(tmp1, gh);
    tmp1 = veorq_u8(tmp1, t3);
    tmp1 = veorq_u8(tmp1, tmp7);

    tee = veorq_u8(tee, tmp1);
    return veorq_u8(high, tee);

}

uint8x16_t gfmul_multi_reduce(
        const uint8x16_t d0, const uint8x16_t d1, const uint8x16_t d2, const uint8x16_t d3,
        const uint8x16_t h0, const uint8x16_t h1, const uint8x16_t h2, const uint8x16_t h3) {

    uint8x16_t high2, low2, med2, tee2;
    uint8x16_t high, low, med, tee;

    high = (uint8x16_t) vmull_high_p64(d3, h3);
    low = (uint8x16_t) vmull_p64(vget_low_p64(d3), vget_low_p64(h3));
    med = (uint8x16_t) vmull_p64(vget_high_p64(d3), vget_low_p64(h3));
    tee = (uint8x16_t) vmull_p64(vget_low_p64(d3), vget_high_p64(h3));


    high2 = (uint8x16_t) vmull_high_p64(d2, h2);
    low2 = (uint8x16_t) vmull_p64(vget_low_p64(d2), vget_low_p64(h2));
    med2 = (uint8x16_t) vmull_p64(vget_high_p64(d2), vget_low_p64(h2));
    tee2 = (uint8x16_t) vmull_p64(vget_low_p64(d2), vget_high_p64(h2));

    high = veorq_u8(high, high2);
    low = veorq_u8(low, low2);
    med = veorq_u8(med, med2);
    tee = veorq_u8(tee, tee2);

    high2 = (uint8x16_t) vmull_high_p64(d1, h1);
    low2 = (uint8x16_t) vmull_p64(vget_low_p64(d1), vget_low_p64(h1));
    med2 = (uint8x16_t) vmull_p64(vget_high_p64(d1), vget_low_p64(h1));
    tee2 = (uint8x16_t) vmull_p64(vget_low_p64(d1), vget_high_p64(h1));

    high = veorq_u8(high, high2);
    low = veorq_u8(low, low2);
    med = veorq_u8(med, med2);
    tee = veorq_u8(tee, tee2);

    high2 = (uint8x16_t) vmull_high_p64(d0, h0);
    low2 = (uint8x16_t) vmull_p64(vget_low_p64(d0), vget_low_p64(h0));
    med2 = (uint8x16_t) vmull_p64(vget_high_p64(d0), vget_low_p64(h0));
    tee2 = (uint8x16_t) vmull_p64(vget_low_p64(d0), vget_high_p64(h0));

    high = veorq_u8(high, high2);
    low = veorq_u8(low, low2);
    med = veorq_u8(med, med2);
    tee = veorq_u8(tee, tee2);

    tee = veorq_u8((uint8x16_t) tee, (uint8x16_t) med);
    med = vextq_u8(zero, tee, 8); //vget_low_p64(gh);
    tee = vextq_u8(tee, zero, 8); //vget_low_p64(gh);
    low = veorq_u8(low, med);
    high = veorq_u8(high, tee);

    return reduce(tee,high);


}


#endif //BC_LTS_C_GCM_HASH_H
