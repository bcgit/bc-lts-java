//
//

#ifndef BC_LTS_C_GCM_HASH_H
#define BC_LTS_C_GCM_HASH_H

#include "arm_neon.h"

static const uint8x16_t zero = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

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
    tmp7 = vextq_u8(tmp6,zero, 4);
    tmp6 = vextq_u8(zero,tmp6, 4);
    t2 = veorq_u8(t2, tmp6);

    uint8x16_t tmp1 = vsriq_n_u32(zero,t2, 1);
    gh = vsriq_n_u32(zero,t2, 2);
    t3 = vsriq_n_u32(zero,t2, 7);

    tmp1 = veorq_u8(tmp1, gh);
    tmp1 = veorq_u8(tmp1, t3);
    tmp1 = veorq_u8(tmp1, tmp7);

    t2 = veorq_u8(t2, tmp1);
    return veorq_u8(t1, t2);

}


#endif //BC_LTS_C_GCM_HASH_H
