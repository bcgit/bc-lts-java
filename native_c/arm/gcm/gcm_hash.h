//
//

#ifndef BC_LTS_C_GCM_HASH_H
#define BC_LTS_C_GCM_HASH_H

#include "arm_neon.h"
#include "gcm_common.h"

/**
 * Multiply a x b return result.
 * @param a
 * @param b
 * @return the result
 */
static inline uint8x16_t gfmul(uint8x16_t a, uint8x16_t b) {

    poly64x2_t a_ = vreinterpretq_p64_u8(a);
    poly64x2_t b_ = vreinterpretq_p64_u8(b);

    uint32x4_t t1 = vreinterpretq_u32_p128(vmull_high_p64(a_, b_));
    uint32x4_t t2 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(a_), (poly64_t) vget_low_p64(b_)));
    uint32x4_t t3 = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_high_p64(a_), (poly64_t) vget_low_p64(b_)));
    uint32x4_t gh = vreinterpretq_u32_p128(vmull_p64((poly64_t) vget_low_p64(a_), (poly64_t) vget_high_p64(b_)));

    gh = veorq_u32(gh, t3);
    t3 = vreinterpretq_u32_u8(  vextq_u8(zero, vreinterpretq_u8_u32(gh), 8)); //vget_low_p64(gh);
    gh = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(gh), zero, 8)); //vget_low_p64(gh);
    t2 = veorq_u32(t2, t3);
    t1 = veorq_u32(t1, gh);

    uint32x4_t tmp6 = vsriq_n_u32(vreinterpretq_u32_u8(zero), t2, 31);
    uint32x4_t tmp7 = vsriq_n_u32(vreinterpretq_u32_u8(zero), t1, 31);
    t2 = vsliq_n_u32(vreinterpretq_u32_u8(zero), t2, 1);
    t1 = vsliq_n_u32(vreinterpretq_u32_u8(zero), t1, 1);


    uint32x4_t tmp8 = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tmp6), zero, 12));
    tmp7 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp7), 12));
    tmp6 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp6), 12));
    t2 = vorrq_u32(t2, tmp6);
    t1 = vorrq_u32(t1, tmp7);
    t1 = vorrq_u32(t1, tmp8);

    tmp6 = vsliq_n_u32(vreinterpretq_u32_u8(zero), t2, 31);
    tmp7 = vsliq_n_u32(vreinterpretq_u32_u8(zero), t2, 30);
    tmp8 = vsliq_n_u32(vreinterpretq_u32_u8(zero), t2, 25);

    tmp6 = veorq_u32(tmp6, tmp7);
    tmp6 = veorq_u32(tmp6, tmp8);
    tmp7 = vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(tmp6), zero, 4));
    tmp6 = vreinterpretq_u32_u8(vextq_u8(zero, vreinterpretq_u8_u32(tmp6), 4));
    t2 = veorq_u32(t2, tmp6);

    uint32x4_t tmp1 = vsriq_n_u32(vreinterpretq_u32_u8(zero), t2, 1);
    gh = vsriq_n_u32(vreinterpretq_u32_u8(zero), t2, 2);
    t3 = vsriq_n_u32(vreinterpretq_u32_u8(zero), t2, 7);

    tmp1 = veorq_u32(tmp1, gh);
    tmp1 = veorq_u32(tmp1, t3);
    tmp1 = veorq_u32(tmp1, tmp7);

    t2 = veorq_u32(t2, tmp1);
    return vreinterpretq_u8_u32(veorq_u32(t1, t2));

}


#endif //BC_LTS_C_GCM_HASH_H
