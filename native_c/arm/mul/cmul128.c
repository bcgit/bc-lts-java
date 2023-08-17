//
//
//


#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>


void cmul_acc(int64_t *x, int64_t *y, int64_t *z, size_t size) {
    size_t i = 0;

    if (size >= 2) {

        size_t limit = size - 2;

        while (i <= limit) {
            poly64x2_t x01 = vreinterpretq_p64_u8(vld1q_u8((uint8_t *) &x[i]));
            size_t j = 0;
            while (j <= limit) {

                poly64x2_t tmp1, tmp6, tmp7, tmp8;

                poly64x2_t y01 = vreinterpretq_p64_u8(vld1q_u8((uint8_t *) &y[j]));

                uint64x2_t z01 = vreinterpretq_u64_p128(
                        vmull_p64((poly64_t) vget_low_p64(x01), (poly64_t) vget_low_p64(y01)));

                uint64x2_t z12 =
                        veorq_u64(
                                vreinterpretq_u64_p64(vreinterpretq_p64_p128(
                                        vmull_p64((poly64_t) vget_low_p64(x01), (poly64_t) vget_high_p64(y01)))),
                                vreinterpretq_u64_p64(vreinterpretq_p64_p128(
                                        vmull_p64((poly64_t) vget_high_p64(x01), (poly64_t) vget_low_p64(y01)))));

                uint64x2_t z23 = vreinterpretq_u64_p128(vmull_high_p64(x01, y01));


                z[i + j + 0] ^= (int64_t) vget_low_u64(z01);
                z[i + j + 1] ^= (int64_t) (vget_high_u64(z01) ^ vget_low_u64(z12));
                z[i + j + 2] ^= (int64_t) (vget_low_u64(z23) ^
                                           vget_high_u64(z12));
                z[i + j + 3] ^= (int64_t) vget_high_u64(z23);

                j += 2;
            }
            i += 2;
        }

    }

    if (i < size) {


        uint64x2_t Z;

        uint64x2_t Xi = vsetq_lane_u64((uint64_t) x[i], vdupq_n_u64(0), 0);
        uint64x2_t Yi = vsetq_lane_u64((uint64_t) y[i], vdupq_n_u64(0), 0);

        for (size_t j = 0; j < i; j++) {
            uint64x2_t Xj = vsetq_lane_u64((uint64_t)x[j], vdupq_n_u64(0), 0);
            uint64x2_t Yj = vsetq_lane_u64((uint64_t)y[j], vdupq_n_u64(0), 0);

            Z = veorq_u64(
                    vreinterpretq_u64_p64(vreinterpretq_p64_p128(
                            vmull_p64((poly64_t) vget_low_p64(vreinterpretq_p64_u64( Xi)), (poly64_t) vget_low_p64(vreinterpretq_p64_u64(Yj))))),
                    vreinterpretq_u64_p64(vreinterpretq_p64_p128(
                            vmull_p64((poly64_t) vget_low_p64(vreinterpretq_p64_u64(Yi)), (poly64_t) vget_low_p64(vreinterpretq_p64_u64(Xj)))))
            );

            z[i + j + 0] ^= (int64_t) vget_low_u64(Z);
            z[i + j + 1] ^= (int64_t) vget_high_u64(Z);
        }


        Z = vreinterpretq_u64_p128(vmull_p64((poly64_t) vget_low_p64(vreinterpretq_p64_u64(Xi)), (poly64_t) vget_low_p64(vreinterpretq_p64_u64(Yi))));

        z[i + i + 0] ^= (int64_t) vget_low_u64(Z);
        z[i + i + 1] ^= (int64_t) vget_high_u64(Z);

    }

}