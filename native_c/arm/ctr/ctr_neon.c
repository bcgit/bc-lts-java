
#include "arm_neon.h"
#include "ctr.h"

static inline void aes_ctr128_wide(
        uint8x16_t *d0,
        uint8x16_t *d1,
        uint8x16_t *d2,
        uint8x16_t *d3,
        uint8x16_t *roundKeys,
        const uint8x16_t ctr,
        const uint32_t max_rounds,
        const uint32_t blocks) {

    uint8x16_t t0, t1, t2, t3;

    if (blocks == 4) {
        t1 = vaddq_u64(ctr, one);
        t2 = vaddq_u64(ctr, two);
        t3 = vaddq_u64(ctr, three);

        t0 = swap_endian(ctr);
        t1 = swap_endian(t1);
        t2 = swap_endian(t2);
        t3 = swap_endian(t3);
        uint32_t r;
        for (r = 0; r < max_rounds - 1; r++) {
            const uint8x16_t rk0 = roundKeys[r];
            t0 = vaeseq_u8(t0, rk0);
            t1 = vaeseq_u8(t1, rk0);
            t2 = vaeseq_u8(t2, rk0);
            t3 = vaeseq_u8(t3, rk0);
            t0 = vaesmcq_u8(t0);
            t1 = vaesmcq_u8(t1);
            t2 = vaesmcq_u8(t2);
            t3 = vaesmcq_u8(t3);
        }

        const uint8x16_t r0 = roundKeys[r];
        t0 = vaeseq_u8(t0, r0);
        t1 = vaeseq_u8(t1, r0);
        t2 = vaeseq_u8(t2, r0);
        t3 = vaeseq_u8(t3, r0);

        const uint8x16_t r1 = roundKeys[r + 1];

        t0 = veorq_u8(t0, r1);
        t1 = veorq_u8(t1, r1);
        t2 = veorq_u8(t2, r1);
        t3 = veorq_u8(t3, r1);

        *d0 = veorq_u8(*d0, t0);
        *d1 = veorq_u8(*d1, t1);
        *d2 = veorq_u8(*d2, t2);
        *d3 = veorq_u8(*d3, t3);

    } else if (blocks == 3) {
        t1 = vaddq_u64(ctr, one);
        t2 = vaddq_u64(ctr, two);

        t0 = swap_endian(ctr);
        t1 = swap_endian(t1);
        t2 = swap_endian(t2);

        uint32_t r;
        for (r = 0; r < max_rounds - 1; r++) {
            const uint8x16_t rk0 = roundKeys[r];
            t0 = vaeseq_u8(t0, rk0);
            t1 = vaeseq_u8(t1, rk0);
            t2 = vaeseq_u8(t2, rk0);

            t0 = vaesmcq_u8(t0);
            t1 = vaesmcq_u8(t1);
            t2 = vaesmcq_u8(t2);

        }

        const uint8x16_t r0 = roundKeys[r];
        t0 = vaeseq_u8(t0, r0);
        t1 = vaeseq_u8(t1, r0);
        t2 = vaeseq_u8(t2, r0);


        const uint8x16_t r1 = roundKeys[r + 1];

        t0 = veorq_u8(t0, r1);
        t1 = veorq_u8(t1, r1);
        t2 = veorq_u8(t2, r1);

        *d0 = veorq_u8(*d0, t0);
        *d1 = veorq_u8(*d1, t1);
        *d2 = veorq_u8(*d2, t2);

    } else if (blocks == 2) {
        t1 = vaddq_u64(ctr, one);

        t0 = swap_endian(ctr);
        t1 = swap_endian(t1);

        uint32_t r;
        for (r = 0; r < max_rounds - 1; r++) {
            const uint8x16_t rk0 = roundKeys[r];
            t0 = vaeseq_u8(t0, rk0);
            t1 = vaeseq_u8(t1, rk0);
            t0 = vaesmcq_u8(t0);
            t1 = vaesmcq_u8(t1);
        }

        const uint8x16_t r0 = roundKeys[r];
        t0 = vaeseq_u8(t0, r0);
        t1 = vaeseq_u8(t1, r0);


        const uint8x16_t r1 = roundKeys[r + 1];

        t0 = veorq_u8(t0, r1);
        t1 = veorq_u8(t1, r1);
        *d0 = veorq_u8(*d0, t0);
        *d1 = veorq_u8(*d1, t1);

    } else if (blocks == 1) {

        t0 = swap_endian(ctr);

        uint32_t r;
        for (r = 0; r < max_rounds - 1; r++) {
            const uint8x16_t rk0 = roundKeys[r];
            t0 = vaeseq_u8(t0, rk0);
            t0 = vaesmcq_u8(t0);
        }

        const uint8x16_t r0 = roundKeys[r];
        t0 = vaeseq_u8(t0, r0);

        const uint8x16_t r1 = roundKeys[r + 1];
        t0 = veorq_u8(t0, r1);
        *d0 = veorq_u8(*d0, t0);

    }
    // Do nothing on zero

}


bool ctr_process_bytes(ctr_ctx *pCtr, unsigned char *src, size_t len, unsigned char *dest, size_t *written) {
    unsigned char *destStart = dest;



    // Round out any buffered content.
    while (pCtr->buf_pos > 0 && pCtr->buf_pos < CTR_BLOCK_SIZE && len > 0) {

        unsigned char v = *src;
        if (!ctr_process_byte(pCtr, &v)) {
            return false;
        }
        *dest = v;
        src++;
        dest++;
        len--;
    }


    if (pCtr->buf_pos == 0 && len >= 16) {

        while (len >= CTR_BLOCK_SIZE) {

            const uint64_t ctr = pCtr->ctr;

            if (len >= 4 * CTR_BLOCK_SIZE) {

                if (!ctr_incCtr(pCtr, 4)) {
                    return false;
                    //throw exceptions::CounterException("Counter in CTR mode out of range.");
                }

                const uint8x16_t c0 = veorq_u8(pCtr->IV_le, vsetq_lane_u64(ctr, vdupq_n_u64(0), 0));
                //  _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t) ctr));

                uint8x16_t d0 = vld1q_u8(&src[0 * 16]);
                uint8x16_t d1 = vld1q_u8(&src[1 * 16]);
                uint8x16_t d2 = vld1q_u8(&src[2 * 16]);
                uint8x16_t d3 = vld1q_u8(&src[3 * 16]);


                aes_ctr128_wide(
                        &d0, &d1, &d2, &d3,
                        pCtr->key.round_keys, c0, (uint32_t) pCtr->key.rounds,
                        4);

                vst1q_u8(&dest[0 * 16], d0);
                vst1q_u8(&dest[1 * 16], d1);
                vst1q_u8(&dest[2 * 16], d2);
                vst1q_u8(&dest[3 * 16], d3);

                len -= 4 * CTR_BLOCK_SIZE;
                src += 4 * CTR_BLOCK_SIZE;
                dest += 4 * CTR_BLOCK_SIZE;

            } else if (len >= 3 * CTR_BLOCK_SIZE) {
                if (!ctr_incCtr(pCtr, 3)) {
                    return false;
                    //throw exceptions::CounterException("Counter in CTR mode out of range.");
                }

                const uint8x16_t c0 = veorq_u8(pCtr->IV_le, vsetq_lane_u64(ctr, vdupq_n_u64(0), 0));
                //  _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t) ctr));

                uint8x16_t d0 = vld1q_u8(&src[0 * 16]);
                uint8x16_t d1 = vld1q_u8(&src[1 * 16]);
                uint8x16_t d2 = vld1q_u8(&src[2 * 16]);

                aes_ctr128_wide(
                        &d0, &d1, &d2, &d2,
                        pCtr->key.round_keys, c0, (uint32_t) pCtr->key.rounds,
                        3);

                vst1q_u8(&dest[0 * 16], d0);
                vst1q_u8(&dest[1 * 16], d1);
                vst1q_u8(&dest[2 * 16], d2);

                len -= 3 * CTR_BLOCK_SIZE;
                src += 3 * CTR_BLOCK_SIZE;
                dest += 3 * CTR_BLOCK_SIZE;

            } else if (len >= 2 * CTR_BLOCK_SIZE) {

                if (!ctr_incCtr(pCtr, 2)) {
                    return false;
                    //throw exceptions::CounterException("Counter in CTR mode out of range.");
                }

                const uint8x16_t c0 = veorq_u8(pCtr->IV_le, vsetq_lane_u64(ctr, vdupq_n_u64(0), 0));
                //  _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t) ctr));

                uint8x16_t d0 = vld1q_u8(&src[0 * 16]);
                uint8x16_t d1 = vld1q_u8(&src[1 * 16]);

                aes_ctr128_wide(
                        &d0, &d1, &d1, &d1,
                        pCtr->key.round_keys, c0, (uint32_t) pCtr->key.rounds,
                        2);

                vst1q_u8(&dest[0 * 16], d0);
                vst1q_u8(&dest[1 * 16], d1);


                len -= 2 * CTR_BLOCK_SIZE;
                src += 2 * CTR_BLOCK_SIZE;
                dest += 2 * CTR_BLOCK_SIZE;

            } else {
                if (!ctr_incCtr(pCtr, 1)) {
                    return false;
                    //throw exceptions::CounterException("Counter in CTR mode out of range.");
                }

                const uint8x16_t c0 = veorq_u8(pCtr->IV_le, vsetq_lane_u64(ctr, vdupq_n_u64(0), 0));

                //  _mm_xor_si128(pCtr->IV_le, _mm_set_epi64x(0, (int64_t) ctr));

                uint8x16_t d0 = vld1q_u8(&src[0 * 16]);

                aes_ctr128_wide(
                        &d0, &d0, &d0, &d0,
                        pCtr->key.round_keys, c0, (uint32_t)pCtr->key.rounds,
                        1);

                vst1q_u8(&dest[0 * 16], d0);


                len -= 1 * CTR_BLOCK_SIZE;
                src += 1 * CTR_BLOCK_SIZE;
                dest += 1 * CTR_BLOCK_SIZE;

            }
        }
    }


    // Process trailing bytes
    while (len > 0) {
        unsigned char v = *src;
        if (!ctr_process_byte(pCtr, &v)) {
            return false;
        }
        *dest = v;
        src++;
        dest++;
        len--;
    }

    *written = (size_t) (dest - destStart);
    return true;

}


