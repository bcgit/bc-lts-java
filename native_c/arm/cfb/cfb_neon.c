//
//
//

#include "cfb.h"


static inline void decrypt_blocks(uint8x16_t *rk,
                                  uint8x16_t *d0,
                                  uint8x16_t *d1,
                                  uint8x16_t *d2,
                                  uint8x16_t *d3,
                                  uint8x16_t *feedback,
                                  const size_t blocks,
                                  const size_t rounds
) {


    if (blocks == 4) {
        size_t r;
        uint8x16_t tmp0 = *feedback;
        uint8x16_t tmp1 = *d0;
        uint8x16_t tmp2 = *d1;
        uint8x16_t tmp3 = *d2;

        for (r = 0; r < rounds - 1; r++) {
            const uint8x16_t rk0 = rk[r];
            tmp0 = vaeseq_u8(tmp0, rk0);
            tmp1 = vaeseq_u8(tmp1, rk0);
            tmp2 = vaeseq_u8(tmp2, rk0);
            tmp3 = vaeseq_u8(tmp3, rk0);
            tmp0 = vaesmcq_u8(tmp0);
            tmp1 = vaesmcq_u8(tmp1);
            tmp2 = vaesmcq_u8(tmp2);
            tmp3 = vaesmcq_u8(tmp3);
        }
        *feedback = *d3;

        const uint8x16_t r0 = rk[r];

        tmp0 = vaeseq_u8(tmp0, r0);
        tmp1 = vaeseq_u8(tmp1, r0);
        tmp2 = vaeseq_u8(tmp2, r0);
        tmp3 = vaeseq_u8(tmp3, r0);

        const uint8x16_t r1 = rk[r + 1];


        tmp0 = veorq_u8(tmp0, r1);
        tmp1 = veorq_u8(tmp1, r1);
        tmp2 = veorq_u8(tmp2, r1);
        tmp3 = veorq_u8(tmp3, r1);


        *d0 = veorq_u8(*d0, tmp0);
        *d1 = veorq_u8(*d1, tmp1);
        *d2 = veorq_u8(*d2, tmp2);
        *d3 = veorq_u8(*d3, tmp3);

    } else if (blocks == 3) {
        size_t r;
        uint8x16_t tmp0 = *feedback;
        uint8x16_t tmp1 = *d0;
        uint8x16_t tmp2 = *d1;


        for (r = 0; r < rounds - 1; r++) {
            const uint8x16_t rk0 = rk[r];
            tmp0 = vaeseq_u8(tmp0, rk0);
            tmp1 = vaeseq_u8(tmp1, rk0);
            tmp2 = vaeseq_u8(tmp2, rk0);

            tmp0 = vaesmcq_u8(tmp0);
            tmp1 = vaesmcq_u8(tmp1);
            tmp2 = vaesmcq_u8(tmp2);

        }
        *feedback = *d2;

        const uint8x16_t r0 = rk[r];

        tmp0 = vaeseq_u8(tmp0, r0);
        tmp1 = vaeseq_u8(tmp1, r0);
        tmp2 = vaeseq_u8(tmp2, r0);

        const uint8x16_t r1 = rk[r + 1];

        tmp0 = veorq_u8(tmp0, r1);
        tmp1 = veorq_u8(tmp1, r1);
        tmp2 = veorq_u8(tmp2, r1);

        *d0 = veorq_u8(*d0, tmp0);
        *d1 = veorq_u8(*d1, tmp1);
        *d2 = veorq_u8(*d2, tmp2);

    } else if (blocks == 2) {
        size_t r;
        uint8x16_t tmp0 = *feedback;
        uint8x16_t tmp1 = *d0;


        for (r = 0; r < rounds - 1; r++) {
            const uint8x16_t rk0 = rk[r];
            tmp0 = vaeseq_u8(tmp0, rk0);
            tmp1 = vaeseq_u8(tmp1, rk0);
            tmp0 = vaesmcq_u8(tmp0);
            tmp1 = vaesmcq_u8(tmp1);
        }
        *feedback = *d1;

        const uint8x16_t r0 = rk[r];

        tmp0 = vaeseq_u8(tmp0, r0);
        tmp1 = vaeseq_u8(tmp1, r0);

        const uint8x16_t r1 = rk[r + 1];

        tmp0 = veorq_u8(tmp0, r1);
        tmp1 = veorq_u8(tmp1, r1);

        *d0 = veorq_u8(*d0, tmp0);
        *d1 = veorq_u8(*d1, tmp1);

    } else if (blocks == 1) {
        size_t r;
        uint8x16_t tmp0 = *feedback;

        for (r = 0; r < rounds - 1; r++) {
            const uint8x16_t rk0 = rk[r];
            tmp0 = vaeseq_u8(tmp0, rk0);
            tmp0 = vaesmcq_u8(tmp0);
        }
        *feedback = *d0;

        const uint8x16_t r0 = rk[r];

        tmp0 = vaeseq_u8(tmp0, r0);

        const uint8x16_t r1 = rk[r + 1];

        tmp0 = veorq_u8(tmp0, r1);

        *d0 = veorq_u8(*d0, tmp0);

    }

    // Do nothing on zero blocks


}


size_t cfb_decrypt(cfb_ctx *cfb, unsigned char *src, size_t len, unsigned char *dest) {
    unsigned char *destStart = dest;

    //
    // Round out buffer.
    //
    while (cfb->buf_index > 0 && len > 0) {
        *dest = cfb_decrypt_byte(cfb, *src);
        len--;
        dest++;
        src++;
    }


    while (len >= CFB_BLOCK_SIZE * 4) {
        uint8x16_t d0 = vld1q_u8(&src[0 * 16]);
        uint8x16_t d1 = vld1q_u8(&src[1 * 16]);
        uint8x16_t d2 = vld1q_u8(&src[2 * 16]);
        uint8x16_t d3 = vld1q_u8(&src[3 * 16]);

        decrypt_blocks(cfb->key.round_keys, &d0, &d1, &d2, &d3, &cfb->feedback, 4, cfb->key.rounds);

        vst1q_u8(&dest[0 * 16], d0);
        vst1q_u8(&dest[1 * 16], d1);
        vst1q_u8(&dest[2 * 16], d2);
        vst1q_u8(&dest[3 * 16], d3);
        len -= CFB_BLOCK_SIZE * 4;
        src += CFB_BLOCK_SIZE * 4;
        dest += CFB_BLOCK_SIZE * 4;
    }


    if (len >= CFB_BLOCK_SIZE * 3) {
        uint8x16_t d0 = vld1q_u8(&src[0 * 16]);
        uint8x16_t d1 = vld1q_u8(&src[1 * 16]);
        uint8x16_t d2 = vld1q_u8(&src[2 * 16]);
        decrypt_blocks(cfb->key.round_keys, &d0, &d1, &d2, &d2, &cfb->feedback, 3, cfb->key.rounds);
        vst1q_u8(&dest[0 * 16], d0);
        vst1q_u8(&dest[1 * 16], d1);
        vst1q_u8(&dest[2 * 16], d2);
        len -= CFB_BLOCK_SIZE * 3;
        src += CFB_BLOCK_SIZE * 3;
        dest += CFB_BLOCK_SIZE * 3;

    } else if (len >= CFB_BLOCK_SIZE * 2) {
        uint8x16_t d0 = vld1q_u8(&src[0 * 16]);
        uint8x16_t d1 = vld1q_u8(&src[1 * 16]);

        decrypt_blocks(cfb->key.round_keys, &d0, &d1, &d1, &d1, &cfb->feedback, 2, cfb->key.rounds);
        vst1q_u8(&dest[0 * 16], d0);
        vst1q_u8(&dest[1 * 16], d1);

        len -= CFB_BLOCK_SIZE * 2;
        src += CFB_BLOCK_SIZE * 2;
        dest += CFB_BLOCK_SIZE * 2;
    } else if (len >= CFB_BLOCK_SIZE) {
        uint8x16_t d0 = vld1q_u8(&src[0 * 16]);

        decrypt_blocks(cfb->key.round_keys, &d0, &d0, &d0, &d0, &cfb->feedback, 1, cfb->key.rounds);
        vst1q_u8(&dest[0 * 16], d0);

        len -= CFB_BLOCK_SIZE;
        src += CFB_BLOCK_SIZE;
        dest += CFB_BLOCK_SIZE;
    }


    //
    // load any trailing bytes into the buffer, the expectation is that
    // whatever is passed in has to be decrypted, ideally callers will
    // try and stick to the AES block size for as long as possible.
    //
    while (len > 0) {
        *dest = cfb_decrypt_byte(cfb, *src);
        len--;
        dest++;
        src++;
    }

    return (size_t) (dest - destStart);
}


unsigned char cfb_decrypt_byte(cfb_ctx *cfb, unsigned char b) {
    if (cfb->buf_index == 0) {
        single_block(&cfb->key, cfb->feedback, &cfb->mask);
    }

    //
    // incrementally mask becomes the last block of cipher text
    //

    unsigned char pt = ((unsigned char *) &cfb->mask)[cfb->buf_index] ^ b;
    ((unsigned char *) &cfb->mask)[cfb->buf_index++] = b; // Mask fills with last cipher text directly.

    if (cfb->buf_index == CFB_BLOCK_SIZE) {
        cfb->buf_index = 0;
        cfb->feedback = cfb->mask;
    }

    return pt;

}