//
//

#ifndef BC_LTS_C_SHAKE3_H
#define BC_LTS_C_SHAKE3_H

#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>
#include <stdbool.h>

#define BUF_SIZE_SHAKE 192
#define SHAKE_MAGIC 0x00030001
#define STATE_LEN 25

typedef struct {
    uint32_t ident;
    uint32_t bitLen;
    uint32_t rate;
    size_t rate_bytes;
    size_t buf_u8_index;
    uint64_t buf[BUF_SIZE_SHAKE / 8];
    uint64_t byteCount;
    uint64x2_t state[STATE_LEN];
    bool squeezing;
} shake_ctx;


shake_ctx * shake_create_ctx(int bitLen);

void shake_free_ctx(shake_ctx *ctx);

void shake_reset(shake_ctx *ctx);

void shake_update(shake_ctx *ctx, uint8_t *input, size_t len);

void shake_update_byte(shake_ctx *ctx, uint8_t b);

void shake_digest(shake_ctx *ctx, uint8_t *output, size_t len);

uint32_t shake_getSize(shake_ctx *ctx);

uint32_t shake_getByteLen(shake_ctx *ctx);

bool shake_restoreFullState(shake_ctx *ctx, const uint8_t *oldState);

size_t shake_encodeFullState(const shake_ctx *ctx, uint8_t *output);

//static const int8_t __attribute__ ((aligned(16))) _endian_swap_sha224[16] = {
//        3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12
//};

//static inline void swap_endian_inplace(uint8x16_t *in) {
//    *in = vrev64q_u8(*in);
//    *in = vextq_u8(*in, *in, 8);
//}
//
//static inline uint8x16_t swap_endian(uint8x16_t in) {
//    in = vrev64q_u8(in);
//    return vextq_u8(in, in, 8);
//}
//
//static inline void swap_u64(uint8x8_t *src) {
//    *src = vrev64_u8( *src);
//}


#endif //BC_LTS_C_SHAKE3_H
