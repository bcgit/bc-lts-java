//
//

#include <printf.h>
#include <libc.h>


#include "debug_neon.h"


#include "gcm/gcm_hash.h"

#define BUF_LEN 128


int main() {

    uint8x16_t insert_32 = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    print_uint8x16_t(&insert_32);

    exit(0);

    uint8_t src[16];
    for (int t=0; t<16;t++) {
        src[t] = t;
    }

//    memset(src, 0, 16);
//    src[0] = 0xFF;

    uint8x16_t zero = vdupq_n_u16(0);

//    uint32_t aa[4] = {0x4e57FF, 0xFFFFFFFF, 0x4e57FF, 0x4e57FF};
//    uint32_t bb[4] = {0xfe, 0x27, 0x33, 0x4e57FF};

    uint8x16_t a = vld1q_u8((const unsigned char *) src);
    print_uint8x16_t(&a);
    a = vrev64q_u8(a);
    a = vextq_u8(a,a,8);


    print_uint8x16_t(&a);




//    a = vrev32q_u8(a);
//    print_uint8x16_t(&a);
//
//    a = vrev16q_u8(a);
//    print_uint8x16_t(&a);
//
//    a = vrev32q_u8(a);
//    print_uint8x16_t(&a);


}