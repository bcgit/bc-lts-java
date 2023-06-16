//
//

#include <printf.h>
#include <libc.h>


#include "debug_neon.h"


#include "gcm/gcm_hash.h"
#include "gcm/gcm.h"

#define BUF_LEN 128


int main() {

//    uint8_t z[16];
//    for (int t = 0; t < 16; t++) {
//        z[t] = t;
//    }
//
//    uint16x8_t tmp1 =vld1q_u8(z);
//
//    print_uint8x16_t(&tmp1);
//
//    tmp1 = vrev64q_u8(tmp1);
//    print_uint8x16_t(&tmp1);
//
//    exit(0);


    int iv_len = 33;
    int aad_len = 17;
    uint8_t key[16];
    uint8_t iv[iv_len];
    uint8_t aad[aad_len];


    memset(key, 1, 16);
    memset(iv, 2, iv_len);
    memset(aad, 3, aad_len);

    gcm_ctx *gcm = gcm_create_ctx();
    gcm_init(
            gcm,
            true,
            key,
            16,
            iv,
            iv_len,
            aad,
            aad_len,
            16);
    gcm_free(gcm);

}