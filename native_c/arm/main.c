//
//

#include <printf.h>
#include <libc.h>


#include "debug_neon.h"


#include "gcm/gcm_hash.h"
#include "gcm/gcm.h"

#define BUF_LEN 128


int main() {

    int mac_size_bits = 128;

    uint8_t *key = from_hex("d0f1f4defa1e8c08b4b26d576392027c");
    size_t iv_len = 0;
    uint8_t *iv = from_hex_with_len("42b4f01eb9f5a1ea5b1eb73b0fb0baed54f387ecaa0393c7d7dffc6af50146ecc021abf7eb9038d4303d91f8d741a11743166c0860208bcc02c6258fd9511a2fa626f96d60b72fcff773af4e88e7a923506e4916ecbd814651e9f445adef4ad6a6b6c7290cc13b956130eef5b837c939fcac0cbbcc9656cd75b13823ee5acdac",&iv_len);

    size_t  ct_len = 0;
//    uint8_t *ct = from_hex_with_len(
//            "5566e4909128d326a4a39ad60ca2658775a03c88a6f6a354882fffc6d3e92548d1be0855bf7835a0b0331b38222e65f4870ad0d11db4c48aeb4b4a53ec5606d2822cb7e04e5566e4909128d326a4a39ad60ca2658775a03c88a6f6a354882fffc6d3e92548d1be0855bf7835a0b0331b38222e65f4870ad0d11db4c48aeb4b4a53ec5606d2822cb7e04e",&ct_len);

    size_t  pt_len = (mac_size_bits/8);

    uint8_t pt[pt_len];
    size_t written = 0;

    gcm_ctx *gcm = gcm_create_ctx();
    gcm_init(gcm, true, key, 16, iv, iv_len, NULL, 0, mac_size_bits);

   // gcm_process_bytes(gcm, ct, ct_len, pt, ct_len-(mac_size_bits/8), &written);
    gcm_err *err = gcm_doFinal(gcm, pt + written, pt_len-written, &written);

    // expected
    size_t  ex_len =0;
    uint8_t * expected = from_hex_with_len("7ab49b57ddf5f62c427950111c5c4f0d",&ex_len);

    print_diff(expected,ex_len, pt,pt_len);

    gcm_free(gcm);

    free(key);


//    int iv_len = 33;
//    int aad_len = 17;
//    uint8_t key[16];
//    uint8_t iv[iv_len];
//    uint8_t aad[aad_len];
//
//
//
//    memset(key, 1, 16);
//    memset(iv, 2, iv_len);
//    memset(aad, 3, aad_len);
//
//    gcm_ctx *gcm = gcm_create_ctx();
//    gcm_init(gcm, true, key, 16, iv, iv_len, aad, aad_len, 32);
//
//    print_uint8x16_t(&gcm->X);
//
//    size_t len = 64;
//    uint8_t in[len];
//    memset(in,1,len);
//
//
//    size_t written = 0;
//    uint8_t out[len+4];
//    memset(out, 0, len+4);
//
//    uint8_t pt[len];
//
//    gcm_process_bytes(gcm,in,len,out,len+4,&written);
//    gcm_doFinal(gcm,out+written,len+4,&written);
//    print_bytes(out,len+4);
//
//    gcm_init(gcm, false, key, 16, iv, iv_len, aad, aad_len, 32);
//
//    written =0;
//
//    gcm_process_bytes(gcm,out,len+4,pt,len,&written);
//    gcm_doFinal(gcm,out+written,len,&written);
//
//    print_bytes(pt,len);
//
//    gcm_free(gcm);

}