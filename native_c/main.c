
#include <stdio.h>
#include <stdlib.h>
//#include <string.h>

#include <stdio.h>
#include "intel/common.h"

#include "intel/packet/gcm_pc/gcm_pc.h"
#include <immintrin.h>
#include <assert.h>
#include <memory.h>
//#include "debug.h"
#include <stdbool.h>
#include <stdbool.h>
#include <stdint-gcc.h>

unsigned char *from_hex(unsigned char *str, size_t len) {

//    if ((str.length() & 1) == 1) {
//        throw
//        std::invalid_argument("string not even number of chars long");
//    }

    unsigned char *out = malloc((sizeof(unsigned char)) * (len >> 1));

    int t = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char val = 0;
        unsigned char v = str[i];
        if (v >= '0' && v <= '9') {
            val |= (v - '0');
        } else if (v >= 'a' && v <= 'f') {
            val |= (10 + (v - 'a'));
        } else if (v >= 'A' && v <= 'F') {
            val |= (10 + (v - 'A'));
        }
        val <<= 4;
        i++;
        v = str[i];
        if (v >= '0' && v <= '9') {
            val |= (v - '0');
        } else if (v >= 'a' && v <= 'f') {
            val |= (10 + (v - 'a'));
        } else if (v >= 'A' && v <= 'F') {
            val |= (10 + (v - 'A'));
        }
        out[t] = val;
        t++;
    }

    return out;
}

void print_bytes(unsigned char *src, size_t len) {
    while (len-- > 0) {
//        printf("%02X", *src);
        printf("%d, ", (*src > 127) ? *src - 256 : *src);
        src++;
    }
    printf("\n");
}

//
void print_bytes_128(__m128i *src) {
    print_bytes((unsigned char *) (src), 16);
}


int main() {
    printf("hello world!\n");
//    exit(0);

//    uint8_t *key = from_hex("abfd13f758cbe63489b579e5076ddfc2f16db58fabfd13f7", 49);
//    uint8_t *iv = from_hex("aafd12f659cae634", 17);
    size_t outputLen;
    uint8_t *K1 = from_hex("feffe9928665731c6d6a8f9467308308", 33);
    uint8_t *N1 = from_hex("cafebabefacedbaddecaf888", 25);
    uint8_t *A1 = from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2", 41);
    uint8_t *P1 = from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 121);
    uint8_t *T1 = from_hex("5bc94fbc3221a5db94fae95ae7121a47", 33);
    uint8_t *C1 = from_hex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", 121);

    uint8_t Cout[76];
    size_t written = 0;
    gcm_pc_process_packet(true, K1, 16, N1, 12, 12, A1, 20, P1, 60, Cout, &written);


    print_bytes(Cout, 76);

    return 0;
}



//
//    unsigned char key[32];
//    unsigned char msg[16];
//
//    memset(key, 1, 32);
//    memset(msg, 2, 16);
//
//    unsigned char pText[16];
//    unsigned char cText[16];
//
//    memset(pText, 4, 16);
//    memset(cText, 5, 16);
//
//    ecb_ctx *enc = ecb_create_ctx();
//    enc->encryption = true;
//    enc->num_rounds = ROUNDS_256;
//    ecb_init(enc, key);
//
//    ecb_ctx *dec = ecb_create_ctx();
//    dec->encryption = false;
//    dec->num_rounds = ROUNDS_256;
//    ecb_init(dec, key);
//
//
//    ecb_process_blocks(enc, msg, 1, cText);
//    ecb_process_blocks(dec, cText, 1, pText);
//
//    print_bytes(msg, 16);
//    print_bytes(cText, 16);
//    print_bytes(pText, 16);

//}


/*
int main() {

//    __m128i k = _mm_set_epi32(0, 1, 0, 0);
//
//    print_m128i(&k);
//
//    printf("here\n");


    unsigned char aad[64];
    memset(aad,0,64);


    unsigned char key[16];
    memset(key, 0, 16);
    unsigned char iv[16];
    memset(iv, 0, 16);
    gcm_ctx *encGcm = gcm_create_ctx();
    gcm_init(encGcm, true, key, 16, iv, 16, NULL, 0, 128);

    int l = 256;

    unsigned char msg[l];
    memset(msg, 1, l);

    unsigned char cText[l + 16];
    memset(cText, 0, l + 16);



    size_t written = 0;

    gcm_err *err;

    err = gcm_process_bytes(encGcm,msg,l,cText,l+16-written, &written);
    if (err != NULL) {
        printf("%s\n", err->msg);
        exit(1);
    }
    gcm_err_free(err);


    printf("Enc X: ");
    print_m128i(&encGcm->X);


    err = gcm_doFinal(encGcm, cText + written, l + 16 - written, &written);
    if (err != NULL) {
        printf("%s\n", err->msg);
        exit(1);
    }

    printf("Cipher text: ");
    print_bytes(cText, l + 16);


    unsigned char pText[l];
    memset(pText, 4, l);

    gcm_ctx *decGcm = gcm_create_ctx();
    gcm_init(decGcm, false, key, 16, iv, 16, NULL, 0, 128);

  //  gcm_process_aad_byte(decGcm,10);
    written = 0;
    err = gcm_process_bytes(decGcm, cText, l + 16, pText, l, &written);

    if (err != NULL) {
        printf("%s\n", err->msg);
        exit(1);
    }
    gcm_err_free(err);




    print_bytes(msg, l);
    printf("\n");
    print_bytes(cText, l + 16);


    err = gcm_doFinal(decGcm, pText + written, l+16-written, &written);
    if (err != NULL) {
        printf("%s\n", err->msg);
    }

    print_bytes(pText, l);



}
 */

//
//
//int main() {
//
////    const __m128i ONE = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
////    print_m128i(&ONE);
////
////    exit(0);
//
//
//    int msgSize = 255*16;
//
//    ctr_ctx *encCtx = ctr_create_ctx();
//    unsigned char *key = from_hex("b244fb3aeece84d2a0478e215fbfe5ef"); // [16];
//
//    print_bytes(key,16);
//
//    unsigned char *iv = from_hex("2fe1f8479e210dd6484dddc448d8c4");
//
//    print_bytes(iv,16);
//
//    encCtx->max_rounds = 10;
//
//    ctr_init(encCtx, key, 16, iv, 15);
//
//    unsigned char *msg[msgSize];
//    memset(msg,0,msgSize);
//
//
//    unsigned char cText[msgSize];
//    memset(cText, 0, msgSize);
//
//    size_t written = 0;
//    if (!ctr_process_bytes(encCtx, msg, msgSize, cText, &written)) {
//        printf("overlow not");
//    }
//
//    if (!ctr_process_bytes(encCtx, msg, msgSize, cText, &written)) {
//        printf("overlow must");
//    }
//
//
//    print_bytes(cText, msgSize);
//
//
//
//    // dec
//
//
//    ctr_ctx *decCtx = ctr_create_ctx();
//    decCtx->max_rounds = 10;
//    ctr_init(decCtx, (unsigned char *) key, 16, iv, 16);
//
//    unsigned char pText[msgSize];
//
//
//    ctr_process_bytes(decCtx, cText, msgSize, pText, &written);
//
//    print_bytes(msg, msgSize);
//    printf("\n");
//    print_bytes(cText, msgSize);
//    printf("\n");
//    print_bytes(pText, msgSize);
//
//    ctr_free_ctx(encCtx);
//    ctr_free_ctx(decCtx);
//
//}
