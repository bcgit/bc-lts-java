
#include <stdio.h>
#include <stdlib.h>
//#include <string.h>

#include <stdio.h>
#include "intel/common.h"
#include "intel/ccm/ccm.h"
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
        printf("%d, ", (*src > 127) ? *src- 256: *src);
        src++;
    }
    printf("\n");
}

//
void print_bytes_128(__m128i *src) {
    print_bytes((unsigned char *) (src), 16);
}

//#include "intel/ctr/ctr.h"
//static inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
//    __m128i temp3;
//    temp2 = _mm_shuffle_epi32(temp2, 0xff);
//    temp3 = _mm_slli_si128(temp1, 0x4);
//    temp1 = _mm_xor_si128(temp1, temp3);
//    temp3 = _mm_slli_si128(temp3, 0x4);
//    temp1 = _mm_xor_si128(temp1, temp3);
//    temp3 = _mm_slli_si128(temp3, 0x4);
//    temp1 = _mm_xor_si128(temp1, temp3);
//    temp1 = _mm_xor_si128(temp1, temp2);
//
//    memset(&temp2, 0, sizeof(__m128i));
//    memset(&temp3, 0, sizeof(__m128i));
//    return temp1;
//}
//
//void init_128(__m128i *rk, unsigned char *uk, bool enc) {
//    __m128i temp1;
//    __m128i temp2;
//    printf("test\n");
//    temp1 = _mm_loadu_si128((__m128i *) uk);
//    rk[0] = temp1;
//    print_bytes_128(&rk[0]);
//    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
//    temp1 = AES_128_ASSIST(temp1, temp2);
//    rk[1] = temp1;
//    print_bytes_128(&rk[1]);
//    temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
//    temp1 = AES_128_ASSIST(temp1, temp2);
//    rk[2] = temp1;
//    print_bytes_128(&temp1);
//    temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
//    temp1 = AES_128_ASSIST(temp1, temp2);
//    rk[3] = temp1;
//    print_bytes_128(&temp1);
//    temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
//    temp1 = AES_128_ASSIST(temp1, temp2);
//    rk[4] = temp1;
//    print_bytes_128(&temp1);
//    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
//    temp1 = AES_128_ASSIST(temp1, temp2);
//    rk[5] = temp1;
//    print_bytes_128(&temp1);
//    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
//    temp1 = AES_128_ASSIST(temp1, temp2);
//    rk[6] = temp1;
//    print_bytes_128(&temp1);
//    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
//    temp1 = AES_128_ASSIST(temp1, temp2);
//    rk[7] = temp1;
//    print_bytes_128(&temp1);
//    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
//    temp1 = AES_128_ASSIST(temp1, temp2);
//    rk[8] = temp1;
//    print_bytes_128(&temp1);
//    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
//    temp1 = AES_128_ASSIST(temp1, temp2);
//    rk[9] = temp1;
//    print_bytes_128(&temp1);
//    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
//    temp1 = AES_128_ASSIST(temp1, temp2);
//    rk[10] = temp1;
//    print_bytes_128(&temp1);
//
//    if (!enc) {
//        __m128i s[11];
//        s[0] = rk[10];
//        s[1] = _mm_aesimc_si128(rk[9]);
//        s[2] = _mm_aesimc_si128(rk[8]);
//        s[3] = _mm_aesimc_si128(rk[7]);
//        s[4] = _mm_aesimc_si128(rk[6]);
//        s[5] = _mm_aesimc_si128(rk[5]);
//        s[6] = _mm_aesimc_si128(rk[4]);
//        s[7] = _mm_aesimc_si128(rk[3]);
//        s[8] = _mm_aesimc_si128(rk[2]);
//        s[9] = _mm_aesimc_si128(rk[1]);
//        s[10] = rk[0];
//
//        memcpy(rk, s, sizeof(__m128i) * 11);
//        memset(s, 0, sizeof(__m128i) * 11);
//    }
//
//    memset(&temp1, 0, sizeof(__m128i));
//    memset(&temp2, 0, sizeof(__m128i));
//}



int main() {
    printf("hello world!\n");
//    exit(0);

//    uint8_t *key = from_hex("abfd13f758cbe63489b579e5076ddfc2f16db58fabfd13f7", 49);
//    uint8_t *iv = from_hex("aafd12f659cae634", 17);
    size_t outputLen;
//
//    uint8_t *K1 = from_hex("404142434445464748494a4b4c4d4e4f", 33);
//    uint8_t *N1 = from_hex("10111213141516", 15);
//    uint8_t *A1 = from_hex("0001020304050607", 17);
//    uint8_t *P1 = from_hex("20212223", 9);
//    uint8_t *T1 = from_hex("6084341b", 9);
//    uint8_t *C1 = from_hex("7162015b4dac255d", 17);
    ccm_ctx *ctx = ccm_create_ctx();
//    printf("sizeof: %d\n", sizeof(ccm_ctx));
//    uint8_t C2[22];
//    uint8_t P2[16];
//    ccm_init(ctx, true, K1, 16, N1, 7, A1, 8, 4);
////    ctx->aad = A1;
////    ctx->aadLen = 8;
//    process_packet(ctx, P1, 4, C2, &outputLen, NULL, 0);
//    printf("output\n");
//    print_bytes(C2, 8);
//    ccm_reset(ctx, false);
////    ccm_ctx *ctx_dec = ccm_create_ctx();
//    ccm_init(ctx, false, K1, 16, N1, 7, A1, 8, 4);
//    print_bytes(ctx->nonce, 15);
//    process_packet(ctx, C1, 8, P2, &outputLen,  NULL, 0);
//    printf("output\n");
//    print_bytes(P2, 4);
//    printf("sizeof: %d\n", sizeof(ccm_ctx));
//    ccm_free(ctx);
//    printf("done\n");
////    ctx = NULL;
////    uint8_t *K2 = from_hex("404142434445464748494a4b4c4d4e4f", 33);
//    uint8_t *N2 = from_hex("1011121314151617", 17);
//    uint8_t *A2 = from_hex("000102030405060708090a0b0c0d0e0f", 33);
//    uint8_t *P2 = from_hex("202122232425262728292a2b2c2d2e2f", 33);
//    uint8_t *T2 = from_hex("7f479ffca464", 9);
//    uint8_t *C2 = from_hex("d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd", 45);
//    uint8_t Cnew[22];
//    uint8_t Pnew[16];
//    ccm_ctx *ctx = ccm_create_ctx();
//    ccm_init(ctx, true, K2, 16, N2, 8, A2, 16, 6);
//    processPacket(ctx, P2, 16, Cnew, &outputLen);
//    printf("output\n");
//    print_bytes(Cnew, 22);
//    ccm_ctx *ctx_dec = ccm_create_ctx();
//    ccm_init(ctx_dec, false, K2, 16, N2, 8, A2, 16, 6);
//    print_bytes(ctx_dec->nonce, 15);
//    for (size_t i = 0; i < 10; ++i) {
//        print_bytes_128(&(ctx_dec->roundKeys[i]));
//    }
//    processPacket(ctx_dec, C2, 22, Pnew, &outputLen);
//    printf("output\n");
//    print_bytes(Pnew, 16);

//    uint8_t *K3 = from_hex("404142434445464748494a4b4c4d4e4f", 33);
//    uint8_t *N3 = from_hex("101112131415161718191a1b", 25);
//    uint8_t *A3 = from_hex("000102030405060708090a0b0c0d0e0f10111213", 41);
//    uint8_t *P3 = from_hex("202122232425262728292a2b2c2d2e2f3031323334353637", 49);
//    uint8_t *T3 = from_hex("67c99240c7d51048", 17);
//    uint8_t *C3 = from_hex("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951", 65);
//    uint8_t Cnew[32];
//    uint8_t Pnew[24];
//    ccm_ctx *ctx = ccm_create_ctx();
//    //ccm_init(ctx, true, K3, 16, N3, 12, A3, 20, 8);
//    ccm_init(ctx, true, K3, 16, N3, 12, NULL, 0, 8);
//    ctx->aad = A3;
//    ctx->aadLen = 20;
//    processPacket(ctx, P3, 24, Cnew, &outputLen);
//    printf("output\n");
//    print_bytes(Cnew, 32);
//    ccm_ctx *ctx_dec = ccm_create_ctx();
//    ccm_init(ctx_dec, false, K3, 16, N3, 12, A3, 20, 8);
//    print_bytes(ctx_dec->nonce, 15);
//    for (size_t i = 0; i < 10; ++i) {
//        print_bytes_128(&(ctx_dec->roundKeys[i]));
//    }
//    processPacket(ctx_dec, C3, 32, Pnew, &outputLen);
//    printf("output\n");
//    print_bytes(Pnew, 24);

    uint8_t *K4 = from_hex("404142434445464748494a4b4c4d4e4f", 33);
    uint8_t *N4 = from_hex("101112131415161718191a1b1c", 27);
    uint8_t *A4 = from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            513);
    uint8_t *P4 = from_hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", 65);
    uint8_t *T4 = from_hex("f4dd5d0ee404617225ffe34fce91", 29);
    uint8_t *C4 = from_hex(
            "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b", 93);
    uint8_t Cnew[270];
    uint8_t Pnew[32];
    uint8_t A5[65536];
//    for (size_t i = 0; i < 256; ++i) {
//        memcpy(A5+256*i, A4, 256);
//    }
//    ccm_ctx *ctx = ccm_create_ctx();
//    ccm_init(ctx, true, K4, 16, N4, 13, A5, 65536, 14);
////    ctx->aad=A4;
////    ctx->aadLen=256;
//    processPacket(ctx, P4, 32, Cnew, &outputLen);
//    printf("output\n");
//    print_bytes(Cnew, outputLen);
//    ccm_ctx *ctx_dec = ccm_create_ctx();
//    ccm_init(ctx_dec, false, K4, 16, N4, 13, A5, 65536, 14);
//    ctx_dec->aad=A4;
//    ctx_dec->aadLen=256;
//
//    processPacket(ctx_dec, C4, 46, Pnew, &outputLen);
//    printf("output\n");
//    print_bytes(Pnew, 32);

//    uint8_t P4[1000];
//    uint8_t P41[1000];
////    uint8_t C4[1004];
//    uint8_t tampered[1004];
//    for (size_t i = 0; i < 1000; ++i) {
//        P4[i] = i;
//    }
//    uint8_t Cnew[1014];
    //ctx = ccm_create_ctx();

    ccm_init(ctx, true, K4, 16, N4, 13, A4, 256, 14);
//    ctx->aad=A4;
//    ctx->aadLen=256;
    process_packet(ctx, A4, 256, Cnew, &outputLen, NULL, 0);
    printf("output\n");
    print_bytes(Cnew, outputLen);
//    memcpy(tampered, C4, 1004);
//    tampered[0]+=1;
    ccm_ctx *ctx_dec = ccm_create_ctx();
//    ccm_init(ctx_dec, false, K1, 16, N2, 8, NULL, 0, 4);
    //processPacket(ctx_dec, tampered, 1004, P41, &outputLen);
    ccm_free(ctx);
//
//
//    uint8_t *input = from_hex("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f");
//    uint8_t *output = from_hex("d66f91b79b39e3abb6af2e3b3fb08846d7314b72cdc9aa7d1133ff4289507336");
//
//    ctr_ctx *ctr = ctr_create_ctx();
//    ctr_init(ctr, key, 24, iv, 8);
//
//    uint8_t ctext[64];
//
//    size_t written;
//    ctr_process_bytes(ctr, input, 32, ctext, &written);
//
//    print_bytes(ctext, 32);
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
