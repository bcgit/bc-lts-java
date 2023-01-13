//
// Created  on 18/5/2022.
//

#include <wmmintrin.h>
#include <cstring>
#include <iostream>
#include "AesEcb512W.h"
#include "../common.h"


/**
 * Return 16 bytes.
 * @return 16
 */
uint32_t intel::ecb::AesEcb512W::getMultiBlockSize() {
    return ECB_BLOCK_SIZE;
}

intel::ecb::AesEcb512W::AesEcb512W() {
    roundKeys512 = new __m512i[15];
}

intel::ecb::AesEcb512W::~AesEcb512W() {
    memset(roundKeys512, 0, 15 * sizeof(__m512i));
    delete[] roundKeys512;
}

void intel::ecb::AesEcb512W::reset() {

}


//
// Key and Direction variants no VAES support
//
intel::ecb::AesEcb512W128E::AesEcb512W128E() : AesEcb512W() {}

intel::ecb::AesEcb512W128E::~AesEcb512W128E() = default;


/**
 * AES ECB 128 Encryption
 * @param input
 * @param in_start
 * @param in_len
 * @param blocks_
 * @param output
 * @param out_start
 * @return
 */
size_t intel::ecb::AesEcb512W128E::processBlocks(unsigned char *input,
                                                 size_t in_start,
                                                 size_t in_len,
                                                 uint32_t blocks,
                                                 unsigned char *output,
                                                 size_t out_start) {

    if (in_len < ECB_BLOCK_SIZE) {
        return 0;
    }

    unsigned char *in = input + in_start;
    unsigned char *out = output + out_start;
    unsigned char *outStart = out;

    while (blocks >= 4) {
        blocks -= 4;

        auto tmp = _mm512_xor_si512(
                _mm512_loadu_si512((__m512i *) in), roundKeys512[0]);

        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[1]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[2]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[3]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[4]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[5]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[6]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[7]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[8]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[9]);

        tmp = _mm512_aesenclast_epi128(tmp, roundKeys512[10]);
        _mm512_storeu_si512((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE_4;
        in += ECB_BLOCK_SIZE_4;

    }


    auto rk256 = (__m256i *) roundKeys512;
    while (blocks >= 2) {
        blocks -= 2;

        auto tmp = _mm256_xor_si256(
                _mm256_loadu_si256((__m256i *) in), rk256[0]);

        tmp = _mm256_aesenc_epi128(tmp, rk256[2]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[4]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[6]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[8]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[10]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[12]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[14]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[16]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[18]);

        tmp = _mm256_aesenclast_epi128(tmp, rk256[20]);
        _mm256_storeu_si256((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE_2;
        in += ECB_BLOCK_SIZE_2;

    }

    //
    // Remaining single blocks_.
    //
    auto rk128 = (__m128i *) roundKeys512;
    while (blocks > 0) {
        blocks--;

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), rk128[0]);

        tmp = _mm_aesenc_si128(tmp, rk128[4]);
        tmp = _mm_aesenc_si128(tmp, rk128[8]);
        tmp = _mm_aesenc_si128(tmp, rk128[12]);
        tmp = _mm_aesenc_si128(tmp, rk128[16]);
        tmp = _mm_aesenc_si128(tmp, rk128[20]);
        tmp = _mm_aesenc_si128(tmp, rk128[24]);
        tmp = _mm_aesenc_si128(tmp, rk128[28]);
        tmp = _mm_aesenc_si128(tmp, rk128[32]);
        tmp = _mm_aesenc_si128(tmp, rk128[36]);

        tmp = _mm_aesenclast_si128(tmp, rk128[40]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;


    }

    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb512W128E::init(unsigned char *uk) {
    auto *rk = new __m128i[15];
    memset(rk, 0, sizeof(__m128i) * 15);
    init_128(rk, uk, true);

    auto rk256 = (__m256i *) roundKeys512;

    for (int t = 0; t < 15; t++) {
        *rk256++ = _mm256_set_m128i(rk[t], rk[t]);
        *rk256++ = _mm256_set_m128i(rk[t], rk[t]);
    }

    memset(rk, 0, sizeof(__m128i) * 15);
    delete[] rk;

}


intel::ecb::AesEcb512W192E::AesEcb512W192E() : AesEcb512W() {}

intel::ecb::AesEcb512W192E::~AesEcb512W192E() = default;


/**
 * AES ECB 192 Encryption
 * @param input
 * @param in_start
 * @param in_len
 * @param blocks
 * @param output
 * @param out_start
 * @return
 */
size_t intel::ecb::AesEcb512W192E::processBlocks(unsigned char *input,
                                                 size_t in_start,
                                                 size_t in_len,
                                                 uint32_t blocks,
                                                 unsigned char *output,
                                                 size_t out_start) {

    if (in_len < ECB_BLOCK_SIZE) {
        return 0;
    }

    unsigned char *in = input + in_start;
    unsigned char *out = output + out_start;
    unsigned char *outStart = out;

    while (blocks >= 4) {

        blocks -= 4;

        auto tmp = _mm512_xor_si512(
                _mm512_loadu_si512((__m512 *) in), roundKeys512[0]);

        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[1]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[2]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[3]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[4]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[5]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[6]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[7]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[8]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[9]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[10]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[11]);

        tmp = _mm512_aesenclast_epi128(tmp, roundKeys512[12]);
        _mm512_storeu_si512((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE_4;
        in += ECB_BLOCK_SIZE_4;

    }


    auto rk256 = (__m256i *) roundKeys512;
    while (blocks >= 2) {
        blocks -= 2;

        auto tmp = _mm256_xor_si256(
                _mm256_loadu_si256((__m256i *) in), rk256[0]);

        tmp = _mm256_aesenc_epi128(tmp, rk256[2]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[4]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[6]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[8]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[10]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[12]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[14]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[16]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[18]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[20]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[22]);

        tmp = _mm256_aesenclast_epi128(tmp, rk256[24]);
        _mm256_storeu_si256((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE_2;
        in += ECB_BLOCK_SIZE_2;

    }

    //
    // Remaining single blocks_.
    //
    auto rk128 = (__m128i *) roundKeys512;
    while (blocks > 0) {
        blocks--;

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), rk128[0]);

        tmp = _mm_aesenc_si128(tmp, rk128[4]);
        tmp = _mm_aesenc_si128(tmp, rk128[8]);
        tmp = _mm_aesenc_si128(tmp, rk128[12]);
        tmp = _mm_aesenc_si128(tmp, rk128[16]);
        tmp = _mm_aesenc_si128(tmp, rk128[20]);
        tmp = _mm_aesenc_si128(tmp, rk128[24]);
        tmp = _mm_aesenc_si128(tmp, rk128[28]);
        tmp = _mm_aesenc_si128(tmp, rk128[32]);
        tmp = _mm_aesenc_si128(tmp, rk128[36]);
        tmp = _mm_aesenc_si128(tmp, rk128[40]);
        tmp = _mm_aesenc_si128(tmp, rk128[44]);

        tmp = _mm_aesenclast_si128(tmp, rk128[48]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;


    }

    return (size_t) (out - outStart);


}


void intel::ecb::AesEcb512W192E::init(unsigned char *key) {

    auto *rk = new __m128i[15];
    memset(rk, 0, sizeof(__m128i) * 15);
    init_192(rk, key, true);

    auto rk256 = (__m256i *) roundKeys512;

    for (int t = 0; t < 15; t++) {
        *rk256++ = _mm256_set_m128i(rk[t], rk[t]);
        *rk256++ = _mm256_set_m128i(rk[t], rk[t]);
    }

    memset(rk, 0, sizeof(__m128i) * 15);
    delete[] rk;

}


intel::ecb::AesEcb512W256E::AesEcb512W256E() : AesEcb512W() {}

intel::ecb::AesEcb512W256E::~AesEcb512W256E() = default;

/**
 * AES ECB 256 Encryption
 * @param input
 * @param in_start
 * @param in_len
 * @param blocks
 * @param output
 * @param out_start
 * @return
 */
size_t intel::ecb::AesEcb512W256E::processBlocks(unsigned char *input,
                                                 size_t in_start,
                                                 size_t in_len,
                                                 uint32_t blocks,
                                                 unsigned char *output,
                                                 size_t out_start) {

    if (in_len < ECB_BLOCK_SIZE) {
        return 0;
    }

    unsigned char *in = input + in_start;
    unsigned char *out = output + out_start;
    unsigned char *outStart = out;

    while (blocks >= 4) {
        blocks -= 4;

        auto tmp = _mm512_xor_si512(
                _mm512_loadu_si512((__m512i *) in), roundKeys512[0]);

        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[1]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[2]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[3]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[4]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[5]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[6]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[7]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[8]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[9]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[10]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[11]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[12]);
        tmp = _mm512_aesenc_epi128(tmp, roundKeys512[13]);

        tmp = _mm512_aesenclast_epi128(tmp, roundKeys512[14]);
        _mm512_storeu_si512((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE_4;
        in += ECB_BLOCK_SIZE_4;

    }


    auto rk256 = (__m256i *) roundKeys512;
    while (blocks >= 2) {
        blocks -= 2;

        auto tmp = _mm256_xor_si256(
                _mm256_loadu_si256((__m256i *) in), rk256[0]);

        tmp = _mm256_aesenc_epi128(tmp, rk256[2]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[4]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[6]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[8]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[10]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[12]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[14]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[16]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[18]);

        tmp = _mm256_aesenc_epi128(tmp, rk256[20]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[22]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[24]);
        tmp = _mm256_aesenc_epi128(tmp, rk256[26]);

        tmp = _mm256_aesenclast_epi128(tmp, rk256[28]);
        _mm256_storeu_si256((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE_2;
        in += ECB_BLOCK_SIZE_2;

    }

    //
    // Remaining single blocks_.
    //
    auto rk128 = (__m128i *) roundKeys512;
    while (blocks > 0) {
        blocks--;

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), rk128[0]);

        tmp = _mm_aesenc_si128(tmp, rk128[4]);
        tmp = _mm_aesenc_si128(tmp, rk128[8]);
        tmp = _mm_aesenc_si128(tmp, rk128[12]);
        tmp = _mm_aesenc_si128(tmp, rk128[16]);
        tmp = _mm_aesenc_si128(tmp, rk128[20]);
        tmp = _mm_aesenc_si128(tmp, rk128[24]);
        tmp = _mm_aesenc_si128(tmp, rk128[28]);
        tmp = _mm_aesenc_si128(tmp, rk128[32]);
        tmp = _mm_aesenc_si128(tmp, rk128[36]);
        tmp = _mm_aesenc_si128(tmp, rk128[40]);
        tmp = _mm_aesenc_si128(tmp, rk128[44]);
        tmp = _mm_aesenc_si128(tmp, rk128[48]);
        tmp = _mm_aesenc_si128(tmp, rk128[52]);

        tmp = _mm_aesenclast_si128(tmp, rk128[56]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;


    }

    return (size_t) (out - outStart);
}

void intel::ecb::AesEcb512W256E::init(unsigned char *key) {
    auto *rk = new __m128i[15];
    memset(rk, 0, sizeof(__m128i) * 15);
    init_256(rk, key, true);

    auto rk256 = (__m256i *) roundKeys512;

    for (int t = 0; t < 15; t++) {
        *rk256++ = _mm256_set_m128i(rk[t], rk[t]);
        *rk256++ = _mm256_set_m128i(rk[t], rk[t]);
    }

    memset(rk, 0, sizeof(__m128i) * 15);
    delete[] rk;
}


intel::ecb::AesEcb512W128D::AesEcb512W128D() : AesEcb512W() {}

intel::ecb::AesEcb512W128D::~AesEcb512W128D() = default;

/**
 * AES ECB 128 Decryption
 * @param input
 * @param in_start
 * @param in_len
 * @param blocks
 * @param output
 * @param out_start
 * @return
 */
size_t intel::ecb::AesEcb512W128D::processBlocks(unsigned char *input,
                                                 size_t in_start,
                                                 size_t in_len,
                                                 uint32_t blocks,
                                                 unsigned char *output,
                                                 size_t out_start) {

    if (in_len < ECB_BLOCK_SIZE) {
        return 0;
    }

    unsigned char *in = input + in_start;
    unsigned char *out = output + out_start;
    unsigned char *outStart = out;


    while (blocks >= 4) {
        blocks -= 4;

        auto tmp = _mm512_xor_si512(
                _mm512_loadu_si512((__m512i *) in), roundKeys512[10]);

        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[9]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[8]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[7]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[6]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[5]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[4]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[3]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[2]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[1]);

        tmp = _mm512_aesdeclast_epi128(tmp, roundKeys512[0]);
        _mm512_storeu_si512((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE_4;
        in += ECB_BLOCK_SIZE_4;

    }


    auto rk256 = (__m256i *) roundKeys512;
    while (blocks >= 2) {
        blocks -= 2;

        auto tmp = _mm256_xor_si256(
                _mm256_loadu_si256((__m256i *) in), rk256[20]);

        tmp = _mm256_aesdec_epi128(tmp, rk256[18]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[16]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[14]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[12]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[10]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[8]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[6]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[4]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[2]);

        tmp = _mm256_aesdeclast_epi128(tmp, rk256[0]);
        _mm256_storeu_si256((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE_2;
        in += ECB_BLOCK_SIZE_2;

    }

    //
    // Remaining single blocks.
    //
    auto rk128 = (__m128i *) roundKeys512;
    while (blocks > 0) {
        blocks--;

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), rk128[40]);

        tmp = _mm_aesdec_si128(tmp, rk128[36]);
        tmp = _mm_aesdec_si128(tmp, rk128[32]);
        tmp = _mm_aesdec_si128(tmp, rk128[28]);
        tmp = _mm_aesdec_si128(tmp, rk128[24]);
        tmp = _mm_aesdec_si128(tmp, rk128[20]);
        tmp = _mm_aesdec_si128(tmp, rk128[16]);
        tmp = _mm_aesdec_si128(tmp, rk128[12]);
        tmp = _mm_aesdec_si128(tmp, rk128[8]);
        tmp = _mm_aesdec_si128(tmp, rk128[4]);

        tmp = _mm_aesdeclast_si128(tmp, rk128[0]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;


    }

    return (size_t) (out - outStart);

}


void intel::ecb::AesEcb512W128D::init(unsigned char *key) {
    auto *rk = new __m128i[15];
    memset(rk, 0, sizeof(__m128i) * 15);
    init_128(rk, key, false);

    auto rk256 = (__m256i *) roundKeys512;

    for (int t = 0; t < 15; t++) {
        *rk256++ = _mm256_set_m128i(rk[t], rk[t]);
        *rk256++ = _mm256_set_m128i(rk[t], rk[t]);
    }

    memset(rk, 0, sizeof(__m128i) * 15);
    delete[] rk;
}


intel::ecb::AesEcb512W192D::AesEcb512W192D() : AesEcb512W() {}

intel::ecb::AesEcb512W192D::~AesEcb512W192D() = default;

/**
 * AES ECB 192 Decryption
 * @param input
 * @param in_start
 * @param in_len
 * @param blocks
 * @param output
 * @param out_start
 * @return
 */
size_t intel::ecb::AesEcb512W192D::processBlocks(unsigned char *input,
                                                 size_t in_start,
                                                 size_t in_len,
                                                 uint32_t blocks,
                                                 unsigned char *output,
                                                 size_t out_start) {

    if (in_len < ECB_BLOCK_SIZE) {
        return 0;
    }

    unsigned char *in = input + in_start;
    unsigned char *out = output + out_start;
    unsigned char *outStart = out;


    while (blocks >= 4) {
        blocks -= 4;

        auto tmp = _mm512_xor_si512(
                _mm512_loadu_si512((__m512i *) in), roundKeys512[12]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[11]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[10]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[9]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[8]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[7]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[6]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[5]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[4]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[3]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[2]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[1]);

        tmp = _mm512_aesdeclast_epi128(tmp, roundKeys512[0]);
        _mm512_storeu_si512((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE_4;
        in += ECB_BLOCK_SIZE_4;

    }


    auto rk256 = (__m256i *) roundKeys512;
    while (blocks >= 2) {
        blocks -= 2;

        auto tmp = _mm256_xor_si256(
                _mm256_loadu_si256((__m256i *) in), rk256[24]);

        tmp = _mm256_aesdec_epi128(tmp, rk256[22]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[20]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[18]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[16]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[14]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[12]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[10]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[8]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[6]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[4]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[2]);

        tmp = _mm256_aesdeclast_epi128(tmp, rk256[0]);
        _mm256_storeu_si256((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE_2;
        in += ECB_BLOCK_SIZE_2;

    }

    //
    // Remaining single blocks.
    //
    auto rk128 = (__m128i *) roundKeys512;
    while (blocks > 0) {
        blocks--;

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), rk128[48]);

        tmp = _mm_aesdec_si128(tmp, rk128[44]);
        tmp = _mm_aesdec_si128(tmp, rk128[40]);
        tmp = _mm_aesdec_si128(tmp, rk128[36]);
        tmp = _mm_aesdec_si128(tmp, rk128[32]);
        tmp = _mm_aesdec_si128(tmp, rk128[28]);
        tmp = _mm_aesdec_si128(tmp, rk128[24]);
        tmp = _mm_aesdec_si128(tmp, rk128[20]);
        tmp = _mm_aesdec_si128(tmp, rk128[16]);
        tmp = _mm_aesdec_si128(tmp, rk128[12]);
        tmp = _mm_aesdec_si128(tmp, rk128[8]);
        tmp = _mm_aesdec_si128(tmp, rk128[4]);

        tmp = _mm_aesdeclast_si128(tmp, rk128[0]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;


    }

    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb512W192D::init(unsigned char *key) {
    auto *rk = new __m128i[15];
    memset(rk, 0, sizeof(__m128i) * 15);
    init_192(rk, key, false);

    auto rk256 = (__m256i *) roundKeys512;

    for (int t = 0; t < 15; t++) {
        *rk256++ = _mm256_set_m128i(rk[t], rk[t]);
        *rk256++ = _mm256_set_m128i(rk[t], rk[t]);
    }

    memset(rk, 0, sizeof(__m128i) * 15);
    delete[] rk;
}


intel::ecb::AesEcb512W256D::AesEcb512W256D() : AesEcb512W() {}

intel::ecb::AesEcb512W256D::~AesEcb512W256D() = default;

/**
 * AES ECB 256 Decryption
 * @param input
 * @param in_start
 * @param in_len
 * @param blocks
 * @param output
 * @param out_start
 * @return
 */
size_t intel::ecb::AesEcb512W256D::processBlocks(unsigned char *input,
                                                 size_t in_start,
                                                 size_t in_len,
                                                 uint32_t blocks,
                                                 unsigned char *output,
                                                 size_t out_start) {

    if (in_len < ECB_BLOCK_SIZE) {
        return 0;
    }

    unsigned char *in = input + in_start;
    unsigned char *out = output + out_start;
    unsigned char *outStart = out;


    while (blocks >= 4) {
        blocks -= 4;

        auto tmp = _mm512_xor_si512(
                _mm512_loadu_si512((__m512i *) in), roundKeys512[14]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[13]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[12]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[11]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[10]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[9]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[8]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[7]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[6]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[5]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[4]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[3]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[2]);
        tmp = _mm512_aesdec_epi128(tmp, roundKeys512[1]);

        tmp = _mm512_aesdeclast_epi128(tmp, roundKeys512[0]);
        _mm512_storeu_si512((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE_4;
        in += ECB_BLOCK_SIZE_4;

    }


    auto rk256 = (__m256i *) roundKeys512;
    while (blocks >= 2) {
        blocks -= 2;

        auto tmp = _mm256_xor_si256(
                _mm256_loadu_si256((__m256i *) in), rk256[28]);

        tmp = _mm256_aesdec_epi128(tmp, rk256[26]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[24]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[22]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[20]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[18]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[16]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[14]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[12]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[10]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[8]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[6]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[4]);
        tmp = _mm256_aesdec_epi128(tmp, rk256[2]);

        tmp = _mm256_aesdeclast_epi128(tmp, rk256[0]);
        _mm256_storeu_si256((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE_2;
        in += ECB_BLOCK_SIZE_2;

    }

    //
    // Remaining single blocks.
    //
    auto rk128 = (__m128i *) roundKeys512;
    while (blocks > 0) {
        blocks--;

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), rk128[56]);

        tmp = _mm_aesdec_si128(tmp, rk128[52]);
        tmp = _mm_aesdec_si128(tmp, rk128[48]);
        tmp = _mm_aesdec_si128(tmp, rk128[44]);
        tmp = _mm_aesdec_si128(tmp, rk128[40]);
        tmp = _mm_aesdec_si128(tmp, rk128[36]);
        tmp = _mm_aesdec_si128(tmp, rk128[32]);
        tmp = _mm_aesdec_si128(tmp, rk128[28]);
        tmp = _mm_aesdec_si128(tmp, rk128[24]);
        tmp = _mm_aesdec_si128(tmp, rk128[20]);
        tmp = _mm_aesdec_si128(tmp, rk128[16]);
        tmp = _mm_aesdec_si128(tmp, rk128[12]);
        tmp = _mm_aesdec_si128(tmp, rk128[8]);
        tmp = _mm_aesdec_si128(tmp, rk128[4]);

        tmp = _mm_aesdeclast_si128(tmp, rk128[0]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;


    }

    return (size_t) (out - outStart);


}

void intel::ecb::AesEcb512W256D::init(unsigned char *key) {
    auto *rk = new __m128i[15];
    memset(rk, 0, sizeof(__m128i) * 15);
    init_256(rk, key, false);

    auto rk256 = (__m256i *) roundKeys512;

    for (int t = 0; t < 15; t++) {
        *rk256++ = _mm256_set_m128i(rk[t], rk[t]);
        *rk256++ = _mm256_set_m128i(rk[t], rk[t]);
    }

    memset(rk, 0, sizeof(__m128i) * 15);
    delete[] rk;
}
