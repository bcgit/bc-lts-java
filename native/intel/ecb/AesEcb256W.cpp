//
// Created  on 18/5/2022.
//

#include <immintrin.h>
#include <cstring>
#include <iostream>
#include "AesEcb256W.h"
#include "../common.h"




/**
 * Return 16 bytes for non VAES variant.
 * @return 16
 */
uint32_t intel::ecb::AesEcb256W::getMultiBlockSize() {
    return ECB_BLOCK_SIZE;
}

intel::ecb::AesEcb256W::AesEcb256W() {
    roundKeys256 = new __m256i[15];
}

intel::ecb::AesEcb256W::~AesEcb256W() {
    memset(roundKeys256, 0, 15 * sizeof(__m256i));
    delete[] roundKeys256;
}

void intel::ecb::AesEcb256W::reset() {

}


//
// Key and Direction variants no VAES support
//
intel::ecb::AesEcb256W128E::AesEcb256W128E() : AesEcb256W() {}

intel::ecb::AesEcb256W128E::~AesEcb256W128E() = default;


/**
 * AES ECB 128 Encryption
 * @param input
 * @param in_start
 * @param in_len
 * @param blocks
 * @param output
 * @param out_start
 * @return
 */
size_t intel::ecb::AesEcb256W128E::processBlocks(unsigned char *input,
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

    int t = blocks;

    while (t >= 2) {
        t -= 2;

        auto tmp = _mm256_xor_si256(
                _mm256_loadu_si256((__m256i *) in), roundKeys256[0]);

        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[1]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[2]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[3]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[4]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[5]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[6]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[7]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[8]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[9]);

        tmp = _mm256_aesenclast_epi128(tmp, roundKeys256[10]);
        _mm256_storeu_si256((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE * 2;
        in += ECB_BLOCK_SIZE * 2;

    }

    //
    // Remaining single blocks.
    //
    auto rk128 = (__m128i *) roundKeys256;
    while (t > 0) {
        t--;

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), rk128[0]);

        tmp = _mm_aesenc_si128(tmp, rk128[2]);
        tmp = _mm_aesenc_si128(tmp, rk128[4]);
        tmp = _mm_aesenc_si128(tmp, rk128[6]);
        tmp = _mm_aesenc_si128(tmp, rk128[8]);
        tmp = _mm_aesenc_si128(tmp, rk128[10]);
        tmp = _mm_aesenc_si128(tmp, rk128[12]);
        tmp = _mm_aesenc_si128(tmp, rk128[14]);
        tmp = _mm_aesenc_si128(tmp, rk128[16]);
        tmp = _mm_aesenc_si128(tmp, rk128[18]);

        tmp = _mm_aesenclast_si128(tmp, rk128[20]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;


    }

    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb256W128E::init(unsigned char *uk) {
    auto *rk = new __m128i[15];
    memset(rk, 0, sizeof(__m128i) * 15);
    init_128(rk, uk, true);

    for (int t = 0; t < 15; t++) {
        roundKeys256[t] = _mm256_set_m128i(rk[t], rk[t]);
    }

    memset(rk, 0, sizeof(__m128i) * 15);
    delete[] rk;

}


intel::ecb::AesEcb256W192E::AesEcb256W192E() : AesEcb256W() {}

intel::ecb::AesEcb256W192E::~AesEcb256W192E() = default;


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
size_t intel::ecb::AesEcb256W192E::processBlocks(unsigned char *input,
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

    int t = blocks;

    while (t >= 2) {
        t -= 2;

        auto tmp = _mm256_xor_si256(
                _mm256_loadu_si256((__m256i *) in), roundKeys256[0]);

        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[1]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[2]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[3]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[4]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[5]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[6]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[7]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[8]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[9]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[10]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[11]);
        tmp = _mm256_aesenclast_epi128(tmp, roundKeys256[12]);
        _mm256_storeu_si256((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE * 2;
        in += ECB_BLOCK_SIZE * 2;

    }

    //
    // Remaining single blocks.
    //
    auto rk128 = (__m128i *) roundKeys256;
    while (t > 0) {
        t--;

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), rk128[0]);

        tmp = _mm_aesenc_si128(tmp, rk128[2]);
        tmp = _mm_aesenc_si128(tmp, rk128[4]);
        tmp = _mm_aesenc_si128(tmp, rk128[6]);
        tmp = _mm_aesenc_si128(tmp, rk128[8]);
        tmp = _mm_aesenc_si128(tmp, rk128[10]);
        tmp = _mm_aesenc_si128(tmp, rk128[12]);
        tmp = _mm_aesenc_si128(tmp, rk128[14]);
        tmp = _mm_aesenc_si128(tmp, rk128[16]);
        tmp = _mm_aesenc_si128(tmp, rk128[18]);
        tmp = _mm_aesenc_si128(tmp, rk128[20]);
        tmp = _mm_aesenc_si128(tmp, rk128[22]);

        tmp = _mm_aesenclast_si128(tmp, rk128[24]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;


    }

    return (size_t) (out - outStart);

}


void intel::ecb::AesEcb256W192E::init(unsigned char *key) {

    auto *rk = new __m128i[15];
    memset(rk, 0, sizeof(__m128i) * 15);
    init_192(rk, key, true);

    for (int t = 0; t < 15; t++) {
        roundKeys256[t] = _mm256_set_m128i(rk[t], rk[t]);
    }

    memset(rk, 0, sizeof(__m128i) * 15);
    delete[] rk;

}


intel::ecb::AesEcb256W256E::AesEcb256W256E() : AesEcb256W() {}

intel::ecb::AesEcb256W256E::~AesEcb256W256E() = default;

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
size_t intel::ecb::AesEcb256W256E::processBlocks(unsigned char *input,
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

    int t = blocks;

    while (t >= 2) {
        t -= 2;

        auto tmp = _mm256_xor_si256(
                _mm256_loadu_si256((__m256i *) in), roundKeys256[0]);

        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[1]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[2]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[3]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[4]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[5]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[6]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[7]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[8]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[9]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[10]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[11]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[12]);
        tmp = _mm256_aesenc_epi128(tmp, roundKeys256[13]);

        tmp = _mm256_aesenclast_epi128(tmp, roundKeys256[14]);
        _mm256_storeu_si256((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE * 2;
        in += ECB_BLOCK_SIZE * 2;

    }

    //
    // Remaining single blocks.
    //
    auto rk128 = (__m128i *) roundKeys256;
    while (t > 0) {
        t--;

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), rk128[0]);

        tmp = _mm_aesenc_si128(tmp, rk128[2]);
        tmp = _mm_aesenc_si128(tmp, rk128[4]);
        tmp = _mm_aesenc_si128(tmp, rk128[6]);
        tmp = _mm_aesenc_si128(tmp, rk128[8]);
        tmp = _mm_aesenc_si128(tmp, rk128[10]);
        tmp = _mm_aesenc_si128(tmp, rk128[12]);
        tmp = _mm_aesenc_si128(tmp, rk128[14]);
        tmp = _mm_aesenc_si128(tmp, rk128[16]);
        tmp = _mm_aesenc_si128(tmp, rk128[18]);
        tmp = _mm_aesenc_si128(tmp, rk128[20]);
        tmp = _mm_aesenc_si128(tmp, rk128[22]);
        tmp = _mm_aesenc_si128(tmp, rk128[24]);
        tmp = _mm_aesenc_si128(tmp, rk128[26]);

        tmp = _mm_aesenclast_si128(tmp, rk128[28]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;


    }

    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb256W256E::init(unsigned char *key) {
    __m128i *rk = new __m128i[15];
    memset(rk, 0, sizeof(__m128i) * 15);
    init_256(rk, key, true);

    for (int t = 0; t < 15; t++) {
        roundKeys256[t] = _mm256_set_m128i(rk[t], rk[t]);
    }

    memset(rk, 0, sizeof(__m128i) * 15);
    delete[] rk;
}


intel::ecb::AesEcb256W128D::AesEcb256W128D() : AesEcb256W() {}

intel::ecb::AesEcb256W128D::~AesEcb256W128D() = default;

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
size_t intel::ecb::AesEcb256W128D::processBlocks(unsigned char *input,
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

    int t = blocks;

    while (t >= 2) {
        t -= 2;

        auto tmp = _mm256_xor_si256(
                _mm256_loadu_si256((__m256i *) in), roundKeys256[10]);

        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[9]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[8]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[7]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[6]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[5]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[4]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[3]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[2]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[1]);

        tmp = _mm256_aesdeclast_epi128(tmp, roundKeys256[0]);
        _mm256_storeu_si256((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE * 2;
        in += ECB_BLOCK_SIZE * 2;

    }

    //
    // Remaining single blocks.
    //
    auto rk128 = (__m128i *) roundKeys256;
    while (t > 0) {
        t--;

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), rk128[20]);

        tmp = _mm_aesdec_si128(tmp, rk128[18]);
        tmp = _mm_aesdec_si128(tmp, rk128[16]);
        tmp = _mm_aesdec_si128(tmp, rk128[14]);
        tmp = _mm_aesdec_si128(tmp, rk128[12]);
        tmp = _mm_aesdec_si128(tmp, rk128[10]);
        tmp = _mm_aesdec_si128(tmp, rk128[8]);
        tmp = _mm_aesdec_si128(tmp, rk128[6]);
        tmp = _mm_aesdec_si128(tmp, rk128[4]);
        tmp = _mm_aesdec_si128(tmp, rk128[2]);

        tmp = _mm_aesdeclast_si128(tmp, rk128[0]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;


    }

    return (size_t) (out - outStart);

}


void intel::ecb::AesEcb256W128D::init(unsigned char *key) {
    __m128i *rk = new __m128i[15];
    memset(rk, 0, sizeof(__m128i) * 15);
    init_128(rk, key, false);

    for (int t = 0; t < 15; t++) {
        roundKeys256[t] = _mm256_set_m128i(rk[t], rk[t]);
    }

    memset(rk, 0, sizeof(__m128i) * 15);
    delete[] rk;
}


intel::ecb::AesEcb256W192D::AesEcb256W192D() : AesEcb256W() {}

intel::ecb::AesEcb256W192D::~AesEcb256W192D() = default;

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
size_t intel::ecb::AesEcb256W192D::processBlocks(unsigned char *input,
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

    int t = blocks;

    while (t >= 2) {
        t -= 2;

        auto tmp = _mm256_xor_si256(
                _mm256_loadu_si256((__m256i *) in), roundKeys256[12]);

        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[11]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[10]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[9]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[8]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[7]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[6]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[5]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[4]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[3]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[2]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[1]);

        tmp = _mm256_aesdeclast_epi128(tmp, roundKeys256[0]);
        _mm256_storeu_si256((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE * 2;
        in += ECB_BLOCK_SIZE * 2;

    }

    //
    // Remaining single blocks.
    //
    auto rk128 = (__m128i *) roundKeys256;
    while (t > 0) {
        t--;

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), rk128[24]);
        tmp = _mm_aesdec_si128(tmp, rk128[22]);
        tmp = _mm_aesdec_si128(tmp, rk128[20]);
        tmp = _mm_aesdec_si128(tmp, rk128[18]);
        tmp = _mm_aesdec_si128(tmp, rk128[16]);
        tmp = _mm_aesdec_si128(tmp, rk128[14]);
        tmp = _mm_aesdec_si128(tmp, rk128[12]);
        tmp = _mm_aesdec_si128(tmp, rk128[10]);
        tmp = _mm_aesdec_si128(tmp, rk128[8]);
        tmp = _mm_aesdec_si128(tmp, rk128[6]);
        tmp = _mm_aesdec_si128(tmp, rk128[4]);
        tmp = _mm_aesdec_si128(tmp, rk128[2]);

        tmp = _mm_aesdeclast_si128(tmp, rk128[0]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;


    }

    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb256W192D::init(unsigned char *key) {
    auto *rk = new __m128i[15];
    memset(rk, 0, sizeof(__m128i) * 15);
    init_192(rk, key, false);

    for (int t = 0; t < 15; t++) {
        roundKeys256[t] = _mm256_set_m128i(rk[t], rk[t]);
    }

    memset(rk, 0, sizeof(__m128i) * 15);
    delete[] rk;
}


intel::ecb::AesEcb256W256D::AesEcb256W256D() : AesEcb256W() {}

intel::ecb::AesEcb256W256D::~AesEcb256W256D() = default;

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
size_t intel::ecb::AesEcb256W256D::processBlocks(unsigned char *input,
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

    int t = blocks;

    while (t >= 2) {
        t -= 2;

        auto tmp = _mm256_xor_si256(
                _mm256_loadu_si256((__m256i *) in), roundKeys256[14]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[13]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[12]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[11]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[10]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[9]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[8]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[7]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[6]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[5]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[4]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[3]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[2]);
        tmp = _mm256_aesdec_epi128(tmp, roundKeys256[1]);

        tmp = _mm256_aesdeclast_epi128(tmp, roundKeys256[0]);
        _mm256_storeu_si256((__m256i *) out, tmp);

        out += ECB_BLOCK_SIZE * 2;
        in += ECB_BLOCK_SIZE * 2;

    }

    //
    // Remaining single blocks.
    //
    auto rk128 = (__m128i *) roundKeys256;
    while (t > 0) {
        t--;

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), rk128[28]);
        tmp = _mm_aesdec_si128(tmp, rk128[26]);
        tmp = _mm_aesdec_si128(tmp, rk128[24]);
        tmp = _mm_aesdec_si128(tmp, rk128[22]);
        tmp = _mm_aesdec_si128(tmp, rk128[20]);
        tmp = _mm_aesdec_si128(tmp, rk128[18]);
        tmp = _mm_aesdec_si128(tmp, rk128[16]);
        tmp = _mm_aesdec_si128(tmp, rk128[14]);
        tmp = _mm_aesdec_si128(tmp, rk128[12]);
        tmp = _mm_aesdec_si128(tmp, rk128[10]);
        tmp = _mm_aesdec_si128(tmp, rk128[8]);
        tmp = _mm_aesdec_si128(tmp, rk128[6]);
        tmp = _mm_aesdec_si128(tmp, rk128[4]);
        tmp = _mm_aesdec_si128(tmp, rk128[2]);

        tmp = _mm_aesdeclast_si128(tmp, rk128[0]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;

    }

    return (size_t) (out - outStart);


}

void intel::ecb::AesEcb256W256D::init(unsigned char *key) {
    auto *rk = new __m128i[15];
    memset(rk, 0, sizeof(__m128i) * 15);
    init_256(rk, key, false);

    for (int t = 0; t < 15; t++) {
        roundKeys256[t] = _mm256_set_m128i(rk[t], rk[t]);
    }

    memset(rk, 0, sizeof(__m128i) * 15);
    delete[] rk;
}
