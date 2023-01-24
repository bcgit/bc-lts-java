//
// Created  on 18/5/2022.
//

#include <immintrin.h>
#include <cstring>
#include "AesEcb.h"
#include "../common.h"



/**
 * Return 16 bytes for non VAES variant.
 * @return 16
 */
uint32_t intel::ecb::AesEcb::getMultiBlockSize() {
    return ECB_BLOCK_SIZE;
}


intel::ecb::AesEcb::AesEcb() {
    roundKeys = new __m128i[15];
}

intel::ecb::AesEcb::~AesEcb() {
    memset(roundKeys,0, 15 * sizeof(__m128i));
    delete[] roundKeys;
}

void intel::ecb::AesEcb::reset() {

}


//
// Key and Direction variants no VAES support
//
intel::ecb::AesEcb128E::AesEcb128E() : AesEcb() {}

intel::ecb::AesEcb128E::~AesEcb128E() = default;


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
size_t intel::ecb::AesEcb128E::processBlocks(unsigned char *input,
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

    for (int t = 0; t < blocks; t++) {

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), roundKeys[0]);

        tmp = _mm_aesenc_si128(tmp, roundKeys[1]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[2]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[3]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[4]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[5]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[6]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[7]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[8]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[9]);

        tmp = _mm_aesenclast_si128(tmp, roundKeys[10]);
        _mm_storeu_si128((__m128i *) out, tmp);


        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;
    }

    return (size_t)(out - outStart);

}

void intel::ecb::AesEcb128E::init(unsigned char *key) {
    init_128(roundKeys,key, true);
}


intel::ecb::AesEcb192E::AesEcb192E() : AesEcb() {}

intel::ecb::AesEcb192E::~AesEcb192E() = default;


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
size_t intel::ecb::AesEcb192E::processBlocks(unsigned char *input,
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

    for (int t = 0; t < blocks; t++) {

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), roundKeys[0]);

        tmp = _mm_aesenc_si128(tmp, roundKeys[1]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[2]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[3]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[4]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[5]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[6]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[7]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[8]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[9]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[10]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[11]);

        tmp = _mm_aesenclast_si128(tmp, roundKeys[12]);
        _mm_storeu_si128((__m128i *) out, tmp);


        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;
    }

    return (size_t)(out - outStart);

}


void intel::ecb::AesEcb192E::init(unsigned char *key) {
    init_192(roundKeys,key, true);
}




intel::ecb::AesEcb256E::AesEcb256E() : AesEcb() {}

intel::ecb::AesEcb256E::~AesEcb256E() = default;

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
size_t intel::ecb::AesEcb256E::processBlocks(unsigned char *input,
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

    for (int t = 0; t < blocks; t++) {

        auto tmp = _mm_xor_si128(
                _mm_loadu_si128((__m128i *) in), roundKeys[0]);

        tmp = _mm_aesenc_si128(tmp, roundKeys[1]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[2]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[3]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[4]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[5]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[6]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[7]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[8]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[9]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[10]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[11]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[12]);
        tmp = _mm_aesenc_si128(tmp, roundKeys[13]);

        tmp = _mm_aesenclast_si128(tmp, roundKeys[14]);
        _mm_storeu_si128((__m128i *) out, tmp);


        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;
    }

    return (size_t)(out - outStart);

}

void intel::ecb::AesEcb256E::init(unsigned char *key) {
    init_256(roundKeys,key, true);
}




intel::ecb::AesEcb128D::AesEcb128D() : AesEcb() {}

intel::ecb::AesEcb128D::~AesEcb128D() = default;

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
size_t intel::ecb::AesEcb128D::processBlocks(unsigned char *input,
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

    for (int t = 0; t < blocks; t++) {

        auto tmp = _mm_loadu_si128((__m128i *) in);

        tmp = _mm_xor_si128(tmp, roundKeys[10]);

        tmp = _mm_aesdec_si128(tmp, roundKeys[9]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[8]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[7]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[6]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[5]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[4]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[3]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[2]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[1]);

        tmp = _mm_aesdeclast_si128(tmp, roundKeys[0]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;
    }

    return (size_t)(out - outStart);

}


void intel::ecb::AesEcb128D::init(unsigned char *key) {
    init_128(roundKeys,key, false);
}




intel::ecb::AesEcb192D::AesEcb192D() : AesEcb(){}

intel::ecb::AesEcb192D::~AesEcb192D() = default;

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
size_t intel::ecb::AesEcb192D::processBlocks(unsigned char *input,
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

    for (int t = 0; t < blocks; t++) {

        auto tmp = _mm_loadu_si128((__m128i *) in);

        tmp = _mm_xor_si128(tmp, roundKeys[12]);

        tmp = _mm_aesdec_si128(tmp, roundKeys[11]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[10]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[9]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[8]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[7]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[6]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[5]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[4]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[3]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[2]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[1]);

        tmp = _mm_aesdeclast_si128(tmp, roundKeys[0]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;
    }

    return (size_t)(out - outStart);

}

void intel::ecb::AesEcb192D::init(unsigned char *key) {
    init_192(roundKeys,key, false);
}



intel::ecb::AesEcb256D::AesEcb256D() : AesEcb() {}

intel::ecb::AesEcb256D::~AesEcb256D() = default;

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
size_t intel::ecb::AesEcb256D::processBlocks(unsigned char *input,
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

    for (int t = 0; t < blocks; t++) {

        auto tmp = _mm_loadu_si128((__m128i *) in);

        tmp = _mm_xor_si128(tmp, roundKeys[14]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[13]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[12]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[11]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[10]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[9]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[8]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[7]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[6]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[5]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[4]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[3]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[2]);
        tmp = _mm_aesdec_si128(tmp, roundKeys[1]);

        tmp = _mm_aesdeclast_si128(tmp, roundKeys[0]);
        _mm_storeu_si128((__m128i *) out, tmp);

        out += ECB_BLOCK_SIZE;
        in += ECB_BLOCK_SIZE;
    }

    return (size_t)(out - outStart);

}

void intel::ecb::AesEcb256D::init(unsigned char *key) {
    init_256(roundKeys,key, false);
}
