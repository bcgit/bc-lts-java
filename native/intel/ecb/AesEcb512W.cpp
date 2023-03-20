//
// Created  on 18/5/2022.
//

#include <immintrin.h>
#include <cstring>
#include <iostream>
#include "AesEcb512W.h"
#include "../common.h"
#include "../aes/aes_common_512b.h"


/**
 * Return 16 bytes.
 * @return 16
 */
uint32_t intel::ecb::AesEcb512W::getMultiBlockSize() {
    return ECB_BLOCK_SIZE_16;
}

intel::ecb::AesEcb512W::AesEcb512W() {
    roundKeys = new __m128i[15];
}

intel::ecb::AesEcb512W::~AesEcb512W() {
    memset(roundKeys, 0, 15 * sizeof(__m128i));
    delete[] roundKeys;
}

void intel::ecb::AesEcb512W::reset() {

}

static inline void aes_ecb_blocks(unsigned char *in, unsigned char *out,
                                  const __m128i *roundKeys, const uint32_t blocks,
                                  const int num_rounds, const int is_encrypt) {

    if (blocks >= 16) {
        auto tmp1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        auto tmp2 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
        auto tmp3 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
        auto tmp4 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);

        if (is_encrypt)
            aesenc_16_blocks_512b(tmp1, tmp2, tmp3, tmp4, roundKeys, num_rounds, 16);
        else
            aesdec_16_blocks_512b(tmp1, tmp2, tmp3, tmp4, roundKeys, num_rounds, 16);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], tmp1);
        _mm512_storeu_si512((__m512i *) &out[1 * 64], tmp2);
        _mm512_storeu_si512((__m512i *) &out[2 * 64], tmp3);
        _mm512_storeu_si512((__m512i *) &out[3 * 64], tmp4);
    } else if (blocks > 12) {
        const uint32_t partial_blocks = blocks - 12;
        auto tmp1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        auto tmp2 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
        auto tmp3 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
        auto tmp4 = mm512_loadu_128b_blocks(&in[3 * 64], partial_blocks);

        if (is_encrypt)
            aesenc_16_blocks_512b(tmp1, tmp2, tmp3, tmp4, roundKeys, num_rounds, 16);
        else
            aesdec_16_blocks_512b(tmp1, tmp2, tmp3, tmp4, roundKeys, num_rounds, 16);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], tmp1);
        _mm512_storeu_si512((__m512i *) &out[1 * 64], tmp2);
        _mm512_storeu_si512((__m512i *) &out[2 * 64], tmp3);
        mm512_storeu_128b_blocks(&out[3 * 64], tmp4, partial_blocks);
    } else if (blocks > 8) {
        const uint32_t partial_blocks = blocks - 8;
        auto tmp1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        auto tmp2 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
        auto tmp3 = mm512_loadu_128b_blocks(&in[2 * 64], partial_blocks);

        if (is_encrypt)
            aesenc_16_blocks_512b(tmp1, tmp2, tmp3, tmp3, roundKeys, num_rounds, 12);
        else
            aesdec_16_blocks_512b(tmp1, tmp2, tmp3, tmp3, roundKeys, num_rounds, 12);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], tmp1);
        _mm512_storeu_si512((__m512i *) &out[1 * 64], tmp2);
        mm512_storeu_128b_blocks(&out[2 * 64], tmp3, partial_blocks);
    } else if (blocks > 4) {
        const uint32_t partial_blocks = blocks - 4;
        auto tmp1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        auto tmp2 = mm512_loadu_128b_blocks(&in[1 * 64], partial_blocks);

        if (is_encrypt)
            aesenc_16_blocks_512b(tmp1, tmp2, tmp2, tmp2, roundKeys, num_rounds, 8);
        else
            aesdec_16_blocks_512b(tmp1, tmp2, tmp2, tmp2, roundKeys, num_rounds, 8);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], tmp1);
        mm512_storeu_128b_blocks(&out[1 * 64], tmp2, partial_blocks);
    } else if (blocks > 0) {
        const uint32_t partial_blocks = blocks;
        auto tmp1 = mm512_loadu_128b_blocks(in, partial_blocks);

        if (is_encrypt)
            aesenc_16_blocks_512b(tmp1, tmp1, tmp1, tmp1, roundKeys, num_rounds, 4);
        else
            aesdec_16_blocks_512b(tmp1, tmp1, tmp1, tmp1, roundKeys, num_rounds, 4);

        mm512_storeu_128b_blocks(out, tmp1, partial_blocks);
    }

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


    while (blocks >= 16) {
        aes_ecb_blocks(in, out, roundKeys, 16, 10, 1);
        blocks -= 16;
        out += ECB_BLOCK_SIZE_16;
        in += ECB_BLOCK_SIZE_16;

    }

    aes_ecb_blocks(in, out, roundKeys, blocks, 10, 1);
    out += (blocks * ECB_BLOCK_SIZE);

    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb512W128E::init(unsigned char *key) {
    init_128(roundKeys, key, true);
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

    while (blocks >= 16) {
        aes_ecb_blocks(in, out, roundKeys, 16, 12, 1);
        blocks -= 16;
        out += ECB_BLOCK_SIZE_16;
        in += ECB_BLOCK_SIZE_16;

    }

    aes_ecb_blocks(in, out, roundKeys, blocks, 12, 1);
    out += (blocks * ECB_BLOCK_SIZE);

    return (size_t) (out - outStart);
}

void intel::ecb::AesEcb512W192E::init(unsigned char *key) {
    init_192(roundKeys, key, true);
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


    while (blocks >= 16) {
        aes_ecb_blocks(in, out, roundKeys, 16, 14, 1);
        blocks -= 16;
        out += ECB_BLOCK_SIZE_16;
        in += ECB_BLOCK_SIZE_16;

    }

    aes_ecb_blocks(in, out, roundKeys, blocks, 14, 1);
    out += (blocks * ECB_BLOCK_SIZE);

    return (size_t) (out - outStart);
}

void intel::ecb::AesEcb512W256E::init(unsigned char *key) {
    init_256(roundKeys, key, true);
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

    while (blocks >= 16) {
        aes_ecb_blocks(in, out, roundKeys, 16, 10, 0);
        blocks -= 16;
        out += ECB_BLOCK_SIZE_16;
        in += ECB_BLOCK_SIZE_16;

    }

    aes_ecb_blocks(in, out, roundKeys, blocks, 10, 0);
    out += (blocks * ECB_BLOCK_SIZE);


    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb512W128D::init(unsigned char *key) {
    init_128(roundKeys, key, false);
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


    while (blocks >= 16) {
        aes_ecb_blocks(in, out, roundKeys, 16, 12, 0);
        blocks -= 16;
        out += ECB_BLOCK_SIZE_16;
        in += ECB_BLOCK_SIZE_16;

    }

    aes_ecb_blocks(in, out, roundKeys, blocks, 12, 0);
    out += (blocks * ECB_BLOCK_SIZE);


    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb512W192D::init(unsigned char *key) {
    init_192(roundKeys, key, false);
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


    while (blocks >= 16) {
        aes_ecb_blocks(in, out, roundKeys, 16, 14, 0);
        blocks -= 16;
        out += ECB_BLOCK_SIZE_16;
        in += ECB_BLOCK_SIZE_16;

    }

    aes_ecb_blocks(in, out, roundKeys, blocks, 14, 0);
    out += (blocks * ECB_BLOCK_SIZE);


    return (size_t) (out - outStart);


}

void intel::ecb::AesEcb512W256D::init(unsigned char *key) {
    init_256(roundKeys, key, false);
}
