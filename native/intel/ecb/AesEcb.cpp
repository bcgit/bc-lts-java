//
// Created  on 18/5/2022.
//

#include <cstring>
#include "AesEcb.h"
#include "../common.h"
#include "../aes/aes_common_128b.h"


/**
 * Return 16 bytes for non VAES variant.
 * @return 16
 */
uint32_t intel::ecb::AesEcb::getMultiBlockSize() {
    return ECB_BLOCK_SIZE_4;
}


intel::ecb::AesEcb::AesEcb() {
    roundKeys = new __m128i[15];
}

intel::ecb::AesEcb::~AesEcb() {
    memset(roundKeys, 0, 15 * sizeof(__m128i));
    delete[] roundKeys;
}

void intel::ecb::AesEcb::reset() {

}


//
// Key and Direction variants no VAES support
//
intel::ecb::AesEcb128E::AesEcb128E() : AesEcb() {}

intel::ecb::AesEcb128E::~AesEcb128E() = default;

static inline void aes_ecb_blocks_128b(unsigned char *in, unsigned char *out,
                                           const __m128i *roundKeys, const uint32_t num_blocks,
                                           const int num_rounds, const int is_encrypt) {

    if (num_blocks >= 8) {
        auto b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        auto b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);
        auto b3 = _mm_loadu_si128((const __m128i *) &in[2 * 16]);
        auto b4 = _mm_loadu_si128((const __m128i *) &in[3 * 16]);
        auto b5 = _mm_loadu_si128((const __m128i *) &in[4 * 16]);
        auto b6 = _mm_loadu_si128((const __m128i *) &in[5 * 16]);
        auto b7 = _mm_loadu_si128((const __m128i *) &in[6 * 16]);
        auto b8 = _mm_loadu_si128((const __m128i *) &in[7 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(b1, b2, b3, b4, b5, b6, b7, b8, roundKeys, num_rounds, 8);
        else
            aesdec_8_blocks_128b(b1, b2, b3, b4, b5, b6, b7, b8, roundKeys, num_rounds, 8);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 16], b3);
        _mm_storeu_si128((__m128i *) &out[3 * 16], b4);
        _mm_storeu_si128((__m128i *) &out[4 * 16], b5);
        _mm_storeu_si128((__m128i *) &out[5 * 16], b6);
        _mm_storeu_si128((__m128i *) &out[6 * 16], b7);
        _mm_storeu_si128((__m128i *) &out[7 * 16], b8);
    } else if (num_blocks == 7) {
        auto b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        auto b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);
        auto b3 = _mm_loadu_si128((const __m128i *) &in[2 * 16]);
        auto b4 = _mm_loadu_si128((const __m128i *) &in[3 * 16]);
        auto b5 = _mm_loadu_si128((const __m128i *) &in[4 * 16]);
        auto b6 = _mm_loadu_si128((const __m128i *) &in[5 * 16]);
        auto b7 = _mm_loadu_si128((const __m128i *) &in[6 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(b1, b2, b3, b4, b5, b6, b7, b7, roundKeys, num_rounds, 7);
        else
            aesdec_8_blocks_128b(b1, b2, b3, b4, b5, b6, b7, b7, roundKeys, num_rounds, 7);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 16], b3);
        _mm_storeu_si128((__m128i *) &out[3 * 16], b4);
        _mm_storeu_si128((__m128i *) &out[4 * 16], b5);
        _mm_storeu_si128((__m128i *) &out[5 * 16], b6);
        _mm_storeu_si128((__m128i *) &out[6 * 16], b7);
    } else if (num_blocks == 6) {
        auto b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        auto b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);
        auto b3 = _mm_loadu_si128((const __m128i *) &in[2 * 16]);
        auto b4 = _mm_loadu_si128((const __m128i *) &in[3 * 16]);
        auto b5 = _mm_loadu_si128((const __m128i *) &in[4 * 16]);
        auto b6 = _mm_loadu_si128((const __m128i *) &in[5 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(b1, b2, b3, b4, b5, b6, b6, b6, roundKeys, num_rounds, 6);
        else
            aesdec_8_blocks_128b(b1, b2, b3, b4, b5, b6, b6, b6, roundKeys, num_rounds, 6);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 16], b3);
        _mm_storeu_si128((__m128i *) &out[3 * 16], b4);
        _mm_storeu_si128((__m128i *) &out[4 * 16], b5);
        _mm_storeu_si128((__m128i *) &out[5 * 16], b6);
    } else if (num_blocks == 5) {
        auto b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        auto b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);
        auto b3 = _mm_loadu_si128((const __m128i *) &in[2 * 16]);
        auto b4 = _mm_loadu_si128((const __m128i *) &in[3 * 16]);
        auto b5 = _mm_loadu_si128((const __m128i *) &in[4 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(b1, b2, b3, b4, b5, b5, b5, b5, roundKeys, num_rounds, 5);
        else
            aesdec_8_blocks_128b(b1, b2, b3, b4, b5, b5, b5, b5, roundKeys, num_rounds, 5);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 16], b3);
        _mm_storeu_si128((__m128i *) &out[3 * 16], b4);
        _mm_storeu_si128((__m128i *) &out[4 * 16], b5);
    } else if (num_blocks == 4) {
        auto b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        auto b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);
        auto b3 = _mm_loadu_si128((const __m128i *) &in[2 * 16]);
        auto b4 = _mm_loadu_si128((const __m128i *) &in[3 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(b1, b2, b3, b4, b4, b4, b4, b4, roundKeys, num_rounds, 4);
        else
            aesdec_8_blocks_128b(b1, b2, b3, b4, b4, b4, b4, b4, roundKeys, num_rounds, 4);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 16], b3);
        _mm_storeu_si128((__m128i *) &out[3 * 16], b4);
    } else if (num_blocks == 3) {
        auto b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        auto b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);
        auto b3 = _mm_loadu_si128((const __m128i *) &in[2 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(b1, b2, b3, b3, b3, b3, b3, b3, roundKeys, num_rounds, 3);
        else
            aesdec_8_blocks_128b(b1, b2, b3, b3, b3, b3, b3, b3, roundKeys, num_rounds, 3);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 16], b3);
    } else if (num_blocks == 2) {
        auto b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);
        auto b2 = _mm_loadu_si128((const __m128i *) &in[1 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(b1, b2, b2, b2, b2, b2, b2, b2, roundKeys, num_rounds, 2);
        else
            aesdec_8_blocks_128b(b1, b2, b2, b2, b2, b2, b2, b2, roundKeys, num_rounds, 2);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 16], b2);
    } else if (num_blocks == 1) {
        auto b1 = _mm_loadu_si128((const __m128i *) &in[0 * 16]);

        if (is_encrypt)
            aesenc_8_blocks_128b(b1, b1, b1, b1, b1, b1, b1, b1, roundKeys, num_rounds, 1);
        else
            aesdec_8_blocks_128b(b1, b1, b1, b1, b1, b1, b1, b1, roundKeys, num_rounds, 1);

        _mm_storeu_si128((__m128i *) &out[0 * 16], b1);
    }

}


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


    while (blocks >= 8) {
        aes_ecb_blocks_128b(in, out, roundKeys, 8, 10, 1);
        blocks -= 8;
        out += (ECB_BLOCK_SIZE * 8);
        in += (ECB_BLOCK_SIZE * 8);
    }


    aes_ecb_blocks_128b(in, out, roundKeys, blocks, 10, 1);
    out += (ECB_BLOCK_SIZE * blocks);


    size_t len = (out - outStart);



    return len;

}

void intel::ecb::AesEcb128E::init(unsigned char *key) {
    init_128(roundKeys, key, true);
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

    while (blocks >= 8) {
        aes_ecb_blocks_128b(in, out, roundKeys, 8, 12, 1);
        blocks -= 8;
        out += (ECB_BLOCK_SIZE * 8);
        in += (ECB_BLOCK_SIZE * 8);
    }

    aes_ecb_blocks_128b(in, out, roundKeys, blocks, 12, 1);
    out += (ECB_BLOCK_SIZE * blocks);


    return (size_t) (out - outStart);

}


void intel::ecb::AesEcb192E::init(unsigned char *key) {
    init_192(roundKeys, key, true);
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

    while (blocks >= 8) {
        aes_ecb_blocks_128b(in, out, roundKeys, 8, 14, 1);
        blocks -= 8;
        out += (ECB_BLOCK_SIZE * 8);
        in += (ECB_BLOCK_SIZE * 8);
    }

    aes_ecb_blocks_128b(in, out, roundKeys, blocks, 14, 1);
    out += (ECB_BLOCK_SIZE * blocks);


    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb256E::init(unsigned char *key) {
    init_256(roundKeys, key, true);
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

    while (blocks >= 8) {
        aes_ecb_blocks_128b(in, out, roundKeys, 8, 10, 0);
        blocks -= 8;
        out += (ECB_BLOCK_SIZE * 8);
        in += (ECB_BLOCK_SIZE * 8);
    }

    aes_ecb_blocks_128b(in, out, roundKeys, blocks, 10, 0);
    out += (ECB_BLOCK_SIZE * blocks);


    return (size_t) (out - outStart);

}


void intel::ecb::AesEcb128D::init(unsigned char *key) {
    init_128(roundKeys, key, false);

}


intel::ecb::AesEcb192D::AesEcb192D() : AesEcb() {}

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

    while (blocks >= 8) {
        aes_ecb_blocks_128b(in, out, roundKeys, 8, 12, 0);
        blocks -= 8;
        out += (ECB_BLOCK_SIZE * 8);
        in += (ECB_BLOCK_SIZE * 8);
    }

    aes_ecb_blocks_128b(in, out, roundKeys, blocks, 12, 0);
    out += (ECB_BLOCK_SIZE * blocks);


    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb192D::init(unsigned char *key) {
    init_192(roundKeys, key, false);
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

    while (blocks >= 8) {
        aes_ecb_blocks_128b(in, out, roundKeys, 8, 14, 0);
        blocks -= 8;
        out += (ECB_BLOCK_SIZE * 8);
        in += (ECB_BLOCK_SIZE * 8);
    }

    aes_ecb_blocks_128b(in, out, roundKeys, blocks, 14, 0);
    out += (ECB_BLOCK_SIZE * blocks);


    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb256D::init(unsigned char *key) {
    init_256(roundKeys, key, false);
}
