//
// Created  on 18/5/2022.
//

#include <cstring>
#include "AesEcb256W.h"
#include "../common.h"
#include "../aes/aes_common_256b.h"


/**
 * Return 16 bytes for non VAES variant.
 * @return 16
 */
uint32_t intel::ecb::AesEcb256W::getMultiBlockSize() {
    return ECB_BLOCK_SIZE_16;
}


intel::ecb::AesEcb256W::AesEcb256W() {
    roundKeys = new __m128i[15];
}

intel::ecb::AesEcb256W::~AesEcb256W() {
    memset(roundKeys, 0, 15 * sizeof(__m128i));
    delete[] roundKeys;
}

void intel::ecb::AesEcb256W::reset() {

}


//
// Key and Direction variants no VAES support
//
intel::ecb::AesEcb256W128E::AesEcb256W128E() : AesEcb256W() {}

intel::ecb::AesEcb256W128E::~AesEcb256W128E() = default;

static inline void aes_ecb_blocks_128b(unsigned char *in, unsigned char *out,
                                       const __m128i *roundKeys, const uint32_t num_blocks,
                                       const int num_rounds, const int is_encrypt) {

    if (num_blocks >= 16) {
        auto b0 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        auto b3 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        auto b4 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);
        auto b5 = _mm256_loadu_si256((const __m256i *) &in[5 * 32]);
        auto b6 = _mm256_loadu_si256((const __m256i *) &in[6 * 32]);
        auto b7 = _mm256_loadu_si256((const __m256i *) &in[7 * 32]);

        if (is_encrypt)
            aesenc_16_blocks_256b(b0, b1, b2, b3, b4, b5, b6, b7, roundKeys, num_rounds, 16);
        else
            aesdec_16_blocks_256b(b0, b1, b2, b3, b4, b5, b6, b7, roundKeys, num_rounds, 16);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], b5);
        _mm256_storeu_si256((__m256i *) &out[6 * 32], b6);
        _mm256_storeu_si256((__m256i *) &out[7 * 32], b7);
    } else if (num_blocks >= 15) {
        auto b0 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        auto b3 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        auto b4 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);
        auto b5 = _mm256_loadu_si256((const __m256i *) &in[5 * 32]);
        auto b6 = _mm256_loadu_si256((const __m256i *) &in[6 * 32]);
        auto b7 = _mm256_broadcastsi128_si256(_mm_load_si128((const __m128i *) &in[7 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(b0, b1, b2, b3, b4, b5, b6, b7, roundKeys, num_rounds, 16);
        else
            aesdec_16_blocks_256b(b0, b1, b2, b3, b4, b5, b6, b7, roundKeys, num_rounds, 16);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], b5);
        _mm256_storeu_si256((__m256i *) &out[6 * 32], b6);
        _mm_storeu_si128((__m128i *) &out[7 * 32], _mm256_castsi256_si128(b7));
    } else if (num_blocks == 14) {
        auto b0 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        auto b3 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        auto b4 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);
        auto b5 = _mm256_loadu_si256((const __m256i *) &in[5 * 32]);
        auto b6 = _mm256_loadu_si256((const __m256i *) &in[6 * 32]);

        if (is_encrypt)
            aesenc_16_blocks_256b(b0, b1, b2, b3, b4, b5, b6, b6, roundKeys, num_rounds, 14);
        else
            aesdec_16_blocks_256b(b0, b1, b2, b3, b4, b5, b6, b6, roundKeys, num_rounds, 14);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], b5);
        _mm256_storeu_si256((__m256i *) &out[6 * 32], b6);

    } else if (num_blocks == 13) {
        auto b0 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        auto b3 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        auto b4 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);
        auto b5 = _mm256_loadu_si256((const __m256i *) &in[5 * 32]);
        auto b6 = _mm256_broadcastsi128_si256(_mm_load_si128((const __m128i *) &in[6 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(b0, b1, b2, b3, b4, b5, b6, b6, roundKeys, num_rounds, 14);
        else
            aesdec_16_blocks_256b(b0, b1, b2, b3, b4, b5, b6, b6, roundKeys, num_rounds, 14);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b0);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], b5);
        _mm_storeu_si128((__m128i *) &out[6 * 32], _mm256_castsi256_si128(b6));

    } else if (num_blocks == 12) {
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        auto b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        auto b4 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        auto b5 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);
        auto b6 = _mm256_loadu_si256((const __m256i *) &in[5 * 32]);


        if (is_encrypt)
            aesenc_16_blocks_256b(b1, b2, b3, b4, b5, b6, b6, b6, roundKeys, num_rounds, 12);
        else
            aesdec_16_blocks_256b(b1, b2, b3, b4, b5, b6, b6, b6, roundKeys, num_rounds, 12);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b5);
        _mm256_storeu_si256((__m256i *) &out[5 * 32], b6);
    } else if (num_blocks == 11) {
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        auto b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        auto b4 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        auto b5 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);
        auto b6 = _mm256_broadcastsi128_si256(_mm_load_si128((const __m128i *) &in[5 * 32]));


        if (is_encrypt)
            aesenc_16_blocks_256b(b1, b2, b3, b4, b5, b6, b6, b6, roundKeys, num_rounds, 12);
        else
            aesdec_16_blocks_256b(b1, b2, b3, b4, b5, b6, b6, b6, roundKeys, num_rounds, 12);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b5);
        _mm_storeu_si128((__m128i *) &out[5 * 32], _mm256_castsi256_si128(b6));
    } else if (num_blocks == 10) {
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        auto b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        auto b4 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        auto b5 = _mm256_loadu_si256((const __m256i *) &in[4 * 32]);


        if (is_encrypt)
            aesenc_16_blocks_256b(b1, b2, b3, b4, b5, b5, b5, b5, roundKeys, num_rounds, 10);
        else
            aesdec_16_blocks_256b(b1, b2, b3, b4, b5, b5, b5, b5, roundKeys, num_rounds, 10);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b4);
        _mm256_storeu_si256((__m256i *) &out[4 * 32], b5);

    } else if (num_blocks == 9) {
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        auto b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        auto b4 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);
        auto b5 = _mm256_broadcastsi128_si256(_mm_load_si128((const __m128i *) &in[4 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(b1, b2, b3, b4, b5, b5, b5, b5, roundKeys, num_rounds, 10);
        else
            aesdec_16_blocks_256b(b1, b2, b3, b4, b5, b5, b5, b5, roundKeys, num_rounds, 10);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b4);
        _mm_storeu_si128((__m128i *) &out[4 * 32], _mm256_castsi256_si128(b5));
    } else if (num_blocks == 8) {
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        auto b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        auto b4 = _mm256_loadu_si256((const __m256i *) &in[3 * 32]);

        if (is_encrypt)
            aesenc_16_blocks_256b(b1, b2, b3, b4, b4, b4, b4, b4, roundKeys, num_rounds, 8);
        else
            aesdec_16_blocks_256b(b1, b2, b3, b4, b4, b4, b4, b4, roundKeys, num_rounds, 8);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);
        _mm256_storeu_si256((__m256i *) &out[3 * 32], b4);


    } else if (num_blocks == 7) {
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        auto b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);
        auto b4 = _mm256_broadcastsi128_si256(_mm_load_si128((const __m128i *) &in[3 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(b1, b2, b3, b4, b4, b4, b4, b4, roundKeys, num_rounds, 8);
        else
            aesdec_16_blocks_256b(b1, b2, b3, b4, b4, b4, b4, b4, roundKeys, num_rounds, 8);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);
        _mm_storeu_si128((__m128i *) &out[3 * 32], _mm256_castsi256_si128(b4));
    } else if (num_blocks == 6) {
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        auto b3 = _mm256_loadu_si256((const __m256i *) &in[2 * 32]);


        if (is_encrypt)
            aesenc_16_blocks_256b(b1, b2, b3, b3, b3, b3, b3, b3, roundKeys, num_rounds, 6);
        else
            aesdec_16_blocks_256b(b1, b2, b3, b3, b3, b3, b3, b3, roundKeys, num_rounds, 6);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm256_storeu_si256((__m256i *) &out[2 * 32], b3);

    } else if (num_blocks == 5) {
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);
        auto b3 = _mm256_broadcastsi128_si256(_mm_load_si128((const __m128i *) &in[2 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(b1, b2, b3, b3, b3, b3, b3, b3, roundKeys, num_rounds, 6);
        else
            aesdec_16_blocks_256b(b1, b2, b3, b3, b3, b3, b3, b3, roundKeys, num_rounds, 6);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);
        _mm_storeu_si128((__m128i *) &out[2 * 32], _mm256_castsi256_si128(b3));
    } else if (num_blocks == 4) {
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b2 = _mm256_loadu_si256((const __m256i *) &in[1 * 32]);


        if (is_encrypt)
            aesenc_16_blocks_256b(b1, b2, b2, b2, b2, b2, b2, b2, roundKeys, num_rounds, 4);
        else
            aesdec_16_blocks_256b(b1, b2, b2, b2, b2, b2, b2, b2, roundKeys, num_rounds, 4);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm256_storeu_si256((__m256i *) &out[1 * 32], b2);


    } else if (num_blocks == 3) {
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);
        auto b2 = _mm256_broadcastsi128_si256(_mm_load_si128((const __m128i *) &in[1 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(b1, b2, b2, b2, b2, b2, b2, b2, roundKeys, num_rounds, 4);
        else
            aesdec_16_blocks_256b(b1, b2, b2, b2, b2, b2, b2, b2, roundKeys, num_rounds, 4);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);
        _mm_storeu_si128((__m128i *) &out[1 * 32], _mm256_castsi256_si128(b2));
    } else if (num_blocks == 2) {
        auto b1 = _mm256_loadu_si256((const __m256i *) &in[0 * 32]);

        if (is_encrypt)
            aesenc_16_blocks_256b(b1, b1, b1, b1, b1, b1, b1, b1, roundKeys, num_rounds, 2);
        else
            aesdec_16_blocks_256b(b1, b1, b1, b1, b1, b1, b1, b1, roundKeys, num_rounds, 2);

        _mm256_storeu_si256((__m256i *) &out[0 * 32], b1);


    } else if (num_blocks == 1) {

        auto b1 = _mm256_broadcastsi128_si256(_mm_load_si128((const __m128i *) &in[0 * 32]));

        if (is_encrypt)
            aesenc_16_blocks_256b(b1, b1, b1, b1, b1, b1, b1, b1, roundKeys, num_rounds, 2);
        else
            aesdec_16_blocks_256b(b1, b1, b1, b1, b1, b1, b1, b1, roundKeys, num_rounds, 2);

        _mm_storeu_si128((__m128i *) &out[0 * 32], _mm256_castsi256_si128(b1));
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


    while (blocks >= 16) {
        aes_ecb_blocks_128b(in, out, roundKeys, 16, 10, 1);
        blocks -= 16;
        out += (ECB_BLOCK_SIZE_16);
        in += (ECB_BLOCK_SIZE_16);
    }


    aes_ecb_blocks_128b(in, out, roundKeys, blocks, 10, 1);
    out += (ECB_BLOCK_SIZE * blocks);


    size_t len = (out - outStart);


    return len;

}

void intel::ecb::AesEcb256W128E::init(unsigned char *key) {
    init_128(roundKeys, key, true);
}


intel::ecb::AesEcb256W192E::AesEcb256W192E() : AesEcb256W() {}

intel::ecb::AesEcb256W192E::~AesEcb256W192E() =
default;


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

    while (blocks >= 16) {
        aes_ecb_blocks_128b(in, out, roundKeys, 16, 12, 1);
        blocks -= 16;
        out += (ECB_BLOCK_SIZE_16);
        in += (ECB_BLOCK_SIZE_16);
    }

    aes_ecb_blocks_128b(in, out, roundKeys, blocks, 12, 1);
    out += (ECB_BLOCK_SIZE * blocks);


    return (size_t) (out - outStart);

}


void intel::ecb::AesEcb256W192E::init(unsigned char *key) {
    init_192(roundKeys, key, true);
}


intel::ecb::AesEcb256W256E::AesEcb256W256E() : AesEcb256W() {}

intel::ecb::AesEcb256W256E::~AesEcb256W256E() =
default;

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

    while (blocks >= 16) {
        aes_ecb_blocks_128b(in, out, roundKeys, 16, 14, 1);
        blocks -= 16;
        out += (ECB_BLOCK_SIZE_16);
        in += (ECB_BLOCK_SIZE_16);
    }

    aes_ecb_blocks_128b(in, out, roundKeys, blocks, 14, 1);
    out += (ECB_BLOCK_SIZE * blocks);


    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb256W256E::init(unsigned char *key) {
    init_256(roundKeys, key, true);
}


intel::ecb::AesEcb256W128D::AesEcb256W128D() : AesEcb256W() {}

intel::ecb::AesEcb256W128D::~AesEcb256W128D() =
default;

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

    while (blocks >= 16) {
        aes_ecb_blocks_128b(in, out, roundKeys, 16, 10, 0);
        blocks -= 16;
        out += (ECB_BLOCK_SIZE_16);
        in += (ECB_BLOCK_SIZE_16);
    }

    aes_ecb_blocks_128b(in, out, roundKeys, blocks, 10, 0);
    out += (ECB_BLOCK_SIZE * blocks);


    return (size_t) (out - outStart);

}


void intel::ecb::AesEcb256W128D::init(unsigned char *key) {
    init_128(roundKeys, key, false);

}


intel::ecb::AesEcb256W192D::AesEcb256W192D() : AesEcb256W() {}

intel::ecb::AesEcb256W192D::~AesEcb256W192D() =
default;

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

    while (blocks >= 16) {
        aes_ecb_blocks_128b(in, out, roundKeys, 16, 12, 0);
        blocks -= 16;
        out += (ECB_BLOCK_SIZE_16);
        in += (ECB_BLOCK_SIZE_16);
    }

    aes_ecb_blocks_128b(in, out, roundKeys, blocks, 12, 0);
    out += (ECB_BLOCK_SIZE * blocks);


    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb256W192D::init(unsigned char *key) {
    init_192(roundKeys, key, false);
}


intel::ecb::AesEcb256W256D::AesEcb256W256D() : AesEcb256W() {}

intel::ecb::AesEcb256W256D::~AesEcb256W256D() =
default;

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

    while (blocks >= 16) {
        aes_ecb_blocks_128b(in, out, roundKeys, 16, 14, 0);
        blocks -= 16;
        out += (ECB_BLOCK_SIZE_16);
        in += (ECB_BLOCK_SIZE_16);
    }

    aes_ecb_blocks_128b(in, out, roundKeys, blocks, 14, 0);
    out += (ECB_BLOCK_SIZE * blocks);


    return (size_t) (out - outStart);

}

void intel::ecb::AesEcb256W256D::init(unsigned char *key) {
    init_256(roundKeys, key, false);
}
