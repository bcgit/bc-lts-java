//
// Created  on 18/5/2022.
//

#include <cstring>
#include <stdexcept>
#include "gcm.h"
#include "AesGcm.h"
#include "../../exceptions/CipherTextException.h"
#include "../../exceptions/OutputLengthException.h"
#include <iostream>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>


__m128i intel::gcm::AesGcm::BSWAP_EPI64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);
__m128i intel::gcm::AesGcm::BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

#define BLOCKS_REMAINING_INIT ((1L << 32) - 2L)

bool areEqualCT(unsigned char *left, unsigned char *right, size_t len) {

    if (left == nullptr) {
        throw (std::invalid_argument("left is null"));
    }

    if (right == nullptr) {
        throw (std::invalid_argument("right is null"));
    }

    uint32_t nonEqual = 0;

    for (int i = 0; i != len; i++) {
        nonEqual |= (left[i] ^ right[i]);
    }

    return nonEqual == 0;

}

__m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32 (temp2, 0xff);
    temp3 = _mm_slli_si128 (temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);

    memset(&temp2, 0, sizeof(__m128i));
    memset(&temp3, 0, sizeof(__m128i));
    return temp1;
}

inline void KEY_192_ASSIST(__m128i *temp1, __m128i *temp2, __m128i *temp3) {
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32 (*temp2, 0x55);
    temp4 = _mm_slli_si128 (*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
    *temp2 = _mm_shuffle_epi32(*temp1, 0xff);
    temp4 = _mm_slli_si128 (*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, *temp2);
}

inline void KEY_256_ASSIST_1(__m128i *temp1, __m128i *temp2) {
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
    temp4 = _mm_slli_si128 (*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
}

inline void KEY_256_ASSIST_2(__m128i *temp1, __m128i *temp3) {
    __m128i temp2, temp4;
    temp4 = _mm_aeskeygenassist_si128 (*temp1, 0x0);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128 (*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, temp2);
}

inline void init_256(__m128i *rk, unsigned char *uk, bool enc) {
    __m128i temp1, temp2, temp3;

    temp1 = _mm_loadu_si128((__m128i *) uk);
    temp3 = _mm_loadu_si128((__m128i *) (uk + 16));
    rk[0] = temp1;
    rk[1] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x01);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[2] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    rk[3] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x02);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[4] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    rk[5] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x04);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[6] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    rk[7] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x08);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[8] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    rk[9] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x10);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[10] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    rk[11] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x20);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[12] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    rk[13] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x40);
    KEY_256_ASSIST_1(&temp1, &temp2);
    rk[14] = temp1;

    if (!enc) {
        rk[1] = _mm_aesimc_si128(rk[1]);
        rk[2] = _mm_aesimc_si128(rk[2]);
        rk[3] = _mm_aesimc_si128(rk[3]);
        rk[4] = _mm_aesimc_si128(rk[4]);
        rk[5] = _mm_aesimc_si128(rk[5]);
        rk[6] = _mm_aesimc_si128(rk[6]);
        rk[7] = _mm_aesimc_si128(rk[7]);
        rk[8] = _mm_aesimc_si128(rk[8]);
        rk[9] = _mm_aesimc_si128(rk[9]);
        rk[10] = _mm_aesimc_si128(rk[10]);
        rk[11] = _mm_aesimc_si128(rk[11]);
        rk[12] = _mm_aesimc_si128(rk[12]);
        rk[13] = _mm_aesimc_si128(rk[13]);
    }

    memset(&temp1, 0, sizeof(__m128i));
    memset(&temp2, 0, sizeof(__m128i));
    memset(&temp3, 0, sizeof(__m128i));
}

inline void init_192(__m128i *rk, unsigned char *uk, bool enc) {
    __m128i temp1, temp2, temp3, temp4;

    temp1 = _mm_loadu_si128((__m128i *) uk);
    temp3 = _mm_loadu_si128((__m128i *) (uk + 16));
    rk[0] = temp1;
    rk[1] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x1);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);


    rk[1] = (__m128i) _mm_shuffle_pd((__m128d) rk[1],
                                     (__m128d) temp1, 0);
    rk[2] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x2);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    rk[3] = temp1;
    rk[4] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x4);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);

    rk[4] = (__m128i) _mm_shuffle_pd((__m128d) rk[4],
                                     (__m128d) temp1, 0);
    rk[5] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


    rk[4] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(rk[4]),
                                            _mm_castsi128_pd(temp1), 0));
    rk[5] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 1));


    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x8);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    rk[6] = temp1;
    rk[7] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x10);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);


    rk[7] = (__m128i) _mm_shuffle_pd((__m128d) rk[7],
                                     (__m128d) temp1, 0);
    rk[8] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x20);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    rk[9] = temp1;
    rk[10] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x40);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);


    rk[10] = (__m128i) _mm_shuffle_pd((__m128d) rk[10],
                                      (__m128d) temp1, 0);
    rk[11] = (__m128i) _mm_shuffle_pd((__m128d) temp1, (__m128d) temp3, 1);


    temp2 = _mm_aeskeygenassist_si128 (temp3, 0x80);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    rk[12] = temp1;


    if (!enc) {
        rk[1] = _mm_aesimc_si128(rk[1]);
        rk[2] = _mm_aesimc_si128(rk[2]);
        rk[3] = _mm_aesimc_si128(rk[3]);
        rk[4] = _mm_aesimc_si128(rk[4]);
        rk[5] = _mm_aesimc_si128(rk[5]);
        rk[6] = _mm_aesimc_si128(rk[6]);
        rk[7] = _mm_aesimc_si128(rk[7]);
        rk[8] = _mm_aesimc_si128(rk[8]);
        rk[9] = _mm_aesimc_si128(rk[9]);
        rk[10] = _mm_aesimc_si128(rk[10]);
        rk[11] = _mm_aesimc_si128(rk[11]);
    }

    memset(&temp1, 0, sizeof(__m128i));
    memset(&temp2, 0, sizeof(__m128i));
    memset(&temp3, 0, sizeof(__m128i));
    memset(&temp4, 0, sizeof(__m128i));
}

inline void init_128(__m128i *rk, unsigned char *uk, bool enc) {
    __m128i temp1;
    __m128i temp2;

    temp1 = _mm_loadu_si128((__m128i *) uk);
    rk[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1, 0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    rk[10] = temp1;

    if (!enc) {
        rk[1] = _mm_aesimc_si128(rk[1]);
        rk[2] = _mm_aesimc_si128(rk[2]);
        rk[3] = _mm_aesimc_si128(rk[3]);
        rk[4] = _mm_aesimc_si128(rk[4]);
        rk[5] = _mm_aesimc_si128(rk[5]);
        rk[6] = _mm_aesimc_si128(rk[6]);
        rk[7] = _mm_aesimc_si128(rk[7]);
        rk[8] = _mm_aesimc_si128(rk[8]);
        rk[9] = _mm_aesimc_si128(rk[9]);
    }
    memset(&temp1, 0, sizeof(__m128i));
    memset(&temp2, 0, sizeof(__m128i));
}


intel::gcm::AesGcm::AesGcm() : GCM() {
    roundKeys = new __m128i[15];
    rounds = 0;
    encryption = false;
    macBlock = nullptr;
    macBlockLen = 0;
    last_aad_block = _mm_setzero_si128();
    S_atPre = _mm_setzero_si128();
    S_at = _mm_setzero_si128();
    initAD = nullptr;
    bufBlock = nullptr;
    bufBlockPtr = 0;
    bufBlockLen = 0;
    exp = new Exponentiator();

    blocksRemaining = BLOCKS_REMAINING_INIT; // page 8, len(P) <= 2^39 - 256, one block taken by tag, but doFinal on J0.
}

intel::gcm::AesGcm::~AesGcm() {
    memset(roundKeys, 0, sizeof(__m128i) * 15);
    delete[] roundKeys;
    rounds = 0;
    delete[] macBlock;
    delete[] initAD;

    if (bufBlock != nullptr) {
        memset(bufBlock, 0, bufBlockLen);
        delete[] bufBlock;
    }

    delete exp;

}

void intel::gcm::AesGcm::reset(bool keepMac) {

    atLength = 0;
    totalBytes = 0;
    bufBlockPtr = 0;
    atBlockPos = 0;
    atLengthPre = 0;
    last_aad_block = _mm_setzero_si128();
    last_block = _mm_setzero_si128();
    S_atPre = _mm_setzero_si128();
    S_at = _mm_setzero_si128();


    memset(bufBlock, 0, bufBlockLen);

    if (!keepMac) {
        memset(macBlock, 0, macBlockLen);
    }

    X = initialX;
    Y = initialY;
    T = initialT;
    H = initialH;

    if (initAD != nullptr) {
        processAADBytes(initAD, 0, initADLen);
    }

    last_block = _mm_setzero_si128();
    ctr1 = _mm_shuffle_epi8(Y, BSWAP_EPI64);

    blocksRemaining = BLOCKS_REMAINING_INIT; // page 8, len(P) <= 2^39 - 256, one block taken by tag, but doFinal on J0.

}


void intel::gcm::AesGcm::init(bool encryption, unsigned char *key, size_t keyLen, unsigned char *nonce, size_t nonceLen,
                              unsigned char *initialText,
                              size_t initialTextLen, size_t macSizeBytes) {


    this->encryption = encryption;
    atLength = 0;
    totalBytes = 0;
    atBlockPos = 0;
    atLengthPre = 0;
    last_aad_block = _mm_setzero_si128(); // holds partial block of associated text.
    last_block = _mm_setzero_si128();


    // We had old initial text drop it here.
    if (initAD != nullptr) {
        memset(initAD, 0, initADLen);
        delete[] initAD;
        initAD = nullptr;
        initADLen = 0;
    }

    if (initialText != nullptr) {

        //
        // We keep a copy so that if the instances is reset it can be returned to
        // the same state it was before the first data is processed.
        //

        initAD = new unsigned char[initialTextLen];
        initADLen = initialTextLen;
        memcpy(initAD, initialText, initADLen);
    }


    //
    // the assumption here is that init is called rarely.
    // so we will zero and create a new macBlock and bufBlock
    //
    if (macBlock != nullptr) {
        memset(macBlock, 0, macBlockLen);
        delete macBlock;
    }

    //
    // Setup new mac block
    //
    this->macBlockLen = macSizeBytes;
    macBlock = new unsigned char[macBlockLen];
    memset(macBlock, 0, macBlockLen);


    if (bufBlock != nullptr) {
        memset(bufBlock, 0, bufBlockLen);
        delete[] bufBlock;
        bufBlockPtr = 0;
    }

    bufBlockLen = encryption ? FOUR_BLOCKS : (FOUR_BLOCKS + macSizeBytes);
    bufBlock = new unsigned char[bufBlockLen];
    memset(bufBlock, 0, bufBlockLen);
    bufBlockPtr = 0;


    switch (keyLen) {
        case 16:
            rounds = 10;
            init_128(this->roundKeys, key, true);
            break;

        case 24:
            rounds = 12;
            init_192(this->roundKeys, key, true);
            break;

        case 32:
            rounds = 14;
            init_256(this->roundKeys, key, true);
            break;

        default:
            throw std::invalid_argument("invalid key len");
    }

//    //
//    // Set up key schedule.
//    //
//    intel::aes::init(rounds, true, this->roundKeys, key);

    S_at = _mm_setzero_si128();
    S_atPre = _mm_setzero_si128();

    X = _mm_setzero_si128();
    Y = _mm_setzero_si128();
    T = _mm_setzero_si128();
    H = _mm_setzero_si128();

    __m128i tmp1, tmp2, tmp3, tmp4;

    if (nonceLen == 12) {
        Y = _mm_loadu_si128((__m128i *) nonce);
        Y = _mm_insert_epi32(Y, 0x1000000, 3);

        tmp1 = _mm_xor_si128(X, roundKeys[0]);
        tmp2 = _mm_xor_si128(Y, roundKeys[0]);
        for (int j = 1; j < rounds - 1; j += 2) {
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j]);
            tmp2 = _mm_aesenc_si128(tmp2, roundKeys[j]);
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j + 1]);
            tmp2 = _mm_aesenc_si128(tmp2, roundKeys[j + 1]);
        }

        tmp1 = _mm_aesenc_si128(tmp1, roundKeys[rounds - 1]);
        tmp2 = _mm_aesenc_si128(tmp2, roundKeys[rounds - 1]);

        H = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);
        T = _mm_aesenclast_si128(tmp2, roundKeys[rounds]);
        H = _mm_shuffle_epi8(H, BSWAP_MASK);

    } else {
        tmp1 = _mm_xor_si128(X, roundKeys[0]);
        int j;
        for (j = 1; j < rounds; j++) {
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j]);
        }
        H = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);
        H = _mm_shuffle_epi8(H, BSWAP_MASK);
        Y = _mm_xor_si128(Y, Y); // ?
        int i;
        for (i = 0; i < nonceLen / 16; i++) {
            tmp1 = _mm_loadu_si128(&((__m128i *) nonce)[i]);
            tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
            Y = _mm_xor_si128(Y, tmp1);
            gfmul(Y, H, &Y);
        }
        if (nonceLen % 16) {
            for (j = 0; j < nonceLen % 16; j++) {
                ((unsigned char *) &last_block)[j] = nonce[i * 16 + j];
            }
            tmp1 = last_block;
            tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
            Y = _mm_xor_si128(Y, tmp1);
            gfmul(Y, H, &Y);
        }
        tmp1 = _mm_insert_epi64(tmp1, nonceLen * 8, 0);
        tmp1 = _mm_insert_epi64(tmp1, 0, 1);

        Y = _mm_xor_si128(Y, tmp1);
        gfmul(Y, H, &Y);
        Y = _mm_shuffle_epi8(Y, BSWAP_MASK);
        // E(K,Y0)

        tmp1 = _mm_xor_si128(Y, roundKeys[0]);
        for (j = 1; j < rounds; j++) {
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j]);
        }
        T = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);
    }

    //
    // Capture initial state.
    //
    initialX = X;
    initialY = Y;
    initialT = T;
    initialH = H;

    //
    // Process any initial associated data.
    //
    if (initAD != nullptr) {
        processAADBytes(initAD, 0, initADLen);
    }

    last_block = _mm_setzero_si128();

    //
    // Counter is pre incremented in processBlock and processFourBlocks
    //
    ctr1 = _mm_shuffle_epi8(Y, BSWAP_EPI64);

}

size_t intel::gcm::AesGcm::getMacLen() {
    return this->macBlockLen;
}

void intel::gcm::AesGcm::getMac(unsigned char *dest) {
    memcpy(dest, macBlock, macBlockLen);
}


size_t intel::gcm::AesGcm::getOutputSize(size_t len) {
    size_t totalData = len + bufBlockPtr;
    if (encryption) {
        return totalData + macBlockLen;
    }
    return totalData < macBlockLen ? 0 : totalData - macBlockLen;
}

size_t intel::gcm::AesGcm::getUpdateOutputSize(size_t len) {
    size_t totalData = len + bufBlockPtr;
    if (!encryption) {
        if (totalData < bufBlockLen) {
            return 0;
        }
         totalData -= macBlockLen;
    }
    return totalData - totalData % FOUR_BLOCKS;
}

void intel::gcm::AesGcm::processAADByte(unsigned char in) {
    ((unsigned char *) &last_aad_block)[atBlockPos] = in;
    if (++atBlockPos == BLOCK_SIZE) {
        // _gcm_processAadBlock(&last_aad_block,&S_at,&H);
        last_aad_block = _mm_shuffle_epi8(last_aad_block, BSWAP_MASK);
        S_at = _mm_xor_si128(S_at, last_aad_block);
        gfmul(S_at, H, &S_at);
        last_aad_block = _mm_setzero_si128();
        atBlockPos = 0;
        atLength += BLOCK_SIZE;
    }
}

void intel::gcm::AesGcm::processAADBytes(unsigned char *in, size_t inOff, size_t len) {

    auto start = in + inOff;
    auto end = start + len;

    for (unsigned char *pos = start; pos < end;) {
        if (atBlockPos != 0) {
            //
            // Round up to block boundary if possible.
            //
            processAADByte(*pos);
            pos++;
        } else if (end - pos >= BLOCK_SIZE) {
            //
            // Block by block consumption.
            //
            // _gcm_processAadBlock((__m128i *) pos,&S_at,&H);

            last_aad_block = _mm_loadu_si128((__m128i *) pos);
            last_aad_block = _mm_shuffle_epi8(last_aad_block, BSWAP_MASK);
            S_at = _mm_xor_si128(S_at, last_aad_block);
            gfmul(S_at, H, &S_at);
            last_aad_block = _mm_setzero_si128();

            pos += BLOCK_SIZE;
            atLength += BLOCK_SIZE;
        } else if (atBlockPos == 0 && end - pos < BLOCK_SIZE) {
            //
            // first trailing byte
            //
            processAADByte(*pos);
            pos++;
        }
    }
}


size_t intel::gcm::AesGcm::processByte(unsigned char in, unsigned char *out, size_t outputLen) {

    if (totalBytes == 0) {
        initCipher();
    }

    size_t read = 0;
    size_t written = 0;

    processBuffer(&in, 1, out, outputLen, read, written);

    return written;
}


size_t intel::gcm::AesGcm::processBytes(unsigned char *in, size_t inOff, size_t len, unsigned char *out, int outOff,
                                        size_t outputLen) {

    if (totalBytes == 0) {
        initCipher();
    }

    size_t read = 0;
    size_t written = 0;

    unsigned char *start = in + inOff;
    unsigned char *end = start + len;
    unsigned char *outPtr = out + outOff;
    unsigned char *outStart = outPtr;

    for (unsigned char *readPos = start; readPos < end;) {
        processBuffer(readPos, (size_t)(end - readPos), outPtr, outputLen, read, written);
        readPos += read;
        outPtr += written;
    }

    return (size_t)(outPtr - outStart);

}


size_t intel::gcm::AesGcm::doFinal(unsigned char *output, size_t outOff, size_t outLen) {


    if (totalBytes == 0) {
        initCipher();
    }

    unsigned char *start = output + outOff;
    unsigned char *outPtr = start;

    __m128i tmp1;

    size_t limit = bufBlockPtr;

    if (!encryption) {
        if (macBlockLen > bufBlockPtr) {
            throw exceptions::CipherTextException("cipher text too short");
        }
        limit -= macBlockLen;
        totalBytes -= macBlockLen;
    }

    if (bufBlockPtr > 0) {

        //
        // As we process data in four block hunks, our doFinal needs
        // to clean up any:
        // 1. Whole remaining blocks.
        // 2. Any remaining bytes less than one block in length.
        //

        int t = 0;
        if (limit >= BLOCK_SIZE) {

            //
            // Process whole blocks.
            //

            for (; t < ((limit >> 4) << 4); t += BLOCK_SIZE) {
                processBlock(&bufBlock[t], outPtr, outLen);
                outPtr += BLOCK_SIZE;
                outLen -= BLOCK_SIZE;
            }
        }

        if (limit % 16) {
            //
            //  Process remaining data less than one block in length.
            //

            if (outLen < limit % 16) {
                throw exceptions::OutputLengthException("output len too short");
            }

            //
            // Check block count.
            //

            blocksRemaining -= 1;

            if (blocksRemaining < 0) {
                throw std::runtime_error("attempt to process too many blocks in GCM");
            }


            ctr1 = _mm_add_epi32(ctr1, ONE);
            tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
            tmp1 = _mm_xor_si128(tmp1, roundKeys[0]);
            for (int j = 1; j < rounds - 1; j += 2) {
                tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j]);
                tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j + 1]);
            }
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys[rounds - 1]);
            tmp1 = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);

            __m128i in1 = _mm_loadu_si128((__m128i *) &bufBlock[t]);

            tmp1 = _mm_xor_si128(tmp1, in1);
            last_block = tmp1;
            int j = 0;
            for (j = 0; j < limit % 16; j++) {
                *outPtr = ((unsigned char *) &last_block)[j];
                outPtr++;
            }
            for (; j < BLOCK_SIZE; j++) {
                ((unsigned char *) &last_block)[j] = 0;
                ((unsigned char *) &in1)[j] = 0;
            }
            tmp1 = last_block;
            tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);

            if (encryption) {
                X = _mm_xor_si128(X, tmp1);
            } else {
                X = _mm_xor_si128(X, _mm_shuffle_epi8(in1, BSWAP_MASK));
            }
            gfmul(X, H, &X);
        }
    }

    atLength += atBlockPos;

    //
    // Deal with additional associated text that was supplied after
    // the init or reset methods were called.
    //
    if (atLength > atLengthPre) {

        if (atBlockPos > 0) {
            //
            // finalise any outstanding associated data
            // that was less than the block size.
            //
            tmp1 = last_aad_block;
            tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
            S_at = _mm_xor_si128(S_at, tmp1);
            gfmul(S_at, H, &S_at);
        }


        if (atLengthPre > 0) {
            S_at = _mm_xor_si128(S_at, S_atPre);
        }

        size_t c = ((totalBytes * 8) + 127) >> 7;
        __m128i H_c = _mm_setzero_si128();
        exp->init(H);
        exp->exponentiateX(c, &H_c);

        gfmul(S_at, H_c, &S_at);

        X = _mm_xor_si128(X, S_at);
    }


    tmp1 = _mm_insert_epi64(tmp1, totalBytes * 8, 0);
    tmp1 = _mm_insert_epi64(tmp1, atLength * 8, 1);

    unsigned char tmpTag[BLOCK_SIZE];

    X = _mm_xor_si128(X, tmp1);
    gfmul(X, H, &X);
    X = _mm_shuffle_epi8(X, BSWAP_MASK);
    T = _mm_xor_si128(X, T);
    _mm_storeu_si128((__m128i *) tmpTag, T);

    // Copy into mac block
    memcpy(macBlock, tmpTag, macBlockLen);
    memset(tmpTag, 0, BLOCK_SIZE);


    if (encryption) {
        // Append to end of message
        memcpy(outPtr, macBlock, macBlockLen);
        outPtr += macBlockLen;
    } else {
        if (!areEqualCT(macBlock, bufBlock + limit, macBlockLen)) {
            throw exceptions::CipherTextException("mac check in GCM failed");
        }
    }

    reset(true);
    return (size_t)(outPtr - start);
}

void
intel::gcm::AesGcm::processBuffer(unsigned char *in, size_t inlen, unsigned char *out, size_t outputLen, size_t &read,
                                  size_t &written) {


    size_t rem = bufBlockLen - bufBlockPtr;
    size_t toCopy = inlen < rem ? inlen : rem;
    memcpy(bufBlock + bufBlockPtr, in, toCopy);
    bufBlockPtr += toCopy;
    totalBytes += toCopy;

    if (bufBlockPtr == bufBlockLen) {
        if (outputLen < FOUR_BLOCKS) {
            throw exceptions::OutputLengthException("output len too short");
        }
        processFourBlocks(bufBlock, out);
        if (!encryption) {
            memcpy(bufBlock, bufBlock + FOUR_BLOCKS, macBlockLen);
        }
        bufBlockPtr -= FOUR_BLOCKS;
        written = FOUR_BLOCKS;
    } else {
        written = 0;
    }
    read = toCopy;
}


void intel::gcm::AesGcm::processBlock(unsigned char *in, unsigned char *out, size_t outputLen) {

    blocksRemaining -= 1;

    if (blocksRemaining < 0) {
        throw std::runtime_error("attempt to process too many blocks in GCM");
    }

    if (outputLen < BLOCK_SIZE) {
        throw exceptions::OutputLengthException("output len too short");
    }
    int j;
    ctr1 = _mm_add_epi32(ctr1, ONE);
    __m128i tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);

    // print_bytes("ctr: ", &tmp1);
    tmp1 = _mm_xor_si128(tmp1, roundKeys[0]);
    for (j = 1; j < rounds - 1; j += 2) {
        tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j]);
        tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j + 1]);
    }
    tmp1 = _mm_aesenc_si128(tmp1, roundKeys[rounds - 1]);
    tmp1 = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);
    __m128i in1 = _mm_loadu_si128((__m128i *) in);
    tmp1 = _mm_xor_si128(tmp1, in1);
    _mm_storeu_si128((__m128i *) (out), tmp1);
    tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);

    if (encryption) {
        X = _mm_xor_si128(X, tmp1);
    } else {
        X = _mm_xor_si128(X, _mm_shuffle_epi8(in1, BSWAP_MASK));
    }
    gfmul(X, H, &X);


}

void intel::gcm::AesGcm::processFourBlocks(unsigned char *in, unsigned char *out) {
    blocksRemaining -= 4;
    if (blocksRemaining < 0) {
        throw std::runtime_error("attempt to process too many blocks in GCM");
    }
    ctr1 = _mm_add_epi32(ctr1, ONE);

    __m128i ctr2 = _mm_add_epi32(ctr1, ONE);
    __m128i ctr3 = _mm_add_epi32(ctr2, ONE);
    __m128i ctr4 = _mm_add_epi32(ctr3, ONE);

    __m128i tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
    __m128i tmp2 = _mm_shuffle_epi8(ctr2, BSWAP_EPI64);
    __m128i tmp3 = _mm_shuffle_epi8(ctr3, BSWAP_EPI64);
    __m128i tmp4 = _mm_shuffle_epi8(ctr4, BSWAP_EPI64);


    __m128i in1 = _mm_loadu_si128(((__m128i *) in));
    in += BLOCK_SIZE;
    __m128i in2 = _mm_loadu_si128(((__m128i *) in));
    in += BLOCK_SIZE;
    __m128i in3 = _mm_loadu_si128(((__m128i *) in));
    in += BLOCK_SIZE;
    __m128i in4 = _mm_loadu_si128(((__m128i *) in));
    in += BLOCK_SIZE;


    tmp1 = _mm_xor_si128(tmp1, roundKeys[0]);
    tmp2 = _mm_xor_si128(tmp2, roundKeys[0]);
    tmp3 = _mm_xor_si128(tmp3, roundKeys[0]);
    tmp4 = _mm_xor_si128(tmp4, roundKeys[0]);


    for (int j = 1; j < rounds - 1; j += 2) {
        tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j]);
        tmp2 = _mm_aesenc_si128(tmp2, roundKeys[j]);
        tmp3 = _mm_aesenc_si128(tmp3, roundKeys[j]);
        tmp4 = _mm_aesenc_si128(tmp4, roundKeys[j]);

        tmp1 = _mm_aesenc_si128(tmp1, roundKeys[j + 1]);
        tmp2 = _mm_aesenc_si128(tmp2, roundKeys[j + 1]);
        tmp3 = _mm_aesenc_si128(tmp3, roundKeys[j + 1]);
        tmp4 = _mm_aesenc_si128(tmp4, roundKeys[j + 1]);
    }

    tmp1 = _mm_aesenc_si128(tmp1, roundKeys[rounds - 1]);
    tmp2 = _mm_aesenc_si128(tmp2, roundKeys[rounds - 1]);
    tmp3 = _mm_aesenc_si128(tmp3, roundKeys[rounds - 1]);
    tmp4 = _mm_aesenc_si128(tmp4, roundKeys[rounds - 1]);

    tmp1 = _mm_aesenclast_si128(tmp1, roundKeys[rounds]);
    tmp2 = _mm_aesenclast_si128(tmp2, roundKeys[rounds]);
    tmp3 = _mm_aesenclast_si128(tmp3, roundKeys[rounds]);
    tmp4 = _mm_aesenclast_si128(tmp4, roundKeys[rounds]);

    tmp1 = _mm_xor_si128(tmp1, in1);
    tmp2 = _mm_xor_si128(tmp2, in2);
    tmp3 = _mm_xor_si128(tmp3, in3);
    tmp4 = _mm_xor_si128(tmp4, in4);

    _mm_storeu_si128((__m128i *) out, tmp1);
    out += BLOCK_SIZE;
    _mm_storeu_si128((__m128i *) out, tmp2);
    out += BLOCK_SIZE;
    _mm_storeu_si128((__m128i *) out, tmp3);
    out += BLOCK_SIZE;
    _mm_storeu_si128((__m128i *) out, tmp4);
    out += BLOCK_SIZE;

    tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
    tmp2 = _mm_shuffle_epi8(tmp2, BSWAP_MASK);
    tmp3 = _mm_shuffle_epi8(tmp3, BSWAP_MASK);
    tmp4 = _mm_shuffle_epi8(tmp4, BSWAP_MASK);

    if (encryption) {
        X = _mm_xor_si128(X, tmp1);
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, tmp2);
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, tmp3);
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, tmp4);
        gfmul(X, H, &X);
    } else {
        X = _mm_xor_si128(X, _mm_shuffle_epi8(in1, BSWAP_MASK));
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, _mm_shuffle_epi8(in2, BSWAP_MASK));
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, _mm_shuffle_epi8(in3, BSWAP_MASK));
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, _mm_shuffle_epi8(in4, BSWAP_MASK));
        gfmul(X, H, &X);
    }

    ctr1 = ctr4;
}

void intel::gcm::AesGcm::initCipher() {
    if (atLength > 0) {
        S_atPre = S_at;
        atLengthPre = atLength;
    }

    if (atBlockPos > 0) {
        __m128i tmp = _mm_shuffle_epi8(last_aad_block, BSWAP_MASK);
        S_atPre = _mm_xor_si128(S_atPre, tmp);
        gfmul(S_atPre, H, &S_atPre);
        atLengthPre += atBlockPos;
    }

    if (atLengthPre > 0) {
        X = S_atPre;
    }

}

void intel::gcm::AesGcm::setBlocksRemainingDown(int64_t down) {

    if (totalBytes > 0) {
        throw std::runtime_error("cannot be called once transformation has processed data");
    }

    if (blocksRemaining - down > blocksRemaining) {
        throw std::runtime_error("blocks remaining would end up more than exising value");
    }

    blocksRemaining -= down;
}


void intel::gcm::gfmul(__m128i a, __m128i b, __m128i *res) {
    __m128i tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;

    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);

    tmp7 = _mm_srli_epi32(tmp3, 31);
    tmp8 = _mm_srli_epi32(tmp6, 31);
    tmp3 = _mm_slli_epi32(tmp3, 1);
    tmp6 = _mm_slli_epi32(tmp6, 1);


    tmp9 = _mm_srli_si128(tmp7, 12);
    tmp8 = _mm_slli_si128(tmp8, 4);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp3 = _mm_or_si128(tmp3, tmp7);
    tmp6 = _mm_or_si128(tmp6, tmp8);
    tmp6 = _mm_or_si128(tmp6, tmp9);


    tmp7 = _mm_slli_epi32(tmp3, 31);
    tmp8 = _mm_slli_epi32(tmp3, 30);
    tmp9 = _mm_slli_epi32(tmp3, 25);


    tmp7 = _mm_xor_si128(tmp7, tmp8);
    tmp7 = _mm_xor_si128(tmp7, tmp9);
    tmp8 = _mm_srli_si128(tmp7, 4);
    tmp7 = _mm_slli_si128(tmp7, 12);
    tmp3 = _mm_xor_si128(tmp3, tmp7);


    tmp2 = _mm_srli_epi32(tmp3, 1);
    tmp4 = _mm_srli_epi32(tmp3, 2);
    tmp5 = _mm_srli_epi32(tmp3, 7);
    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp2 = _mm_xor_si128(tmp2, tmp5);
    tmp2 = _mm_xor_si128(tmp2, tmp8);


    tmp3 = _mm_xor_si128(tmp3, tmp2);
    tmp6 = _mm_xor_si128(tmp6, tmp3);
    *res = tmp6;

}


intel::gcm::Exponentiator::Exponentiator() {
    this->lookupPow2 = new std::vector<_m128i_wrapper>();
}

intel::gcm::Exponentiator::~Exponentiator() {
    delete lookupPow2;
}

void intel::gcm::Exponentiator::init(__m128i x) {
    lookupPow2->clear();
    lookupPow2->push_back(_m128i_wrapper{x});
}

//y = _mm_shuffle_epi8(y, BSWAP_MASK);

void intel::gcm::Exponentiator::exponentiateX(uint64_t pow, __m128i *output) {
    __m128i y = _mm_set_epi32(1 << 31, 0, 0, 0);

    uint64_t bit = 0;
    while (pow > 0) {
        if ((pow & 1) != 0) {
            ensureAvailable(bit);
            auto tmp = lookupPow2->at(bit);
            gfmul(y, tmp.val, &y);
        }
        ++bit;
        pow >>= 1;
    }
    *output = y;

}

void intel::gcm::Exponentiator::ensureAvailable(uint64_t bit) {
    auto count = lookupPow2->size();
    if (count <= bit) {
        __m128i tmp = lookupPow2->at(count - 1).val;
        do {
            gfmul(tmp, tmp, &tmp);
            lookupPow2->push_back(_m128i_wrapper{tmp});
        } while (++count <= bit);
    }
}



