//
// Created  on 18/5/2022.
//

#include <cstring>
#include <stdexcept>
#include "gcm.h"
#include "AesGcm512wide.h"
#include "../../exceptions/CipherTextException.h"
#include "../../exceptions/OutputLengthException.h"
#include <immintrin.h>
#include "../common.h"
#include "ghash_512b.h"

__m128i intel::gcm::AesGcm512wideEncrypt::BSWAP_EPI64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6,
                                                                     7);
__m512i intel::gcm::AesGcm512wideEncrypt::BSWAP_EPI64_512 = _mm512_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4,
                                                                            5, 6,
                                                                            7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3,
                                                                            4, 5,
                                                                            6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2,
                                                                            3, 4,
                                                                            5, 6,
                                                                            7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3,
                                                                            4, 5,
                                                                            6, 7);

__m128i intel::gcm::AesGcm512wideEncrypt::BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                                                                    15);
__m512i intel::gcm::AesGcm512wideEncrypt::BSWAP_MASK_512 = _mm512_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                                                           14,
                                                                           15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                                                           13,
                                                                           14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
                                                                           12,
                                                                           13, 14,
                                                                           15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                                                           13,
                                                                           14, 15);


#define BLOCKS_REMAINING_INIT ((1L << 32) - 2L)

bool areEqualCT(const unsigned char *left, const unsigned char *right, size_t len) {

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


intel::gcm::AesGcm512wideEncrypt::AesGcm512wideEncrypt() : GCM() {
    hashKeys = new __m128i[HashKey_Len];
    roundKeys128 = new __m128i[15];
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
    T = _mm_setzero_si128();
    H = _mm_setzero_si128();
    Y = _mm_setzero_si128();
    X = _mm_setzero_si128();
    ctr1 = _mm_setzero_si128();
    ctr12 = _mm512_setzero_si512();
    ctr34 = _mm512_setzero_si512();
    ctr56 = _mm512_setzero_si512();
    ctr78 = _mm512_setzero_si512();
    last_block = _mm_setzero_si128();
    initialH = _mm_setzero_si128();
    initialX = _mm_setzero_si128();
    initialT = _mm_setzero_si128();
    initialY = _mm_setzero_si128();
}

intel::gcm::AesGcm512wideEncrypt::~AesGcm512wideEncrypt() {
    memset(hashKeys, 0, sizeof(__m128i) * HashKey_Len);
    delete[] hashKeys;

    memset(roundKeys128, 0, sizeof(__m128i) * 15);
    delete[] roundKeys128;
    rounds = 0;
    if (macBlock != nullptr) {
        memset(macBlock, 0, macBlockLen);
    }
    delete[] macBlock;

    if (initAD != nullptr) {
        memset(initAD, 0, initADLen);
    }
    delete[] initAD;

    if (bufBlock != nullptr) {
        memset(bufBlock, 0, bufBlockLen);
    }
    delete[] bufBlock;

    memset(&T, 0, sizeof(__m128i));
    memset(&H, 0, sizeof(__m128i));
    memset(&Y, 0, sizeof(__m128i));
    memset(&X, 0, sizeof(__m128i));
    memset(&ctr1, 0, sizeof(__m128i));
    memset(&ctr12, 0, sizeof(__m512i));
    memset(&ctr34, 0, sizeof(__m512i));
    memset(&ctr56, 0, sizeof(__m512i));
    memset(&ctr78, 0, sizeof(__m512i));
    memset(&initialT, 0, sizeof(__m128i));
    memset(&initialH, 0, sizeof(__m128i));
    memset(&initialY, 0, sizeof(__m128i));
    memset(&initialX, 0, sizeof(__m128i));

    delete exp;


}

void intel::gcm::AesGcm512wideEncrypt::reset(bool keepMac) {

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

    // precompute(H, hashKeys);

    if (initAD != nullptr) {
        processAADBytes(initAD, 0, initADLen);
    }

    last_block = _mm_setzero_si128();
    ctr1 = _mm_shuffle_epi8(Y, BSWAP_EPI64);


    ctr12 = _mm512_add_epi32(_mm512_broadcast_i32x4(ctr1),
                             _mm512_set_epi32(0, 4, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0));
    ctr34 = _mm512_add_epi32(_mm512_broadcast_i32x4(ctr1),
                             _mm512_set_epi32(0, 8, 0, 0, 0, 7, 0, 0, 0, 6, 0, 0, 0, 5, 0, 0));
    ctr56 = _mm512_add_epi32(_mm512_broadcast_i32x4(ctr1),
                             _mm512_set_epi32(0, 12, 0, 0, 0, 11, 0, 0, 0, 10, 0, 0, 0, 9, 0, 0));
    ctr78 = _mm512_add_epi32(_mm512_broadcast_i32x4(ctr1),
                             _mm512_set_epi32(0, 16, 0, 0, 0, 15, 0, 0, 0, 14, 0, 0, 0, 13, 0, 0));


    blocksRemaining = BLOCKS_REMAINING_INIT; // page 8, len(P) <= 2^39 - 256, one block taken by tag, but doFinal on J0.

}


void intel::gcm::AesGcm512wideEncrypt::init(bool encryption_, unsigned char *key, size_t keyLen, unsigned char *nonce,
                                            size_t nonceLen,
                                            unsigned char *initialText,
                                            size_t initialTextLen, size_t macSizeBits) {


    this->encryption = encryption_;
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

    this->macBlockLen = macSizeBits / 8;

    macBlock = new unsigned char[macBlockLen];
    memset(macBlock, 0, macBlockLen);


    if (bufBlock != nullptr) {
        memset(bufBlock, 0, bufBlockLen);
        delete[] bufBlock;
        bufBlockPtr = 0;
    }

    bufBlockLen = encryption_ ? BLOCKS_16 : (BLOCKS_16 + macBlockLen);
    bufBlock = new unsigned char[bufBlockLen];
    memset(bufBlock, 0, bufBlockLen);
    bufBlockPtr = 0;


    switch (keyLen) {
        case 16:
            rounds = 10;
            init_128(this->roundKeys128, key, true);
            break;

        case 24:
            rounds = 12;
            init_192(this->roundKeys128, key, true);
            break;

        case 32:
            rounds = 14;
            init_256(this->roundKeys128, key, true);
            break;

        default:
            throw std::invalid_argument("invalid key len");
    }


    S_at = _mm_setzero_si128();
    S_atPre = _mm_setzero_si128();

    X = _mm_setzero_si128();
    Y = _mm_setzero_si128();
    T = _mm_setzero_si128();
    H = _mm_setzero_si128();

    __m128i tmp1, tmp2;
    if (nonceLen == 12) {
        // TODO could cause page fault or something.
        Y = _mm_loadu_si128((__m128i *) nonce);
        Y = _mm_insert_epi32(Y, 0x1000000, 3);

        tmp1 = _mm_xor_si128(X, roundKeys128[0]);
        tmp2 = _mm_xor_si128(Y, roundKeys128[0]);
        for (int j = 1; j < rounds - 1; j += 2) {
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[j]);
            tmp2 = _mm_aesenc_si128(tmp2, roundKeys128[j]);
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[j + 1]);
            tmp2 = _mm_aesenc_si128(tmp2, roundKeys128[j + 1]);
        }

        tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[rounds - 1]);
        tmp2 = _mm_aesenc_si128(tmp2, roundKeys128[rounds - 1]);

        H = _mm_aesenclast_si128(tmp1, roundKeys128[rounds]);
        T = _mm_aesenclast_si128(tmp2, roundKeys128[rounds]);
        H = _mm_shuffle_epi8(H, BSWAP_MASK);


    } else {

        tmp1 = _mm_xor_si128(X, roundKeys128[0]);
        int j;
        for (j = 1; j < rounds; j++) {
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[j]);
        }
        H = _mm_aesenclast_si128(tmp1, roundKeys128[j]);
        H = _mm_shuffle_epi8(H, BSWAP_MASK);
        Y = _mm_xor_si128(Y, Y); // ?
        int i;
        for (i = 0; i < nonceLen / 16; i++) {
            tmp1 = _mm_loadu_si128(&((__m128i *)
                    nonce)[i]);
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
        tmp1 = _mm_insert_epi64(tmp1, (long long) nonceLen * 8, 0);
        tmp1 = _mm_insert_epi64(tmp1, 0, 1);

        Y = _mm_xor_si128(Y, tmp1);
        gfmul(Y, H, &Y);
        Y = _mm_shuffle_epi8(Y, BSWAP_MASK);
        // E(K,Y0)

        tmp1 = _mm_xor_si128(Y, roundKeys128[0]);
        for (j = 1; j < rounds; j++) {
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[j]);
        }
        T = _mm_aesenclast_si128(tmp1, roundKeys128[rounds]);
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


    ctr1 = _mm_shuffle_epi8(Y, BSWAP_EPI64);

    ctr12 = _mm512_add_epi32(_mm512_broadcast_i32x4(ctr1),
                             _mm512_set_epi32(0, 4, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0));
    ctr34 = _mm512_add_epi32(_mm512_broadcast_i32x4(ctr1),
                             _mm512_set_epi32(0, 8, 0, 0, 0, 7, 0, 0, 0, 6, 0, 0, 0, 5, 0, 0));
    ctr56 = _mm512_add_epi32(_mm512_broadcast_i32x4(ctr1),
                             _mm512_set_epi32(0, 12, 0, 0, 0, 11, 0, 0, 0, 10, 0, 0, 0, 9, 0, 0));
    ctr78 = _mm512_add_epi32(_mm512_broadcast_i32x4(ctr1),
                             _mm512_set_epi32(0, 16, 0, 0, 0, 15, 0, 0, 0, 14, 0, 0, 0, 13, 0, 0));


    //
    // Setup some hash keys
    //

    hashKeys[HashKey_0] = H;
    for (int t = HashKey_1; t >= 0; t--) {
        gfmul(hashKeys[t + 1], H, &tmp1);
        hashKeys[t] = tmp1;
    }


    blocksRemaining = BLOCKS_REMAINING_INIT; // page 8, len(P) <= 2^39 - 256, one block taken by tag, but doFinal on J0.
}

size_t intel::gcm::AesGcm512wideEncrypt::getMacLen() {
    return this->macBlockLen;
}

void intel::gcm::AesGcm512wideEncrypt::getMac(unsigned char *dest) {
    memcpy(dest, macBlock, macBlockLen);
}


size_t intel::gcm::AesGcm512wideEncrypt::getOutputSize(size_t len) {
    size_t totalData = len + bufBlockPtr;
    if (encryption) {
        return totalData + macBlockLen;
    }
    return totalData < macBlockLen ? 0 : totalData - macBlockLen;
}

size_t intel::gcm::AesGcm512wideEncrypt::getUpdateOutputSize(size_t len) {
    size_t totalData = len + bufBlockPtr;
    if (!encryption) {
        if (totalData < bufBlockLen) {
            return 0;
        }
        totalData -= macBlockLen;
    }
    return totalData - totalData % BLOCKS_16;
}

void intel::gcm::AesGcm512wideEncrypt::processAADByte(unsigned char in) {
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

void intel::gcm::AesGcm512wideEncrypt::processAADBytes(unsigned char *in, size_t inOff, size_t len) {

    auto start = in + inOff;
    auto end = start + len;

    for (unsigned char *pos = start; pos < end;) {
        if (atBlockPos != 0 || end - pos < BLOCK_SIZE) {
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

            last_aad_block = _mm_loadu_si128((__m128i *)
                                                     pos);
            last_aad_block = _mm_shuffle_epi8(last_aad_block, BSWAP_MASK);
            S_at = _mm_xor_si128(S_at, last_aad_block);
            gfmul(S_at, H, &S_at);
            last_aad_block = _mm_setzero_si128();

            pos += BLOCK_SIZE;
            atLength += BLOCK_SIZE;
        }
    }
}


size_t intel::gcm::AesGcm512wideEncrypt::processByte(unsigned char in, unsigned char *out, size_t outputLen) {

    if (totalBytes == 0) {
        initCipher();
    }

    size_t read = 0;
    size_t written = 0;

    processBuffer(&in, 1, out, outputLen, read, written);

    return written;
}


size_t
intel::gcm::AesGcm512wideEncrypt::processBytes(unsigned char *in, size_t inOff, size_t len, unsigned char *out,
                                               int outOff,
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
        processBuffer(readPos, (size_t) (end - readPos), outPtr, outputLen, read, written);
        readPos += read;
        outPtr += written;
        outputLen -= written;
    }


    return (size_t) (outPtr - outStart);

}


size_t
intel::gcm::AesGcm512wideDecrypt::processBytes(unsigned char *in, size_t inOff, size_t len, unsigned char *out,
                                               int outOff,
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
        processBuffer(readPos, (size_t) (end - readPos), outPtr, outputLen, read, written);
        readPos += read;
        outPtr += written;
        outputLen -= written;
    }


    return (size_t) (outPtr - outStart);

}


size_t intel::gcm::AesGcm512wideEncrypt::doFinal(unsigned char *output, size_t outOff, size_t outLen) {


    if (totalBytes == 0) {
        initCipher();
    }

    unsigned char *start = output + outOff;
    unsigned char *outPtr = start;

    __m128i tmp1;

    size_t limit = bufBlockPtr;

    if (!encryption) {

        // We need at least a mac block
        if (macBlockLen > bufBlockPtr) {
            throw exceptions::CipherTextException("cipher text too short on decryption");
        }
        limit -= macBlockLen; // Limit of cipher text before tag.
        totalBytes -= macBlockLen;

        // decryption so output buffer cannot be less than limit.
        // bytes are to limit are the mac block (tag)
        if (outLen - outOff < limit) {
            throw exceptions::OutputLengthException("output buffer too small on decryption");
        }
    } else {
        // encryption, output must take remaining buffer + mac block
        if (outLen - outOff < bufBlockPtr + macBlockLen) {
            throw exceptions::OutputLengthException("output buffer too small on encryption");
        }
    }

    if (bufBlockPtr > 0) {

        //
        // As we process data in four block hunks, our doFinal needs
        // to clean up any:
        // 1. Whole remaining blocks.
        // 2. Any remaining bytes less than one block in length.
        //

        uint32_t partialBlockPtr = 0;

        if (limit >= BLOCK_SIZE) {
            uint32_t wholeBlockLimit = (uint32_t) ((limit >> 4) << 4);
            uint32_t blocksOfFour = wholeBlockLimit / 64;

            // TODO make inlined function that can do 1,2 or three blocks of four
            // and defer as many reductions as possible.

            //
            // This series of if statements is due to the need to use a different counter and hash key for each
            // block of four.
            // In the final you can have up to 3 sets of four blocks and up to 3 full single blocks + partial data
            //

            if (blocksOfFour > 0) { // First remaining block of four
                ctr1 = _mm_add_epi32(ctr1, FOUR);
                processFourBlocks(&bufBlock[0 * 64], outPtr, outLen, _mm512_loadu_si512((__m512i *) &hashKeys[12]),
                                  ctr12);
                outPtr += BLOCKS_4;
                outLen -= BLOCKS_4;
                partialBlockPtr = BLOCKS_4;

            }

            if (blocksOfFour > 1) { // Second remaining block of four, note different counter and hash key
                ctr1 = _mm_add_epi32(ctr1, FOUR);
                processFourBlocks(&bufBlock[1 * 64], outPtr, outLen, _mm512_loadu_si512((__m512i *) &hashKeys[12]),
                                  ctr34);
                outPtr += BLOCKS_4;
                outLen -= BLOCKS_4;
                partialBlockPtr = BLOCKS_4 * 2;

            }

            if (blocksOfFour > 2) { // Third remaining block of four, note different counter and hash key
                ctr1 = _mm_add_epi32(ctr1, FOUR);
                processFourBlocks(&bufBlock[2 * 64], outPtr, outLen, _mm512_loadu_si512((__m512i *) &hashKeys[12]),
                                  ctr56);
                outPtr += BLOCKS_4;
                outLen -= BLOCKS_4;
                partialBlockPtr = BLOCKS_4 * 3;

            }

            //
            // remaining single blocks/
            //

            for (; partialBlockPtr < wholeBlockLimit; partialBlockPtr += BLOCK_SIZE) {
                processBlock(&bufBlock[partialBlockPtr], outPtr, outLen);
                outPtr += BLOCK_SIZE;
                outLen -= BLOCK_SIZE;
            }
        }

        if (limit % 16) {

            //
            // Check block count.
            //

            blocksRemaining -= 1;

            if (blocksRemaining < 0) {
                throw std::runtime_error("attempt to process too many blocks in GCM");
            }


            ctr1 = _mm_add_epi32(ctr1, ONE);
            tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
            tmp1 = _mm_xor_si128(tmp1, roundKeys128[0]);
            for (int j = 1; j < rounds - 1; j += 2) {
                tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[j]);
                tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[j + 1]);
            }
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[rounds - 1]);
            tmp1 = _mm_aesenclast_si128(tmp1, roundKeys128[rounds]);

            __m128i in1 = _mm_loadu_si128((__m128i *) &bufBlock[partialBlockPtr]);

            tmp1 = _mm_xor_si128(tmp1, in1);
            last_block = tmp1;
            int j;
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


    tmp1 = _mm_insert_epi64(tmp1, (long long) totalBytes * 8, 0);
    tmp1 = _mm_insert_epi64(tmp1, (long long) atLength * 8, 1);

    unsigned char tmpTag[BLOCK_SIZE];

    X = _mm_xor_si128(X, tmp1);
    gfmul(X, H, &X);
    X = _mm_shuffle_epi8(X, BSWAP_MASK);
    T = _mm_xor_si128(X, T);
    _mm_storeu_si128((__m128i *)
                             tmpTag, T);

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

    return (size_t) (outPtr - start);
}

void
intel::gcm::AesGcm512wideEncrypt::processBuffer(unsigned char *in, size_t inlen, unsigned char *out, size_t outputLen,
                                                size_t &read,
                                                size_t &written) {

    read = written = 0;


    if (encryption && bufBlockPtr == 0 && inlen > BLOCKS_16 && outputLen > BLOCKS_16) {
        // Special case when nothing is buffered, and we have more than 16 blocks to process, and we are doing
        // encryption.

        // The hash is calculated on the cipher text so if we are going to interleave reduction and encryption
        // then the reduction is always going to be on the previous cipher texts.
        // Eg:
        // 1. Create initial cipher texts
        // 2. Create subsequent cipher texts supplying previous cipher texts for reduction.
        // 3. Loop back to 2 until input is consumed.
        // 4. Final trailing reduction
        //

        if (out == nullptr) {
            //
            // Java api my supply a null output array if it expects no output, however
            // if output does occur then we need to catch that here.
            //
            throw std::runtime_error("out is null, output generated when no output was expected by caller");
        }

        blocksRemaining -= 16;
        if (blocksRemaining < 0) {
            throw std::runtime_error("attempt to process too many blocks in GCM");
        }

        // Hash keys are constant throughout.
        const __m512i h4 = _mm512_loadu_si512((__m512i *) &hashKeys[12]);
        const __m512i h3 = _mm512_loadu_si512((__m512i *) &hashKeys[8]);
        const __m512i h2 = _mm512_loadu_si512((__m512i *) &hashKeys[4]);
        const __m512i h1 = _mm512_loadu_si512((__m512i *) &hashKeys[0]);

        // Initial set of 16 blocks.
        auto id0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
        auto id1 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
        auto id2 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
        auto id3 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);

        __m512i tmp12 = _mm512_shuffle_epi8(ctr12, BSWAP_EPI64_512);
        __m512i tmp34 = _mm512_shuffle_epi8(ctr34, BSWAP_EPI64_512);
        __m512i tmp56 = _mm512_shuffle_epi8(ctr56, BSWAP_EPI64_512);
        __m512i tmp78 = _mm512_shuffle_epi8(ctr78, BSWAP_EPI64_512);

        ctr1 = _mm_add_epi32(ctr1, SIXTEEN);

        // Move ctrs forward.
        ctr12 = _mm512_add_epi32(ctr12, INC16);
        ctr34 = _mm512_add_epi32(ctr34, INC16);
        ctr56 = _mm512_add_epi32(ctr56, INC16);
        ctr78 = _mm512_add_epi32(ctr78, INC16);


        apply_aes_no_reduction(id0, id1, id2, id3, tmp12, tmp34, tmp56, tmp78, roundKeys128, rounds);

        _mm512_storeu_si512((__m512i *) &out[0 * 64], id0);
        _mm512_storeu_si512((__m512i *) &out[1 * 64], id1);
        _mm512_storeu_si512((__m512i *) &out[2 * 64], id2);
        _mm512_storeu_si512((__m512i *) &out[3 * 64], id3);


        // id0..3 are the initial set of cipher texts but bit swapped

        id0 = _mm512_shuffle_epi8(id0, BSWAP_MASK_512);
        id1 = _mm512_shuffle_epi8(id1, BSWAP_MASK_512);
        id2 = _mm512_shuffle_epi8(id2, BSWAP_MASK_512);
        id3 = _mm512_shuffle_epi8(id3, BSWAP_MASK_512);


        written += BLOCKS_16;
        read += BLOCKS_16;
        totalBytes += BLOCKS_16;
        inlen -= BLOCKS_16;
        outputLen -= BLOCKS_16;

        in += BLOCKS_16;
        out += BLOCKS_16;

        while (inlen >= BLOCKS_16 && outputLen >= BLOCKS_16) {

            blocksRemaining -= 16;
            if (blocksRemaining < 0) {
                throw std::runtime_error("attempt to process too many blocks in GCM");
            }

            // Encrypt next set of 16 blocks passing the result of the last encryption for reduction.

            auto d0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
            auto d1 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
            auto d2 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
            auto d3 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);

            tmp12 = _mm512_shuffle_epi8(ctr12, BSWAP_EPI64_512);
            tmp34 = _mm512_shuffle_epi8(ctr34, BSWAP_EPI64_512);
            tmp56 = _mm512_shuffle_epi8(ctr56, BSWAP_EPI64_512);
            tmp78 = _mm512_shuffle_epi8(ctr78, BSWAP_EPI64_512);

            ctr1 = _mm_add_epi32(ctr1, SIXTEEN);

            // Move ctrs forward.
            ctr12 = _mm512_add_epi32(ctr12, INC16);
            ctr34 = _mm512_add_epi32(ctr34, INC16);
            ctr56 = _mm512_add_epi32(ctr56, INC16);
            ctr78 = _mm512_add_epi32(ctr78, INC16);


            id0 = _mm512_xor_si512(id0, _mm512_castsi128_si512(X));
            apply_aes_with_reduction(d0, d1, d2, d3,
                                     id0, id1, id2, id3,
                                     h1, h2, h3, h4,
                                     tmp12, tmp34, tmp56, tmp78,
                                     roundKeys128, X, rounds);

            _mm512_storeu_si512((__m512i *) &out[0 * 64], d0);
            _mm512_storeu_si512((__m512i *) &out[1 * 64], d1);
            _mm512_storeu_si512((__m512i *) &out[2 * 64], d2);
            _mm512_storeu_si512((__m512i *) &out[3 * 64], d3);

            // id0..3 are now the last cipher texts but bit swapped

            id0 = _mm512_shuffle_epi8(d0, BSWAP_MASK_512);
            id1 = _mm512_shuffle_epi8(d1, BSWAP_MASK_512);
            id2 = _mm512_shuffle_epi8(d2, BSWAP_MASK_512);
            id3 = _mm512_shuffle_epi8(d3, BSWAP_MASK_512);

            written += BLOCKS_16;
            read += BLOCKS_16;
            totalBytes += BLOCKS_16;
            inlen -= BLOCKS_16;
            outputLen -= BLOCKS_16;
            in += BLOCKS_16;
            out += BLOCKS_16;

        }

        //
        // Do trailing reduction
        //

        id0 = _mm512_xor_si512(id0, _mm512_castsi128_si512(X));
        gfmul_multi_reduce(id0, id1, id2, id3, h1, h2, h3, h4, X);

        // fall through to existing code that will buffer trailing blocks if necessary

    }


    if (bufBlockPtr == 0 && inlen > bufBlockLen) {
        if (outputLen < BLOCKS_16) {
            throw exceptions::OutputLengthException("output len too short");
        }
        process16Blocks(in, out);
        written += BLOCKS_16;
        read += BLOCKS_16;
        totalBytes += BLOCKS_16;

    } else {
        size_t rem = bufBlockLen - bufBlockPtr;
        const size_t toCopy = inlen < rem ? inlen : rem;

        memcpy(bufBlock + bufBlockPtr, in, toCopy);
        bufBlockPtr += toCopy;
        totalBytes += toCopy;

        if (bufBlockPtr == bufBlockLen) {
            if (outputLen < BLOCKS_16) {
                throw exceptions::OutputLengthException("output len too short");
            }
            process16Blocks(bufBlock, out);
            bufBlockPtr -= BLOCKS_16;
            written += BLOCKS_16;
        }
        read += toCopy;
    }

}


/**
 * Decryption version, note different class.
 * @param in
 * @param inlen
 * @param out
 * @param outputLen
 * @param read
 * @param written
 */
void
intel::gcm::AesGcm512wideDecrypt::processBuffer(unsigned char *in, size_t inlen, unsigned char *out, size_t outputLen,
                                                size_t &read,
                                                size_t &written) {

    read = written = 0;

    // Buffer has content.





    if (bufBlockPtr > 0 && bufBlockPtr + inlen > bufBlockLen) {

        // We have 16 or more blocks with of data in the buffer.
        // Process them now and copy any residual back to the start of the buffer.
        if (bufBlockPtr >= BLOCKS_16) {
            if (outputLen < BLOCKS_16) {
                throw exceptions::OutputLengthException("output len too short");
            }
            process16Blocks(bufBlock, out);
            written += BLOCKS_16;
            outputLen -= BLOCKS_16;
            out += BLOCKS_16;

            //
            // Copy whatever bytes after the 16 blocks back to the start of the buffer.
            // Internal copy so read does not change.
            //

            size_t toCopy = bufBlockPtr - BLOCKS_16;
            memcpy(bufBlock, bufBlock + bufBlockPtr, toCopy);
            bufBlockPtr = toCopy;
        }

        //
        // There may still data in the buffer but less than before, does
        // our condition for rounding the buffer out still exist with respect
        // to the available input?
        //
        if (bufBlockPtr > 0 && bufBlockPtr + inlen > bufBlockLen) {
            size_t toCopy = BLOCKS_16 - bufBlockPtr;

            // Copy from the input what we need to round out the buffer.
            memcpy(bufBlock + bufBlockPtr, in, toCopy);
            if (outputLen < BLOCKS_16) {
                throw exceptions::OutputLengthException("output len too short");
            }
            process16Blocks(bufBlock, out);
            bufBlockPtr = 0;
            written += BLOCKS_16;
            read += toCopy;
            totalBytes += toCopy;
            outputLen -= BLOCKS_16;
            in += toCopy;
            out += BLOCKS_16;
        }
    }


    //
    // Bulk decryption.
    //
    if (bufBlockPtr == 0 && inlen > bufBlockLen && outputLen > BLOCKS_16) {

        // Hash keys are constant throughout.
        const __m512i h4 = _mm512_loadu_si512((__m512i *) &hashKeys[12]);
        const __m512i h3 = _mm512_loadu_si512((__m512i *) &hashKeys[8]);
        const __m512i h2 = _mm512_loadu_si512((__m512i *) &hashKeys[4]);
        const __m512i h1 = _mm512_loadu_si512((__m512i *) &hashKeys[0]);

        __m512i d0, d1, d2, d3, tmp12, tmp34, tmp56, tmp78;

        while (inlen > bufBlockLen && outputLen > BLOCKS_16) {

            blocksRemaining -= 16;
            if (blocksRemaining < 0) {
                throw std::runtime_error("attempt to process too many blocks in GCM");
            }

            // Encrypt next set of 16 blocks passing the result of the last encryption for reduction.

            d0 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
            d1 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
            d2 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
            d3 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);


            tmp12 = _mm512_shuffle_epi8(ctr12, BSWAP_EPI64_512);
            tmp34 = _mm512_shuffle_epi8(ctr34, BSWAP_EPI64_512);
            tmp56 = _mm512_shuffle_epi8(ctr56, BSWAP_EPI64_512);
            tmp78 = _mm512_shuffle_epi8(ctr78, BSWAP_EPI64_512);

            ctr1 = _mm_add_epi32(ctr1, SIXTEEN);

            // Move ctrs forward.
            ctr12 = _mm512_add_epi32(ctr12, INC16);
            ctr34 = _mm512_add_epi32(ctr34, INC16);
            ctr56 = _mm512_add_epi32(ctr56, INC16);
            ctr78 = _mm512_add_epi32(ctr78, INC16);


            apply_aes_with_reduction(d0, d1, d2, d3,
                                     h1, h2, h3, h4,
                                     tmp12, tmp34, tmp56, tmp78,
                                     roundKeys128, X, rounds);

            _mm512_storeu_si512((__m512i *) &out[0 * 64], d0);
            _mm512_storeu_si512((__m512i *) &out[1 * 64], d1);
            _mm512_storeu_si512((__m512i *) &out[2 * 64], d2);
            _mm512_storeu_si512((__m512i *) &out[3 * 64], d3);

            // id0..3 are now the last cipher texts but bit swapped

            written += BLOCKS_16;
            read += BLOCKS_16;
            totalBytes += BLOCKS_16;
            inlen -= BLOCKS_16;
            outputLen -= BLOCKS_16;
            in += BLOCKS_16;
            out += BLOCKS_16;
        }
    } else {


        if (bufBlockPtr == 0 && inlen > bufBlockLen) {
            if (outputLen < BLOCKS_16) {
                throw exceptions::OutputLengthException("output len too short");
            }
            process16Blocks(in, out);
            written += BLOCKS_16;
            read += BLOCKS_16;
            totalBytes += BLOCKS_16;

        } else {
            size_t rem = bufBlockLen - bufBlockPtr;
            size_t toCopy = inlen < rem ? inlen : rem;
            memcpy(bufBlock + bufBlockPtr, in, toCopy);
            bufBlockPtr += toCopy;
            totalBytes += toCopy;

            if (bufBlockPtr == bufBlockLen) {
                if (outputLen < BLOCKS_16) {
                    throw exceptions::OutputLengthException("output len too short");
                }
                process16Blocks(bufBlock, out);

                if (macBlockLen == 16) {
                    _mm_storeu_si128((__m128i *) bufBlock, _mm_loadu_si128((__m128i *) (bufBlock + BLOCKS_16)));
                } else {
                    memcpy(bufBlock, bufBlock + BLOCKS_16, macBlockLen);
                }

                bufBlockPtr -= BLOCKS_16;
                written += BLOCKS_16;
            }
            read += toCopy;
        }
    }

}


void intel::gcm::AesGcm512wideEncrypt::processBlock(unsigned char *in, unsigned char *out, size_t outputLen) {

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
    tmp1 = _mm_xor_si128(tmp1, roundKeys128[0]);
    for (j = 1; j < rounds - 1; j += 2) {
        tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[j]);
        tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[j + 1]);
    }
    tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[rounds - 1]);
    tmp1 = _mm_aesenclast_si128(tmp1, roundKeys128[rounds]);
    __m128i
            in1 = _mm_loadu_si128((__m128i *)
                                          in);
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


/**
 * Encrypt 16 blocks
 * @param in the plain text
 * @param out  the ciher text
 */
void intel::gcm::AesGcm512wideEncrypt::process16Blocks(unsigned char *in, unsigned char *out) {

    const uint32_t aes_round_max = rounds;
    const __m512i h4 = _mm512_loadu_si512((__m512i *) &hashKeys[12]);
    const __m512i h3 = _mm512_loadu_si512((__m512i *) &hashKeys[8]);
    const __m512i h2 = _mm512_loadu_si512((__m512i *) &hashKeys[4]);
    const __m512i h1 = _mm512_loadu_si512((__m512i *) &hashKeys[0]);


    if (out == nullptr) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        throw std::runtime_error("out is null, output generated when no output was expected by caller");
    }


    blocksRemaining -= 16;
    if (blocksRemaining < 0) {
        throw std::runtime_error("attempt to process too many blocks in GCM");
    }

    __m512i tmp12 = _mm512_shuffle_epi8(ctr12, BSWAP_EPI64_512);
    __m512i tmp34 = _mm512_shuffle_epi8(ctr34, BSWAP_EPI64_512);
    __m512i tmp56 = _mm512_shuffle_epi8(ctr56, BSWAP_EPI64_512);
    __m512i tmp78 = _mm512_shuffle_epi8(ctr78, BSWAP_EPI64_512);


    //
    // ctr1 is used during doFinal, we need that 128b value before
    // incrementing.
    //
    ctr1 = _mm_add_epi32(ctr1,
                         SIXTEEN);  //_mm256_extracti128_si256(ctr78, 1); //   _mm_add_epi32(ctr1, _mm_set_epi32(0, 4, 0, 0));

    //
    // Post increment
    //
    ctr12 = _mm512_add_epi32(ctr12, INC16);
    ctr34 = _mm512_add_epi32(ctr34, INC16);
    ctr56 = _mm512_add_epi32(ctr56, INC16);
    ctr78 = _mm512_add_epi32(ctr78, INC16);

    __m512i inw1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
    __m512i inw2 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
    __m512i inw3 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
    __m512i inw4 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);


    tmp12 = _mm512_xor_si512(tmp12, _mm512_broadcast_i32x4(roundKeys128[0]));
    tmp34 = _mm512_xor_si512(tmp34, _mm512_broadcast_i32x4(roundKeys128[0]));
    tmp56 = _mm512_xor_si512(tmp56, _mm512_broadcast_i32x4(roundKeys128[0]));
    tmp78 = _mm512_xor_si512(tmp78, _mm512_broadcast_i32x4(roundKeys128[0]));

    uint32_t aes_round;


    for (aes_round = 1; aes_round < aes_round_max; aes_round++) {
        tmp12 = _mm512_aesenc_epi128(tmp12, _mm512_broadcast_i32x4(roundKeys128[aes_round]));
        tmp34 = _mm512_aesenc_epi128(tmp34, _mm512_broadcast_i32x4(roundKeys128[aes_round]));
        tmp56 = _mm512_aesenc_epi128(tmp56, _mm512_broadcast_i32x4(roundKeys128[aes_round]));
        tmp78 = _mm512_aesenc_epi128(tmp78, _mm512_broadcast_i32x4(roundKeys128[aes_round]));
    }


    tmp12 = _mm512_aesenclast_epi128(tmp12, _mm512_broadcast_i32x4(roundKeys128[aes_round]));
    tmp34 = _mm512_aesenclast_epi128(tmp34, _mm512_broadcast_i32x4(roundKeys128[aes_round]));
    tmp56 = _mm512_aesenclast_epi128(tmp56, _mm512_broadcast_i32x4(roundKeys128[aes_round]));
    tmp78 = _mm512_aesenclast_epi128(tmp78, _mm512_broadcast_i32x4(roundKeys128[aes_round]));


    tmp12 = _mm512_xor_si512(tmp12, inw1);
    tmp34 = _mm512_xor_si512(tmp34, inw2);
    tmp56 = _mm512_xor_si512(tmp56, inw3);
    tmp78 = _mm512_xor_si512(tmp78, inw4);

    _mm512_storeu_si512((__m256i *) &out[0 * 64], tmp12);
    _mm512_storeu_si512((__m256i *) &out[1 * 64], tmp34);
    _mm512_storeu_si512((__m256i *) &out[2 * 64], tmp56);
    _mm512_storeu_si512((__m256i *) &out[3 * 64], tmp78);


    tmp12 = _mm512_shuffle_epi8(tmp12, BSWAP_MASK_512);
    tmp34 = _mm512_shuffle_epi8(tmp34, BSWAP_MASK_512);
    tmp56 = _mm512_shuffle_epi8(tmp56, BSWAP_MASK_512);
    tmp78 = _mm512_shuffle_epi8(tmp78, BSWAP_MASK_512);

    tmp12 = _mm512_xor_si512(tmp12, _mm512_castsi128_si512(X));
    gfmul_multi_reduce(tmp12, tmp34, tmp56, tmp78, h1, h2, h3, h4, X);

}


void intel::gcm::AesGcm512wideEncrypt::processFourBlocks(unsigned char *in, unsigned char *out, size_t outputLen,
                                                         const __m512i hashKey, __m512i ctr) {


    const uint32_t aes_round_max = rounds;
    if (out == nullptr) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        throw std::runtime_error("out is null, output generated when no output was expected by caller");
    }

    blocksRemaining -= 4;
    if (blocksRemaining < 0) {
        throw std::runtime_error("attempt to process too many blocks in GCM");
    }

    ctr = _mm512_shuffle_epi8(ctr, BSWAP_EPI64_512);
    __m512i inw1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);

    ctr = _mm512_xor_si512(ctr, _mm512_broadcast_i32x4(roundKeys128[0]));

    uint32_t aes_round;

    for (aes_round = 1; aes_round < aes_round_max; aes_round++) {
        ctr = _mm512_aesenc_epi128(ctr, _mm512_broadcast_i32x4(roundKeys128[aes_round]));
    }

    ctr = _mm512_aesenclast_epi128(ctr, _mm512_broadcast_i32x4(roundKeys128[aes_round]));

    ctr = _mm512_xor_si512(ctr, inw1);
    _mm512_storeu_si512((__m256i *) &out[0 * 64], ctr);

    if (encryption) {
        ctr = _mm512_shuffle_epi8(ctr, BSWAP_MASK_512);
        ctr = _mm512_xor_si512(ctr, _mm512_castsi128_si512(X));
        gfmul_512_reduce(ctr, hashKey, X);
    } else {
        inw1 = _mm512_shuffle_epi8(inw1, BSWAP_MASK_512);
        inw1 = _mm512_xor_si512(inw1, _mm512_castsi128_si512(X));
        gfmul_512_reduce(inw1, hashKey, X);
    }

}


/**
 * Decryption version.
 *
 * NOTE: This method is declared on the child "AesGcm512wideDecrypt" class.
 *
 * @param in the cipher text
 * @param out  the plain text
 */
void intel::gcm::AesGcm512wideDecrypt::process16Blocks(unsigned char *in, unsigned char *out) {

    __m512i high1, high2, low1, low2, med1, med2, tee1, tee2;
    __m512i high, low, med, tee;

    if (out == nullptr) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        throw std::runtime_error("out is null, output generated when no output was expected by caller");
    }


    blocksRemaining -= 16;
    if (blocksRemaining < 0) {
        throw std::runtime_error("attempt to process too many blocks in GCM");
    }

    const uint32_t aes_round_max = rounds;
    const __m512i h4 = _mm512_loadu_si512((__m512i *) &hashKeys[12]);
    const __m512i h3 = _mm512_loadu_si512((__m512i *) &hashKeys[8]);
    const __m512i h2 = _mm512_loadu_si512((__m512i *) &hashKeys[4]);
    const __m512i h1 = _mm512_loadu_si512((__m512i *) &hashKeys[0]);

    __m512i ctr12s = _mm512_shuffle_epi8(ctr12, BSWAP_EPI64_512);
    __m512i ctr34s = _mm512_shuffle_epi8(ctr34, BSWAP_EPI64_512);
    __m512i ctr56s = _mm512_shuffle_epi8(ctr56, BSWAP_EPI64_512);
    __m512i ctr78s = _mm512_shuffle_epi8(ctr78, BSWAP_EPI64_512);


    //
    // ctr1 is used during doFinal, we need that 128b value before
    // incrementing.
    //
    ctr1 = _mm_add_epi32(ctr1,
                         SIXTEEN);

    //
    // Post increment
    //
    ctr12 = _mm512_add_epi32(ctr12, INC16);
    ctr34 = _mm512_add_epi32(ctr34, INC16);
    ctr56 = _mm512_add_epi32(ctr56, INC16);
    ctr78 = _mm512_add_epi32(ctr78, INC16);



    // Load 16 blocks to decrypt
    __m512i in1 = _mm512_loadu_si512((__m512i *) &in[0 * 64]);
    __m512i in2 = _mm512_loadu_si512((__m512i *) &in[1 * 64]);
    __m512i in3 = _mm512_loadu_si512((__m512i *) &in[2 * 64]);
    __m512i in4 = _mm512_loadu_si512((__m512i *) &in[3 * 64]);

//    // Shuffle input blocks into constants.
//    const __m512i inw1 = _mm512_xor_si512(_mm512_castsi128_si512(X), _mm512_shuffle_epi8(in1, BSWAP_MASK_512));
//    const __m512i inw2 = _mm512_shuffle_epi8(in2, BSWAP_MASK_512);
//    const __m512i inw3 = _mm512_shuffle_epi8(in3, BSWAP_MASK_512);
//    const __m512i inw4 = _mm512_shuffle_epi8(in4, BSWAP_MASK_512);


    apply_aes_with_reduction(
            in1, in2, in3, in4,
            h1, h2, h3, h4,
            ctr12s, ctr34s, ctr56s, ctr78s,
            roundKeys128, X, aes_round_max);


//    aes_xor(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[0]));
//
//
//    high1 = _mm512_clmulepi64_epi128(inw4, h4, 0x11);
//    low1 = _mm512_clmulepi64_epi128(inw4, h4, 0x00);
//    med1 = _mm512_clmulepi64_epi128(inw4, h4, 0x01);
//    tee1 = _mm512_clmulepi64_epi128(inw4, h4, 0x10);
//
//    aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[1]));
//
//
//    high2 = _mm512_clmulepi64_epi128(inw3, h3, 0x11);
//    low2 = _mm512_clmulepi64_epi128(inw3, h3, 0x00);
//    med2 = _mm512_clmulepi64_epi128(inw3, h3, 0x01);
//    tee2 = _mm512_clmulepi64_epi128(inw3, h3, 0x10);
//
//
//    aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[2]));
//
//    high = _mm512_xor_si512(high1, high2);
//    low = _mm512_xor_si512(low1, low2);
//    med = _mm512_xor_si512(med1, med2);
//    tee = _mm512_xor_si512(tee1, tee2);
//
//
//    aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[3]));
//
//    high1 = _mm512_clmulepi64_epi128(inw2, h2, 0x11);
//    low1 = _mm512_clmulepi64_epi128(inw2, h2, 0x00);
//    med1 = _mm512_clmulepi64_epi128(inw2, h2, 0x01);
//    tee1 = _mm512_clmulepi64_epi128(inw2, h2, 0x10);
//
//    aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[4]));
//
//    high2 = _mm512_clmulepi64_epi128(inw1, h1, 0x11);
//    low2 = _mm512_clmulepi64_epi128(inw1, h1, 0x00);
//    med2 = _mm512_clmulepi64_epi128(inw1, h1, 0x01);
//    tee2 = _mm512_clmulepi64_epi128(inw1, h1, 0x10);
//
//
//    aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[5]));
//
//
//    high = _mm512_ternarylogic_epi64(high, high1, high2, 0x96);
//    low = _mm512_ternarylogic_epi64(low, low1, low2, 0x96);
//    med = _mm512_ternarylogic_epi64(med, med1, med2, 0x96);
//    tee = _mm512_ternarylogic_epi64(tee, tee1, tee2, 0x96);
//
//
//    aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[6]));
//    aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[7]));
//    aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[8]));
//    aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[9]));
//
//    if (aes_round_max == 10) {
//        aes_enc_last(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[10]));
//    } else if (aes_round_max == 12) {
//        aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[10]));
//        aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[11]));
//        aes_enc_last(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[12]));
//    } else {
//        aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[10]));
//        aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[11]));
//        aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[12]));
//        aes_enc(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[13]));
//        aes_enc_last(ctr12s, ctr34s, ctr56s, ctr78s, _mm512_broadcast_i32x4(roundKeys128[14]));
//    }


    _mm512_storeu_si512((__m256i *) &out[0 * 64], in1);
    _mm512_storeu_si512((__m256i *) &out[1 * 64], in2);
    _mm512_storeu_si512((__m256i *) &out[2 * 64], in3);
    _mm512_storeu_si512((__m256i *) &out[3 * 64], in4);


//    tee = _mm512_xor_epi32(tee, med);
//    med = _mm512_bsrli_epi128(tee, 8);
//    tee = _mm512_bslli_epi128(tee, 8);
//    high = _mm512_xor_si512(high, med);
//    tee = _mm512_xor_si512(tee, low);
//
//    X = reduceWide(tee, high);


}


void intel::gcm::AesGcm512wideEncrypt::initCipher() {
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


void intel::gcm::AesGcm512wideEncrypt::setBlocksRemainingDown(int64_t down) {

    if (totalBytes > 0) {
        throw std::runtime_error("cannot be called once transformation has processed data");
    }

    blocksRemaining -= down;
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
    __m128i y = _mm_set_epi32(-2147483648, 0, 0, 0);

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




