//
// Created  on 18/5/2022.
//

#include <cstring>
#include <stdexcept>
#include "gcm.h"
#include "AesGcm256wide.h"
#include "../../exceptions/CipherTextException.h"
#include "../../exceptions/OutputLengthException.h"
#include <immintrin.h>
#include "../common.h"

__m128i intel::gcm::AesGcm256wide::BSWAP_EPI64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);
__m256i intel::gcm::AesGcm256wide::BSWAP_EPI64_256 = _mm256_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6,
                                                                     7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5,
                                                                     6, 7);

__m128i intel::gcm::AesGcm256wide::BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

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


intel::gcm::AesGcm256wide::AesGcm256wide() : GCM() {
    roundKeys256 = new __m256i[15];
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
}

intel::gcm::AesGcm256wide::~AesGcm256wide() {
    memset(roundKeys256, 0, sizeof(__m256i) * 15);
    delete[] roundKeys256;
    memset(roundKeys128, 0, sizeof(__m128i) * 15);
    delete[] roundKeys128;
    rounds = 0;
    delete[] macBlock;
    delete[] initAD;

    if (bufBlock != nullptr) {
        memset(bufBlock, 0, bufBlockLen);
        delete[] bufBlock;
    }

    delete exp;

}

void intel::gcm::AesGcm256wide::reset(bool keepMac) {

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


void intel::gcm::AesGcm256wide::init(bool encryption, unsigned char *key, size_t keyLen, unsigned char *nonce,
                                     size_t nonceLen,
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

    bufBlockLen = encryption ? EIGHT_BLOCKS : (EIGHT_BLOCKS + macSizeBytes);
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

    for (int t = 0; t < 15; t++) {
        roundKeys256[t] = _mm256_set_m128i(roundKeys128[t], roundKeys128[t]);
    }


    S_at = _mm_setzero_si128();
    S_atPre = _mm_setzero_si128();

    X = _mm_setzero_si128();
    Y = _mm_setzero_si128();
    T = _mm_setzero_si128();
    H = _mm_setzero_si128();

    __m128i tmp1, tmp2, tmp3, tmp4;
    __m256i zulu1, zulu2;
    if (nonceLen == 12) {
        Y = _mm_loadu_si128((__m128i * )
        nonce);
        Y = _mm_insert_epi32(Y, 0x1000000, 3);

        __m256i zulu = _mm256_set_m128i(X, Y);
        zulu = _mm256_xor_si256(zulu, roundKeys256[0]);

        for (int j = 1; j < rounds - 1; j += 2) {
            zulu = _mm256_aesenc_epi128(zulu, roundKeys256[j]);
            zulu = _mm256_aesenc_epi128(zulu, roundKeys256[j + 1]);
        }

        zulu = _mm256_aesenc_epi128(zulu, roundKeys256[rounds - 1]);


        zulu = _mm256_aesenclast_epi128(zulu, roundKeys256[rounds]);

        H = _mm256_extracti128_si256(zulu, 1);
        T = _mm256_extracti128_si256(zulu, 0);

        H = _mm_shuffle_epi8(H, BSWAP_MASK);

    } else {

        tmp1 = _mm_xor_si128(X, roundKeys128[0]);
        int j;
        for (j = 1; j < rounds; j++) {
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[j]);
        }
        H = _mm_aesenclast_si128(tmp1, roundKeys128[rounds]);
        H = _mm_shuffle_epi8(H, BSWAP_MASK);
        Y = _mm_xor_si128(Y, Y); // ?
        int i;
        for (i = 0; i < nonceLen / 16; i++) {
            tmp1 = _mm_loadu_si128(&((__m128i * )
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
        tmp1 = _mm_insert_epi64(tmp1, nonceLen * 8, 0);
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

    ctr12 = _mm256_set_m128i(
            _mm_add_epi32(ctr1, _mm_set_epi32(0, 2, 0, 0)),
            _mm_add_epi32(ctr1, _mm_set_epi32(0, 1, 0, 0)));
    ctr34 = _mm256_set_m128i(
            _mm_add_epi32(ctr1, _mm_set_epi32(0, 4, 0, 0)),
            _mm_add_epi32(ctr1, _mm_set_epi32(0, 3, 0, 0)));

    ctr56 = _mm256_set_m128i(
            _mm_add_epi32(ctr1, _mm_set_epi32(0, 6, 0, 0)),
            _mm_add_epi32(ctr1, _mm_set_epi32(0, 5, 0, 0)));

    ctr78 = _mm256_set_m128i(
            _mm_add_epi32(ctr1, _mm_set_epi32(0, 8, 0, 0)),
            _mm_add_epi32(ctr1, _mm_set_epi32(0, 7, 0, 0)));
}

size_t intel::gcm::AesGcm256wide::getMacLen() {
    return this->macBlockLen;
}

void intel::gcm::AesGcm256wide::getMac(unsigned char *dest) {
    memcpy(dest, macBlock, macBlockLen);
}


size_t intel::gcm::AesGcm256wide::getOutputSize(size_t len) {
    size_t totalData = len + bufBlockPtr;
    if (encryption) {
        return totalData + macBlockLen;
    }
    return totalData < macBlockLen ? 0 : totalData - macBlockLen;
}

size_t intel::gcm::AesGcm256wide::getUpdateOutputSize(size_t len) {
    size_t totalData = len + bufBlockPtr;
    if (!encryption) {
        if (totalData < bufBlockLen) {
            return 0;
        }
        totalData -= macBlockLen;
    }
    return totalData - totalData % EIGHT_BLOCKS;
}

void intel::gcm::AesGcm256wide::processAADByte(unsigned char in) {
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

void intel::gcm::AesGcm256wide::processAADBytes(unsigned char *in, size_t inOff, size_t len) {

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

            last_aad_block = _mm_loadu_si128((__m128i * )
            pos);
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


size_t intel::gcm::AesGcm256wide::processByte(unsigned char in, unsigned char *out, size_t outputLen) {

    if (totalBytes == 0) {
        initCipher();
    }

    size_t read = 0;
    size_t written = 0;

    processBuffer(&in, 1, out, outputLen, read, written);

    return written;
}


size_t
intel::gcm::AesGcm256wide::processBytes(unsigned char *in, size_t inOff, size_t len, unsigned char *out, int outOff,
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
    }

    return (size_t) (outPtr - outStart);

}


size_t intel::gcm::AesGcm256wide::doFinal(unsigned char *output, size_t outOff, size_t outLen) {


    if (totalBytes == 0) {
        initCipher();
    }

    unsigned char *start = output + outOff;
    unsigned char *outPtr = start;
    unsigned char *end = start + outLen;

    __m128i tmp1;

    size_t limit = bufBlockPtr;

    if (!encryption) {
        if (macBlockLen > bufBlockPtr) {
            throw exceptions::CipherTextException("cipher text too short");
        }
        limit -= macBlockLen;
        totalBytes -= macBlockLen;

        // decryption so output buffer cannot be less than limit.
        // bytes are to limit are the mac block (tag)
        if (outLen - outOff < limit) {
            throw exceptions::OutputLengthException("output buffer too small");
        }
    } else {
        // encryption, output must take remaining buffer + mac block
        if (outLen - outOff < bufBlockPtr + macBlockLen) {
            throw exceptions::OutputLengthException("output buffer too small");
        }
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
            tmp1 = _mm_xor_si128(tmp1, roundKeys128[0]);
            for (int j = 1; j < rounds - 1; j += 2) {
                tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[j]);
                tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[j + 1]);
            }
            tmp1 = _mm_aesenc_si128(tmp1, roundKeys128[rounds - 1]);
            tmp1 = _mm_aesenclast_si128(tmp1, roundKeys128[rounds]);

            __m128i in1 = _mm_loadu_si128((__m128i * ) & bufBlock[t]);

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
    _mm_storeu_si128((__m128i * )
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
intel::gcm::AesGcm256wide::processBuffer(unsigned char *in, size_t inlen, unsigned char *out, size_t outputLen,
                                         size_t &read,
                                         size_t &written) {

    size_t rem = bufBlockLen - bufBlockPtr;
    size_t toCopy = inlen < rem ? inlen : rem;
    memcpy(bufBlock + bufBlockPtr, in, toCopy);
    bufBlockPtr += toCopy;
    totalBytes += toCopy;

    if (bufBlockPtr == bufBlockLen) {
        if (outputLen < EIGHT_BLOCKS) {
            throw exceptions::OutputLengthException("output len too short");
        }
        processFourBlocks(bufBlock, out);
        if (!encryption) {
            memcpy(bufBlock, bufBlock + EIGHT_BLOCKS, macBlockLen);
        }
        bufBlockPtr -= EIGHT_BLOCKS;
        written = EIGHT_BLOCKS;
    } else {
        written = 0;
    }
    read = toCopy;
}


void intel::gcm::AesGcm256wide::processBlock(unsigned char *in, unsigned char *out, size_t outputLen) {

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
    in1 = _mm_loadu_si128((__m128i * )
    in);
    tmp1 = _mm_xor_si128(tmp1, in1);
    _mm_storeu_si128((__m128i * )(out), tmp1);
    tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);

    if (encryption) {
        X = _mm_xor_si128(X, tmp1);
    } else {
        X = _mm_xor_si128(X, _mm_shuffle_epi8(in1, BSWAP_MASK));
    }
    gfmul(X, H, &X);


}

void intel::gcm::AesGcm256wide::processFourBlocks(unsigned char *in, unsigned char *out) {


    if (out == nullptr) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        throw std::runtime_error("out is null, output generated when no output was expected by caller");
    }

    auto out256 = (__m256i *) out;
    auto in256 = (__m256i *) in;

    blocksRemaining -= 8;
    if (blocksRemaining < 0) {
        throw std::runtime_error("attempt to process too many blocks in GCM");
    }

    __m256i tmp12s = _mm256_shuffle_epi8(ctr12, BSWAP_EPI64_256);
    __m256i tmp34s = _mm256_shuffle_epi8(ctr34, BSWAP_EPI64_256);
    __m256i tmp56s = _mm256_shuffle_epi8(ctr56, BSWAP_EPI64_256);
    __m256i tmp78s = _mm256_shuffle_epi8(ctr78, BSWAP_EPI64_256);


    //
    // ctr1 is used during doFinal, we need that 128b value before
    // incrementing.
    //
    ctr1 = _mm256_extracti128_si256(ctr78, 1); //   _mm_add_epi32(ctr1, _mm_set_epi32(0, 4, 0, 0));

    //
    // Post increment
    //
    ctr12 = _mm256_add_epi32(ctr12, INC8);
    ctr34 = _mm256_add_epi32(ctr34, INC8);
    ctr56 = _mm256_add_epi32(ctr56, INC8);
    ctr78 = _mm256_add_epi32(ctr78, INC8);

    __m256i inw1 = _mm256_loadu_si256(in256++);
    __m256i inw2 = _mm256_loadu_si256(in256++);
    __m256i inw3 = _mm256_loadu_si256(in256++);
    __m256i inw4 = _mm256_loadu_si256(in256++);

    __m256i tmp12 = _mm256_xor_si256(tmp12s, roundKeys256[0]);
    __m256i tmp34 = _mm256_xor_si256(tmp34s, roundKeys256[0]);
    __m256i tmp56 = _mm256_xor_si256(tmp56s, roundKeys256[0]);
    __m256i tmp78 = _mm256_xor_si256(tmp78s, roundKeys256[0]);


    for (int j = 1; j < rounds - 1; j += 2) {
        tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[j]);
        tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[j]);
        tmp56 = _mm256_aesenc_epi128(tmp56, roundKeys256[j]);
        tmp78 = _mm256_aesenc_epi128(tmp78, roundKeys256[j]);

        tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[j + 1]);
        tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[j + 1]);
        tmp56 = _mm256_aesenc_epi128(tmp56, roundKeys256[j + 1]);
        tmp78 = _mm256_aesenc_epi128(tmp78, roundKeys256[j + 1]);
    }


    tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[rounds - 1]);
    tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[rounds - 1]);
    tmp56 = _mm256_aesenc_epi128(tmp56, roundKeys256[rounds - 1]);
    tmp78 = _mm256_aesenc_epi128(tmp78, roundKeys256[rounds - 1]);

    tmp12 = _mm256_aesenclast_epi128(tmp12, roundKeys256[rounds]);
    tmp34 = _mm256_aesenclast_epi128(tmp34, roundKeys256[rounds]);
    tmp56 = _mm256_aesenclast_epi128(tmp56, roundKeys256[rounds]);
    tmp78 = _mm256_aesenclast_epi128(tmp78, roundKeys256[rounds]);


    tmp12 = _mm256_xor_si256(tmp12, inw1);
    tmp34 = _mm256_xor_si256(tmp34, inw2);
    tmp56 = _mm256_xor_si256(tmp56, inw3);
    tmp78 = _mm256_xor_si256(tmp78, inw4);

    _mm256_storeu_si256(out256++, tmp12);
    _mm256_storeu_si256(out256++, tmp34);
    _mm256_storeu_si256(out256++, tmp56);
    _mm256_storeu_si256(out256++, tmp78);

    if (encryption) {
        __m128i tmp1 = _mm_shuffle_epi8(_mm256_extracti128_si256(tmp12, 0), BSWAP_MASK);
        __m128i tmp2 = _mm_shuffle_epi8(_mm256_extracti128_si256(tmp12, 1), BSWAP_MASK);
        __m128i tmp3 = _mm_shuffle_epi8(_mm256_extracti128_si256(tmp34, 0), BSWAP_MASK);
        __m128i tmp4 = _mm_shuffle_epi8(_mm256_extracti128_si256(tmp34, 1), BSWAP_MASK);
        __m128i tmp5 = _mm_shuffle_epi8(_mm256_extracti128_si256(tmp56, 0), BSWAP_MASK);
        __m128i tmp6 = _mm_shuffle_epi8(_mm256_extracti128_si256(tmp56, 1), BSWAP_MASK);
        __m128i tmp7 = _mm_shuffle_epi8(_mm256_extracti128_si256(tmp78, 0), BSWAP_MASK);
        __m128i tmp8 = _mm_shuffle_epi8(_mm256_extracti128_si256(tmp78, 1), BSWAP_MASK);

        X = _mm_xor_si128(X, tmp1);
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, tmp2);
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, tmp3);
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, tmp4);
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, tmp5);
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, tmp6);
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, tmp7);
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, tmp8);
        gfmul(X, H, &X);
    } else {
        X = _mm_xor_si128(X, _mm_shuffle_epi8(_mm256_extracti128_si256(inw1, 0), BSWAP_MASK));
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, _mm_shuffle_epi8(_mm256_extracti128_si256(inw1, 1), BSWAP_MASK));
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, _mm_shuffle_epi8(_mm256_extracti128_si256(inw2, 0), BSWAP_MASK));
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, _mm_shuffle_epi8(_mm256_extracti128_si256(inw2, 1), BSWAP_MASK));
        gfmul(X, H, &X);

        X = _mm_xor_si128(X, _mm_shuffle_epi8(_mm256_extracti128_si256(inw3, 0), BSWAP_MASK));
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, _mm_shuffle_epi8(_mm256_extracti128_si256(inw3, 1), BSWAP_MASK));
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, _mm_shuffle_epi8(_mm256_extracti128_si256(inw4, 0), BSWAP_MASK));
        gfmul(X, H, &X);
        X = _mm_xor_si128(X, _mm_shuffle_epi8(_mm256_extracti128_si256(inw4, 1), BSWAP_MASK));
        gfmul(X, H, &X);
    }


}


/*
 * void intel::gcm::AesGcm256wide::processFourBlocks(unsigned char *in, unsigned char *out) {

    if (out == nullptr) {
        //
        // Java api my supply a null output array if it expects no output, however
        // if output does occur then we need to catch that here.
        //
        throw std::runtime_error("out is null, output generated when no output was expected by caller");
    }

    auto out256 = (__m256i *) out;
    auto in256 = (__m256i *) in;

    blocksRemaining -= 4;
    if (blocksRemaining < 0) {
        throw std::runtime_error("attempt to process too many blocks in GCM");
    }

    __m256i tmp12s = _mm256_shuffle_epi8(ctr12, BSWAP_EPI64_256);
    __m256i tmp34s = _mm256_shuffle_epi8(ctr34, BSWAP_EPI64_256);

    //
    // ctr1 is used during doFinal, we need that 128b value before
    // incrementing.
    //
    ctr1 = _mm256_extracti128_si256(ctr34, 1); //   _mm_add_epi32(ctr1, _mm_set_epi32(0, 4, 0, 0));

    //
    // Post increment
    //
    ctr12 = _mm256_add_epi32(ctr12, INC4);
    ctr34 = _mm256_add_epi32(ctr34, INC4);


    __m256i inw1 = _mm256_loadu_si256(in256++);
    __m256i inw2 = _mm256_loadu_si256(in256++);

    __m256i tmp12 = _mm256_xor_si256(tmp12s, roundKeys256[0]);
    __m256i tmp34 = _mm256_xor_si256(tmp34s, roundKeys256[0]);


    for (int t = 1; t < rounds - 1; t += 4) {
        tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[t]);
        tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[t]);
        tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[t + 1]);
        tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[t + 1]);

        tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[t+2]);
        tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[t+2]);
        tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[t + 3]);
        tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[t + 3]);
    }

    tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[rounds - 1]);
    tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[rounds - 1]);

    tmp12 = _mm256_aesenclast_epi128(tmp12, roundKeys256[rounds]);
    tmp34 = _mm256_aesenclast_epi128(tmp34, roundKeys256[rounds]);

    /*
    switch (rounds) {
        case 10:
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[1]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[1]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[2]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[2]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[3]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[3]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[4]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[4]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[5]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[5]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[6]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[6]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[7]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[7]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[8]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[8]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[9]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[9]);
            tmp12 = _mm256_aesenclast_epi128(tmp12, roundKeys256[10]);
            tmp34 = _mm256_aesenclast_epi128(tmp34, roundKeys256[10]);
            break;

        case 12:
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[1]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[1]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[2]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[2]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[3]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[3]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[4]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[4]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[5]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[5]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[6]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[6]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[7]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[7]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[8]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[8]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[9]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[9]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[10]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[10]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[11]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[11]);
            tmp12 = _mm256_aesenclast_epi128(tmp12, roundKeys256[12]);
            tmp34 = _mm256_aesenclast_epi128(tmp34, roundKeys256[12]);
            break;

        case 14:
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[1]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[1]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[2]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[2]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[3]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[3]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[4]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[4]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[5]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[5]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[6]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[6]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[7]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[7]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[8]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[8]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[9]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[9]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[10]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[10]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[11]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[11]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[12]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[12]);
            tmp12 = _mm256_aesenc_epi128(tmp12, roundKeys256[13]);
            tmp34 = _mm256_aesenc_epi128(tmp34, roundKeys256[13]);
            tmp12 = _mm256_aesenclast_epi128(tmp12, roundKeys256[14]);
            tmp34 = _mm256_aesenclast_epi128(tmp34, roundKeys256[14]);
            break;

        default:
            throw std::runtime_error("invalid rounds at lowest level of api");
            break;
    }



tmp12 = _mm256_xor_si256(tmp12, inw1);
tmp34 = _mm256_xor_si256(tmp34, inw2);

_mm256_storeu_si256(out256++, tmp12);
_mm256_storeu_si256(out256++, tmp34);


if (encryption) {
__m128i tmp1 = _mm_shuffle_epi8(_mm256_extracti128_si256(tmp12, 0), BSWAP_MASK);
__m128i tmp2 = _mm_shuffle_epi8(_mm256_extracti128_si256(tmp12, 1), BSWAP_MASK);
__m128i tmp3 = _mm_shuffle_epi8(_mm256_extracti128_si256(tmp34, 0), BSWAP_MASK);
__m128i tmp4 = _mm_shuffle_epi8(_mm256_extracti128_si256(tmp34, 1), BSWAP_MASK);
X = _mm_xor_si128(X, tmp1);
gfmul(X, H, &X);
X = _mm_xor_si128(X, tmp2);
gfmul(X, H, &X);
X = _mm_xor_si128(X, tmp3);
gfmul(X, H, &X);
X = _mm_xor_si128(X, tmp4);
gfmul(X, H, &X);
} else {
X = _mm_xor_si128(X, _mm_shuffle_epi8(_mm256_extracti128_si256(inw1, 0), BSWAP_MASK));
gfmul(X, H, &X);
X = _mm_xor_si128(X, _mm_shuffle_epi8(_mm256_extracti128_si256(inw1, 1), BSWAP_MASK));
gfmul(X, H, &X);
X = _mm_xor_si128(X, _mm_shuffle_epi8(_mm256_extracti128_si256(inw2, 0), BSWAP_MASK));
gfmul(X, H, &X);
X = _mm_xor_si128(X, _mm_shuffle_epi8(_mm256_extracti128_si256(inw2, 1), BSWAP_MASK));
gfmul(X, H, &X);
}


}
 */


void intel::gcm::AesGcm256wide::initCipher() {
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


void intel::gcm::AesGcm256wide::setBlocksRemainingDown(int64_t down) {

    if (totalBytes > 0) {
        throw std::runtime_error("cannot be called once transformation has processed data");
    }

    if (blocksRemaining - down > blocksRemaining) {
        throw std::runtime_error("blocks remaining would end up more than exising value");
    }

    blocksRemaining -= down;
}



void intel::gcm::gfmul(__m128i a, __m128i b, __m128i *res) {
    __m128i tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8;

    tmp2 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp3 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x11);


    tmp3 = _mm_xor_si128(tmp3, tmp4);
    tmp4 = _mm_slli_si128(tmp3, 8);
    tmp3 = _mm_srli_si128(tmp3, 8);
    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp5 = _mm_xor_si128(tmp5, tmp3);

    tmp6 = _mm_srli_epi32(tmp2, 31);
    tmp7 = _mm_srli_epi32(tmp5, 31);
    tmp2 = _mm_slli_epi32(tmp2, 1);
    tmp5 = _mm_slli_epi32(tmp5, 1);

    tmp8 = _mm_srli_si128(tmp6, 12);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp6 = _mm_slli_si128(tmp6, 4);
    tmp2 = _mm_or_si128(tmp2, tmp6);
    tmp5 = _mm_or_si128(tmp5, tmp7);
    tmp5 = _mm_or_si128(tmp5, tmp8);

    //
    tmp6 = _mm_slli_epi32(tmp2, 31);
    tmp7 = _mm_slli_epi32(tmp2, 30);
    tmp8 = _mm_slli_epi32(tmp2, 25);

    tmp6 = _mm_xor_si128(tmp6, tmp7);
    tmp6 = _mm_xor_si128(tmp6, tmp8);
    tmp7 = _mm_srli_si128(tmp6, 4);
    tmp6 = _mm_slli_si128(tmp6, 12);
    tmp2 = _mm_xor_si128(tmp2, tmp6);

    tmp1 = _mm_srli_epi32(tmp2, 1);
    tmp3 = _mm_srli_epi32(tmp2, 2);
    tmp4 = _mm_srli_epi32(tmp2, 7);
    tmp1 = _mm_xor_si128(tmp1, tmp3);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp1 = _mm_xor_si128(tmp1, tmp7);

    tmp2 = _mm_xor_si128(tmp2, tmp1);
    tmp5 = _mm_xor_si128(tmp5, tmp2);
    *res = tmp5;

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




