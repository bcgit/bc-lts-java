//
//

#include <immintrin.h>
#include <assert.h>
#include "gcm_siv.h"
#include <stdlib.h>
#include "gcm_sivHash128.h"
#include <memory.h>
#include <stdio.h>
#include "../common.h"


gcm_siv_err *make_gcm_siv_error(const char *msg, int type) {
    gcm_siv_err *err = calloc(1, sizeof(gcm_siv_err));
    err->msg = msg;
    err->type = type;
    return err;
}

void gcm_siv_err_free(gcm_siv_err *err) {
    if (err != NULL) {
        free(err);
    }
}

gcm_siv_ctx *gcm_siv_create_ctx() {
    gcm_siv_ctx *ctx = calloc(1, sizeof(gcm_siv_ctx));
    return ctx;
}

void gcm_siv_free(gcm_siv_ctx *ctx) {
    if (ctx->initAD != NULL) {
        memset(ctx->initAD, 0, ctx->initADLen);
        free(ctx->initAD);
    }

    memset(ctx, 0, sizeof(gcm_siv_ctx));
    free(ctx);
}

void gcm_siv_reset(gcm_siv_ctx *ctx, bool keepMac) {
    if (!keepMac) {
        memset(ctx->macBlock, 0, 16);
    }
    gcm_siv_hasher_reset(&ctx->theAEADHasher);
    gcm_siv_hasher_reset(&ctx->theDataHasher);
    /* Initialise AEAD if required */
    ctx->theFlags &= ~AEAD_COMPLETE;
    memset(ctx->theGHash, 0, BLOCK_SIZE);
    if (ctx->initAD != NULL) {
        gcm_siv_hasher_updateHash(&ctx->theAEADHasher, &ctx->theMultiplier, ctx->initAD, ctx->initADLen,
                                  ctx->theReverse, ctx->theGHash);
    }
}


size_t gcm_siv_getMac(gcm_siv_ctx *ctx, uint8_t *destination) {
    if (destination == NULL) {
        return BLOCK_SIZE;
    }
    memcpy(destination, ctx->macBlock, BLOCK_SIZE);
    return BLOCK_SIZE;
}


/**
 *
 * @param encryption
 * @param key
 * @param keyLen
 * @param nonce
 * @param nonceLen
 * @return NULL if no error, other ptr to struct CALLER NEEDS TO FREE
 */
gcm_siv_err *gcm_siv_init(
        gcm_siv_ctx *ctx,
        bool encryption,
        uint8_t *key,
        size_t keyLen,
        uint8_t *nonce,
        size_t nonceLen,
        uint8_t *initialText,
        size_t initialTextLen) {
    ctx->encryption = encryption;
    ctx->theFlags = 0;

    // We had old initial text drop it here.
    if (ctx->initAD != NULL) {
        memset(ctx->initAD, 0, ctx->initADLen);
        free(ctx->initAD);
        ctx->initAD = NULL;
        ctx->initADLen = 0;
    }

    if (initialText != NULL) {
        //
        // We keep a copy so that if the instances is reset it can be returned to
        // the same state it was before the first data is processed.
        //
        ctx->initAD = malloc(initialTextLen);
        ctx->initADLen = initialTextLen;
        memcpy(ctx->initAD, initialText, initialTextLen);
    }

    // Zero out mac block
    memset(ctx->macBlock, 0, MAC_BLOCK_LEN);
    memcpy(ctx->nonce, nonce, NONCELEN);

    ctx->theFlags = deriveKeys(&ctx->theMultiplier, ctx->roundKeys, key, (char *) ctx->nonce, &ctx->num_rounds, keyLen,
                               ctx->theFlags);

    resetStreams(ctx);
    return NULL;// All good
}


size_t gcm_siv_get_output_size(bool encryption, size_t len) {
    if (encryption) {
        return len + BLOCK_SIZE;
    }
    return len < BLOCK_SIZE ? 0 : len - BLOCK_SIZE;
}

void fillReverse(const uint8_t *pInput, int pLength, uint8_t *pOutput) {
    /* Loop through the buffer */
    for (int i = 0, j = BLOCK_SIZE - 1; i < pLength; i++, j--) {
        /* Copy byte */
        pOutput[j] = pInput[i];
    }
}

void gcm_siv_hasher_reset(gcm_siv_hasher *p_gsh) {
    p_gsh->numActive = 0;
    p_gsh->numHashed = 0;
}


void
gcm_siv_hasher_updateHash(gcm_siv_hasher *p_gsh, tables4kGCMMultiplier *p_multiplier, uint8_t *pBuffer,
                          int pLen, uint8_t *theReverse, uint8_t *theGHash) {
    /* If we should process the cache */
    const int mySpace = BLOCK_SIZE - p_gsh->numActive;
    int numProcessed = 0;
    int myRemaining = pLen;
    __m128i d0;
    if (p_gsh->numActive > 0 && pLen >= mySpace) {
        /* Copy data into the cache and hash it */
        memcpy(p_gsh->theBuffer + p_gsh->numActive, pBuffer, (size_t) mySpace);
        reverse_bytes((__m128i *) p_gsh->theBuffer, (__m128i *) theReverse);
        gHASH(p_multiplier, theGHash, theReverse);
        /* Adjust counters */
        numProcessed += mySpace;
        myRemaining -= mySpace;
        p_gsh->numActive = 0;
    }
    /* While we have full blocks */
    while (myRemaining >= BLOCK_SIZE) {
        /* Access the next data */
        d0 = _mm_loadu_si128((__m128i *) (pBuffer + numProcessed));
        reverse_bytes(&d0, &d0);
        gHASH(p_multiplier, theGHash, &d0);
        /* Adjust counters */
        numProcessed += BLOCK_SIZE;
        myRemaining -= BLOCK_SIZE;
    }
    /* If we have remaining data */
    if (myRemaining > 0) {
        /* Copy data into the cache */
        memcpy(p_gsh->theBuffer + p_gsh->numActive, pBuffer + numProcessed, (size_t) myRemaining);
        p_gsh->numActive += myRemaining;
    }
    /* Adjust the number of bytes processed */
    p_gsh->numHashed += pLen;
}

void gcm_siv_hasher_completeHash(gcm_siv_hasher *p_gsh, uint8_t *theReverse, tables4kGCMMultiplier *p_multiplier,
                                 const uint8_t *theGHash) {
    /* If we have remaining data */
    if (p_gsh->numActive > 0) {
        /* Access the next data */
        memset(theReverse, 0, BLOCK_SIZE);
        fillReverse(p_gsh->theBuffer, p_gsh->numActive, theReverse);
        /* hash value */
        gHASH(p_multiplier, theGHash, theReverse);
    }
}

void tables4kGCMMultiplier_init(tables4kGCMMultiplier *p_multiplier, uint8_t *H) {
    if (areEqual(p_multiplier->H, H, BLOCK_SIZE)) {
        return;
    }
    memcpy(p_multiplier->H, H, BLOCK_SIZE);
    p_multiplier->T[0] = _mm_setzero_si128();
    __m128i d0 = createBigEndianM128i(p_multiplier->H);
    uint64_t c = ((uint64_t) d0[1]) << 57;
    p_multiplier->T[1][0] = (int64_t) (((uint64_t) d0[0] >> 7) ^ c ^ (c >> 1) ^ (c >> 2) ^ (c >> 7));
    p_multiplier->T[1][1] = (int64_t) (((uint64_t) d0[1] >> 7) | ((uint64_t) d0[0] << 57));
    size_t n;
    for (n = 2; n < 256; n += 2) {
        divideP((__m128i *) (p_multiplier->T + (n >> 1)), (__m128i *) (p_multiplier->T + n));
        p_multiplier->T[n + 1] = _mm_xor_si128(p_multiplier->T[n], p_multiplier->T[1]);
    }
}

void multiplyH(tables4kGCMMultiplier *p_multiplier, const uint8_t *x) {
    __m128i t = p_multiplier->T[x[15] & 0xFF];
    uint64_t z0 = (uint64_t) t[0], z1 = (uint64_t) t[1];

    for (int i = 14; i >= 0; --i) {
        t = p_multiplier->T[x[i] & 0xFF];
        uint64_t c = z1 << 56;
        z1 = (uint64_t) t[1] ^ ((z1 >> 8) | (z0 << 56));
        z0 = (uint64_t) t[0] ^ (z0 >> 8) ^ c ^ (c >> 1) ^ (c >> 2) ^ (c >> 7);
    }
    __m128i z = _mm_set_epi64x(_bswap64(z1), _bswap64 (z0));
    _mm_storeu_si128((__m128i *) x, z);
}

void gHASH(tables4kGCMMultiplier *p_multiplier, const uint8_t *theGHash, __m128i  *pNext) {
    _mm_storeu_si128((__m128i *) theGHash, _mm_xor_si128(*(__m128i *) theGHash, *pNext));
    multiplyH(p_multiplier, theGHash);
}

static inline void encrypt(__m128i *d0, __m128i *roundKeys, const int num_rounds) {
    *d0 = _mm_xor_si128(*d0, roundKeys[0]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[1]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[2]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[3]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[4]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[5]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[6]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[7]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[8]);
    *d0 = _mm_aesenc_si128(*d0, roundKeys[9]);
    if (num_rounds == ROUNDS_128) {
        *d0 = _mm_aesenclast_si128(*d0, roundKeys[10]);
    } else if (num_rounds == ROUNDS_192) {
        *d0 = _mm_aesenc_si128(*d0, roundKeys[10]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[11]);
        *d0 = _mm_aesenclast_si128(*d0, roundKeys[12]);
    } else if (num_rounds == ROUNDS_256) {
        *d0 = _mm_aesenc_si128(*d0, roundKeys[10]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[11]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[12]);
        *d0 = _mm_aesenc_si128(*d0, roundKeys[13]);
        *d0 = _mm_aesenclast_si128(*d0, roundKeys[14]);
    } else {
        assert(0);
    }
}

static inline void encrypt_key(__m128i *d0, __m128i *d1, __m128i *roundKeys, const int num_rounds) {
    *d1 = _mm_xor_si128(*d0, roundKeys[0]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[1]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[2]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[3]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[4]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[5]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[6]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[7]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[8]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[9]);
    if (num_rounds == ROUNDS_128) {
        *d1 = _mm_aesenclast_si128(*d1, roundKeys[10]);
    } else if (num_rounds == ROUNDS_192) {
        *d1 = _mm_aesenc_si128(*d1, roundKeys[10]);
        *d1 = _mm_aesenc_si128(*d1, roundKeys[11]);
        *d1 = _mm_aesenclast_si128(*d1, roundKeys[12]);
    } else if (num_rounds == ROUNDS_256) {
        *d1 = _mm_aesenc_si128(*d1, roundKeys[10]);
        *d1 = _mm_aesenc_si128(*d1, roundKeys[11]);
        *d1 = _mm_aesenc_si128(*d1, roundKeys[12]);
        *d1 = _mm_aesenc_si128(*d1, roundKeys[13]);
        *d1 = _mm_aesenclast_si128(*d1, roundKeys[14]);
    } else {
        assert(0);
    }
}

uint8_t
deriveKeys(tables4kGCMMultiplier *theMultiplier, __m128i *roundKeys, uint8_t *key, char *theNonce, int *num_rounds,
           size_t key_len, uint8_t theFlags) {
    /* Create the buffers */
    /* Prepare for encryption */
    *num_rounds = (int) generate_key(true, key, roundKeys, key_len);
    /* Derive authentication key */
    uint8_t myResult[BLOCK_SIZE << 1];
    __m128i *myResult1 = (__m128i *) myResult, *myResult2 = (__m128i *) (myResult + BLOCK_SIZE);
    __m128i d0 = _mm_set_epi8(theNonce[11], theNonce[10], theNonce[9], theNonce[8], theNonce[7],
                              theNonce[6], theNonce[5], theNonce[4], theNonce[3], theNonce[2], theNonce[1], theNonce[0],
                              0, 0, 0, 0);
    encrypt_key(&d0, myResult1, roundKeys, *num_rounds);
    d0[0]++;
    encrypt_key(&d0, myResult2, roundKeys, *num_rounds);
    (*myResult1)[1] = (*myResult2)[0];
    /* Initialise the multiplier */
    reverse_bytes(myResult1, myResult2);
    uint8_t *myOut = (uint8_t *) myResult2;
    uint8_t myMask = 0;
    for (int i = 0; i < BLOCK_SIZE; i++) {
        uint8_t myValue = myOut[i];
        myOut[i] = (((myValue >> 1) & ~MASK) | myMask);
        myMask = (myValue & 1) == 0 ? 0 : MASK;
    }
    /* Xor in addition if last bit was set */
    if (myMask != 0) {
        myOut[0] ^= ADD;
    }
    tables4kGCMMultiplier_init(theMultiplier, myOut);

    /* Derive encryption key */
    d0[0]++;
    encrypt_key(&d0, myResult1, roundKeys, *num_rounds);

    d0[0]++;
    encrypt_key(&d0, myResult2, roundKeys, *num_rounds);
    (*myResult1)[1] = (*myResult2)[0];

    /* If we have a 32byte key */
    if (key_len == BLOCK_SIZE << 1) {
        /* Derive remainder of encryption key */
        d0[0]++;
        encrypt_key(&d0, myResult2, roundKeys, *num_rounds);

        d0[0]++;
        encrypt_key(&d0, &d0, roundKeys, *num_rounds);
        (*myResult2)[1] = d0[0];
    }
    /* Initialise the Cipher */
    generate_key(true, myResult, roundKeys, key_len);
    return theFlags | INIT;
}

void resetStreams(gcm_siv_ctx *ctx) {
    /* Reset hashers */
    gcm_siv_hasher_reset(&ctx->theAEADHasher);
    gcm_siv_hasher_reset(&ctx->theDataHasher);
    /* Initialise AEAD if required */
    ctx->theFlags &= ~AEAD_COMPLETE;
    memset(ctx->theGHash, 0, BLOCK_SIZE);
    if (ctx->initAD != NULL) {
        gcm_siv_hasher_updateHash(&ctx->theAEADHasher, &ctx->theMultiplier, ctx->initAD, ctx->initADLen,
                                  ctx->theReverse, ctx->theGHash);
    }
}

void calculateTag(gcm_siv_hasher *theDataHasher, gcm_siv_hasher *theAEADHasher, uint8_t *theReverse,
                  tables4kGCMMultiplier *theMultiplier, __m128i *roundKeys, int num_rounds, uint8_t *theGHash,
                  const uint8_t *theNonce, uint8_t *macBlock) {
    /* Complete the hash */
    gcm_siv_hasher_completeHash(theDataHasher, theReverse, theMultiplier, theGHash);
    __m128i myPolyVal = _mm_set_epi64x(_bswap64(theAEADHasher->numHashed << 3),
                                       _bswap64(theDataHasher->numHashed << 3));
    gHASH(theMultiplier, theGHash, &myPolyVal);
    reverse_bytes((__m128i *) theGHash, &myPolyVal);
    __m128i d1 = _mm_set_epi8(0, 0, 0, 0, theNonce[11], theNonce[10], theNonce[9], theNonce[8], theNonce[7],
                              theNonce[6], theNonce[5], theNonce[4], theNonce[3], theNonce[2], theNonce[1],
                              theNonce[0]);
    myPolyVal = _mm_xor_si128(myPolyVal, d1);
    ((uint8_t *) &myPolyVal)[BLOCK_SIZE - 1] &= 0x7f;
    encrypt(&myPolyVal, roundKeys, num_rounds);
    _mm_storeu_si128((__m128i *) macBlock, myPolyVal);
}

void
gcm_siv_process_packet(const uint8_t *mySrc, int myRemaining, uint8_t *pCounter, __m128i *roundKeys, int num_rounds,
                       uint8_t *output) {
    /* Access buffer and length */
    __m128i counter = _mm_loadu_si128((__m128i *) pCounter);
    counter[1] |= 1L << 63;
    uint8_t myMask[BLOCK_SIZE];
    int myOff = 0, i;
    __m128i d0;
    __m128i buffer;
    /* While we have data to process */
    while (myRemaining > 0) {
        /* Generate the next mask */
        d0 = _mm_loadu_si128(&counter);
        encrypt(&d0, roundKeys, num_rounds);
        if (BLOCK_SIZE > myRemaining) {
            _mm_storeu_si128((__m128i *) myMask, d0);
            for (i = 0; i < myRemaining; ++i) {
                output[i + myOff] = mySrc[i + myOff] ^ myMask[i];
            }
            break;
        } else {
            buffer = _mm_loadu_si128((__m128i *) (mySrc + myOff));
            buffer = _mm_xor_si128(buffer, d0);
            _mm_storeu_si128((__m128i *) (output + myOff), buffer);
            myOff += BLOCK_SIZE;
            incrementCounter((uint8_t *) &counter);
            myRemaining -= BLOCK_SIZE;
        }
    }
}

void incrementCounter(uint8_t *pCounter) {
    /* Loop through the bytes incrementing counter */
    for (int i = 0; i < 4; i++) {
        if (++pCounter[i] != 0) {
            break;
        }
    }
}

gcm_siv_err *gcm_siv_doFinal(gcm_siv_ctx *ctx, uint8_t *input, size_t len, uint8_t *output, size_t *written) {
    gcm_siv_hasher_completeHash(&ctx->theAEADHasher, ctx->theReverse, &ctx->theMultiplier, ctx->theGHash);
    if (ctx->encryption) {
        gcm_siv_hasher_updateHash(&ctx->theDataHasher, &ctx->theMultiplier, input,
                                  (int) len, ctx->theReverse, ctx->theGHash);
        calculateTag(&ctx->theDataHasher, &ctx->theAEADHasher, ctx->theReverse, &ctx->theMultiplier, ctx->roundKeys,
                     ctx->num_rounds, ctx->theGHash, ctx->nonce, ctx->macBlock);
        gcm_siv_process_packet(input, (int) len, ctx->macBlock, ctx->roundKeys, ctx->num_rounds, output);
        memcpy(output + len, ctx->macBlock, BLOCK_SIZE);
        resetStreams(ctx);
        *written = len + BLOCK_SIZE;
        return NULL;
    } else {
        size_t outputLen = len - BLOCK_SIZE;
        gcm_siv_process_packet(input, (int) outputLen, input + outputLen, ctx->roundKeys, ctx->num_rounds, output);
        gcm_siv_hasher_updateHash(&ctx->theDataHasher, &ctx->theMultiplier, output,
                                  (int) outputLen, ctx->theReverse, ctx->theGHash);
        calculateTag(&ctx->theDataHasher, &ctx->theAEADHasher, ctx->theReverse, &ctx->theMultiplier, ctx->roundKeys,
                     ctx->num_rounds, ctx->theGHash, ctx->nonce, ctx->macBlock);
        *written = len - BLOCK_SIZE;
        if (!tag_verification_16(ctx->macBlock, input + outputLen)) {
            return make_gcm_siv_error("mac check  failed", ILLEGAL_CIPHER_TEXT);
        }
    }
    return NULL;
}