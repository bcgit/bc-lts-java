//
//

#include <immintrin.h>
#include <assert.h>
#include "gcm_siv.h"
#include <stdlib.h>
#include <memory.h>

static inline void divideP(__m128i *x, __m128i *z) {
    int64_t x0 = (*x)[0];
    uint64_t x1 = (uint64_t) (*x)[1];
    int64_t m = x0 >> 63;
    x0 ^= (m & E1L);
    (*z)[0] = (x0 << 1) | (int64_t) (x1 >> 63);
    (*z)[1] = (int64_t) (x1 << 1) | -m;
}

static inline __m128i createBigEndianM128iRev(uint64_t q1, uint64_t q0) {
    return _mm_set_epi64x((int64_t)q0, (int64_t) q1);
}

static inline __m128i createBigEndianM128i(uint64_t q1, uint64_t q0) {
    return _mm_set_epi64x(_bswap64((int64_t) q1), _bswap64((int64_t) q0));
}



static inline void reverse_bytes(__m128i *input, __m128i *output) {
    *output = _mm_shuffle_epi8(*input, *SWAP_ENDIAN_128);
}

static inline void encrypt128(__m128i *d0, __m128i *d1, __m128i *roundKeys) {
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
    *d1 = _mm_aesenclast_si128(*d1, roundKeys[10]);
}

static inline void encrypt192(__m128i *d0, __m128i *d1, __m128i *roundKeys) {
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
    *d1 = _mm_aesenc_si128(*d1, roundKeys[10]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[11]);
    *d1 = _mm_aesenclast_si128(*d1, roundKeys[12]);
}

static inline void encrypt256(__m128i *d0, __m128i *d1, __m128i *roundKeys) {
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
    *d1 = _mm_aesenc_si128(*d1, roundKeys[10]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[11]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[12]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[13]);
    *d1 = _mm_aesenclast_si128(*d1, roundKeys[14]);
}

void generateKey(bool encryption, uint8_t *key, __m128i *roundKeys, size_t keyLen, encrypt_function *fun) {
    memzero(roundKeys, sizeof(__m128i) * 15);
    switch (keyLen) {
        case 16:
            *fun = (void (*)(__m128i *, __m128i *, __m128i *)) encrypt128;
            init_128(roundKeys, key, encryption);
            break;
        case 24:
            *fun = (void (*)(__m128i *, __m128i *, __m128i *)) encrypt192;
            init_192(roundKeys, key, encryption);
            break;
        case 32:
            *fun = (void (*)(__m128i *, __m128i *, __m128i *)) encrypt256;
            init_256(roundKeys, key, encryption);
            break;
        default:
            assert(0);
    }
}

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
    assert((size_t)MAX_DATALEN + BLOCK_SIZE > (size_t)MAX_DATALEN);
    ctx->max_dl = MAX_DATALEN;
    return ctx;
}

void gcm_siv_free(gcm_siv_ctx *ctx) {
    if (ctx->initAD != NULL) {
        memzero(ctx->initAD, (size_t) ctx->initADLen);
        free(ctx->initAD);
    }
    memzero(ctx, sizeof(gcm_siv_ctx));
    free(ctx);
}

void gcm_siv_reset(gcm_siv_ctx *ctx, bool keepMac) {
    if (!keepMac) {
        memzero(ctx->macBlock, 16);
    }
    resetStreams(ctx);
}

size_t gcm_siv_getMac(gcm_siv_ctx *ctx, uint8_t *destination) {
    if (destination != NULL) {
        memcpy(destination, ctx->macBlock, BLOCK_SIZE);
    }
    return BLOCK_SIZE;
}


/**
 *
 * @param encryption
 * @param key
 * @param keyLen
 * @param nonce
 * @return NULL if no error, other ptr to struct CALLER NEEDS TO FREE
 */
gcm_siv_err *gcm_siv_init(
        gcm_siv_ctx *ctx,
        bool encryption,
        uint8_t *key,
        size_t keyLen,
        uint8_t *nonce,
        uint8_t *initialText,
        size_t initialTextLen) {
    ctx->encryption = encryption;

    // We had old initial text drop it here.
    if (ctx->initAD != NULL) {
        memzero(ctx->initAD, (size_t) ctx->initADLen);
        free(ctx->initAD);
        ctx->initAD = NULL;
        ctx->initADLen = 0;
    }

    if (initialText != NULL) {
        //
        // We keep a copy so that if the instances is reset it can be returned to
        // the same state it was before the first data is processed.
        //
        ctx->initAD = malloc((size_t) initialTextLen);
        ctx->initADLen = initialTextLen;
        memcpy(ctx->initAD, initialText, (size_t) initialTextLen);
    } else {
        assert(initialTextLen == 0);
    }

    // Zero out mac block
    memzero(ctx->macBlock, BLOCK_SIZE);
    memcpy(ctx->nonce, nonce, NONCELEN);
    deriveKeys(ctx->T, &ctx->H, ctx->roundKeys, key, (char *) ctx->nonce, keyLen, &ctx->encrypt);

    resetStreams(ctx);
    return NULL;// All good
}


int64_t gcm_siv_get_output_size(bool encryption, size_t len) {

    if (encryption) {
        return (int64_t) (len + BLOCK_SIZE);
    }

    if (len < BLOCK_SIZE) {
        return -1;
    }

    return (int64_t) (len - BLOCK_SIZE);
}


void gcm_siv_hasher_reset(gcm_siv_hasher *p_gsh) {
    p_gsh->numActive = 0;
    p_gsh->numHashed = 0;
    memzero(p_gsh->theBuffer, BLOCK_SIZE);
}


void gcm_siv_hasher_updateHash(gcm_siv_hasher *p_gsh, __m128i *T, uint8_t *pBuffer, size_t pLen, __m128i *theGHash) {
    /* If we should process the cache */
    const uint64_t mySpace = BLOCK_SIZE - p_gsh->numActive;
    uint64_t numProcessed = 0;
    uint64_t myRemaining = pLen;
    __m128i d0;
    if (p_gsh->numActive > 0 && pLen >= mySpace) {
        /* Copy data into the cache and hash it */
        memcpy(p_gsh->theBuffer + p_gsh->numActive, pBuffer, (size_t) mySpace);
        //reverse_bytes((__m128i *) p_gsh->theBuffer, &d0);
        gHASH(T, theGHash, (__m128i *)p_gsh->theBuffer);
        /* Adjust counters */
        numProcessed += mySpace;
        myRemaining -= mySpace;
        p_gsh->numActive = 0;
    }
    /* While we have full blocks */
    while (myRemaining >= BLOCK_SIZE) {
        /* Access the next data */
        d0 = _mm_loadu_si128((__m128i *) (pBuffer + numProcessed));
        gHASH(T, theGHash, &d0);
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

void gcm_siv_hasher_completeHash(gcm_siv_hasher *p_gsh, __m128i *T, __m128i *theGHash) {
    /* If we have remaining data */
    if (p_gsh->numActive > 0) {
        memzero(p_gsh->theBuffer + p_gsh->numActive, (size_t) (BLOCK_SIZE - p_gsh->numActive));
        gHASH(T, theGHash, (__m128i *) p_gsh->theBuffer);
    }
}


void gHASH(__m128i *T, __m128i *theGHash, __m128i *pNext) {
    _mm_storeu_si128(theGHash, _mm_xor_si128(*theGHash, *pNext));
    uint8_t *p = (uint8_t *) theGHash;
    __m128i t = T[p[0] & 0xFF];
    uint64_t z0 = (uint64_t) t[0], z1 = (uint64_t) t[1];

    for (int i = 1; i < 16; i++) {
        t = T[p[i] & 0xFF];
        uint64_t c = z1 << 56;
        z1 = (uint64_t) t[1] ^ ((z1 >> 8) | (z0 << 56));
        z0 = (uint64_t) t[0] ^ (z0 >> 8) ^ c ^ (c >> 1) ^ (c >> 2) ^ (c >> 7);
    }

    _mm_storeu_si128(theGHash, createBigEndianM128iRev(z1, z0));
}


void
deriveKeys(__m128i *T, __m128i *H, __m128i *roundKeys, uint8_t *key, char *theNonce, size_t key_len,
           encrypt_function *encrypt) {
    /* Create the buffers */
    uint8_t myResult[BLOCK_SIZE << 1];
    __m128i *myResult1 = (__m128i *) myResult, *myResult2 = (__m128i *) (myResult + BLOCK_SIZE);
    uint8_t *myOut = (uint8_t *) myResult2;
    uint8_t myMask = 0;
    __m128i d0 = _mm_set_epi8(theNonce[11], theNonce[10], theNonce[9], theNonce[8], theNonce[7],
                              theNonce[6], theNonce[5], theNonce[4], theNonce[3], theNonce[2], theNonce[1], theNonce[0],
                              0, 0, 0, 0);
    generateKey(true, key, roundKeys, key_len, encrypt);
    (*encrypt)(&d0, myResult1, roundKeys);
    d0[0]++;

    (*encrypt)(&d0, myResult2, roundKeys);
    (*myResult1)[1] = (*myResult2)[0];
    /* Initialise the multiplier */
    reverse_bytes(myResult1, myResult2);

    for (int i = 0; i < BLOCK_SIZE; i++) {
        uint8_t myValue = myOut[i];
        myOut[i] = (uint8_t) (((myValue >> 1) & ~MASK) | myMask);
        myMask = (myValue & 1) == 0 ? 0 : MASK;
    }
    /* Xor in addition if last bit was set */
    if (myMask != 0) {
        myOut[0] ^= ADD;
    }

    // TODO use carry-less multiply intrinsic instead of table
    T[0] = _mm_xor_si128(*H, *myResult2);
    if ((T[0][0] | T[0][1]) != 0) {
        T[0] = _mm_setzero_si128();
        _mm_storeu_si128(H, *myResult2);
        __m128i d1 = createBigEndianM128i((size_t) (*H)[1], (size_t) (*H)[0]);
        uint64_t c = ((uint64_t) d1[1]) << 57;
        T[1][0] = (int64_t) (((uint64_t) d1[0] >> 7) ^ c ^ (c >> 1) ^ (c >> 2) ^ (c >> 7));
        T[1][1] = (int64_t) (((uint64_t) d1[1] >> 7) | ((uint64_t) d1[0] << 57));
        size_t n;
        for (n = 2; n < 256; n += 2) {
            divideP((__m128i *) (T + (n >> 1)), (__m128i *) (T + n));
            T[n + 1] = _mm_xor_si128(T[n], T[1]);
        }
    }

    /* Derive encryption key */
    d0[0]++;
    (*encrypt)(&d0, myResult1, roundKeys);
    d0[0]++;
    (*encrypt)(&d0, myResult2, roundKeys);
    (*myResult1)[1] = (*myResult2)[0];

    /* If we have a 32byte key */
    if (key_len == BLOCK_SIZE << 1) {
        /* Derive remainder of encryption key */
        d0[0]++;
        (*encrypt)(&d0, myResult2, roundKeys);
        d0[0]++;
        (*encrypt)(&d0, &d0, roundKeys);
        (*myResult2)[1] = d0[0];
    }
    /* Initialise the Cipher */
    generate_key(true, myResult, roundKeys, key_len);
}

void resetStreams(gcm_siv_ctx *ctx) {
    /* Reset hashers */
    gcm_siv_hasher_reset(&ctx->theAEADHasher);
    gcm_siv_hasher_reset(&ctx->theDataHasher);
    /* Initialise AEAD if required */
    ctx->theGHash = _mm_setzero_si128();
    if (ctx->initAD != NULL) {
        gcm_siv_hasher_updateHash(&ctx->theAEADHasher, ctx->T, ctx->initAD, ctx->initADLen,
                                  &ctx->theGHash);
    }
}

void calculateTag(gcm_siv_hasher *theDataHasher, gcm_siv_hasher *theAEADHasher, __m128i *T, __m128i *roundKeys,
                  __m128i *theGHash, const int8_t *theNonce, uint8_t *macBlock,
                  encrypt_function *encrypt) {
    /* Complete the hash */
    gcm_siv_hasher_completeHash(theDataHasher, T, theGHash);

    __m128i myPolyVal =  createBigEndianM128iRev((uint64_t)(theAEADHasher->numHashed << 3),(uint64_t) (theDataHasher->numHashed << 3));

    gHASH(T, theGHash, &myPolyVal);
    myPolyVal = *theGHash;
    int32_t *p = (int32_t *) theNonce;
    __m128i d1 = _mm_setr_epi32(*p, p[1], p[2], 0);
    myPolyVal = _mm_xor_si128(myPolyVal, d1);
    ((uint8_t *) &myPolyVal)[BLOCK_SIZE - 1] &= 0x7f;
    (*encrypt)(&myPolyVal, (__m128i *) macBlock, roundKeys);
}

void
gcm_siv_process_packet(const uint8_t *mySrc, int myRemaining, uint8_t *pCounter, __m128i *roundKeys,
                       uint8_t *output, encrypt_function *encrypt) {
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
        (*encrypt)(&d0, &d0, roundKeys);
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
    gcm_siv_hasher_completeHash(&ctx->theAEADHasher, ctx->T, &ctx->theGHash); // ad
    if (ctx->encryption) {
        gcm_siv_hasher_updateHash(&ctx->theDataHasher, ctx->T, input, len, &ctx->theGHash); // input
        calculateTag(&ctx->theDataHasher, &ctx->theAEADHasher, ctx->T, ctx->roundKeys,
                     &ctx->theGHash, (int8_t *) ctx->nonce, ctx->macBlock, &ctx->encrypt);
        gcm_siv_process_packet(input, (int) len, ctx->macBlock, ctx->roundKeys, output, &ctx->encrypt);
        memcpy(output + len, ctx->macBlock, BLOCK_SIZE);
        *written = len + BLOCK_SIZE;
    } else {
        *written = len - BLOCK_SIZE;
        gcm_siv_process_packet(input, (int) *written, input + *written, ctx->roundKeys, output,
                               &ctx->encrypt);
        gcm_siv_hasher_updateHash(&ctx->theDataHasher, ctx->T, output, *written, &ctx->theGHash);
        calculateTag(&ctx->theDataHasher, &ctx->theAEADHasher, ctx->T, ctx->roundKeys,
                     &ctx->theGHash, (int8_t *) ctx->nonce, ctx->macBlock, &ctx->encrypt);
        if (!tag_verification(ctx->macBlock, input + *written,BLOCK_SIZE)) {
            return make_gcm_siv_error("mac check  failed", ILLEGAL_CIPHER_TEXT);
        }
    }
    resetStreams(ctx);
    return NULL;
}