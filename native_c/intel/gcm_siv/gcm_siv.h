//
//

#include <stdbool.h>
#include <stdint.h>
#include <immintrin.h>
#include <stdlib.h>
#include <stdio.h>
#include "../packet/packet_utils.h"

#ifndef BC_LTS_C_GCM_SIV_H
#define BC_LTS_C_GCM_SIV_H

#define NONCELEN 12
// MAX_DATALEN=2^31-1-8-BUFLEN
#define MAX_DATALEN 2147483623
#define MASK 0x80
#define ADD 0xE1
#define INIT 1
#define AEAD_COMPLETE 2


typedef struct {
    const char *msg; // the message
    int type; // relates to exception needed on jvm side
} gcm_siv_err;


gcm_siv_err *make_gcm_siv_error(const char *msg, int type);

void gcm_siv_err_free(gcm_siv_err *err);


typedef struct {
    uint8_t theBuffer[BLOCK_SIZE];
    int numActive;
    long numHashed;
} gcm_siv_hasher;

typedef struct {
    __m128i roundKeys[15];
    __m128i theGHash;
    __m128i H;
    int num_rounds;
    bool encryption;
    uint8_t nonce[NONCELEN];
    __m128i theNonce;
    uint8_t macBlock[BLOCK_SIZE];
    uint8_t *initAD;
    int initADLen;
    __m128i T[256];
    gcm_siv_hasher theAEADHasher;
    gcm_siv_hasher theDataHasher;
    //uint8_t theFlags;
} gcm_siv_ctx;


gcm_siv_ctx *gcm_siv_create_ctx();

void gcm_siv_free(gcm_siv_ctx *);

void gcm_siv_reset(gcm_siv_ctx *, bool keepMac);


/**
 * Call with NULL destination to get len.
 * @param destination destination to copy mac
 * @return the length
 */
size_t gcm_siv_getMac(gcm_siv_ctx *, uint8_t *destination);

size_t gcm_siv_get_output_size(bool encryption, size_t len);

/**
 *
 * @param encryption
 * @param key
 * @param keyLen
 * @param nonce
 * @param nonceLen
 * @return NULL if no error, other ptr to struct CALLER NEEDS TO FREE
 */
gcm_siv_err *
gcm_siv_init(gcm_siv_ctx *ctx, bool encryption, uint8_t *key, size_t keyLen, uint8_t *nonce,
             uint8_t *intialText, int initialTextLen);

void gcm_siv_hasher_reset(gcm_siv_hasher *p_gsh);

void gcm_siv_hasher_updateHash(gcm_siv_hasher *p_gsh, __m128i *T, uint8_t *pBuffer, int pLen, __m128i *theGHash);

void gcm_siv_hasher_completeHash(gcm_siv_hasher *p_gsh, __m128i *T, __m128i *theGHash);

void gHASH(__m128i *T, __m128i *theGHash, __m128i *pNext);

//uint8_t
//deriveKeys(__m128i *T, __m128i *H, __m128i *roundKeys, uint8_t *key, char *theNonce, int *num_rounds,
//           size_t key_len, uint8_t theFlags);

void
deriveKeys(__m128i *T, __m128i *H, __m128i *roundKeys, uint8_t *key, char *theNonce, int *num_rounds, size_t key_len);

void resetStreams(gcm_siv_ctx *ctx);

void calculateTag(gcm_siv_hasher *theDataHasher, gcm_siv_hasher *theAEADHasher, __m128i *T, __m128i *roundKeys,
                  int num_rounds, __m128i *theGHash, const int8_t *theNonce, uint8_t *macBlock);

void incrementCounter(uint8_t *pCounter);

void
gcm_siv_process_packet(const uint8_t *mySrc, int myRemaining, uint8_t *myCounter, __m128i *roundKeys, int num_rounds,
                       uint8_t *output);

gcm_siv_err *gcm_siv_doFinal(gcm_siv_ctx *ctx, uint8_t *input, size_t len, uint8_t *output, size_t *written);

#endif //BC_FIPS_C_GCM_H
