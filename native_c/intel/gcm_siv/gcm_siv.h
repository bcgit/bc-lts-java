//
//

#include <stdbool.h>
#include <stdint.h>
#include <immintrin.h>
#include <stdlib.h>
#include <stdio.h>
#include "../packet/packet_utils.h"

#ifndef BC_FIPS_C_GCM_H
#define BC_FIPS_C_GCM_H


//
// Exponentiator
//

#define ILLEGAL_STATE 1
#define ILLEGAL_ARGUMENT 2
#define ILLEGAL_CIPHER_TEXT 3
#define OUTPUT_LENGTH 4


#define GCM_BLOCK_SIZE 16
#define BLOCK_SIZE 16
#define FOUR_BLOCKS 64
#define EIGHT_BLOCKS 128
#define SIXTEEN_BLOCKS 256

#define BLOCKS_REMAINING_INIT ((1L << 32) - 2L)
#define MAC_BLOCK_LEN 16


//#ifdef BC_AVX
//#define HASHKEY_1 2
//#define HASHKEY_0 3
//#define HASHKEY_LEN 4
//#else
#define HASHKEY_1 14
#define HASHKEY_0 15
#define HASHKEY_LEN 16
//#endif

#define BUFLEN 16
#define HALFBUFLEN 8
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

#define BUF_BLK_SIZE (17 * 16) // 17 blocks because we need to hold the potential tag on decryption.
typedef struct {
    uint8_t theBuffer[16];
    uint8_t theByte;
    int numActive;
    long numHashed;
} gcm_siv_hasher;

typedef struct {
    uint8_t H[16];
    __m128i T[256];
} tables4kGCMMultiplier;

typedef struct {
    __m128i roundKeys[15];
    int num_rounds;
    bool encryption;
    uint8_t nonce[NONCELEN];
    uint8_t macBlock[MAC_BLOCK_LEN];
    uint8_t *initAD;
    size_t initADLen;

    gcm_siv_hasher theAEADHasher;
    gcm_siv_hasher theDataHasher;
    uint8_t theFlags;
    tables4kGCMMultiplier theMultiplier;
    uint8_t theGHash[BLOCK_SIZE];
    uint8_t theBuffer[BLOCK_SIZE];
    uint8_t theReverse[BLOCK_SIZE];
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
gcm_siv_init(gcm_siv_ctx *ctx, bool encryption, uint8_t *key, size_t keyLen, uint8_t *nonce, size_t nonceLen,
             uint8_t *intialText, size_t initialTextLen);


void fillReverse(const uint8_t *pInput, int pOffset, int pLength, uint8_t *pOutput);

void gcm_siv_hasher_reset(gcm_siv_hasher *p_gsh);

void
gcm_siv_hasher_updateHash(gcm_siv_hasher *p_gsh, tables4kGCMMultiplier *p_multiplier, uint8_t *pBuffer,
                          int pLen, uint8_t *theReverse, uint8_t *theGHash);

void tables4kGCMMultiplier_init(tables4kGCMMultiplier *p_multipler, uint8_t *H);

void gcm_siv_hasher_completeHash(gcm_siv_hasher *p_gsh, uint8_t *theReverse, tables4kGCMMultiplier *p_multiplier,
                                 const uint8_t *theGHash);

void multiplyH(tables4kGCMMultiplier *p_multipler, const uint8_t *x);

void gHASH(tables4kGCMMultiplier *p_multiplier, const uint8_t *theGHash, const uint8_t *pNext);

uint8_t
deriveKeys(tables4kGCMMultiplier *theMultiplier, __m128i *roundKeys, uint8_t *key, uint8_t *theNonce, int* num_rounds,
           size_t key_len,  uint8_t theFlags);

void resetStreams(gcm_siv_ctx *ctx);

void calculateTag(gcm_siv_hasher *theDataHasher, gcm_siv_hasher *theAEADHasher, uint8_t *theReverse,
                  tables4kGCMMultiplier *theMultiplier, __m128i *roundKeys, int num_rounds, uint8_t *theGHash,
                  const uint8_t *theNonce, uint8_t *macBlock);
void incrementCounter(uint8_t *pCounter);

void gcm_siv_process_packet(const uint8_t *mySrc, int myRemaining, uint8_t *myCounter,  __m128i *roundKeys, int num_rounds,
                    uint8_t *output);

gcm_siv_err* gcm_siv_doFinal(gcm_siv_ctx *ctx, uint8_t *input, size_t len, uint8_t *output, size_t* written);
#endif //BC_FIPS_C_GCM_H
