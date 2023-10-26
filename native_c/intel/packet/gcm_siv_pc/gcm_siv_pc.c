
#include <immintrin.h>
#include "gcm_siv_pc.h"
#include <memory.h>

packet_err *
gcm_siv_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *nonce, uint8_t *aad, size_t aadLen,
                          uint8_t *p_in, size_t inLen, uint8_t *p_out, size_t *outputLen) {
    __m128i roundKeys[15];
    __m128i theGHash = _mm_setzero_si128();
    __m128i H = _mm_setzero_si128();
    __m128i T[256];
    gcm_siv_hasher theAEADHasher;
    gcm_siv_hasher theDataHasher;
    uint8_t macBlock[BLOCK_SIZE];
    memset(macBlock, 0, BLOCK_SIZE);
    encrypt_function p_encrypt;
    deriveKeys(T, &H, roundKeys, key, (char *) nonce, keysize, &p_encrypt);
    gcm_siv_hasher_reset(&theAEADHasher);
    gcm_siv_hasher_reset(&theDataHasher);
    if (aad != NULL) {
        gcm_siv_hasher_updateHash(&theAEADHasher, T, aad, aadLen, &theGHash);
    }
    gcm_siv_hasher_completeHash(&theAEADHasher, T, &theGHash);
    if (encryption) {
        gcm_siv_hasher_updateHash(&theDataHasher, T, p_in, inLen, &theGHash);
        calculateTag(&theDataHasher, &theAEADHasher, T, roundKeys, &theGHash, (int8_t *) nonce, macBlock, &p_encrypt);
        gcm_siv_process_packet(p_in, (int) inLen, macBlock, roundKeys, p_out, &p_encrypt);
        memcpy(p_out + inLen, macBlock, BLOCK_SIZE);
        *outputLen = inLen + BLOCK_SIZE;
    } else {
        *outputLen = inLen - BLOCK_SIZE;
        gcm_siv_process_packet(p_in, (int) *outputLen, p_in + *outputLen, roundKeys, p_out, &p_encrypt);
        gcm_siv_hasher_updateHash(&theDataHasher, T, p_out,  *outputLen, &theGHash);
        calculateTag(&theDataHasher, &theAEADHasher, T, roundKeys, &theGHash, (int8_t *) nonce, macBlock, &p_encrypt);
        if (!tag_verification_16(macBlock, p_in + *outputLen)) {
            memset(p_out, 0, *outputLen);
            return make_packet_error("mac check  failed", ILLEGAL_CIPHER_TEXT);
        }
    }
    return NULL;
}