
#include <immintrin.h>
#include "gcm_siv_pc.h"
#include <memory.h>

packet_err *
gcm_siv_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *nonce, uint8_t *aad, size_t aadLen,
                          uint8_t *p_in, size_t inLen, uint8_t *p_out, size_t *outputLen) {
    __m128i roundKeys[15];
    __m128i theGHash = _mm_setzero_si128();
    __m128i H= _mm_setzero_si128();
    __m128i T[256];
    gcm_siv_hasher theAEADHasher;
    gcm_siv_hasher theDataHasher;
    uint8_t macBlock[BLOCK_SIZE];
    uint8_t theFlags = 0;
    int num_rounds;
    memset(macBlock, 0, BLOCK_SIZE);
    deriveKeys(T, &H, roundKeys, key, (char *) nonce, &num_rounds, keysize, theFlags);
    gcm_siv_hasher_reset(&theAEADHasher);
    gcm_siv_hasher_reset(&theDataHasher);
    if (aad != NULL) {
        gcm_siv_hasher_updateHash(&theAEADHasher, T, aad, aadLen, &theGHash);
    }
    gcm_siv_hasher_completeHash(&theAEADHasher, T, &theGHash);
    if (encryption) {
        gcm_siv_hasher_updateHash(&theDataHasher, T, p_in, (int) inLen, &theGHash);
        calculateTag(&theDataHasher, &theAEADHasher, T, roundKeys,
                     num_rounds, &theGHash, (int8_t *) nonce, macBlock);
        gcm_siv_process_packet(p_in, (int) inLen, macBlock, roundKeys, num_rounds, p_out);
        memcpy(p_out + inLen, macBlock, BLOCK_SIZE);
        *outputLen = inLen + BLOCK_SIZE;
    } else {
        *outputLen = inLen - BLOCK_SIZE;
        gcm_siv_process_packet(p_in, (int) *outputLen, p_in + *outputLen, roundKeys, num_rounds, p_out);
        gcm_siv_hasher_updateHash(&theDataHasher, T, p_out, (int) *outputLen, &theGHash);
        calculateTag(&theDataHasher, &theAEADHasher, T, roundKeys,
                     num_rounds, &theGHash, (int8_t *) nonce, macBlock);
        if (!tag_verification_16(macBlock, p_in + *outputLen)) {
            return make_packet_error("mac check  failed", ILLEGAL_CIPHER_TEXT);
        }
    }
    return NULL;
}