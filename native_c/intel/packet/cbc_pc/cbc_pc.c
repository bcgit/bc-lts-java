#include "cbc_pc.h"
#include <string.h>

packet_err *
cbc_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *iv, uint8_t *p_in,
                      size_t inLen, uint8_t *p_out, size_t *outputLen) {
    __m128i roundKeys[15];
    __m128i chainblock = _mm_loadu_si128((__m128i *) iv);
    int num_rounds = generate_key(encryption, key, roundKeys, keysize);
    if (encryption) {
        *outputLen = cbc_pc_encrypt(p_in, (uint32_t) (inLen >> 4), p_out, &chainblock, roundKeys, num_rounds);
        if (inLen & 15) {
            uint8_t tail_block[BLOCK_SIZE] = {0};
            memcpy(tail_block, p_in+*outputLen, inLen-*outputLen);
            *outputLen +=cbc_pc_encrypt(tail_block, 1, p_out+*outputLen, &chainblock, roundKeys, num_rounds);
        }
    } else {
        *outputLen = cbc_pc_decrypt(p_in, (uint32_t) (inLen >> 4), p_out, &chainblock, roundKeys, num_rounds);
    }
    return NULL;
}








