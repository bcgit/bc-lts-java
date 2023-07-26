
#ifndef BC_LTS_C_CCM_PC_H
#define BC_LTS_C_CCM_PC_H

#include <stdbool.h>
#include <stdint.h>
#include <immintrin.h>
#include <stdlib.h>
#include <memory.h>
#include "../packet_utils.h"

#define TEXT_LENGTH_UPPER_BOUND ((1 << 16) - (1 << 8))

packet_err* ccm_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *iv, size_t ivsize, size_t macSize,
                          uint8_t *aad, size_t aadLen, uint8_t *p_in, size_t inLen, uint8_t *p_out, size_t *outputLen);

bool ccm_pc_incCtr(uint64_t magnitude, uint64_t *ctr, uint64_t initialCTR, uint64_t ctrMask, bool* ctrAtEnd);

void ccm_pc_generate_partial_block(__m128i *IV_le, uint64_t ctr, __m128i* roundKeys, uint32_t num_rounds, __m128i* partialBlock);

bool ccm_pc_ctr_process_byte(unsigned char *io, uint32_t *buf_pos, uint64_t *ctr, uint64_t initialCTR, uint64_t ctrMast,
                             bool* ctrAtEnd, __m128i* IV_le, __m128i* roundKeys, uint32_t num_rounds, __m128i* partialBlock);

bool ccm_pc_ctr_process_bytes(unsigned char *src, size_t len, unsigned char *dest, size_t *written, uint32_t *buf_pos,
                              uint64_t* ctr, uint64_t initialCTR, uint64_t ctrMast, bool* ctrAtEnd, __m128i* IV_le,
                              __m128i* roundKeys, uint32_t num_rounds, __m128i* partialBlock);

static inline void packet_encrypt(__m128i *d0, const __m128i chainblock, __m128i *roundKeys, const uint32_t num_rounds);

size_t cbc_pc_encrypt(unsigned char *src, uint32_t blocks, unsigned char *dest, __m128i* chainblock, __m128i *roundKeys,
                      uint32_t num_rounds);

void cbc_pc_mac_update(uint8_t *src, size_t len, uint8_t *buf, size_t *buf_ptr, uint8_t *macBlock, __m128i* chainblock,
                       __m128i *roundKeys, uint32_t num_rounds);

void ccm_pc_calculateMac(uint8_t *input, size_t len, uint8_t *initAD, size_t initADLen, size_t mac_size, uint8_t *nonce,
                         size_t nonceLen, uint8_t *buf, uint8_t *macBlock, __m128i *chainblock, __m128i *roundKeys,
                         uint32_t num_rounds, size_t *buf_ptr);
#endif //BC_LTS_C_CCM_PC_H
