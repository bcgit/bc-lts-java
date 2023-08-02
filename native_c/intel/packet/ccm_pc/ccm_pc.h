
#ifndef BC_LTS_C_CCM_PC_H
#define BC_LTS_C_CCM_PC_H

#include <stdbool.h>
#include <stdint.h>
#include <immintrin.h>
#include <stdlib.h>
#include <memory.h>
#include "../packet_utils.h"
#include "../ctr_pc/ctr_pc_utils.h"

#define TEXT_LENGTH_UPPER_BOUND ((1 << 16) - (1 << 8))

packet_err* ccm_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *iv, size_t ivsize, size_t macSize,
                          uint8_t *aad, size_t aadLen, uint8_t *p_in, size_t inLen, uint8_t *p_out, size_t *outputLen);

void cbc_pc_mac_update(uint8_t *src, size_t len, uint8_t *buf, size_t *buf_ptr, uint8_t *macBlock, __m128i* chainblock,
                       __m128i *roundKeys, uint32_t num_rounds);

void ccm_pc_calculateMac(uint8_t *input, size_t len, uint8_t *initAD, size_t initADLen, size_t mac_size, uint8_t *nonce,
                         size_t nonceLen, uint8_t *buf, uint8_t *macBlock, __m128i *chainblock, __m128i *roundKeys,
                         uint32_t num_rounds, size_t *buf_ptr);
#endif //BC_LTS_C_CCM_PC_H
