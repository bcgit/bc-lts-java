

#ifndef BC_LTS_C_CBC_PC_H
#define BC_LTS_C_CBC_PC_H

#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>
#include "../packet_utils.h"

size_t cbc_pc_encrypt(unsigned char *src, uint32_t blocks, unsigned char *dest, __m128i *chainblock, __m128i *roundKeys,
                      int num_rounds);

size_t cbc_pc_decrypt(unsigned char *src, uint32_t blocks, unsigned char *dest, __m128i *chainblock, __m128i *roundKeys,
                      int num_rounds);

packet_err *
cbc_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *iv, uint8_t *p_in,
                      size_t inLen, uint8_t *p_out, size_t *outputLen);

#endif //BC_LTS_C_CBC_PC_H
