//
//

#ifndef BC_FIPS_C_CFB_H
#define BC_FIPS_C_CFB_H

#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>
#include "../ctr_pc/ctr_pc_utils.h"

#define CFB_BLOCK_SIZE 16

packet_err *
cfb_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *iv, size_t ivLen, uint8_t *p_in,
                      size_t inLen, uint8_t *p_out, size_t *outputLen);


size_t
cfb_pc_encrypt(unsigned char *src, size_t len, unsigned char *dest, __m128i *roundKeys, __m128i *mask,
               __m128i *feedback,
               uint32_t *buf_index, uint32_t num_rounds);

unsigned char
cfb_pc_encrypt_byte(unsigned char b, __m128i *roundKeys, __m128i *mask, __m128i *feedback, uint32_t *buf_index,
                    uint32_t num_rounds);

//
// Decrypt methods implementation vary depending on which of cfb128, cfb256 or cfb512.c files are imported.
//
size_t
cfb_pc_decrypt(unsigned char *src, size_t len, unsigned char *dest, __m128i *roundKeys, __m128i *mask,
               __m128i *feedback, uint32_t *buf_index, uint32_t num_rounds);

unsigned char
cfb_pc_decrypt_byte(unsigned char b, __m128i *roundKeys, __m128i *mask, __m128i *feedback, uint32_t *buf_index,
                 uint32_t num_rounds);


#endif //BC_FIPS_C_CFB_H
