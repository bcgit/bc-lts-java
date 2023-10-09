
#ifndef BC_FIPS_C_CTR_H
#define BC_FIPS_C_CTR_H


#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>
#include "../packet_utils.h"
#include "ctr_pc_utils.h"

packet_err *
ctr_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *iv, size_t ivLen, uint8_t *p_in,
                      size_t inLen, uint8_t *p_out, size_t *outputLen);

#endif //BC_FIPS_C_CFB_H




