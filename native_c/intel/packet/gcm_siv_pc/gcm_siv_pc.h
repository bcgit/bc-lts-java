//
//

#include <stdbool.h>
#include <stdint.h>
#include <immintrin.h>
#include <stdlib.h>
#include <stdio.h>
#include "../packet_utils.h"
#include "../../gcm_siv/gcm_siv.h"

#ifndef BC_FIPS_C_GCM_SIV_PC_H
#define BC_FIPS_C_GCM_SIV_PC_H

packet_err* gcm_siv_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *iv,
                                  uint8_t *aad, int aadLen, uint8_t *p_in, size_t inLen, uint8_t *p_out, size_t *outputLen);




#endif //BC_FIPS_C_GCM_H
