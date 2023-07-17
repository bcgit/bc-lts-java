//
//

#ifndef BC_LTS_C_ECB_H
#define BC_LTS_C_ECB_H

#include "../aes/aes_common_neon.h"

#define ECB_BLOCK_SIZE 16

size_t ecb_process_blocks(aes_key *key, uint8_t *src, uint32_t blocks, uint8_t *dest);


#endif //BC_LTS_C_ECB_H
