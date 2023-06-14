//

//

#ifndef BC_LTS_C_AES_COMMON_128B_H
#define BC_LTS_C_AES_COMMON_128B_H

#include <arm_neon.h>
#include <stdlib.h>
#include <stdbool.h>

typedef struct aes_key {
    uint8x16_t round_keys[15];
    size_t rounds;
    bool encryption;
} aes_key;


/**
 * Create an aes_key on the heap.
 * @return
 */
aes_key *create_aes_key();

/**
 * Initialise an AES key, round keys will be in the correct order depending on mode.
 * @param key the aes_key instance, asserted not null
 * @param user_key Pointer to the user key asserted not null.
 * @param key_len the length of the key which is asserted as 16, 24 or 32 bytes.
 */
void init_aes_key(aes_key *key, uint8_t *user_key, size_t key_len, bool encryption);

/**
 * NULL safe zeroing of the key.
 *
 * Clear the aes key zeroing the struct, this method is also called by free_aes_key().
 * Use in cases where the aes_key is stack allocated. Will do nothing if the key is null.
 */
void clear_aes_key(aes_key *key);

/**
 * NULL safe freeing of aes keys.
 *
 * Clears then frees the key, use only if created via create_aes_key, calling this on stack allocated instances will
 * cause a fault. Will do nothing if key is null.
 *
 * In stack allocated cases simply call "clear_aes_key" when finished using the key.
 */
void free_aes_key(aes_key *key);


#endif //BC_LTS_C_AES_COMMON_128B_H
