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


/**
 * AES Key with IV
 */
typedef struct aes_key_with_iv {
    aes_key key;
    uint8_t iv[16];
} aes_key_with_iv;

aes_key_with_iv *create_key_with_iv();

/**
 * Initialise with aes_key instance and the iv, the iv will be copied into the struct up to a
 * maximum of the block size.
 *
 * NB: The aes_key instance state will be copied.
 *
 * @param ctx the aes_key_with_iv, asserted not NULL.
 * @param key the aes_key instance, asserted not NULL.
 * @param iv the iv to copy from
 * @param iv_len the number of bytes to copy, will only copy up to the block size of 16 bytes.
 *
 */
void init_aes_key_with_iv(aes_key_with_iv *ctx, aes_key *key, uint8_t *iv, size_t iv_len);


/**
 * Initialise with aes_key instance and the iv, the iv will be copied into the struct up to a
 * maximum of the block size.
 * @param ctx the aes_key_with_iv asserted not NULL.
 * @param user_key Pointer to the user key asserted not null.
 * @param key_len the length of the key which is asserted as 16, 24 or 32 bytes.
 * @param iv Pointer to the iv, this will be copied into the struct to the block size in length.
 * @param iv_len the length of the iv.
 * @param encryption direction.
 */
void init_aes_key_with_iv_from_parameters(
        aes_key_with_iv *ctx,
        uint8_t *user_key,
        size_t key_len,
        uint8_t *iv,
        size_t iv_len,
        bool encryption);


/**
 * NULL safe zeroing of the structure.
 *
 * This function is also called by free_key_with_iv().
 *
 * Clears the structure.
 *
 * If using stack allocated structure call before leaving the scope.
 */
void clear_key_with_iv(aes_key_with_iv *ctx);

/**
 * Null safe free of the key with iv.
 *
 * Clears then frees the key, use only if created via create_key_with_iv, calling this on stack allocated instances will
 * cause a fault. Will do nothing if key is null.
 *
 * In stack allocated cases simply call "clear_key_with_iv" when finished using the key.
 *
 * @param ctx
 */
void free_key_with_iv(aes_key_with_iv *ctx);

#endif //BC_LTS_C_AES_COMMON_128B_H
