//
//
//
#include <assert.h>
#include <memory.h>
#include "aes_common_neon.h"
#include "schedule.h"

aes_key *create_aes_key() {
    aes_key *key = calloc(1, sizeof(aes_key));
    return key;
}


void init_aes_key(aes_key *key, uint8_t *user_key, size_t key_len, bool encryption) {
    assert(key != NULL);
    assert(user_key != NULL);
    assert(key_len == 16 || key_len == 24 || key_len == 32);
    memset(key->round_keys, 0, sizeof(uint8x16_t) * 15);
    key->encryption = encryption;
    key->rounds = calculate_round_keys(
            user_key,
            key_len,
            encryption,
            key->round_keys);

}

void clear_aes_key(aes_key *key) {
    if (key != NULL) {
        memset(key, 0, sizeof(aes_key));
    }
}


void free_aes_key(aes_key *key) {
    if (key == NULL) {
        return;
    }
    clear_aes_key(key);
    free(key);
}

