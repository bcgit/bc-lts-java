#include "packet_utils.h"

int get_aead_output_size(bool encryption, int len, int macSize) {
    if (encryption) {
        return len + macSize;
    } else if (len < macSize) {
        return -1;
    } else {
        return len - macSize;
    }
}

int get_output_size(bool encryption, int len) {
    if (encryption) {
        return len + ((len & 15) ? BLOCK_SIZE : 0);
    } else if (len & 15) {
        return -1;
    } else {
        return len;
    }
}

void packet_err_free(packet_err *err) {
    if (err != NULL) {
        free(err);
    }
}

packet_err *make_packet_error(const char *msg, int type) {
    packet_err *err = calloc(1, sizeof(packet_err));
    assert(err != NULL);
    err->msg = msg;
    err->type = type;
    return err;
}

uint32_t generate_key(bool encryption, uint8_t *key, __m128i *roundKeys, size_t keyLen) {
    uint32_t num_rounds;
    memset(roundKeys, 0, sizeof(__m128i) * 15);
    switch (keyLen) {
        case 16:
            num_rounds = ROUNDS_128;
            init_128(roundKeys, key, encryption);
            break;
        case 24:
            num_rounds = ROUNDS_192;
            init_192(roundKeys, key, encryption);
            break;
        case 32:
            num_rounds = ROUNDS_256;
            init_256(roundKeys, key, encryption);
            break;
        default:
            assert(0);
    }
    return num_rounds;
}
