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

int generate_key(bool encryption, uint8_t *key, __m128i *roundKeys, size_t keyLen) {
    int num_rounds;
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

static inline void encrypt(__m128i *d0, __m128i *d1, __m128i *roundKeys, const int num_rounds) {
    *d1 = _mm_xor_si128(*d0, roundKeys[0]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[1]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[2]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[3]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[4]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[5]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[6]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[7]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[8]);
    *d1 = _mm_aesenc_si128(*d1, roundKeys[9]);
    if (num_rounds == ROUNDS_128) {
        *d1 = _mm_aesenclast_si128(*d1, roundKeys[10]);
    } else if (num_rounds == ROUNDS_192) {
        *d1 = _mm_aesenc_si128(*d1, roundKeys[10]);
        *d1 = _mm_aesenc_si128(*d1, roundKeys[11]);
        *d1 = _mm_aesenclast_si128(*d1, roundKeys[12]);
    } else if (num_rounds == ROUNDS_256) {
        *d1 = _mm_aesenc_si128(*d1, roundKeys[10]);
        *d1 = _mm_aesenc_si128(*d1, roundKeys[11]);
        *d1 = _mm_aesenc_si128(*d1, roundKeys[12]);
        *d1 = _mm_aesenc_si128(*d1, roundKeys[13]);
        *d1 = _mm_aesenclast_si128(*d1, roundKeys[14]);
    } else {
        assert(0);
    }
}

size_t cbc_pc_encrypt(unsigned char *src, uint32_t blocks, unsigned char *dest, __m128i *chainblock, __m128i *roundKeys,
                      int num_rounds) {
    unsigned char *destStart = dest;
    __m128i d0;
    __m128i tmpCb = *chainblock;
    while (blocks > 0) {
        d0 = _mm_xor_si128(_mm_loadu_si128((__m128i *) src), tmpCb);
        encrypt(&d0, &d0, roundKeys, num_rounds);
        _mm_storeu_si128((__m128i *) dest, d0);
        blocks--;
        src += BLOCK_SIZE;
        dest += BLOCK_SIZE;
        tmpCb = d0;
    }
    *chainblock = tmpCb;
    return (size_t) (dest - destStart);
}

bool tag_verification(const uint8_t *left, const uint8_t *right, size_t len) {
    assert(left != NULL);
    assert(right != NULL);
    uint32_t nonEqual = 0;
    for (int i = 0; i != len; i++) {
        nonEqual |= (left[i] ^ right[i]);
    }
    return nonEqual == 0;
}

bool tag_verification_16(const uint8_t *macblock, const uint8_t *ciphertext) {
    __m128i d0 = _mm_loadu_si128((__m128i *) ciphertext);
    d0 = _mm_xor_si128(*(__m128i *) macblock, d0);
    return (d0[0] | d0[1]) == 0;
}

void divideP(__m128i *x, __m128i *z) {
    int64_t x0 = (*x)[0];
    uint64_t x1 = (uint64_t)(*x)[1];
    int64_t m = x0 >> 63;
    x0 ^= (m & E1L);
    (*z)[0] = (x0 << 1) | (int64_t) (x1 >> 63);
    (*z)[1] = (int64_t) (x1 << 1) | -m;
}

 __m128i createBigEndianM128i(long q1, long q0) {
    return _mm_set_epi64x(_bswap64(q1), _bswap64(q0));
}

void reverse_bytes(__m128i *input, __m128i *output) {
    *output = _mm_shuffle_epi8(*input, *SWAP_ENDIAN_128);
}
