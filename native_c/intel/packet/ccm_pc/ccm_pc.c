#include "ccm_pc.h"

packet_err *
ccm_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *nonce, size_t nonceLen, size_t mac_size,
                      uint8_t *initAD, size_t initADLen, uint8_t *p_in, size_t inLen, uint8_t *p_out,
                      size_t *outputLen) {
    size_t q = 15 - nonceLen;
    __m128i roundKeys[15];
    uint8_t buf[BLOCK_SIZE];
    // mac block
    uint8_t macBlock[BLOCK_SIZE];
    size_t buf_ptr = 0;
    //ctr
    uint64_t ctr;
    uint64_t initialCTR;
    __m128i IV_le;
    uint32_t buf_pos = 0;
    __m128i partialBlock = _mm_setzero_si128();
    uint64_t ctrMask = 0xFFFFFFFFFFFFFFFF;
    bool ctrAtEnd = false;

    int num_rounds = generate_key(true, key, roundKeys, keysize);
    __m128i chainblock = _mm_setzero_si128();

    memset(buf, 0, BLOCK_SIZE);

    buf_ptr = 0;
    memset(macBlock, 0, BLOCK_SIZE);
    macBlock[0] = (q - 1) & 0x7;
    memcpy(macBlock + 1, nonce, nonceLen);

    IV_le = _mm_shuffle_epi8(*(__m128i *) macBlock, *SWAP_ENDIAN_128);
    ctr = (uint64_t) _mm_extract_epi64(IV_le, 0);
    initialCTR = ctr;
    IV_le = _mm_and_si128(IV_le, _mm_set_epi64x(-1, 0));

    // Zero out mac block
    memset(macBlock, 0, BLOCK_SIZE);

    if (q < 4) {
        int limitLen = 1 << (q << 3);
        if (inLen >= limitLen) {
            return make_packet_error("CCM packet too large for choice of q", ILLEGAL_STATE);
        }
    }

    if (encryption) {
        *outputLen = 0;
        ccm_pc_calculateMac(p_in, inLen, initAD, initADLen, mac_size, nonce, nonceLen, buf, macBlock, &chainblock,
                            roundKeys, num_rounds, &buf_ptr);
        ctr_pc_process_bytes(macBlock, BLOCK_SIZE, macBlock, outputLen, &buf_pos, &ctr, initialCTR, ctrMask,
                             &ctrAtEnd,
                             &IV_le, roundKeys, num_rounds, &partialBlock);
        ctr_pc_process_bytes(p_in, inLen, p_out, outputLen, &buf_pos, &ctr, initialCTR, ctrMask, &ctrAtEnd,
                             &IV_le, roundKeys, num_rounds, &partialBlock);
        memcpy(p_out + *outputLen, macBlock, mac_size);
        *outputLen = inLen + mac_size;
    } else {
        if (inLen < mac_size) {
            return make_packet_error("ciphertext too short", ILLEGAL_CIPHER_TEXT);
        }
        *outputLen = inLen - mac_size;
        size_t written = 0;
        uint8_t tmp[BLOCK_SIZE] = {
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0};
        memcpy(macBlock, p_in + *outputLen, mac_size);
        memset(macBlock + mac_size, 0, (BLOCK_SIZE - mac_size));
        ctr_pc_process_bytes(macBlock, BLOCK_SIZE, tmp, &written, &buf_pos, &ctr, initialCTR, ctrMask, &ctrAtEnd,
                             &IV_le, roundKeys, num_rounds, &partialBlock);
        ctr_pc_process_bytes(p_in, *outputLen, p_out, &written, &buf_pos, &ctr, initialCTR, ctrMask, &ctrAtEnd,
                             &IV_le, roundKeys, num_rounds, &partialBlock);
        ccm_pc_calculateMac(p_out, *outputLen, initAD, initADLen, mac_size, nonce, nonceLen, buf, macBlock, &chainblock,
                            roundKeys, num_rounds, &buf_ptr);

        uint8_t nonEqual = 0;
        for (int i = 0; i < mac_size; i++) {
            nonEqual |= (macBlock[i] ^ tmp[i]);
        }
        memset(tmp, 0, BLOCK_SIZE);
        //"mac check in CCM failed"
        if (nonEqual) {
            memset(p_out, 0, *outputLen);
            return make_packet_error("mac check in CCM failed", ILLEGAL_CIPHER_TEXT);
        }
    }
    return NULL;
}


void ccm_pc_calculateMac(uint8_t *input, size_t len, uint8_t *initAD, size_t initADLen, size_t mac_size, uint8_t *nonce,
                         size_t nonceLen, uint8_t *buf, uint8_t *macBlock, __m128i *chainblock, __m128i *roundKeys,
                         int num_rounds, size_t *buf_ptr) {
    if (initADLen) {
        buf[0] |= 0x40;
    }
    buf[0] |= ((((mac_size - 2) >> 1) & 0x7) << 3) | (((15 - nonceLen) - 1) & 0x7);
    memcpy(buf + 1, nonce, nonceLen); // nonceLen is <=13, buf is 16
    size_t count = 1;
    size_t q = len;
    while (q > 0) {
        buf[BLOCK_SIZE - count++] = (uint8_t) (q & 0xFF);
        q >>= 8;
    }
    cbc_pc_encrypt(buf, 1, macBlock, chainblock, roundKeys, num_rounds);
    if (initADLen) {
        if (initADLen < TEXT_LENGTH_UPPER_BOUND) {
            buf[0] = (uint8_t) (initADLen >> 8);
            buf[1] = (uint8_t) (initADLen);
            *buf_ptr = 2;
        } else {
            buf[0] = 0xff;
            buf[1] = 0xfe;
            buf[2] = (uint8_t) (initADLen >> 24);
            buf[3] = (uint8_t) (initADLen >> 16);
            buf[4] = (uint8_t) (initADLen >> 8);
            buf[5] = (uint8_t) (initADLen);
            *buf_ptr = 6;
        }
        if (initAD != NULL) {
            cbc_pc_mac_update(initAD, initADLen, buf, buf_ptr, macBlock, chainblock, roundKeys, num_rounds);
        }
        memset(buf + *buf_ptr, 0, (BLOCK_SIZE - *buf_ptr));
        cbc_pc_encrypt(buf, 1, macBlock, chainblock, roundKeys, num_rounds);
        *buf_ptr = 0;
    }
    cbc_pc_mac_update(input, len, buf, buf_ptr, macBlock, chainblock, roundKeys, num_rounds);
    if (*buf_ptr) {
        memset(buf + *buf_ptr, 0, BLOCK_SIZE - *buf_ptr);
        cbc_pc_encrypt(buf, 1, macBlock, chainblock, roundKeys, num_rounds);
    }
    memset(macBlock + mac_size, 0, BLOCK_SIZE - mac_size);
}


void cbc_pc_mac_update(uint8_t *src, size_t len, uint8_t *buf, size_t *buf_ptr, uint8_t *macBlock, __m128i *chainblock,
                       __m128i *roundKeys, int num_rounds) {
    size_t gapLen = BLOCK_SIZE - *buf_ptr;
    if (len > gapLen) {
        memcpy(buf + *buf_ptr, src, gapLen);
        cbc_pc_encrypt(buf, 1, macBlock, chainblock, roundKeys, num_rounds);
        *buf_ptr = 0;
        len -= gapLen;
        src += gapLen;
        while (len > BLOCK_SIZE) {
            cbc_pc_encrypt(src, 1, macBlock, chainblock, roundKeys, num_rounds);
            len -= BLOCK_SIZE;
            src += BLOCK_SIZE;
        }
    }
    if (len) {
        memcpy(buf + *buf_ptr, src, len);
        *buf_ptr += len;
    }
}


