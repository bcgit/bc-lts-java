
#include "ctr_pc.h"

packet_err *
ctr_pc_process_packet(bool encryption, uint8_t *key, size_t keysize, uint8_t *iv, size_t ivLen, uint8_t *p_in,
                      size_t inLen, uint8_t *p_out, size_t *outputLen) {
    __m128i roundKeys[15];
    uint64_t ctr;
    uint64_t initialCTR;
    __m128i IV_le;
    uint32_t buf_pos = 0;
    __m128i partialBlock = _mm_setzero_si128();
    int num_rounds = generate_key(true, key, roundKeys, keysize);
    uint64_t ctrMask;
    bool ctrAtEnd = false;
    switch (ivLen) {
        case 16:
        case 8:
            ctrMask = 0xFFFFFFFFFFFFFFFF;
            break;
        case 15:
            ctrMask = 0xFF;
            break;
        case 14:
            ctrMask = 0xFFFF;
            break;
        case 13:
            ctrMask = 0xFFFFFF;
            break;
        case 12:
            ctrMask = 0xFFFFFFFF;
            break;
        case 11:
            ctrMask = 0xFFFFFFFFFF;
            break;
        case 10:
            ctrMask = 0xFFFFFFFFFFFF;
            break;
        case 9:
            ctrMask = 0xFFFFFFFFFFFFFF;
            break;
        default:
            assert(0);
    }
    if (ivLen < 16) {
        IV_le = _mm_setzero_si128();
        for (int t = 0; t < ivLen; t++) {
            ((unsigned char *) &IV_le)[15 - t] = iv[t]; // endian
        }
        initialCTR = 0;
    } else {
        //
        // Users know what they are getting into.
        //
        IV_le = _mm_loadu_si128((__m128i *) iv);
        IV_le = _mm_shuffle_epi8(IV_le, *SWAP_ENDIAN_128);

        ctr = (uint64_t) _mm_extract_epi64(IV_le, 0);
        initialCTR = ctr;
        IV_le = _mm_and_si128(IV_le, _mm_set_epi64x(-1, 0));
    }
    ctr = initialCTR;
    size_t written = 0;
    ctr_pc_process_bytes(p_in, inLen, p_out, &written, &buf_pos, &ctr, initialCTR, ctrMask, &ctrAtEnd, &IV_le,
                         roundKeys, num_rounds, &partialBlock);
    return NULL;
}


