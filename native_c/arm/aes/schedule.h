


#ifndef BC_LTS_C_SCHEDULE_H
#define BC_LTS_C_SCHEDULE_H

#include <stdlib.h>
#include <string.h>
#include "../util/util.h"


static const uint8_t rcon[] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
};

static const uint32_t m1 = 0x80808080;
static const uint32_t m2 = 0x7f7f7f7f;
static const uint32_t m3 = 0x0000001b;
static const uint32_t m4 = 0xC0C0C0C0;
static const uint32_t m5 = 0x3f3f3f3f;


static inline uint32_t Shift(uint32_t r, int shift) {
    return (r >> shift) | (r << (32 - shift));
}

static inline uint32_t FFmulX(uint32_t x) {
    return ((x & m2) << 1) ^ (((x & m1) >> 7) * m3);
}

static inline uint32_t FFmulX2(uint32_t x) {
    uint32_t t0 = (x & m5) << 2;
    uint32_t t1 = (x & m4);
    t1 ^= (t1 >> 1);
    return t0 ^ (t1 >> 2) ^ (t1 >> 5);
}

static inline uint32_t Inv_Mcol(uint32_t x) {
    uint32_t t0, t1;
    t0 = x;
    t1 = t0 ^ Shift(t0, 8);
    t0 ^= FFmulX(t1);
    t1 ^= FFmulX2(t0);
    t0 ^= t1 ^ Shift(t1, 16);
    return t0;
}

/**
 * SubWord applies the AES S-box to each byte of a 32 bit word.
 *
 * The table form indexed a 256 byte S-box with four key-derived bytes, which is
 * an array index that comes from a secret. The S-box spans four cache lines, a
 * caller that re-keys for each message recomputes the same schedule many times,
 * and native-code.md bans the pattern for exactly that reason.
 *
 * AESE computes ShiftRows(SubBytes(state XOR key)). Give it a zero round key and
 * put the same word in all four columns: ShiftRows is then the identity, so every
 * 32 bit lane of the result holds SubWord of that word.
 *
 * On Linux the neon-le variant compiles at -march=armv8-a+crypto, so the build
 * flags guarantee AESE. On Darwin it comes from the toolchain default, which
 * this same library already depends on: the ECB, CTR and CFB cores use AESE
 * throughout. At run time every service that can reach this code requires the
 * FEAT_AES HWCAP through the requirement table in arm/jni/services.h, so the
 * instruction is present on the CPU as well.
 */
static inline uint32_t SubWord(uint32_t x) {
    uint8x16_t v = vreinterpretq_u8_u32(vdupq_n_u32(x));
    v = vaeseq_u8(v, vdupq_n_u8(0));
    return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
}



/**
 * Calculate round keys, based on the bc-java C# implementation.
 * TODO optimise if applicable
 * @param user_key the user key, asserted as not null
 * @param user_key_len the length of the user key, asserted as 16,24 or 32
 * @param encrypt direction
 * @param rc  round key array, asserted as not null
 * @return the number of rounds
 */
static inline size_t calculate_round_keys(uint8_t *user_key, size_t user_key_len, bool encrypt,  uint8x16_t *rc) {
    bc_assert(user_key != NULL);
    bc_assert(user_key_len == 16 || user_key_len == 24 || user_key_len == 32);
    bc_assert(rc != NULL);



    size_t rounds = 0;

    uint32_t key[8];
    memcpy(key, user_key, user_key_len);


    uint32_t W[15][4] = {0};

    switch (user_key_len) {
        case 16: {
            rounds = 10;
            uint32_t t0 = key[0]; W[0][0] = t0;
            uint32_t t1 = key[1]; W[0][1] = t1;
            uint32_t t2 = key[2]; W[0][2] = t2;
            uint32_t t3 = key[3]; W[0][3] = t3;

            for (int i = 1; i <= 10; ++i)
            {
                uint32_t u = SubWord(Shift(t3, 8)) ^ rcon[i - 1];
                t0 ^= u;  W[i][0] = t0;
                t1 ^= t0; W[i][1] = t1;
                t2 ^= t1; W[i][2] = t2;
                t3 ^= t2; W[i][3] = t3;
            }
            break;
        }

        case 24:
        {
            rounds = 12;
            uint32_t t0 = key[0]; W[0][0] = t0;
            uint32_t t1 = key[1]; W[0][1] = t1;
            uint32_t t2 = key[2]; W[0][2] = t2;
            uint32_t t3 = key[3]; W[0][3] = t3;
            uint32_t t4 = key[4]; W[1][0] = t4;
            uint32_t t5 = key[5]; W[1][1] = t5;

            uint32_t rcon_ = 1;
            uint32_t u = SubWord(Shift(t5, 8)) ^ rcon_; rcon_ <<= 1;
            t0 ^= u;  W[1][2] = t0;
            t1 ^= t0; W[1][3] = t1;
            t2 ^= t1; W[2][0] = t2;
            t3 ^= t2; W[2][1] = t3;
            t4 ^= t3; W[2][2] = t4;
            t5 ^= t4; W[2][3] = t5;

            for (int i = 3; i < 12; i += 3)
            {
                u = SubWord(Shift(t5, 8)) ^ rcon_; rcon_ <<= 1;
                t0 ^= u;  W[i    ][0] = t0;
                t1 ^= t0; W[i    ][1] = t1;
                t2 ^= t1; W[i    ][2] = t2;
                t3 ^= t2; W[i    ][3] = t3;
                t4 ^= t3; W[i + 1][0] = t4;
                t5 ^= t4; W[i + 1][1] = t5;
                u = SubWord(Shift(t5, 8)) ^ rcon_; rcon_ <<= 1;
                t0 ^= u;  W[i + 1][2] = t0;
                t1 ^= t0; W[i + 1][3] = t1;
                t2 ^= t1; W[i + 2][0] = t2;
                t3 ^= t2; W[i + 2][1] = t3;
                t4 ^= t3; W[i + 2][2] = t4;
                t5 ^= t4; W[i + 2][3] = t5;
            }

            u = SubWord(Shift(t5, 8)) ^ rcon_;
            t0 ^= u;  W[12][0] = t0;
            t1 ^= t0; W[12][1] = t1;
            t2 ^= t1; W[12][2] = t2;
            t3 ^= t2; W[12][3] = t3;

            break;
        }

        case 32:
        {
            rounds = 14;
            uint32_t t0 = key[0]; W[0][0] = t0;
            uint32_t t1 = key[1]; W[0][1] = t1;
            uint32_t t2 = key[2]; W[0][2] = t2;
            uint32_t t3 = key[3]; W[0][3] = t3;
            uint32_t t4 = key[4]; W[1][0] = t4;
            uint32_t t5 = key[5]; W[1][1] = t5;
            uint32_t t6 = key[6]; W[1][2] = t6;
            uint32_t t7 = key[7]; W[1][3] = t7;

            uint32_t u,rcon_ = 1;

            for (int i = 2; i < 14; i += 2)
            {
                u = SubWord(Shift(t7, 8)) ^ rcon_; rcon_ <<= 1;
                t0 ^= u;  W[i    ][0] = t0;
                t1 ^= t0; W[i    ][1] = t1;
                t2 ^= t1; W[i    ][2] = t2;
                t3 ^= t2; W[i    ][3] = t3;
                u = SubWord(t3);
                t4 ^= u;  W[i + 1][0] = t4;
                t5 ^= t4; W[i + 1][1] = t5;
                t6 ^= t5; W[i + 1][2] = t6;
                t7 ^= t6; W[i + 1][3] = t7;
            }

            u = SubWord(Shift(t7, 8)) ^ rcon_;
            t0 ^= u;  W[14][0] = t0;
            t1 ^= t0; W[14][1] = t1;
            t2 ^= t1; W[14][2] = t2;
            t3 ^= t2; W[14][3] = t3;

            break;
        }

        default:
            bc_assert(false);


    }
    if (!encrypt) {
        for (int j = 1; j<rounds; j++) {
            uint32_t *w = W[j];
            for (int i = 0; i < 4; i++)
            {
                w[i] = Inv_Mcol(w[i]);
            }
        }
    }


    memcpy(rc, W, sizeof W);
    memzero(key, sizeof key);
    memzero(W, sizeof W);

    return rounds;
}

#endif //BC_LTS_C_SCHEDULE_H
