


#ifndef BC_LTS_C_SCHEDULE_H
#define BC_LTS_C_SCHEDULE_H

#include <stdlib.h>
#include <string.h>
#include "../util/util.h"


static const uint8_t S[] = {99, 124, 119, 123, 242, 107, 111, 197,
                            48, 1, 103, 43, 254, 215, 171, 118,
                            202, 130, 201, 125, 250, 89, 71, 240,
                            173, 212, 162, 175, 156, 164, 114, 192,
                            183, 253, 147, 38, 54, 63, 247, 204,
                            52, 165, 229, 241, 113, 216, 49, 21,
                            4, 199, 35, 195, 24, 150, 5, 154,
                            7, 18, 128, 226, 235, 39, 178, 117,
                            9, 131, 44, 26, 27, 110, 90, 160,
                            82, 59, 214, 179, 41, 227, 47, 132,
                            83, 209, 0, 237, 32, 252, 177, 91,
                            106, 203, 190, 57, 74, 76, 88, 207,
                            208, 239, 170, 251, 67, 77, 51, 133,
                            69, 249, 2, 127, 80, 60, 159, 168,
                            81, 163, 64, 143, 146, 157, 56, 245,
                            188, 182, 218, 33, 16, 255, 243, 210,
                            205, 12, 19, 236, 95, 151, 68, 23,
                            196, 167, 126, 61, 100, 93, 25, 115,
                            96, 129, 79, 220, 34, 42, 144, 136,
                            70, 238, 184, 20, 222, 94, 11, 219,
                            224, 50, 58, 10, 73, 6, 36, 92,
                            194, 211, 172, 98, 145, 149, 228, 121,
                            231, 200, 55, 109, 141, 213, 78, 169,
                            108, 86, 244, 234, 101, 122, 174, 8,
                            186, 120, 37, 46, 28, 166, 180, 198,
                            232, 221, 116, 31, 75, 189, 139, 138,
                            112, 62, 181, 102, 72, 3, 246, 14,
                            97, 53, 87, 185, 134, 193, 29, 158,
                            225, 248, 152, 17, 105, 217, 142, 148,
                            155, 30, 135, 233, 206, 85, 40, 223,
                            140, 161, 137, 13, 191, 230, 66, 104,
                            65, 153, 45, 15, 176, 84, 187, 22,
};

static const uint8_t Si[] = {
        82, 9, 106, 213, 48, 54, 165, 56,
        191, 64, 163, 158, 129, 243, 215, 251,
        124, 227, 57, 130, 155, 47, 255, 135,
        52, 142, 67, 68, 196, 222, 233, 203,
        84, 123, 148, 50, 166, 194, 35, 61,
        238, 76, 149, 11, 66, 250, 195, 78,
        8, 46, 161, 102, 40, 217, 36, 178,
        118, 91, 162, 73, 109, 139, 209, 37,
        114, 248, 246, 100, 134, 104, 152, 22,
        212, 164, 92, 204, 93, 101, 182, 146,
        108, 112, 72, 80, 253, 237, 185, 218,
        94, 21, 70, 87, 167, 141, 157, 132,
        144, 216, 171, 0, 140, 188, 211, 10,
        247, 228, 88, 5, 184, 179, 69, 6,
        208, 44, 30, 143, 202, 63, 15, 2,
        193, 175, 189, 3, 1, 19, 138, 107,
        58, 145, 17, 65, 79, 103, 220, 234,
        151, 242, 207, 206, 240, 180, 230, 115,
        150, 172, 116, 34, 231, 173, 53, 133,
        226, 249, 55, 232, 28, 117, 223, 110,
        71, 241, 26, 113, 29, 41, 197, 137,
        111, 183, 98, 14, 170, 24, 190, 27,
        252, 86, 62, 75, 198, 210, 121, 32,
        154, 219, 192, 254, 120, 205, 90, 244,
        31, 221, 168, 51, 136, 7, 199, 49,
        177, 18, 16, 89, 39, 128, 236, 95,
        96, 81, 127, 169, 25, 181, 74, 13,
        45, 229, 122, 159, 147, 201, 156, 239,
        160, 224, 59, 77, 174, 42, 245, 176,
        200, 235, 187, 60, 131, 83, 153, 97,
        23, 43, 4, 126, 186, 119, 214, 38,
        225, 105, 20, 99, 85, 33, 12, 125,
};

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

static inline uint32_t SubWord(uint32_t x) {
    return (uint32_t) S[x & 255]
           | (((uint32_t) S[(x >> 8) & 255]) << 8)
           | (((uint32_t) S[(x >> 16) & 255]) << 16)
           | (((uint32_t) S[(x >> 24) & 255]) << 24);
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
    memzero(W, sizeof W);

    return rounds;
}

#endif //BC_LTS_C_SCHEDULE_H
