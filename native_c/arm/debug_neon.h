

#ifndef BC_LTS_C_DEBUG_NEON_H
#define BC_LTS_C_DEBUG_NEON_H

#include <arm_neon.h>
#include <stdio.h>
#include <string.h>

unsigned char *from_hex_len(const char *str, uint32_t len);


unsigned char *from_hex_with_len(const char *str, size_t *len) {
    size_t  l = strlen(str);
    *len  = l/2;
    return from_hex_len(str, l);

}

unsigned char *from_hex(const char *str) {
    uint32_t len = strlen(str);
    return from_hex_len(str, len);

}

unsigned char *from_hex_len(const char *str, uint32_t len) {

    if ((strlen(str) & 1) == 1) {
        printf("string has odd length");
        exit(1);
    }

    unsigned char *out = calloc(len / 2,1);
    unsigned char *start = out;

    for (int t = 0; t < len/2; t++) {
        unsigned char val = 0;
        uint8_t v = *str;
        str++;
        if (v >= '0' && v <= '9') {
            val |= (v - '0');
        } else if (v >= 'a' && v <= 'f') {
            val |= (10 + (v - 'a'));
        } else if (v >= 'A' && v <= 'F') {
            val |= (10 + (v - 'A'));
        }
        val <<= 4;

        v = *str;
        str++;
        if (v >= '0' && v <= '9') {
            val |= (v - '0');
        } else if (v >= 'a' && v <= 'f') {
            val |= (10 + (v - 'a'));
        } else if (v >= 'A' && v <= 'F') {
            val |= (10 + (v - 'A'));
        }
        *out = val;
        out++;
    }

    return start;
}



//
void print_uint32x4_t(uint32x4_t *v) {
    for (int t = 0; t < sizeof(uint32x4_t); t++) {
        printf("%02X", ((uint8_t *) v)[t]);
    }
    printf("\n");
}

void print_poly128_t(poly128_t *v) {
    for (int t = 0; t < sizeof(poly128_t); t++) {
        printf("%02X", ((uint8_t *) v)[t]);
    }
    printf("\n");
}

void print_uint8x16_t(uint8x16_t *v) {
    for (int t = 0; t < sizeof(uint8x16_t); t++) {
        printf("%02X", ((uint8_t *) v)[t]);
    }
    printf("\n");
}

void print_uint8x16_t_arr(uint8x16_t *v, size_t elements) {
    while (elements>0) {
        print_uint8x16_t(v);
        v++;
        elements--;
    }
    printf("\n");
}

void print_bytes(uint8_t *d, size_t len) {
    for (int t = 0; t < len; t++) {
        printf("%02X", d[t]);
    }
    printf("\n");
}


void print_diff(uint8_t *left, size_t  ll, uint8_t *right, size_t rl) {

    size_t l = ll > rl?rl:ll;

    print_bytes(left,ll);
    print_bytes(right,rl);

    for (int t=0; t<l; t++) {
        if (left[t] != right[t]) {
            printf("!!");
        } else {
            printf("  ");
        }
    }
    printf("\n");


}

#endif