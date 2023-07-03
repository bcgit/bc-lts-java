
#include <arm_neon.h>
#include <stdio.h>


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

void print_bytes(uint8_t *d, size_t len) {
    for (int t = 0; t < len; t++) {
        printf("%02X", d[t]);
    }
    printf("\n");
}