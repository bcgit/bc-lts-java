
#include <stdio.h>
#include <stdlib.h>
//#include <string.h>

#include <stdio.h>
#include "intel/common.h"

#include "intel/gcm_siv/gcm_siv.h"
#include <immintrin.h>
#include <assert.h>
#include <memory.h>
//#include "debug.h"
#include <stdbool.h>
#include <stdbool.h>
#include <stdint-gcc.h>
#include "intel/packet/packet_utils.h"

unsigned char *from_hex(unsigned char *str, size_t len) {

//    if ((str.length() & 1) == 1) {
//        throw
//        std::invalid_argument("string not even number of chars long");
//    }

    unsigned char *out = malloc((sizeof(unsigned char)) * (len >> 1));

    int t = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char val = 0;
        unsigned char v = str[i];
        if (v >= '0' && v <= '9') {
            val |= (v - '0');
        } else if (v >= 'a' && v <= 'f') {
            val |= (10 + (v - 'a'));
        } else if (v >= 'A' && v <= 'F') {
            val |= (10 + (v - 'A'));
        }
        val <<= 4;
        i++;
        v = str[i];
        if (v >= '0' && v <= '9') {
            val |= (v - '0');
        } else if (v >= 'a' && v <= 'f') {
            val |= (10 + (v - 'a'));
        } else if (v >= 'A' && v <= 'F') {
            val |= (10 + (v - 'A'));
        }
        out[t] = val;
        t++;
    }

    return out;
}

void print_bytes(unsigned char *src, size_t len) {
    while (len-- > 0) {
        printf("%02X", *src);
//        printf("%d, ", (*src > 127) ? *src - 256 : *src);
        src++;
    }
    printf("\n");
}

//
void print_bytes_128(__m128i *src) {
    print_bytes((unsigned char *) (src), 16);
}


int main() {
    __m128i k = _mm_set_epi32(0, 0, 0, 1);
    __m128i j = _mm_set_epi32(0, 0, 0, 1);

    bool val = tag_verification_16(&k,&j);
    assert(val == true);
    printf("%d\n", val);
}

