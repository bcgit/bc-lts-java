//
// Created on 31/5/2022.
//

#include "debug.h"
#include <stdio.h>
#include <emmintrin.h>
#include <string.h>
//#include <algorithm.h>


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
//
//unsigned char *from_hex(std::string str, size_t
//
//&len) {
//
//if ((str.
//
//length()
//
//& 1) == 1) {
//throw std::invalid_argument(
//
//"string not even number of chars long");
//}
//
//auto out = new
//unsigned char[str.
//
//length()
//
/// 2];
//
//int t = 0;
//for (
//std::string::iterator it = str.begin();
//it != str.
//
//end();
//
//) {
//unsigned char val = 0;
//uint8_t v = *it;
//if (v >= '0' && v <= '9') {
//val |= (v - '0');
//} else if (v >= 'a' && v <= 'f') {
//val |= (10 + (v - 'a'));
//} else if (v >= 'A' && v <= 'F') {
//val |= (10 + (v - 'A'));
//}
//val <<= 4;
//it++;
//v = *it;
//if (v >= '0' && v <= '9') {
//val |= (v - '0');
//} else if (v >= 'a' && v <= 'f') {
//val |= (10 + (v - 'a'));
//} else if (v >= 'A' && v <= 'F') {
//val |= (10 + (v - 'A'));
//}
//it++;
//out[t] =
//val;
//t++;
//}
//
//len = t;
//return
//out;
//}
//
//__m512i fill512(int start) {
//    unsigned char buf[64];
//    for (int t = 0; t < 64; t++) {
//        buf[t] = start + t;
//    }
//    return _mm512_loadu_si512(buf);
//}

//
//__m512i fromHex512(std::string str) {
//    if (str.length() != 128) {
//        throw
//        "must be 128 characters";
//    }
//
//    auto b = from_hex(str);
//
//    //std::reverse(b,b+64);
//
//
//    auto v = _mm512_loadu_si512(b);
//    delete b;
//    return v;
//}
//
//__m256i fromHex256(std::string str) {
//    if (str.length() != 64) {
//        throw
//        "must be 64 characters";
//    }
//
//    auto b = from_hex(str);
//    //std::reverse(b,b+32);
//    auto v = _mm256_loadu_si256(reinterpret_cast<const __m256i_u *>(b));
//    delete b;
//    return v;
//}
//
//__m128i fromHex128(std::string str) {
//    if (str.length() != 32) {
//        throw
//        "must be 32 characters";
//    }
//    auto b = from_hex(str);
//    //std::reverse(b,b+16);
//    auto v = _mm_loadu_si128(reinterpret_cast<const __m128i_u *>(b));
//    delete b;
//    return v;
//}
//
//
void print_bytes(unsigned char *src, size_t len) {
    while (len-- > 0) {
        printf("%02X", *src);
      //  printf("%d, ", (*src > 127) ? *src- 256: *src);
        src++;
    }
    printf("\n");
}

//
void print_bytes_128(__m128i *src) {
    print_bytes((unsigned char *) (src), 16);
}



//
//void print_bytes(__m256i *src) {
//    print_bytes(reinterpret_cast<unsigned char *>(src), 32);
//}
//
//void print_bytes(__m512i *src) {
//    print_bytes(reinterpret_cast<unsigned char *>(src), 64);
//}
//
//
//void print_bytes(std::string txt, unsigned char *src, size_t len) {
//    std::cout << txt << " ";
//    while (len-- > 0) {
//        printf("%02X", *src);
//        src++;
//    }
//    std::cout << std::endl;
//}
//
//void print_bytes(std::string txt, __m128i *src) {
//    std::cout << txt << " ";
//    print_bytes(reinterpret_cast<unsigned char *>(src), 16);
//}
//
//void print_bytes(std::string txt, __m256i *src) {
//    std::cout << txt << " ";
//    print_bytes(reinterpret_cast<unsigned char *>(src), 32);
//}
//
//void print_bytes(std::string txt, __m512i *src) {
//    std::cout << txt << " ";
//    print_bytes(reinterpret_cast<unsigned char *>(src), 64);
//}
//
//
//LeLe::LeLe(std::string
//str) {
//
//if ((str.
//
//length()
//
//& 1) == 1) {
//throw std::invalid_argument(
//
//"string not even number of chars long");
//}
//
//size = str.length() / 8;
//if (str.
//
//length()
//
//% 8) {
//size += 1;
//}
//
//val = new
//uint32_t[size];
//memset(val,
//0, size * 4);
//
//size_t t = ((size * 4) - 1);
//
//
//for (
//std::string::iterator it = str.begin();
//it != str.
//
//end();
//
//) {
//unsigned char j = 0;
//uint8_t v = *it;
//if (v >= '0' && v <= '9') {
//j |= (v - '0');
//} else if (v >= 'a' && v <= 'f') {
//j |= (10 + (v - 'a'));
//} else if (v >= 'A' && v <= 'F') {
//j |= (10 + (v - 'A'));
//}
//j <<= 4;
//it++;
//v = *it;
//if (v >= '0' && v <= '9') {
//j |= (v - '0');
//} else if (v >= 'a' && v <= 'f') {
//j |= (10 + (v - 'a'));
//} else if (v >= 'A' && v <= 'F') {
//j |= (10 + (v - 'A'));
//}
//it++;
//((unsigned char *) val)[t] =
//j;
//t--;
//}
//
//
//}