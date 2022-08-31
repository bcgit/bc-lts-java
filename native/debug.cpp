//
// Created on 31/5/2022.
//

#include "debug.h"
#include <iostream>
#include <emmintrin.h>

unsigned char *from_hex(std::string str) {

    if ((str.length() & 1) == 1) {
        throw std::invalid_argument("string not even number of chars long");
    }

    auto out = new unsigned char[str.length() / 2];

    int t = 0;
    for (std::string::iterator it = str.begin(); it != str.end();) {
        unsigned char val = 0;
        uint8_t v = *it;
        if (v >= '0' && v <= '9') {
            val |= (v - '0');
        } else if (v >= 'a' && v <= 'f') {
            val |= (10 + (v - 'a'));
        } else if (v >= 'A' && v <= 'F') {
            val |= (10 + (v - 'A'));
        }
        val <<= 4;
        it++;
        v = *it;
        if (v >= '0' && v <= '9') {
            val |= (v - '0');
        } else if (v >= 'a' && v <= 'f') {
            val |= (10 + (v - 'a'));
        } else if (v >= 'A' && v <= 'F') {
            val |= (10 + (v - 'A'));
        }
        it++;
        out[t] = val;
        t++;
    }

    return out;
}

unsigned char *from_hex(std::string str, size_t &len) {

    if ((str.length() & 1) == 1) {
        throw std::invalid_argument("string not even number of chars long");
    }

    auto out = new unsigned char[str.length() / 2];

    int t = 0;
    for (std::string::iterator it = str.begin(); it != str.end();) {
        unsigned char val = 0;
        uint8_t v = *it;
        if (v >= '0' && v <= '9') {
            val |= (v - '0');
        } else if (v >= 'a' && v <= 'f') {
            val |= (10 + (v - 'a'));
        } else if (v >= 'A' && v <= 'F') {
            val |= (10 + (v - 'A'));
        }
        val <<= 4;
        it++;
        v = *it;
        if (v >= '0' && v <= '9') {
            val |= (v - '0');
        } else if (v >= 'a' && v <= 'f') {
            val |= (10 + (v - 'a'));
        } else if (v >= 'A' && v <= 'F') {
            val |= (10 + (v - 'A'));
        }
        it++;
        out[t] = val;
        t++;
    }

    len = t;
    return out;
}

void print_bytes(unsigned char *src, size_t len) {
    while (len-- > 0) {
        printf("%02X", *src);
        src++;
    }
    std::cout << std::endl;
}

void print_bytes(__m128i *src) {
    print_bytes(reinterpret_cast<unsigned char *>(src), 16);
}

void print_bytes(std::string txt, unsigned char *src, size_t len) {
    std::cout << txt << " ";
    while (len-- > 0) {
        printf("%02X", *src);
        src++;
    }
    std::cout << std::endl;
}

void print_bytes(std::string txt, __m128i *src) {
    std::cout << txt << " ";
    print_bytes(reinterpret_cast<unsigned char *>(src), 16);
}

LeLe::LeLe(std::string str) {

    if ((str.length() & 1) == 1) {
        throw std::invalid_argument("string not even number of chars long");
    }

    size = str.length() / 8;
    if (str.length() % 8) {
        size += 1;
    }

    val = new uint32_t[size];
    memset(val, 0, size * 4);

    size_t t = ((size*4) - 1);


    for (std::string::iterator it = str.begin(); it != str.end();) {
        unsigned char j = 0;
        uint8_t v = *it;
        if (v >= '0' && v <= '9') {
            j |= (v - '0');
        } else if (v >= 'a' && v <= 'f') {
            j |= (10 + (v - 'a'));
        } else if (v >= 'A' && v <= 'F') {
            j |= (10 + (v - 'A'));
        }
        j <<= 4;
        it++;
        v = *it;
        if (v >= '0' && v <= '9') {
            j |= (v - '0');
        } else if (v >= 'a' && v <= 'f') {
            j |= (10 + (v - 'a'));
        } else if (v >= 'A' && v <= 'F') {
            j |= (10 + (v - 'A'));
        }
        it++;
        ((unsigned char *) val)[t] = j;
        t--;
    }


}

LeLe::~LeLe() {
    delete[] val;
}

size_t LeLe::len() {
    return this->size;
}

uint32_t *LeLe::value() {
    return this->val;
}