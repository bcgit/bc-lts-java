//
// Created  on 31/5/2022.
//

#ifndef CORENATIVE_DEBUG_H
#define CORENATIVE_DEBUG_H

#include <stdio.h>
#include <immintrin.h>


unsigned char *from_hex(unsigned char *str, size_t len);
//char* convertArrayToString(unsigned char* input, size_t len);

//unsigned char *from_hex(std::string str, size_t &len);
void print_bytes(unsigned char *src, size_t len);
void print_bytes_128(__m128i *src);
//
//void print_bytes(__m256i *src);
//void print_bytes(__m512i *src);
//
//
//void print_bytes(std::string txt,   unsigned char *src, size_t len);
//void print_bytes(std::string txt,__m128i *src);
//void print_bytes(std::string txt,__m256i *src);
//void print_bytes(std::string txt,__m512i *src);
//
//__m512i fromHex512(std::string str);
//__m256i fromHex256(std::string str);
//__m128i fromHex128(std::string str);
//
//__m512i fill512(int start);

#endif //CORENATIVE_DEBUG_H