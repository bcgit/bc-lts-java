//
// Created  on 31/5/2022.
//

#ifndef CORENATIVE_DEBUG_H
#define CORENATIVE_DEBUG_H

#include <iostream>
#include <wmmintrin.h>


class LeLe {
private:
    size_t  size;
    uint32_t *val;
public:
    LeLe(std::string text);
    ~LeLe();
    size_t len();
    uint32_t  *value();


};


unsigned char *from_hex(std::string str);

unsigned char *from_hex(std::string str, size_t &len);
void print_bytes(unsigned char *src, size_t len);
void print_bytes(__m128i *src);

void print_bytes(std::string txt,   unsigned char *src, size_t len);
void print_bytes(std::string txt,__m128i *src);


#endif //CORENATIVE_DEBUG_H
