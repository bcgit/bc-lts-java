 //
// Created by Megan Woods on 31/8/2022.
//
#include "Rand.h"
#include  <arm_acle.h>
#include <cassert>
#include <cstring>

#define RAND_MOD 8

 int arm::Rand::modulus() {
     return RAND_MOD;
 }

 bool arm::Rand::isPredictionResistant() {
     return true;
 }

 void arm::Rand::populateArrayRng(jniutil::JavaByteArray *array) {
     assert(!array->isNull());

     // Assert that array length is a multiple of the modulus.
     assert((array->length() % RAND_MOD) == 0);

     // Clear on the way in.
     memset(array->value(), 0, array->length());

     auto *ptr = reinterpret_cast<unsigned long long *>(array->value());

     size_t count = array->length() / RAND_MOD;

     uint64_t val =0;
     while (count-- > 0) {
         int flag = __rndr(&val);
         while (flag == 0) {
             flag = __rndr(&val);
         }
         *ptr = val;
         ptr++;
     }


 }

 void arm::Rand::populateArraySeed(jniutil::JavaByteArray *array) {
     assert(!array->isNull());

     // Assert that array length is a multiple of the modulus.
     assert((array->length() % RAND_MOD) == 0);

     // Clear on the way in.
     memset(array->value(), 0, array->length());

     auto *ptr = reinterpret_cast<unsigned long long *>(array->value());

     size_t count = array->length() / RAND_MOD;

     uint64_t val =0;
     while (count-- > 0) {
         int flag = __rndrrs(&val);
         while (flag == 0) {
             flag = __rndrrs(&val);
         }
         *ptr = val;
         ptr++;
     }
 }

