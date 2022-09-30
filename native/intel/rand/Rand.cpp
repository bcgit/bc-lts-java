//
// Created  on 17/5/2022.
//

#include <cstdint>
#include <cstring>
#include <cassert>
#include <immintrin.h>

#include "Rand.h"
#include "../../jniutil/JavaByteArrayCritical.h"

#define RAND_MOD 8

namespace intel {

    int Rand::modulus() {
        return RAND_MOD;
    }

    bool Rand::isPredictionResistant() {
        return true;
    }


    void Rand::populateArrayRng(jniutil::JavaByteArrayCritical *array) {

        // Assert the target is not null.
        assert(!array->isNull());

        // Assert that array length is a multiple of the modulus.
        assert((array->length() % RAND_MOD) == 0);

        // Clear on the way in.
        memset(array->value(), 0, array->length());

        auto *ptr = reinterpret_cast<unsigned long long *>(array->value());

#if  defined(__INTEL_COMPILER) or defined(__INTEL_LLVM_COMPILER)
        unsigned long val = 0;
#elif defined(__APPLE__) or defined(__GNUC__)
        unsigned long long val = 0;
#else
        unsigned long val = 0;
#endif
        size_t count = array->length() / RAND_MOD;

        while (count-- > 0) {
            int flag = _rdrand64_step(&val);
            while (flag == 0) {
                _mm_pause();
                flag = _rdrand64_step(&val);
            }
            *ptr = val;
            ptr++;
        }

    }

    void Rand::populateArraySeed(jniutil::JavaByteArrayCritical *array) {
        // Assert the target is not null.
        assert(!array->isNull());

        // Assert that array length is a multiple of the modulus.
        assert((array->length() % RAND_MOD) == 0);

        // Clear on the way in.
        memset(array->value(), 0, array->length());

        auto *ptr = reinterpret_cast<unsigned long long *>(array->value());

#if  defined(__INTEL_COMPILER) or defined(__INTEL_LLVM_COMPILER)
        unsigned long val = 0;
#elif defined(__APPLE__) or defined(__GNUC__)
        unsigned long long val = 0;
#else
        unsigned long val = 0;
#endif

        size_t count = array->length() / RAND_MOD;

        while (count-- > 0) {
            int flag = _rdseed64_step(&val);
            while (flag == 0) {
                _mm_pause();
                flag = _rdseed64_step(&val);
            }
            *ptr = val;
            ptr++;
        }
    }


}

