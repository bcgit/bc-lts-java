
#ifndef CORENATIVE_RAND_H
#define CORENATIVE_RAND_H


#include <jni.h>
#include "../../jniutil/JavaByteArray.h"

namespace intel {

    class Rand {
    private:
        bool hasRdSeed;

    public:

        static int modulus();

        static bool isPredictionResistant();

        static void populateArrayRng(jniutil::JavaByteArray *array);
        static void populateArraySeed(jniutil::JavaByteArray *array);
    };

}
#endif //CORENATIVE_RAND_H
