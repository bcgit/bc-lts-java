
#ifndef CORENATIVE_RAND_H
#define CORENATIVE_RAND_H


#include <jni.h>
#include "../../jniutil/JavaByteArray.h"
#include "../../jniutil/JavaByteArrayCritical.h"

namespace intel {

    class Rand {
    private:
        bool hasRdSeed;

    public:

        static int modulus();

        static bool isPredictionResistant();

        static void populateArrayRng(jniutil::JavaByteArrayCritical *array);
        static void populateArraySeed(jniutil::JavaByteArrayCritical *array);
    };

}
#endif //CORENATIVE_RAND_H
