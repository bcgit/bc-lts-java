//
// Created  on 17/5/2022.
//

#ifndef CORENATIVE_JAVAENVUTILS_H
#define CORENATIVE_JAVAENVUTILS_H


#include <jni.h>

namespace jniutil {
    class JavaEnvUtils {
    public:
        static void throwIllegalArgumentException(JNIEnv *env, const char *message);

        [[maybe_unused]] static bool exceptionThrown(JNIEnv *env);

        static void throwException(JNIEnv *pEnv, const char *classname, const char *msg);

    };

}

#endif //CORENATIVE_JAVAENVUTILS_H
