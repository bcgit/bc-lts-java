//
// Created  on 17/5/2022.
//

#include <cassert>
#include <iostream>
#include "JavaEnvUtils.h"

namespace jniutil {
    void JavaEnvUtils::throwIllegalArgumentException(JNIEnv *env, const char *message) {
        jclass exClass = env->FindClass("java/lang/IllegalArgumentException");
        assert(exClass != nullptr);
        env->ThrowNew(exClass, message);
    }

    [[maybe_unused]] [[maybe_unused]]bool JavaEnvUtils::exceptionThrown(JNIEnv *env) {
        auto thrown = env->ExceptionCheck();
        return thrown == JNI_TRUE;
    }

    void JavaEnvUtils::throwException(JNIEnv *env, const char *classname, const char *msg) {
        jclass exClass = env->FindClass(classname);
        assert(exClass != nullptr);
        env->ThrowNew(exClass, msg);
    }
}
