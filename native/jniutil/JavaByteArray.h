//
// Created  on 17/5/2022.
//

#ifndef CORENATIVE_JAVABYTEARRAY_H
#define CORENATIVE_JAVABYTEARRAY_H


#include <cstdlib>
#include <jni.h>

namespace jniutil {
    class JavaByteArray {
    private:
        char *val;
        size_t len;
        JNIEnv *env;
        bool wasCopy;
        bool wasNull;
        jbyteArray array;
        bool reverse;

    public:
        JavaByteArray(const JavaByteArray &) = delete;

        JavaByteArray(JNIEnv *env, jbyteArray array);

        JavaByteArray(JNIEnv *env, jbyteArray array, bool reverse);

        ~JavaByteArray();

        char *value();

        unsigned char *uvalue();

        size_t length();

        bool isNull();

    };
}


#endif //CORENATIVE_JAVABYTEARRAY_H
