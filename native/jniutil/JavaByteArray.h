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
        bool wasNull;
        jbyteArray array;


    public:
        JavaByteArray(const JavaByteArray &) = delete;

        JavaByteArray(JNIEnv *env, jbyteArray array);

        ~JavaByteArray();

        [[maybe_unused]] char *value();

        unsigned char *uvalue();

        [[nodiscard]] size_t length() const;

        [[nodiscard]] bool isNull() const;

    };
}


#endif //CORENATIVE_JAVABYTEARRAY_H
