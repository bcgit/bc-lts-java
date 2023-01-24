//
// Created  on 17/5/2022.
//

#ifndef CORENATIVE_JAVABYTEARRAYCRIT_H
#define CORENATIVE_JAVABYTEARRAYCRIT_H


#include <cstdlib>
#include <jni.h>

namespace jniutil {
    class JavaByteArrayCritical {
    private:
        char *val;
        size_t len;
        JNIEnv *env;
        bool wasCopy;
        bool wasNull;
        jbyteArray array;


    public:
        JavaByteArrayCritical(const JavaByteArrayCritical &) = delete;

        JavaByteArrayCritical(JNIEnv *env, jbyteArray array);

        ~JavaByteArrayCritical();

        char *value();

        unsigned char *uvalue();

        [[nodiscard]] size_t length() const;

        [[nodiscard]] bool isNull() const;

        void disposeNow();

    };
}


#endif //CORENATIVE_JAVABYTEARRAYCRIT_H
