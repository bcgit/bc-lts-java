//
// Created  on 17/5/2022.
//


#include "JavaByteArrayCritical.h"

#include <iterator>


namespace jniutil {

    JavaByteArrayCritical::JavaByteArrayCritical(JNIEnv *env, jbyteArray array) {
        if (array == nullptr) {
            this->env = env;
            this->array = array;
            len = 0;
            val = nullptr;
            wasCopy = false;
            wasNull = true;
            return;
        }

        jboolean isCopy = false;
        this->env = env;
        this->array = array;
        len = (size_t)env->GetArrayLength(array);
        val = reinterpret_cast<char *>( env->GetPrimitiveArrayCritical(array, &isCopy));
        wasCopy = isCopy != 0;
        wasNull = false;

    }


    JavaByteArrayCritical::~JavaByteArrayCritical() {

        if (wasNull) {
            return;
        }

        this->env->ReleasePrimitiveArrayCritical(array, reinterpret_cast<jbyte *>(val), 0);
    }

    char *JavaByteArrayCritical::value() {
        return val;
    }

    size_t JavaByteArrayCritical::length() const {
        return len;
    }

    bool JavaByteArrayCritical::isNull() const {
        return wasNull;
    }

    unsigned char *JavaByteArrayCritical::uvalue() {
        return (unsigned char *) val;
    }

    void JavaByteArrayCritical::disposeNow() {
        if (wasNull) {
            return;
        }

        this->env->ReleasePrimitiveArrayCritical(array, reinterpret_cast<jbyte *>(val), 0);
        wasNull = true;

    }


}