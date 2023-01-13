//
// Created  on 17/5/2022.
//


#include "JavaByteArray.h"

#include <iterator>


namespace jniutil {

    JavaByteArray::JavaByteArray(JNIEnv *env, jbyteArray array) {
        if (array == nullptr) {
            this->env = env;
            this->array = array;
            len = 0;
            val = nullptr;
            wasNull = true;
            return;
        }

        jboolean isCopy = false;
        this->env = env;
        this->array = array;
        len = (size_t)env->GetArrayLength(array);
        val = reinterpret_cast<char *>( env->GetByteArrayElements(array, &isCopy));
        wasNull = false;

    }


    JavaByteArray::~JavaByteArray() {

        if (wasNull) {
            return;
        }

        this->env->ReleaseByteArrayElements(array, reinterpret_cast<jbyte *>(val), 0);
    }

    [[maybe_unused]] [[maybe_unused]] char *JavaByteArray::value() {
        return val;
    }

    [[maybe_unused]] size_t JavaByteArray::length() const {
        return len;
    }

    [[maybe_unused]] bool JavaByteArray::isNull() const {
        return wasNull;
    }

    unsigned char *JavaByteArray::uvalue() {
        return (unsigned char *) val;
    }



}