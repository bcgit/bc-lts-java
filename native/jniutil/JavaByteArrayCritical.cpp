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
            reverse = false;
            return;
        }

        jboolean isCopy = false;
        this->env = env;
        this->array = array;
        len = (size_t)env->GetArrayLength(array);
        val = reinterpret_cast<char *>( env->GetPrimitiveArrayCritical(array, &isCopy));
        wasCopy = isCopy != 0;
        wasNull = false;
        reverse = false;
    }

    JavaByteArrayCritical::JavaByteArrayCritical(JNIEnv *env, jbyteArray array, bool reverse) {
        if (array == nullptr) {
            this->env = env;
            this->array = array;
            len = 0;
            val = nullptr;
            wasCopy = false;
            wasNull = true;
            reverse = false;
            return;
        }

        jboolean isCopy = false;
        this->env = env;
        this->array = array;
        len = (size_t)env->GetArrayLength(array);
        val = reinterpret_cast<char *>( env->GetPrimitiveArrayCritical(array, &isCopy));
        wasCopy = isCopy != 0;
        wasNull = false;
        reverse = reverse;

        if (reverse) {
            // TODO Optimise
            char *right = val + len - 1;
            char *left = val;
            while (left < right) {
                std::swap(*left, *right);
                left++;
                right--;
            }

        }

    }


    JavaByteArrayCritical::~JavaByteArrayCritical() {

        if (wasNull) {
            return;
        }

        if (reverse) {
            // TODO Optimise
            char *right = val + len - 1;
            char *left = val;
            while (left < right) {
                std::swap(*left, *right);
                left++;
                right--;
            }

        }


        this->env->ReleasePrimitiveArrayCritical(array, reinterpret_cast<jbyte *>(val), 0);
    }

    char *JavaByteArrayCritical::value() {
        return val;
    }

    size_t JavaByteArrayCritical::length() {
        return len;
    }

    bool JavaByteArrayCritical::isNull() {
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