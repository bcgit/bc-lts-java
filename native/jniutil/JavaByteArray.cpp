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
            wasCopy = false;
            wasNull = true;
            reverse = false;
            return;
        }

        jboolean isCopy = false;
        this->env = env;
        this->array = array;
        len = (size_t)env->GetArrayLength(array);
        val = reinterpret_cast<char *>( env->GetByteArrayElements(array, &isCopy));
        wasCopy = isCopy != 0;
        wasNull = false;
        reverse = false;
    }

    JavaByteArray::JavaByteArray(JNIEnv *env, jbyteArray array, bool reverse) {
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
        val = reinterpret_cast<char *>( env->GetByteArrayElements(array, &isCopy));
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


    JavaByteArray::~JavaByteArray() {

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


        this->env->ReleaseByteArrayElements(array, reinterpret_cast<jbyte *>(val), 0);
    }

    char *JavaByteArray::value() {
        return val;
    }

    size_t JavaByteArray::length() {
        return len;
    }

    bool JavaByteArray::isNull() {
        return wasNull;
    }

    unsigned char *JavaByteArray::uvalue() {
        return (unsigned char *) val;
    }



}