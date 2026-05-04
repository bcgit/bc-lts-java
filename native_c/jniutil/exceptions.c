//
//

#include "exceptions.h"
#include <assert.h>

void throw_java_NPE(JNIEnv *env, const char *msg) {
    jclass exClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    bc_assert(exClass != NULL);
    (*env)->ThrowNew(env, exClass, msg);
}

void throw_java_illegal_argument(JNIEnv *env, const char *msg) {
    jclass exClass = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    bc_assert(exClass != NULL);
    (*env)->ThrowNew(env, exClass, msg);
}

void throw_java_invalid_state(JNIEnv *env, const char *msg) {
    jclass exClass = (*env)->FindClass(env, "java/lang/IllegalStateException");
    bc_assert(exClass != NULL);
    (*env)->ThrowNew(env, exClass, msg);
}

void throw_bc_data_length_exception(JNIEnv *env, const char *msg) {
    jclass exClass = (*env)->FindClass(env, "org/bouncycastle/crypto/DataLengthException");
    bc_assert(exClass != NULL);
    (*env)->ThrowNew(env, exClass, msg);
}

void throw_bc_output_length_exception(JNIEnv *env, const char *msg) {
    jclass exClass = (*env)->FindClass(env, "org/bouncycastle/crypto/OutputLengthException");
    bc_assert(exClass != NULL);
    (*env)->ThrowNew(env, exClass, msg);
}

void throw_bc_invalid_ciphertext_exception(JNIEnv *env, const char *msg) {
    jclass exClass = (*env)->FindClass(env, "org/bouncycastle/crypto/InvalidCipherTextException");
    bc_assert(exClass != NULL);
    (*env)->ThrowNew(env, exClass, msg);
}