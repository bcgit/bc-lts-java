//
//

#include "exceptions.h"
#include <assert.h>

void throw_java_NPE(JNIEnv *env, const char *msg) {
    jclass exClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    assert(exClass != NULL);
    (*env)->ThrowNew(env, exClass, msg);
}

void throw_java_illegal_argument(JNIEnv *env, const char *msg) {
    jclass exClass = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    assert(exClass != NULL);
    (*env)->ThrowNew(env, exClass, msg);
}

void throw_java_invalid_state(JNIEnv *env, const char *msg) {
    jclass exClass = (*env)->FindClass(env, "java/lang/IllegalStateException");
    assert(exClass != NULL);
    (*env)->ThrowNew(env, exClass, msg);
}

void throw_bc_data_length_exception(JNIEnv *env, const char *msg) {
    jclass exClass = (*env)->FindClass(env, "org/bouncycastle/crypto/DataLengthException");
    assert(exClass != NULL);
    (*env)->ThrowNew(env, exClass, msg);
}

void throw_bc_output_length_exception(JNIEnv *env, const char *msg) {
    jclass exClass = (*env)->FindClass(env, "org/bouncycastle/crypto/OutputLengthException");
    assert(exClass != NULL);
    (*env)->ThrowNew(env, exClass, msg);
}

void throw_bc_invalid_ciphertext_exception(JNIEnv *env, const char *msg) {
    jclass exClass = (*env)->FindClass(env, "org/bouncycastle/crypto/InvalidCipherTextException");
    assert(exClass != NULL);
    (*env)->ThrowNew(env, exClass, msg);
}