//
//
//

#ifndef BC_FIPS_EXCEPTIONS_H
#define BC_FIPS_EXCEPTIONS_H

#include "jni.h"

void throw_java_NPE( JNIEnv  *env, const char *msg);
void throw_java_illegal_argument(JNIEnv *enc, const char *msg);
void throw_java_invalid_state(JNIEnv *enc, const char *msg);
void throw_bc_data_length_exception(JNIEnv *enc, const char *msg);
void throw_bc_output_length_exception(JNIEnv *env, const char *msg);
void throw_bc_invalid_ciphertext_exception(JNIEnv *env, const char *msg);

#endif //BC_FIPS_EXCEPTIONS_H
