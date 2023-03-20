
#include "org_bouncycastle_crypto_NativeLibIdentity.h"
#include "jni.h"

#ifndef BC_VARIANT
#define BC_VARIANT "Unknown"
#endif

/*
 * Class:     Java_org_bouncycastle_crypto_NativeLibIdentity\
 * Method:    getLibIdent
 * Signature: ()Ljava/lang/String;
 */
//[[maybe_unused]] JNIEXPORT jstring JNICALL Java_org_bouncycastle_crypto_fips_NativeLibIdentity_getLibIdent
JNIEXPORT jstring JNICALL Java_org_bouncycastle_crypto_NativeLibIdentity_getLibIdent
        (JNIEnv *env, jclass) {

    // Owned by JVM
    auto str = env->NewStringUTF(BC_VARIANT);
    return str;
}

//[[maybe_unused]] JNIEXPORT jstring JNICALL Java_org_bouncycastle_crypto_fips_NativeLibIdentity_getBuiltTimeStamp
JNIEXPORT jstring JNICALL Java_org_bouncycastle_crypto_NativeLibIdentity_getBuiltTimeStamp
        (JNIEnv *env, jclass) {
    auto str = env->NewStringUTF(BUILD_TS"");
    return str;
}