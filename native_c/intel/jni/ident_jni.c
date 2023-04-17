
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
__attribute__((unused)) JNIEXPORT jstring JNICALL Java_org_bouncycastle_crypto_NativeLibIdentity_getLibIdent
        (JNIEnv *env, jclass) {

    // Owned by JVM
    jstring str = (*env)->NewStringUTF(env, BC_VARIANT);
    return str;
}

__attribute__((unused)) JNIEXPORT jstring JNICALL Java_org_bouncycastle_crypto_NativeLibIdentity_getBuiltTimeStamp
        (JNIEnv *env, jclass) {
    jstring str = (*env)->NewStringUTF(env, BUILD_TS"");
    return str;
}
