
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
JNIEXPORT jstring JNICALL Java_org_bouncycastle_crypto_NativeLibIdentity_getLibIdent
        (JNIEnv *env, jclass) {

    // Owned by JVM
    auto str = env->NewStringUTF(BC_VARIANT_PREFIX"-" BC_VARIANT);
    return str;
}