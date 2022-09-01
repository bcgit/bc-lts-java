
#include "org_bouncycastle_util_NativeFeatures.h"
#include  <arm_acle.h>


/*
 * Class:     org_bouncycastle_util_NativeFeatures
 * Method:    nativeRand
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_util_NativeFeatures_nativeRand
        (JNIEnv *, jclass) {

#ifndef __ARM_FEATURE_RNG
    return JNI_FALSE;
#else
    return JNI_TRUE;
#endif
}

/*
 * Class:     org_bouncycastle_util_NativeFeatures
 * Method:    nativeSeed
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_util_NativeFeatures_nativeSeed
        (JNIEnv *, jclass) {
   return JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_util_NativeFeatures
 * Method:    nativeAES
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_util_NativeFeatures_nativeAES
        (JNIEnv *, jclass) {
    return JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_util_NativeFeatures
 * Method:    nativeCMUL
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_util_NativeFeatures_nativeCMUL
        (JNIEnv *, jclass) {
    return JNI_FALSE;
}


/*
 * Class:     org_bouncycastle_util_NativeFeatures
 * Method:    nativeSHA2
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_util_NativeFeatures_nativeSHA2
        (JNIEnv *, jclass) {
    return JNI_FALSE;
}