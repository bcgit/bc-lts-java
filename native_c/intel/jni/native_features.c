
#include <stdbool.h>
#include "org_bouncycastle_crypto_NativeFeatures.h"


typedef struct cpuid_struct {
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
} cpuid_t;

void cpuid(cpuid_t *info, unsigned int leaf, unsigned int subleaf) {
    __asm__ volatile("cpuid"
            : "=a" (info->eax), "=b" (info->ebx), "=c" (info->ecx), "=d" (info->edx)
            : "a" (leaf), "c" (subleaf)
            );
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCBC
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCBC
        (JNIEnv *env, jclass cl) {
    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 25)) != 0 ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCBCPC
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCBCPC
        (JNIEnv *env, jclass cl) {
    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 25)) != 0 ? JNI_TRUE : JNI_FALSE;
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCFB
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCFB
        (JNIEnv *env, jclass cl) {
    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 25)) != 0 ? JNI_TRUE : JNI_FALSE;
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCFBPC
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCFBPC
        (JNIEnv *env, jclass cl) {
    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 25)) != 0 ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCTR
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCTR
        (JNIEnv *env, jclass cl) {
    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 25)) != 0 ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCTRPC
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCTRPC
        (JNIEnv *env, jclass cl) {
    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 25)) != 0 ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeAES
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeAES
        (JNIEnv *env, jclass cl) {

    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 25)) != 0 ? JNI_TRUE : JNI_FALSE;

}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeGCM
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeGCM
        (JNIEnv *env, jclass cl) {

    cpuid_t info;
    cpuid(&info, 1, 0);

    bool aes = (info.ecx & (1 << 25)) != 0;
    bool pclmulqdq = (info.ecx & (1 << 1)) != 0;

    return (aes && pclmulqdq) ? JNI_TRUE : JNI_FALSE;

}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeGCM
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeGCMSIV
        (JNIEnv *env, jclass cl) {

    cpuid_t info;
    cpuid(&info, 1, 0);

    bool aes = (info.ecx & (1 << 25)) != 0;
    bool pclmulqdq = (info.ecx & (1 << 1)) != 0;

    return (aes && pclmulqdq) ? JNI_TRUE : JNI_FALSE;

}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeGCMPC
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeGCMPC
        (JNIEnv *env, jclass cl) {

    cpuid_t info;
    cpuid(&info, 1, 0);

    bool aes = (info.ecx & (1 << 25)) != 0;
    bool pclmulqdq = (info.ecx & (1 << 1)) != 0;

    return (aes && pclmulqdq) ? JNI_TRUE : JNI_FALSE;

}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeGCMSIVPC
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeGCMSIVPC
        (JNIEnv *env, jclass cl) {

    cpuid_t info;
    cpuid(&info, 1, 0);

    bool aes = (info.ecx & (1 << 25)) != 0;
    bool pclmulqdq = (info.ecx & (1 << 1)) != 0;

    return (aes && pclmulqdq) ? JNI_TRUE : JNI_FALSE;

}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCCM
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCCM
        (JNIEnv *env, jclass cl) {

    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 25)) != 0 ? JNI_TRUE : JNI_FALSE;

}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCCM
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCCMPC
        (JNIEnv *env, jclass cl) {

    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 25)) != 0 ? JNI_TRUE : JNI_FALSE;

}



/*
 * Class:     org_bouncycastle_util_NativeFeatures
 * Method:    nativeRand
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeRand
        (JNIEnv *env, jclass cl) {

    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 30)) != 0 ? JNI_TRUE : JNI_FALSE;

}

/*
 * Class:     org_bouncycastle_util_NativeFeatures
 * Method:    nativeSeed
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSeed
        (JNIEnv *env, jclass cl) {
    cpuid_t info;
    cpuid(&info, 7, 0);

    return (info.ebx & (1 << 18)) != 0 ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeSHA2
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA256
        (JNIEnv *env, jclass cl) {
    cpuid_t info;
    cpuid(&info, 7, 0);

    return (info.ebx & (1 << 29)) != 0 ? JNI_TRUE : JNI_FALSE;

}

__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA224
        (JNIEnv *env, jclass cl) {
    cpuid_t info;
    cpuid(&info, 7, 0);

    return (info.ebx & (1 << 29)) != 0 ? JNI_TRUE : JNI_FALSE;

}

__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA384
        (JNIEnv *env, jclass cl) {
    return JNI_FALSE;
}


__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA512
        (JNIEnv *env, jclass cl) {
    return JNI_FALSE;

}

__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA3
        (JNIEnv *env, jclass cl) {
    return JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeSlhDSASha256
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSlhDSASha256
        (JNIEnv *env, jclass cl) {
    return Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA256(env,cl);
}

