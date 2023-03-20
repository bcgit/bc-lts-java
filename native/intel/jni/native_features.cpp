
#include "org_bouncycastle_crypto_NativeFeatures.h"


typedef struct cpuid_struct {
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
} cpuid_t;

void cpuid(cpuid_t *info, unsigned int leaf, unsigned int subleaf) {
    asm volatile("cpuid"
            : "=a" (info->eax), "=b" (info->ebx), "=c" (info->ecx), "=d" (info->edx)
            : "a" (leaf), "c" (subleaf)
            );
}



/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCBC
 * Signature: ()Z
 */
//[[maybe_unused]] JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_fips_NativeFeatures_nativeCBC
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCBC
        (JNIEnv *, jclass) {
    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 25)) != 0 ? JNI_TRUE : JNI_FALSE;
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCFB
 * Signature: ()Z
 */
//[[maybe_unused]] JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_fips_NativeFeatures_nativeCFB
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCFB
        (JNIEnv *, jclass) {
    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 25)) != 0 ? JNI_TRUE : JNI_FALSE;
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeAES
 * Signature: ()Z
 */
//[[maybe_unused]] JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_fips_NativeFeatures_nativeAES
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeAES
        (JNIEnv *, jclass) {

    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 25)) != 0 ? JNI_TRUE : JNI_FALSE;

}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeGCM
 * Signature: ()Z
 */
//[[maybe_unused]] JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_fips_NativeFeatures_nativeGCM
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeGCM
        (JNIEnv *, jclass) {

    cpuid_t info;
    cpuid(&info, 1, 0);

    bool aes = (info.ecx & (1 << 25)) != 0;
    bool pclmulqdq = (info.ecx & (1 << 1)) != 0;

    return (aes && pclmulqdq) ? JNI_TRUE : JNI_FALSE;

}


/*
 * Class:     org_bouncycastle_util_NativeFeatures
 * Method:    nativeRand
 * Signature: ()Z
 */
//[[maybe_unused]] JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_fips_NativeFeatures_nativeRand
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeRand
        (JNIEnv *, jclass) {

    cpuid_t info;
    cpuid(&info, 1, 0);

    return (info.ecx & (1 << 30)) != 0 ? JNI_TRUE : JNI_FALSE;

}

/*
 * Class:     org_bouncycastle_util_NativeFeatures
 * Method:    nativeSeed
 * Signature: ()Z
 */
//[[maybe_unused]] JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_fips_NativeFeatures_nativeSeed
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSeed
        (JNIEnv *, jclass) {
    cpuid_t info;
    cpuid(&info, 7, 0);

    return (info.ebx & (1 << 18)) != 0 ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeSHA2
 * Signature: ()Z
 */
//[[maybe_unused]] JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_fips_NativeFeatures_nativeSHA2
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA2
        (JNIEnv *, jclass) {
    cpuid_t info;
    cpuid(&info, 7, 0);

    return (info.ebx & (1 << 29)) != 0 ? JNI_TRUE : JNI_FALSE;

}

