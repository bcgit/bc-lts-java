
#include <stdbool.h>
#include "org_bouncycastle_crypto_NativeFeatures.h"


struct cpuid_info {
    bool loaded;
    bool aes;
    bool sha256;
    bool sha512;
    bool sha3;
    bool neon;
    bool arm64;
    bool sve2;
};

static struct cpuid_info cpu_info = {
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false
};


#ifdef __APPLE__

#include <sys/sysctl.h>
#include <stdio.h>

#define BUF_LEN 128

bool has_feature(const char *name) {
    char buffer[BUF_LEN];
    size_t bufLen = BUF_LEN;

    if (0 == sysctlbyname(name, &buffer, &bufLen, NULL, 0)) {
        return buffer[0] == 1;
    }

    return false;
}


void probe_system() {
    if (!cpu_info.loaded) {
        cpu_info.loaded = true;
        cpu_info.aes = has_feature("hw.optional.arm.FEAT_AES");
        cpu_info.sha256 = has_feature("hw.optional.arm.FEAT_SHA256");
        cpu_info.sha512 = has_feature("hw.optional.arm.FEAT_SHA512");
        cpu_info.sha3 = has_feature("hw.optional.arm.FEAT_SHA512");
        cpu_info.neon = has_feature("hw.optional.neon");
        cpu_info.arm64 = has_feature("hw.optional.arm64");
    }
}

#elif
// Linux version here
#endif

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCBC
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCBC
        (JNIEnv *env, jclass cl) {
    probe_system();
    return JNI_FALSE;
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCFB
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCFB
        (JNIEnv *env, jclass cl) {
    probe_system();
    return JNI_FALSE;
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCFB
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCTR
        (JNIEnv *env, jclass cl) {
    probe_system();
    return JNI_FALSE;
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeAES
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeAES
        (JNIEnv *env, jclass cl) {

    probe_system();
    return cpu_info.aes ? JNI_TRUE : JNI_FALSE;

}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeGCM
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeGCM
        (JNIEnv *env, jclass cl) {

    return JNI_FALSE;

}


/*
 * Class:     org_bouncycastle_util_NativeFeatures
 * Method:    nativeRand
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeRand
        (JNIEnv *env, jclass cl) {

    return JNI_FALSE;

}

/*
 * Class:     org_bouncycastle_util_NativeFeatures
 * Method:    nativeSeed
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSeed
        (JNIEnv *env, jclass cl) {
    return JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeSHA2
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA2
        (JNIEnv *env, jclass cl) {
    return JNI_FALSE;

}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeMulAcc
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeMulAcc
        (JNIEnv *env, jclass cl) {

    return JNI_FALSE;

}


