/*
 * JNI feature bridge: every CPU-gated per-service answer comes from the shared
 * requirement table in arm/jni/services.h. Keep no per-service feature logic
 * here — a service is available iff the host HWCAPs satisfy its mask, otherwise
 * the Java layer falls back to the pure-Java implementation (a knocked-out
 * service, never a SIGILL on a CPU that lacks the instructions).
 */
#include <stdbool.h>
#include "org_bouncycastle_crypto_NativeFeatures.h"
#include "services.h"


static struct cpuid_info cpu_info = {0};

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
        cpu_info.pmull = has_feature("hw.optional.arm.FEAT_PMULL");
        cpu_info.sha256 = has_feature("hw.optional.arm.FEAT_SHA256");
        cpu_info.sha512 = has_feature("hw.optional.arm.FEAT_SHA512");
        cpu_info.sha3 = has_feature("hw.optional.arm.FEAT_SHA3");
        cpu_info.neon = has_feature("hw.optional.neon");
        cpu_info.arm64 = has_feature("hw.optional.arm64");
        cpu_info.le = is_le();
    }
}

#else
#include <sys/auxv.h>
#include <asm/hwcap.h>
#include <sys/utsname.h>
#include <errno.h>
#include <string.h>

#define aa64 "aarch64"

void probe_system() {


    if (!cpu_info.loaded) {

        unsigned long hwcaps = getauxval(AT_HWCAP);

        cpu_info.loaded = true;
        cpu_info.aes = hwcaps & HWCAP_AES;
        // FEAT_PMULL (poly64 PMULL/PMULL2, used by GCM's GHASH) is a separate
        // HWCAP from FEAT_AES; do not infer one from the other.
        cpu_info.pmull = hwcaps & HWCAP_PMULL;
        cpu_info.sha256 = hwcaps & HWCAP_SHA2;
        cpu_info.sha512 = hwcaps & HWCAP_SHA512;
        cpu_info.sha3 = hwcaps & HWCAP_SHA3;
        cpu_info.le = is_le();

        struct utsname buffer;
        errno = 0;
        if (uname(&buffer) < 0) {
            cpu_info.neon = false;
        } else {
            if (strncmp(aa64, buffer.machine, strlen(aa64)) == 0) {
                cpu_info.arm64 = true;
                cpu_info.neon = true;
            }
        }

    }

}
#endif

static jboolean available(bc_arm_service svc) {
    probe_system();
    return bc_arm_service_available(&cpu_info, svc) ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCBC
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCBC
        (JNIEnv *env, jclass cl) {
    return available(BC_SVC_CBC);
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCBCPC
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCBCPC
        (JNIEnv *e, jclass cl) {
    return JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCFB
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCFB
        (JNIEnv *env, jclass cl) {
    return available(BC_SVC_CFB);
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCFBPC
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCFBPC
        (JNIEnv *env, jclass cl) {
    return JNI_FALSE;
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCTR
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCTR
        (JNIEnv *env, jclass cl) {
    return available(BC_SVC_CTR);
}



/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCTRPC
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCTRPC
        (JNIEnv *env, jclass cl) {
    return JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeAES
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeAES
        (JNIEnv *env, jclass cl) {
    return available(BC_SVC_ECB);
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeGCM
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeGCM
        (JNIEnv *env, jclass cl) {
    return available(BC_SVC_GCM);
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeGCMSIV
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeGCMSIV
        (JNIEnv * env, jclass cl) {
    return JNI_FALSE;
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeGCMSIVPC
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeGCMSIVPC
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
 * Method:    nativeSHA256
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA256
        (JNIEnv *env, jclass cl) {
    return available(BC_SVC_SHA256);
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeSHA224
 * Signature: ()Z
 */
__attribute__((unused)) JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA224
        (JNIEnv *env, jclass cl) {
    return available(BC_SVC_SHA224);
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeSHA384
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA384
        (JNIEnv *env, jclass cl) {
    return available(BC_SVC_SHA384);
}



/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeSHA512
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA512
        (JNIEnv *env, jclass cl) {
    return available(BC_SVC_SHA512);
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeMulAcc
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeMulAcc
        (JNIEnv *env, jclass cl) {
    return JNI_TRUE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCCM
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCCM
        (JNIEnv *env, jclass cl) {
    return available(BC_SVC_CCM);
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeSHA3
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHA3
        (JNIEnv *env, jclass cl) {
    return available(BC_SVC_SHA3);
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeSHAKE
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSHAKE
        (JNIEnv *env, jclass cl) {
    return available(BC_SVC_SHAKE);
}




/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeGCMPC
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeGCMPC
        (JNIEnv *env, jclass cl) {
    return JNI_FALSE;
}


/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeCCMPC
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeCCMPC
        (JNIEnv *env, jclass cl) {
    return JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeRSA
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeRSA
        (JNIEnv *env, jclass cl) {
    return JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeFeatures
 * Method:    nativeSlhDSASha256
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeFeatures_nativeSlhDSASha256
        (JNIEnv *, jclass) {
    return JNI_FALSE;
}
