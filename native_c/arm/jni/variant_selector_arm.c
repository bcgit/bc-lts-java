

#include <stdbool.h>
#include "../../jniutil/variant_selector.h"
#include "../util/util.h"
#include "org_bouncycastle_crypto_VariantSelector.h"


static jstring new_str(JNIEnv *env, const char *s) {
    jstring js = (*env)->NewStringUTF(env, s);
    bc_assert(js != NULL);
    return js;
}


static struct cpuid_info cpu_info = {
        false,
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
#include <string.h>

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
        cpu_info.sha256 = hwcaps & HWCAP_SHA2; //  has_feature("hw.optional.arm.FEAT_SHA256");
        cpu_info.sha512 = hwcaps & HWCAP_SHA512; // has_feature("hw.optional.arm.FEAT_SHA512");
        cpu_info.sha3 = hwcaps & HWCAP_SHA3; // has_feature("hw.optional.arm.FEAT_SHA512");
        cpu_info.le = is_le();
        // has_feature("hw.optional.neon");

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
        //cpu_info.arm64 = has_feature("hw.optional.arm64");
    }

}

// Linux version here
#endif

/*
 * Class:     org_bouncycastle_crypto_Probe
 * Method:    getBestVariantName
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_bouncycastle_crypto_VariantSelector_getBestVariantName
        (JNIEnv *env, jclass jc) {

    probe_system();


    // Neon little endian
    if (cpu_info.arm64 && cpu_info.neon && cpu_info.le) {
        return (*env)->NewStringUTF(env, "neon-le");
    }

    return (*env)->NewStringUTF(env, "none");

}

/*
 * Class:     org_bouncycastle_crypto_VariantSelector
 * Method:    getFeatureMatrix
 * Signature: ()[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL Java_org_bouncycastle_crypto_VariantSelector_getFeatureMatrix
        (JNIEnv *env, jclass jc) {

    probe_system();

    jclass stringArrayClass = (*env)->FindClass(env, "[Ljava/lang/String;");
    bc_assert(stringArrayClass != NULL);

    jobjectArray outerArray = (*env)->NewObjectArray(env, 1, stringArrayClass, NULL);
    bc_assert(outerArray != NULL);

    if (cpu_info.neon) {
        jclass stringClass = (*env)->FindClass(env, "java/lang/String");
        bc_assert(stringClass != NULL);

        jobjectArray arm64 = (*env)->NewObjectArray(env, 7, stringClass, NULL);
        bc_assert(arm64 != NULL);

        (*env)->SetObjectArrayElement(env, outerArray, 0, arm64);
        int t = 0;
        (*env)->SetObjectArrayElement(env, arm64, t++, new_str(env, "neon-le"));

        (*env)->SetObjectArrayElement(env, arm64, t++, new_str(env, cpu_info.aes ? "+aes" : "-aes"));
        (*env)->SetObjectArrayElement(env, arm64, t++, new_str(env, cpu_info.sha256 ? "+sha256" : "-sha256"));
        (*env)->SetObjectArrayElement(env, arm64, t++, new_str(env, cpu_info.sha512 ? "+sha512" : "-sha512"));
        (*env)->SetObjectArrayElement(env, arm64, t++, new_str(env, cpu_info.sha3 ? "+sha3" : "-sha3"));
        (*env)->SetObjectArrayElement(env, arm64, t++, new_str(env, cpu_info.neon ? "+neon" : "-neon"));

        const bool supported = cpu_info.arm64 && cpu_info.neon && cpu_info.le;
        (*env)->SetObjectArrayElement(env, arm64, t, new_str(env, supported ? "Variant Supported" : "No Variant Support"));
    }

    return outerArray;
}
