

#include <stdbool.h>
#include "../../jniutil/variant_selector.h"
#include "org_bouncycastle_crypto_VariantSelector.h"




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
        cpu_info.sha3 = has_feature("hw.optional.arm.FEAT_SHA512");
        cpu_info.neon = has_feature("hw.optional.neon");
        cpu_info.arm64 = has_feature("hw.optional.arm64");
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

    // SVE2 later
    if (cpu_info.arm64 && cpu_info.neon) {
        return (*env)->NewStringUTF(env, "neon");
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


    jobjectArray outerArray = (*env)->NewObjectArray(env, 1, (*env)->FindClass(env, "[Ljava/lang/String;"), NULL);

    if (cpu_info.neon) {
        jobjectArray arm64 = (*env)->NewObjectArray(env, 7, (*env)->FindClass(env, "java/lang/String"), NULL);
        (*env)->SetObjectArrayElement(env, outerArray, 0, arm64);
        int t = 0;
        (*env)->SetObjectArrayElement(env, arm64, t++, (*env)->NewStringUTF(env, "neon"));

        if (cpu_info.aes) {
            (*env)->SetObjectArrayElement(env, arm64, t, (*env)->NewStringUTF(env, "+aes"));
        } else {
            (*env)->SetObjectArrayElement(env, arm64, t, (*env)->NewStringUTF(env, "-aes"));
        }
        t++;
        if (cpu_info.sha256) {
            (*env)->SetObjectArrayElement(env, arm64, t, (*env)->NewStringUTF(env, "+sha256"));
        } else {
            (*env)->SetObjectArrayElement(env, arm64, t, (*env)->NewStringUTF(env, "-sha256"));
        }
        t++;
        if (cpu_info.sha512) {
            (*env)->SetObjectArrayElement(env, arm64, t, (*env)->NewStringUTF(env, "+sha512"));
        } else {
            (*env)->SetObjectArrayElement(env, arm64, t, (*env)->NewStringUTF(env, "-sha512"));
        }
        t++;
        if (cpu_info.sha3) {
            (*env)->SetObjectArrayElement(env, arm64, t, (*env)->NewStringUTF(env, "+sha3"));
        } else {
            (*env)->SetObjectArrayElement(env, arm64, t, (*env)->NewStringUTF(env, "-sha3"));
        }
        t++;
        if (cpu_info.neon) {
            (*env)->SetObjectArrayElement(env, arm64, t, (*env)->NewStringUTF(env, "+neon"));
        } else {
            (*env)->SetObjectArrayElement(env, arm64, t, (*env)->NewStringUTF(env, "-neon"));
        }
        t++;
        if (cpu_info.arm64 && cpu_info.neon) {
            (*env)->SetObjectArrayElement(env, arm64, t, (*env)->NewStringUTF(env, "Variant Supported"));
        } else {
            (*env)->SetObjectArrayElement(env, arm64, t, (*env)->NewStringUTF(env, "No Variant Support"));
        }

    }

    return outerArray;
}
