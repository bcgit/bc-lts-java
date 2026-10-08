

#include <stdbool.h>
#include <stdint.h>
#include "org_bouncycastle_crypto_VariantSelector.h"
#include "cpuid_util.h"


typedef struct {
    bool avx;
    bool avx2;
    bool vaes;
    bool avx512f;
    bool avx512bw;
    bool vPCLMULQDQ;
    bool osYmm;    // the OS saves and restores the XMM and YMM state
    bool osZmm;    // ... and also the opmask, ZMM_Hi256 and Hi16_ZMM state
} cpu_features_t;

//
// XGETBV with ECX=0 reads XCR0, the register in which the OS records which register state it
// saves and restores on a context switch. Only valid once CPUID reports OSXSAVE.
//
static uint64_t read_xcr0(void) {
    uint32_t eax, edx;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a" (eax), "=d" (edx) : "c" (0u));
    return ((uint64_t) edx << 32) | eax;
}

static void read_features(cpu_features_t *f) {
    cpuid_t info;

    // Bits from https://en.wikipedia.org/wiki/CPUID

    //
    // Page 1
    //
    cpuid(&info, 1, 0);
    f->avx = ((info.ecx >> 28) & 1) != 0; // avx
    bool osxsave = ((info.ecx >> 27) & 1) != 0; // OSXSAVE, XGETBV usable

    //
    // Page 7
    //
    cpuid(&info, 7, 0);
    f->avx2 = ((info.ebx >> 5) & 1) != 0; // avx2
    f->vaes = ((info.ecx >> 9) & 1) != 0; // vaes
    f->avx512f = ((info.ebx >> 16) & 1) != 0; // avx512f
//    bool avx512vl = ((info.ebx >> 31) & 1) != 0; // avx512vl
    f->avx512bw = ((info.ebx >> 30) & 1) != 0; // AVX512BW
    f->vPCLMULQDQ = ((info.ecx) >> 10 & 1) != 0;// VPCLMULQDQ

    //
    // A CPU feature bit says the instructions exist, not that the OS has enabled the register
    // state they use. Without that, the first instruction touching it faults.
    //
    uint64_t xcr0 = osxsave ? read_xcr0() : 0;
    f->osYmm = (xcr0 & 0x06) == 0x06; // XMM, YMM
    f->osZmm = f->osYmm && (xcr0 & 0xE0) == 0xE0; // opmask, ZMM_Hi256, Hi16_ZMM
}

static bool avx_supported(const cpu_features_t *f) {
    return f->avx && f->osYmm;
}

static bool vaes_supported(const cpu_features_t *f) {
    // the vaes library is built with -mavx2.
    return avx_supported(f) && f->avx2 && f->vaes;
}

static bool vaesf_supported(const cpu_features_t *f) {
    return vaes_supported(f) && f->avx512f && f->avx512bw && f->vPCLMULQDQ && f->osZmm;
}

/*
 * Class:     org_bouncycastle_crypto_Probe
 * Method:    getBestVariantName
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_bouncycastle_crypto_VariantSelector_getBestVariantName
        (JNIEnv *env, jclass jc) {

    cpu_features_t f;
    read_features(&f);

    //
    // Strings owned by JVM
    //
    if (vaesf_supported(&f)) {
        return (*env)->NewStringUTF(env, "vaesf");
    } else if (vaes_supported(&f)) {
        return (*env)->NewStringUTF(env, "vaes");
    } else if (avx_supported(&f)) {
        return (*env)->NewStringUTF(env, "avx");
    }
    return (*env)->NewStringUTF(env, "none");

}

static void set_flag(JNIEnv *env, jobjectArray row, jsize index, bool present, const char *plus, const char *minus) {
    (*env)->SetObjectArrayElement(env, row, index, (*env)->NewStringUTF(env, present ? plus : minus));
}

static void set_support(JNIEnv *env, jobjectArray row, jsize index, bool supported) {
    set_flag(env, row, index, supported, "Variant supported", "No variant support");
}

/*
 * Class:     org_bouncycastle_crypto_VariantSelector
 * Method:    getFeatureMatrix
 * Signature: ()[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL Java_org_bouncycastle_crypto_VariantSelector_getFeatureMatrix
        (JNIEnv *env, jclass jc) {

    cpu_features_t f;
    read_features(&f);

    jclass stringClass = (*env)->FindClass(env, "java/lang/String");
    jobjectArray outerArray = (*env)->NewObjectArray(env, 3, (*env)->FindClass(env, "[Ljava/lang/String;"), NULL);

    //
    // VAESF
    //
    jobjectArray vaesfArray = (*env)->NewObjectArray(env, 8, stringClass, NULL);
    (*env)->SetObjectArrayElement(env, vaesfArray, 0, (*env)->NewStringUTF(env, "VAESF"));
    set_flag(env, vaesfArray, 1, f.vaes, "+vaes", "-vaes");
    set_flag(env, vaesfArray, 2, f.avx2, "+avx2", "-avx2");
    set_flag(env, vaesfArray, 3, f.avx512f, "+avx512f", "-avx512f");
    set_flag(env, vaesfArray, 4, f.avx512bw, "+avx512bw", "-avx512bw");
    set_flag(env, vaesfArray, 5, f.vPCLMULQDQ, "+vpclmulqdq", "-vpclmulqdq");
    set_flag(env, vaesfArray, 6, f.osZmm, "+os-zmm", "-os-zmm");
    set_support(env, vaesfArray, 7, vaesf_supported(&f));
    (*env)->SetObjectArrayElement(env, outerArray, 0, vaesfArray);

    //
    // VAES
    //
    jobjectArray vaesArray = (*env)->NewObjectArray(env, 5, stringClass, NULL);
    (*env)->SetObjectArrayElement(env, vaesArray, 0, (*env)->NewStringUTF(env, "VAES"));
    set_flag(env, vaesArray, 1, f.vaes, "+vaes", "-vaes");
    set_flag(env, vaesArray, 2, f.avx2, "+avx2", "-avx2");
    set_flag(env, vaesArray, 3, f.osYmm, "+os-ymm", "-os-ymm");
    set_support(env, vaesArray, 4, vaes_supported(&f));
    (*env)->SetObjectArrayElement(env, outerArray, 1, vaesArray);

    //
    // AVX
    //
    jobjectArray avxArray = (*env)->NewObjectArray(env, 4, stringClass, NULL);
    (*env)->SetObjectArrayElement(env, avxArray, 0, (*env)->NewStringUTF(env, "AVX"));
    set_flag(env, avxArray, 1, f.avx, "+avx", "-avx");
    set_flag(env, avxArray, 2, f.osYmm, "+os-ymm", "-os-ymm");
    set_support(env, avxArray, 3, avx_supported(&f));
    (*env)->SetObjectArrayElement(env, outerArray, 2, avxArray);

    return outerArray;
}
