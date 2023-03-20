
#include "org_bouncycastle_crypto_VariantSelector.h"


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
 * Class:     org_bouncycastle_crypto_fips_Probe
 * Method:    getBestVariantName
 * Signature: ()Ljava/lang/String;
 */
//[[maybe_unused]] JNIEXPORT jstring JNICALL Java_org_bouncycastle_crypto_fips_VariantSelector_getBestVariantName
JNIEXPORT jstring JNICALL Java_org_bouncycastle_crypto_VariantSelector_getBestVariantName
        (JNIEnv *env, jclass) {


    cpuid_t info;

    // Bits from https://en.wikipedia.org/wiki/CPUID

    //
    // Page 1
    //
    cpuid(&info, 1, 0);
    bool avx = ((info.ecx >> 28) & 1) != 0; // avx

    //
    // Page 7
    //
    cpuid(&info, 7, 0);
    bool vaes = ((info.ecx >> 9) & 1) != 0; // vaes
    bool avx512f = ((info.ebx >> 16) & 1) != 0; // avx512f
//    bool avx512vl = ((info.ebx >> 31) & 1) != 0; // avx512vl
    bool avx512bw = ((info.ebx >> 30) & 1) != 0; // AVX512BW
    bool vPCLMULQDQ = ((info.ecx) >> 10 & 1) != 0;// VPCLMULQDQ

    //
    // Strings owned by JVM
    //
    if (vaes && avx512f && avx512bw && vPCLMULQDQ) {
        return env->NewStringUTF("vaesf");
    } else if (vaes) {
        return env->NewStringUTF("vaes");
    } else if (avx) {
        return env->NewStringUTF("avx");
    }
    return env->NewStringUTF("none");

}

/*
 * Class:     org_bouncycastle_crypto_fips_VariantSelector
 * Method:    getFeatureMatrix
 * Signature: ()[Ljava/lang/String;
 */
//[[maybe_unused]] JNIEXPORT jobjectArray JNICALL Java_org_bouncycastle_crypto_fips_VariantSelector_getFeatureMatrix
JNIEXPORT jobjectArray JNICALL Java_org_bouncycastle_crypto_VariantSelector_getFeatureMatrix
         (JNIEnv *env, jclass) {

    cpuid_t info;

    // Bits from https://en.wikipedia.org/wiki/CPUID

    //
    // Page 1
    //
    cpuid(&info, 1, 0);
    bool avx = ((info.ecx >> 28) & 1) != 0; // avx

    //
    // Page 7
    //
    cpuid(&info, 7, 0);
    bool vaes = ((info.ecx >> 9) & 1) != 0; // vaes
    bool avx512f = ((info.ebx >> 16) & 1) != 0; // avx512f
//    bool avx512vl = ((info.ebx >> 31) & 1) != 0; // avx512vl
    bool avx512bw = ((info.ebx >> 30) & 1) != 0; // AVX512BW
    bool vPCLMULQDQ = ((info.ecx) >> 10 & 1) != 0;// VPCLMULQDQ

    auto outerArray = env->NewObjectArray(3, env->FindClass("[Ljava/lang/String;"), nullptr);

    //
    // VAESF
    //
    auto vaesfArray = env->NewObjectArray(6, env->FindClass("java/lang/String"), nullptr);
    env->SetObjectArrayElement(vaesfArray, 0, env->NewStringUTF("VAESF"));
    if (vaes) {
        env->SetObjectArrayElement(vaesfArray, 1, env->NewStringUTF("+vaes"));
    } else {
        env->SetObjectArrayElement(vaesfArray, 1, env->NewStringUTF("-vaes"));
    }

    if (avx512f) {
        env->SetObjectArrayElement(vaesfArray, 2, env->NewStringUTF("+avx512f"));
    } else {
        env->SetObjectArrayElement(vaesfArray, 2, env->NewStringUTF("-avx512f"));
    }

    if (avx512bw) {
        env->SetObjectArrayElement(vaesfArray, 3, env->NewStringUTF("+avx512bw"));
    } else {
        env->SetObjectArrayElement(vaesfArray, 3, env->NewStringUTF("-avx512bw"));
    }

    if (vPCLMULQDQ) {
        env->SetObjectArrayElement(vaesfArray, 4, env->NewStringUTF("+vpclmulqdq"));
    } else {
        env->SetObjectArrayElement(vaesfArray, 4, env->NewStringUTF("-vpclmulqdq"));
    }

    if (vaes && avx512f && avx512bw && vPCLMULQDQ) {
        env->SetObjectArrayElement(vaesfArray, 5, env->NewStringUTF("Variant supported"));
    } else {
        env->SetObjectArrayElement(vaesfArray, 5, env->NewStringUTF("No variant support"));
    }

    env->SetObjectArrayElement(outerArray, 0, vaesfArray);


    //
    // VAES
    //
    auto vaesArray = env->NewObjectArray(3, env->FindClass("java/lang/String"), nullptr);
    env->SetObjectArrayElement(vaesArray, 0, env->NewStringUTF("VAES"));
    if (vaes) {
        env->SetObjectArrayElement(vaesArray, 1, env->NewStringUTF("+vaes"));
    } else {
        env->SetObjectArrayElement(vaesArray, 1, env->NewStringUTF("-vaes"));
    }

    if (vaes) {
        env->SetObjectArrayElement(vaesArray, 2, env->NewStringUTF("Variant supported"));
    } else {
        env->SetObjectArrayElement(vaesArray, 2, env->NewStringUTF("No variant support"));
    }

    env->SetObjectArrayElement(outerArray, 1, vaesArray);


    //
    // AVX
    //
    auto avxArray = env->NewObjectArray(3, env->FindClass("java/lang/String"), nullptr);
    env->SetObjectArrayElement(avxArray, 0, env->NewStringUTF("AVX"));
    if (avx) {
        env->SetObjectArrayElement(avxArray, 1, env->NewStringUTF("+avx"));
    } else {
        env->SetObjectArrayElement(avxArray, 1, env->NewStringUTF("-avx"));
    }

    if (avx) {
        env->SetObjectArrayElement(avxArray, 2, env->NewStringUTF("Variant supported"));
    } else {
        env->SetObjectArrayElement(avxArray, 2, env->NewStringUTF("No variant support"));
    }

    env->SetObjectArrayElement(outerArray, 2, avxArray);





    return outerArray;
}