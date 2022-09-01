
#include "org_bouncycastle_util_VariantSelector.h"


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
JNIEXPORT jstring JNICALL Java_org_bouncycastle_util_VariantSelector_getBestVariantName
        (JNIEnv *env, jclass) {

    // All new strings are owned by the JVM.

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
    //  bool avx512f = ((info.ebx >> 16) & 1) != 0; // avx512_f
    // bool avx512vl = ((info.ebx >> 31) & 1) != 0; // avx512_vl
    // bool avx2 = ((info.ebx >> 5) & 1) != 0; // avx2

    /*
     * if (vaes) {
        return env->NewStringUTF(BC_VARIANT_PREFIX"-vaes");
    }
     */

    if (avx) {
        return env->NewStringUTF(BC_VARIANT_PREFIX"-avx");
    }
    return env->NewStringUTF(BC_VARIANT_PREFIX"-sse");

}
