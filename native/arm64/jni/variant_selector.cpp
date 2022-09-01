
#include "org_bouncycastle_util_VariantSelector.h"


typedef struct cpuid_struct {
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
} cpuid_t;



/*
 * Class:     org_bouncycastle_crypto_fips_Probe
 * Method:    getBestVariantName
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_bouncycastle_util_VariantSelector_getBestVariantName
        (JNIEnv *env, jclass) {


    return env->NewStringUTF(BC_VARIANT_PREFIX"-v9");

}
