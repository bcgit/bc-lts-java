

#include <stdbool.h>
#include "org_bouncycastle_crypto_VariantSelector.h"


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
 * Class:     org_bouncycastle_crypto_Probe
 * Method:    getBestVariantName
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_bouncycastle_crypto_VariantSelector_getBestVariantName
        (JNIEnv *env, jclass jc) {


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
        return   (*env)->NewStringUTF(env,"vaesf");
    } else if (vaes) {
        return (*env)->NewStringUTF(env,"vaes");
    } else if (avx) {
        return (*env)->NewStringUTF(env,"avx");
    }
    return (*env)->NewStringUTF(env,"none");

}

/*
 * Class:     org_bouncycastle_crypto_VariantSelector
 * Method:    getFeatureMatrix
 * Signature: ()[Ljava/lang/String;
 */
 JNIEXPORT jobjectArray JNICALL Java_org_bouncycastle_crypto_VariantSelector_getFeatureMatrix
        (JNIEnv *env, jclass jc) {

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

    jobjectArray outerArray = (*env)->NewObjectArray(env,3, (*env)->FindClass(env,"[Ljava/lang/String;"), NULL);

    //
    // VAESF
    //
    jobjectArray vaesfArray = (*env)->NewObjectArray(env,6, (*env)->FindClass(env,"java/lang/String"), NULL);
    (*env)->SetObjectArrayElement(env,vaesfArray, 0, (*env)->NewStringUTF(env,"VAESF"));
    if (vaes) {
        (*env)->SetObjectArrayElement(env,vaesfArray, 1, (*env)->NewStringUTF(env,"+vaes"));
    } else {
        (*env)->SetObjectArrayElement(env,vaesfArray, 1, (*env)->NewStringUTF(env,"-vaes"));
    }

    if (avx512f) {
        (*env)->SetObjectArrayElement(env,vaesfArray, 2, (*env)->NewStringUTF(env,"+avx512f"));
    } else {
        (*env)->SetObjectArrayElement(env,vaesfArray, 2, (*env)->NewStringUTF(env,"-avx512f"));
    }

    if (avx512bw) {
        (*env)->SetObjectArrayElement(env,vaesfArray, 3, (*env)->NewStringUTF(env,"+avx512bw"));
    } else {
        (*env)->SetObjectArrayElement(env,vaesfArray, 3, (*env)->NewStringUTF(env,"-avx512bw"));
    }

    if (vPCLMULQDQ) {
        (*env)->SetObjectArrayElement(env,vaesfArray, 4, (*env)->NewStringUTF(env,"+vpclmulqdq"));
    } else {
        (*env)->SetObjectArrayElement(env,vaesfArray, 4, (*env)->NewStringUTF(env,"-vpclmulqdq"));
    }

    if (vaes && avx512f && avx512bw && vPCLMULQDQ) {
        (*env)->SetObjectArrayElement(env,vaesfArray, 5, (*env)->NewStringUTF(env,"Variant supported"));
    } else {
        (*env)->SetObjectArrayElement(env,vaesfArray, 5, (*env)->NewStringUTF(env,"No variant support"));
    }

    (*env)->SetObjectArrayElement(env,outerArray, 0, vaesfArray);


    //
    // VAES
    //
    jobjectArray vaesArray = (*env)->NewObjectArray(env,3, (*env)->FindClass(env,"java/lang/String"), NULL);
    (*env)->SetObjectArrayElement(env,vaesArray, 0, (*env)->NewStringUTF(env,"VAES"));
    if (vaes) {
        (*env)->SetObjectArrayElement(env,vaesArray, 1, (*env)->NewStringUTF(env,"+vaes"));
    } else {
        (*env)->SetObjectArrayElement(env,vaesArray, 1, (*env)->NewStringUTF(env,"-vaes"));
    }

    if (vaes) {
        (*env)->SetObjectArrayElement(env,vaesArray, 2, (*env)->NewStringUTF(env,"Variant supported"));
    } else {
        (*env)->SetObjectArrayElement(env,vaesArray, 2, (*env)->NewStringUTF(env,"No variant support"));
    }

    (*env)->SetObjectArrayElement(env,outerArray, 1, vaesArray);


    //
    // AVX
    //
    jobjectArray avxArray = (*env)->NewObjectArray(env,3, (*env)->FindClass(env,"java/lang/String"), NULL);
    (*env)->SetObjectArrayElement(env,avxArray, 0, (*env)->NewStringUTF(env,"AVX"));
    if (avx) {
        (*env)->SetObjectArrayElement(env,avxArray, 1, (*env)->NewStringUTF(env,"+avx"));
    } else {
        (*env)->SetObjectArrayElement(env,avxArray, 1, (*env)->NewStringUTF(env,"-avx"));
    }

    if (avx) {
        (*env)->SetObjectArrayElement(env,avxArray, 2, (*env)->NewStringUTF(env,"Variant supported"));
    } else {
        (*env)->SetObjectArrayElement(env,avxArray, 2, (*env)->NewStringUTF(env,"No variant support"));
    }

    (*env)->SetObjectArrayElement(env,outerArray, 2, avxArray);





    return outerArray;
}
