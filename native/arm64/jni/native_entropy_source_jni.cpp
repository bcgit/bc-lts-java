//
// Created  on 17/5/2022.
//



#include "../rand/Rand.h"
#include "org_bouncycastle_crypto_NativeEntropySource.h"
#include "../../jniutil/JavaEnvUtils.h"

using jniutil::JavaEnvUtils;


/*
 * Class:     org_bouncycastle_fips_crypto_HWEntropySource
 * Method:    isPredictionResistant
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_isPredictionResistant
        (JNIEnv *, jobject) {
    return JNI_FALSE;
}

/*
 * Class:     org_bouncycastle_fips_crypto_HWEntropySource
 * Method:    modulus
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_modulus
        (JNIEnv *, jobject) {
    return arm::Rand::modulus();
}

/*
 * Class:     org_bouncycastle_fips_crypto_HWEntropySource
 * Method:    seedBuffer
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_seedBuffer
        (JNIEnv *env, jobject, jbyteArray array, jboolean useSeedSource) {

    jniutil::JavaByteArray byteArray(env, array);

    if (byteArray.isNull()) {
        JavaEnvUtils::throwIllegalArgumentException(env,
                                                    "null byte array passed to native entropy source");
        return;
    }

    if (byteArray.length() % arm::Rand::modulus() != 0) {
        JavaEnvUtils::throwIllegalArgumentException(env,
                                                    "array length not multiple of modulus");
        return;
    }

    if (useSeedSource == JNI_TRUE) {
        arm::Rand::populateArraySeed(&byteArray);
        return;
    }

    arm::Rand::populateArrayRng(&byteArray);

}
