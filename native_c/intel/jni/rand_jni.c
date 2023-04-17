//
//


#include "org_bouncycastle_crypto_NativeEntropySource.h"
#include "stdint.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/exceptions.h"
#include <immintrin.h>


#define RAND_MOD 8

/*
 * Class:     org_bouncycastle_crypto_NativeEntropySource
 * Method:    isPredictionResistant
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_isPredictionResistant
        (JNIEnv *env, jobject) {
    return JNI_TRUE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeEntropySource
 * Method:    modulus
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_modulus
        (JNIEnv *env, jobject) {
    return RAND_MOD;
}

/*
 * Class:     org_bouncycastle_crypto_NativeEntropySource
 * Method:    seedBuffer
 * Signature: ([BZ)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_seedBuffer
        (JNIEnv *env, jobject, jbyteArray buf_, jboolean useSeed) {

    java_bytearray_ctx buf;
    init_bytearray_ctx(&buf);

    if (!load_bytearray_ctx(&buf, env, buf_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid array");
        return;
    }

    if (buf.bytearray == NULL) {
        throw_java_NPE(env, "array cannot be null");
        goto exit;
    }

    if (buf.size % RAND_MOD != 0) {
        throw_java_illegal_argument(env, "array must be multiple of modulus");
        goto exit;
    }

    // Clear on the way in.
    memset(buf.bytearray, 0, buf.size);

    size_t count = buf.size / RAND_MOD;

    unsigned long long val = 0;
    unsigned long long *ptr = (unsigned long long *) buf.bytearray;

    if (useSeed) {
        // Use RDSEED
        while (count-- > 0) {
            int flag = _rdseed64_step(&val);
            while (flag == 0) {
                _mm_pause();
                flag = _rdseed64_step(&val);
            }
            *ptr = val;
            ptr++;
        }
    } else {
        // Use RDRAND
        while (count-- > 0) {
            int flag = _rdrand64_step(&val);
            while (flag == 0) {
                _mm_pause();
                flag = _rdrand64_step(&val);
            }
            *ptr = val;
            ptr++;
        }
    }


    exit:
    release_bytearray_ctx(&buf);

}
