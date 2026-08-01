//
//


#include "org_bouncycastle_crypto_NativeEntropySource.h"
#include "stdint.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/exceptions.h"
#include "../util/util.h"
#include <immintrin.h>
#include <string.h>


#define RAND_MOD 8

//
// Bounded retry counts for the hardware entropy sources.
// Per Intel SDM and Intel's "Digital Random Number Generator" software guide.
// They have doubled for safety.
//
#define MAX_RDRAND_RETRIES 20   // Intel-recommended baseline: 10
#define MAX_RDSEED_RETRIES 200  // Intel-recommended baseline: 100

/*
 * Class:     org_bouncycastle_crypto_NativeEntropySource
 * Method:    isPredictionResistant
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_isPredictionResistant
        (JNIEnv *env, jobject jo) {
    return JNI_TRUE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeEntropySource
 * Method:    modulus
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_modulus
        (JNIEnv *env, jobject jo) {
    return RAND_MOD;
}

/*
 * Class:     org_bouncycastle_crypto_NativeEntropySource
 * Method:    seedBuffer
 * Signature: ([BZ)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_seedBuffer
        (JNIEnv *env, jobject jo, jbyteArray buf_, jboolean useSeed) {

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

    // Clear on the way in. Use memzero (un-elidable) rather than memset.
    memzero(buf.bytearray, buf.size);

    size_t count = buf.size / RAND_MOD;

    unsigned long long val = 0;

    if (useSeed) {
        // Use RDSEED
        for (size_t i = 0; i < count; i++) {
            int flag = _rdseed64_step(&val);
            int tries = 0;
            while (flag == 0) {
                if (++tries > MAX_RDSEED_RETRIES) {
                    // Drop any partial entropy already written so the caller
                    // does not observe a partly-filled buffer alongside the
                    // exception. Use memzero (un-elidable) rather than memset.
                    memzero(buf.bytearray, buf.size);
                    throw_java_invalid_state(env,
                        "RDSEED persistently failed to produce entropy");
                    goto exit;
                }
                _mm_pause();
                flag = _rdseed64_step(&val);
            }
            memcpy(buf.bytearray + i * sizeof(val), &val, sizeof(val));
        }
    } else {
        // Use RDRAND
        for (size_t i = 0; i < count; i++) {
            int flag = _rdrand64_step(&val);
            int tries = 0;
            while (flag == 0) {
                if (++tries > MAX_RDRAND_RETRIES) {
                    memzero(buf.bytearray, buf.size);
                    throw_java_invalid_state(env,
                        "RDRAND persistently failed to produce entropy");
                    goto exit;
                }
                _mm_pause();
                flag = _rdrand64_step(&val);
            }
            memcpy(buf.bytearray + i * sizeof(val), &val, sizeof(val));
        }
    }


    exit:
    release_bytearray_ctx(&buf);

}
