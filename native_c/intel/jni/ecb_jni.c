

#include "org_bouncycastle_crypto_engines_AESNativeEngine.h"
#include "../../jniutil/bytearraycritical.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/jni_asserts.h"
#include "../common.h"
#include "../ecb/ecb.h"


__attribute__((unused)) JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_reset
        (JNIEnv *env, jclass cl, jlong ref) {
    ecb_ctx *ctx = (ecb_ctx *) ((void *) ref);
    ecb_reset(ctx);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeEngine
 * Method:    process
 * Signature: (J[BII[BI)I
 */


__attribute__((unused)) JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_process
        (JNIEnv *env, jclass cl, jlong ref, jbyteArray _in, jint inOffset, jint blocks, jbyteArray _out,
         jint outOffset) {

    critical_bytearray_ctx output;
    critical_bytearray_ctx input;


    jint processed = 0;

    void *inStart;
    void *outStart;

    if (block_processing_init(env, &input, &output, _in, inOffset, _out, outOffset, blocks, ECB_BLOCK_SIZE, &inStart,
                              &outStart)) {
        ecb_ctx *ctx = (ecb_ctx *) ((void *) ref);
        //
        // Appropriate variant is determined by which of, ecb[128,256,512].c selected in CMakeLists.txt
        //
        processed = (jint) ecb_process_blocks(ctx, inStart, (uint32_t) blocks, outStart);
    }

    // also does release of java array if necessary
    release_critical_ctx(&input);
    release_critical_ctx(&output);

    return processed;

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeEngine
 * Method:    getMultiBlockSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_getMultiBlockSize
        (JNIEnv * env, jclass cl, jlong l) {
#ifdef BC_AVX
    return ECB_BLOCK_SIZE * 8;
#else
    return ECB_BLOCK_SIZE * 16;
#endif
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeEngine
 * Method:    getBlockSize
 * Signature: (J)I
 */

JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_getBlockSize
        (JNIEnv *env, jclass cl, jlong l) {
    return ECB_BLOCK_SIZE;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeEngine
 * Method:    makeInstance
 * Signature: (IZ)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_makeInstance
        (JNIEnv *env, jclass cl, jint keyLen, jboolean encryption) {


    ecb_ctx *ctx = NULL;
    switch (keyLen) {
        case 16: {
            ctx = ecb_create_ctx();
            ctx->num_rounds = ROUNDS_128;
            ctx->encryption = encryption == JNI_TRUE;
        }
            break;
        case 24: {
            ctx = ecb_create_ctx();
            ctx->num_rounds = ROUNDS_192;
            ctx->encryption = encryption == JNI_TRUE;
        }
            break;
        case 32: {
            ctx = ecb_create_ctx();
            ctx->num_rounds = ROUNDS_256;
            ctx->encryption = encryption == JNI_TRUE;
        }
            break;
        default:
            throw_java_illegal_argument(env, "key must be only 16, 24 or 32 bytes long");
            break;
    }

    //
    // Ownership is managed by the java class that has the reference to it.
    //
    return (jlong) ((void *) ctx);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeEngine
 * Method:    dispose
 * Signature: (J)V
 */

JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_dispose
        (JNIEnv *env, jclass cl, jlong ref) {

    ecb_ctx *ctx = (ecb_ctx *) ((void *) ref);
    ecb_free_ctx(ctx);

}


void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_init
        (JNIEnv *env, jclass cl, jlong ref, jbyteArray _key) {

    java_bytearray_ctx key;

    init_bytearray_ctx(&key);

    if (!load_bytearray_ctx(&key, env, _key)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid array");
        goto exit;
    }

    if (aes_keysize_is_valid_and_not_null(env, &key)) {
        ecb_ctx *ctx = (ecb_ctx *) ((void *) ref);
        ecb_init(ctx, key.bytearray);
    }

    exit:
    release_bytearray_ctx(&key);
}
