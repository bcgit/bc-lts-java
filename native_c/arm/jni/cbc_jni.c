#include "org_bouncycastle_crypto_engines_AESNativeCBC.h"


#include "../cbc/cbc.h"
#include "../../jniutil/bytearraycritical.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/jni_asserts.h"
#include "../aes/aes_common_neon.h"



/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    process
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_process
        (JNIEnv *env, jclass cl, jlong ref, jbyteArray in_, jint inOff, jint blocks, jbyteArray out_, jint outOff) {

    critical_bytearray_ctx output;
    critical_bytearray_ctx input;

    jint processed = 0;

    void *inStart;
    void *outStart;

    if (block_processing_init(env, &input, &output, in_, inOff, out_, outOff, blocks, CBC_BLOCK_SIZE, &inStart,
                              &outStart)) {
        cbc_ctx *ctx = (cbc_ctx *) ((void *) ref);
        if (ctx->encryption) {
            processed = (jint) cbc_encrypt(ctx, inStart, (uint32_t) blocks, outStart);
        } else {
            //
            // The decryption function for each variant is found in cbc128.c, cbc256.c, cbc512.c
            //
            processed = (jint) cbc_decrypt(ctx, inStart, (uint32_t) blocks, outStart);
        }
    }

    // also does release of java array if necessary
    release_critical_ctx(&input);
    release_critical_ctx(&output);

    return processed;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    getMultiBlockSize
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_getMultiBlockSize
        (JNIEnv *e, jclass c, jlong l) {
#ifdef BC_AVX
    return CBC_BLOCK_SIZE * 8;
#else
    return CBC_BLOCK_SIZE * 16;
#endif
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    getBlockSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_getBlockSize
        (JNIEnv *e, jclass class, jlong l) {
    return CBC_BLOCK_SIZE;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    makeNative
 * Signature: (IZ)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_makeNative
        (JNIEnv *env, jclass class, jint keySize, jboolean encryption) {

    cbc_ctx *ctx = NULL;
    switch (keySize) {
        case 16: {
            ctx = cbc_create_ctx();
            ctx->num_rounds = ROUNDS_128;
            ctx->encryption = encryption == JNI_TRUE;
        }
            break;
        case 24: {
            ctx = cbc_create_ctx();
            ctx->num_rounds = ROUNDS_192;
            ctx->encryption = encryption == JNI_TRUE;
        }
            break;
        case 32: {
            ctx = cbc_create_ctx();
            ctx->num_rounds = ROUNDS_256;
            ctx->encryption = encryption == JNI_TRUE;
        }
            break;
        default:
            throw_java_illegal_argument(env, "key must be only 16, 24, or 32 bytes long");
            break;
    }

    //
    // Ownership is managed by the java class that has the reference to it.
    //
    return (jlong) ((void *) ctx);
}


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    init
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_init
        (JNIEnv *env, jobject o, jlong ref, jbyteArray key_, jbyteArray iv_) {

    java_bytearray_ctx key, iv;

    init_bytearray_ctx(&key);
    init_bytearray_ctx(&iv);


    if (!load_bytearray_ctx(&key, env, key_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid array");
        goto exit;
    }

    if (!load_bytearray_ctx(&iv, env, iv_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid array");
        goto exit;
    }

    if (!aes_keysize_is_valid_and_not_null(env, &key)) {
        goto exit;
    }

    if (!ivlen_is_16_and_not_null(env, &iv)) {
        goto exit;
    }

    cbc_ctx *ctx = (cbc_ctx *) ((void *) ref);
    cbc_init(ctx, key.bytearray, iv.bytearray);

    exit:
    release_bytearray_ctx(&iv);
    release_bytearray_ctx(&key);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_dispose
        (JNIEnv *env, jclass cl, jlong ref) {
    cbc_ctx *ctx = (cbc_ctx *) ((void *) ref);
    cbc_free_ctx(ctx);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_reset
        (JNIEnv *env, jclass cl, jlong ref) {
    cbc_ctx *ctx = (cbc_ctx *) ((void *) ref);
    cbc_reset(ctx);
}
