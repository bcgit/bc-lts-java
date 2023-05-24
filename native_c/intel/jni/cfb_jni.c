#include "org_bouncycastle_crypto_engines_AESNativeCFB.h"


#include "../../jniutil/bytearraycritical.h"
#include "../../jniutil/jni_asserts.h"
#include "../cfb/cfb.h"
#include "../common.h"



/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCFB
 * Method:    processByte
 * Signature: (JB)B
 */
JNIEXPORT jbyte JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_processByte
        (JNIEnv *e, jclass class, jlong ref, jbyte in) {
    cfb_ctx *ctx = (cfb_ctx *) ((void *) ref);

    if (ctx->encryption) {
        return (jbyte) cfb_encrypt_byte(ctx, (uint8_t) in);
    }

    return (jbyte) cfb_decrypt_byte(ctx, (uint8_t) in);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCFB
 * Method:    processBytes
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_processBytes
        (JNIEnv *env, jclass class, jlong ref, jbyteArray in_, jint inOff, jint len, jbyteArray out_, jint outOff) {

    critical_bytearray_ctx output;
    critical_bytearray_ctx input;

    void *inStart;
    void *outStart;


    cfb_ctx *ctx = (cfb_ctx *) ((void *) ref);
    jint processed = 0;
    if (byte_processing_init(env, &input, &output, in_, inOff, out_, outOff, len, &inStart, &outStart)) {
        if (ctx->encryption) {
            processed = (jint) cfb_encrypt(ctx, inStart, (size_t) len, outStart);
        } else {
            //
            // The decryption function for each variant is found in cfb128.c, cfb256.c, cfb512.c
            //
            processed = (jint) cfb_decrypt(ctx, inStart, (size_t) len, outStart);
        }
    }


    release_critical_ctx(&input);
    release_critical_ctx(&output);

    return processed;


}


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    makeNative
 * Signature: (IZ)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_makeNative
        (JNIEnv *env, jclass class, jboolean encryption, jint keySize) {

    cfb_ctx *ctx = NULL;
    uint32_t rounds;

    switch (keySize) {
        case 16:
            rounds = ROUNDS_128;
            break;
        case 24:
            rounds = ROUNDS_192;
            break;
        case 32:
            rounds = ROUNDS_256;
            break;
        default:
            throw_java_illegal_argument(env, "key must be only 16,24 or 32 bytes long");
            return 0;
    }

    ctx = cfb_create_ctx();
    ctx->num_rounds = rounds;
    ctx->encryption = encryption == JNI_TRUE;


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
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_init
        (JNIEnv *env, jobject jo, jlong ref, jbyteArray key_, jbyteArray iv_) {

    java_bytearray_ctx key,iv;

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

    cfb_ctx *ctx = (cfb_ctx *) ((void *) ref);
    cfb_init(ctx, key.bytearray, iv.bytearray);

    exit:
    release_bytearray_ctx(&iv);
    release_bytearray_ctx(&key);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_dispose
        (JNIEnv *e, jclass class, jlong ref) {

    cfb_ctx *ctx = (cfb_ctx *) ((void *) ref);
    cfb_free_ctx(ctx);

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_reset
        (JNIEnv *e, jclass cl, jlong ref) {
    cfb_ctx *ctx = (cfb_ctx *) ((void *) ref);
    cfb_reset(ctx);
}


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCFB
 * Method:    getNativeMultiBlockSize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_getNativeMultiBlockSize
        (JNIEnv *env, jclass cl) {
#ifdef BC_AVX
    return CFB_BLOCK_SIZE * 8;
#else
    return CFB_BLOCK_SIZE * 16;
#endif
}
