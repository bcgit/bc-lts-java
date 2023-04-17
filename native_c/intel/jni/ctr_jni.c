//
//
//
#include "org_bouncycastle_crypto_engines_AESNativeCTR.h"
#include "../ctr/ctr.h"
#include "../../jniutil/exceptions.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/jni_asserts.h"

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCTR
 * Method:    makeCTRInstance
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCTR_makeCTRInstance
        (JNIEnv *e, jclass cl) {
    ctr_ctx *ctr = ctr_create_ctx();
    return (jlong) ((void *) ctr);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCTR
 * Method:    getPosition
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCTR_getPosition
        (JNIEnv *env, jclass cl, jlong ref) {
    ctr_ctx *ctx = (ctr_ctx *) ((void *) ref);
    return ctr_get_position(ctx);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCTR
 * Method:    getMultiBlockSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCTR_getMultiBlockSize
        (JNIEnv *env, jclass cl, jlong ref) {
#ifdef BC_AVX
    return CTR_BLOCK_SIZE * 8;
#else
    return CTR_BLOCK_SIZE * 16;
#endif
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCTR
 * Method:    skip
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCTR_skip
        (JNIEnv *env, jclass cl, jlong ref, jlong delta) {

    ctr_ctx *ctx = (ctr_ctx *) ((void *) ref);

    if (!ctr_skip(ctx, delta)) {
        throw_java_invalid_state(env, CTR_ERROR_MSG);
        return 0;
    }

    return delta;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCTR
 * Method:    seekTo
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCTR_seekTo
        (JNIEnv *env, jclass cl, jlong ref, jlong position) {

    if (position < 0) {
        throw_java_illegal_argument(env, "position less than zero");
        return 0;
    }

    ctr_ctx *ctx = (ctr_ctx *) ((void *) ref);
    if (!ctr_seekTo(ctx, position)) {
        throw_java_invalid_state(env, CTR_ERROR_MSG);
        return 0;
    }

    return ctr_get_position(ctx);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCTR
 * Method:    init
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCTR_init
        (JNIEnv *env, jclass, jlong ref, jbyteArray key_, jbyteArray iv_) {

    java_bytearray_ctx key, iv;

    init_bytearray_ctx(&key);
    init_bytearray_ctx(&iv);


    ctr_ctx *ctx = 0;

    if (!load_bytearray_ctx(&key, env, key_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid array");
        goto exit;
    }

    if (!load_bytearray_ctx(&iv, env, iv_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid array");
        goto exit;
    }




    if (!aes_keysize_is_valid_or_null(env, &key)) {
        goto exit;
    }

    if (iv.bytearray == NULL) {
        throw_java_NPE(env, "iv was null");
        goto exit;
    }

    if (iv.size < 8 || iv.size > 16) {
        throw_java_illegal_argument(env, "iv len must be from 8 to 16 bytes");
        goto exit;
    }

    ctx = (ctr_ctx *) ((void *) ref);


    if (key.bytearray == NULL) {
        if (ctx->num_rounds == 0) {
            throw_java_illegal_argument(env, "cannot replace iv unless key was previously supplied");
            goto exit;
        }
    }

    ctr_init(ctx, key.bytearray, key.size, iv.bytearray, iv.size);


    exit:
    release_bytearray_ctx(&iv);
    release_bytearray_ctx(&key);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCTR
 * Method:    returnByte
 * Signature: (JB)B
 */
JNIEXPORT jbyte JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCTR_returnByte
        (JNIEnv *env, jclass, jlong ref, jbyte in) {

    unsigned char v = (unsigned char) in;
    ctr_ctx *ctx = (ctr_ctx *) ((void *) ref);
    if (!ctr_process_byte(ctx, &v)) {
        throw_java_invalid_state(env, CTR_ERROR_MSG);
        return 0;
    }

    return (jbyte) v;

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCTR
 * Method:    processBytes
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCTR_processBytes
        (JNIEnv *env, jclass cl, jlong ref, jbyteArray in, jint inOff, jint len, jbyteArray out, jint outOff) {

    critical_bytearray_ctx output;
    critical_bytearray_ctx input;

    void *inStart;
    void *outStart;

    bool r = true;
    size_t written = 0;

    if (byte_processing_init(env, &input, &output, in, inOff, out, outOff, len, &inStart, &outStart)) {
        ctr_ctx *ctx = (ctr_ctx *) ((void *) ref);
        r = ctr_process_bytes(ctx, inStart, (size_t) len, outStart, &written);
    }

    release_critical_ctx(&input);
    release_critical_ctx(&output);

    if (!r) {
        throw_java_invalid_state(env, CTR_ERROR_MSG);
    }

    return (jint) written;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCTR
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCTR_reset
        (JNIEnv *, jclass, jlong ref) {
    ctr_ctx *ctx = (ctr_ctx *) ((void *) ref);
    ctr_reset(ctx);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCTR
 * Method:    dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCTR_dispose
        (JNIEnv *, jclass, jlong ref) {

    ctr_ctx *ctx = (ctr_ctx *) ((void *) ref);
    ctr_free_ctx(ctx);
}
