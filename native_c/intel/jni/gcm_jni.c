

#include <assert.h>
#include "org_bouncycastle_crypto_engines_AESNativeGCM.h"
#include "../gcm/gcm.h"
#include "../../jniutil/exceptions.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/jni_asserts.h"
#include "../../jniutil/bytearraycritical.h"


void handle_gcm_result(JNIEnv *env, gcm_err *err) {
    if (err == NULL) {
        return;
    }
    switch (err->type) {
        case ILLEGAL_STATE:
            throw_java_invalid_state(env, err->msg);
            break;
        case ILLEGAL_ARGUMENT:
            throw_java_illegal_argument(env, err->msg);
            break;
        case ILLEGAL_CIPHER_TEXT:
            throw_bc_invalid_ciphertext_exception(env, err->msg);
            break;
        case OUTPUT_LENGTH:
            throw_bc_output_length_exception(env, err->msg);
            break;
        default:
            throw_java_invalid_state(env, "unknown error from GCM");
            break;
    }

    gcm_err_free(err);

}


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_reset
        (JNIEnv *, jobject, jlong ref) {

    gcm_ctx *ctx = (gcm_ctx *) ref;
    gcm_reset(ctx, false);

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    initNative
 * Signature: (JZ[B[B[BI)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_initNative
        (JNIEnv *env, jclass, jlong ref, jboolean encryption, jbyteArray key_, jbyteArray iv_, jbyteArray ad_,
         jint macSizeInBits) {

    gcm_err *err = NULL;
    gcm_ctx *ctx = (gcm_ctx *) ref;
    java_bytearray_ctx key, iv, ad;

    init_bytearray_ctx(&key);
    init_bytearray_ctx(&iv);
    init_bytearray_ctx(&ad);

    if (macSizeInBits < 32 || macSizeInBits > 128 || macSizeInBits % 8 != 0) {
        throw_java_illegal_argument(env, "invalid value for MAC size");
        goto exit;
    }


    if (!load_bytearray_ctx(&key, env, key_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid key array");
        goto exit;
    }

    if (!load_bytearray_ctx(&iv, env, iv_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid iv array");
        goto exit;
    }

    if (!load_bytearray_ctx(&ad, env, ad_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid ad array");
        goto exit;
    }


    if (!aes_keysize_is_valid_and_not_null(env, &key)) {
        goto exit;
    }

    if (!bytearray_not_null(&iv, "iv was null", env)) {
        goto exit;
    }

    if (iv.size < 12) {
        throw_java_illegal_argument(env, "IV must be at least 12 bytes");
        goto exit;
    }


    err = gcm_init(
            ctx,
            encryption == JNI_TRUE,
            key.bytearray,
            key.size,
            iv.bytearray,
            iv.size,
            ad.bytearray,
            ad.size,
            (uint32_t) macSizeInBits);


    exit:
    release_bytearray_ctx(&key);
    release_bytearray_ctx(&iv);
    release_bytearray_ctx(&ad);

    handle_gcm_result(env, err);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    makeInstance
 * Signature: (IZ)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_makeInstance
        (JNIEnv *, jclass, jint, jboolean ignored) {
    gcm_ctx *gcm = gcm_create_ctx();
    return (jlong) gcm;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_dispose
        (JNIEnv *, jclass, jlong ref) {
    gcm_ctx *ctx = (gcm_ctx *) ref;
    gcm_free(ctx);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    processAADByte
 * Signature: (JB)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_processAADByte
        (JNIEnv *, jclass, jlong ref, jbyte aadByte) {

    gcm_ctx *ctx = (gcm_ctx *) ref;
    gcm_process_aad_byte(ctx, (uint8_t) aadByte);

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    processAADBytes
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_processAADBytes
        (JNIEnv *env, jclass, jlong ref, jbyteArray aad_, jint offset, jint len) {

    gcm_ctx *ctx = (gcm_ctx *) ref;
    java_bytearray_ctx aad;
    init_bytearray_ctx(&aad);

    if (!load_bytearray_ctx(&aad, env, aad_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid aad array");
        goto exit;
    }


    if (!bytearray_not_null(&aad, "aad was null", env)) {
        goto exit;
    }
    if (!bytearray_offset_and_len_are_in_range(&aad, offset, len, env)) {
        goto exit;
    }

    gcm_process_aad_bytes(ctx, aad.bytearray + offset, (size_t) len);

    exit:
    release_bytearray_ctx(&aad);

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    processByte
 * Signature: (JB[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_processByte
        (JNIEnv *env, jclass, jlong ref, jbyte byte, jbyteArray out, jint offset) {

    gcm_err *err = NULL;
    critical_bytearray_ctx output;
    init_critical_ctx(&output, env, out);

    size_t written = 0;
    gcm_ctx *ctx = (gcm_ctx *) ref;



    if (offset < 0) {
        throw_java_illegal_argument(env, "offset is negative");
        goto exit;
    }

    if (output.array != NULL) {
        if (!critical_offset_is_in_range(&output, offset, env)) {
            goto exit;
        }
    }

    if (!load_critical_ctx(&output)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid output array");
        goto exit;
    }


    // NULL is a valid destination if the caller is not expecting any output
    // GCM will return an error if there is a decryption result is generated.

    uint8_t *dest = output.critical == NULL ? NULL : output.critical + offset;
    size_t outputLen = output.array == NULL ? 0 : output.size - (size_t) offset;

    err = gcm_process_byte(
            ctx,
            (uint8_t) byte,
            dest,
            outputLen, &written);

    exit:
    release_critical_ctx(&output);

    handle_gcm_result(env, err);

    return (jint) written;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    processBytes
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_processBytes
        (JNIEnv *env, jclass, jlong ref, jbyteArray in, jint inOff, jint len, jbyteArray out, jint outoff) {

    gcm_err *err = NULL;
    gcm_ctx *ctx = (gcm_ctx *) ref;
    size_t written = 0;

    critical_bytearray_ctx input, output;
    init_critical_ctx(&output, env, out);
    init_critical_ctx(&input, env, in);


    if (!critical_not_null(&input, "input was null", env)) {
        goto exit;
    }

    if (outoff < 0) {
        throw_java_illegal_argument(env, "output offset is negative");
        goto exit;
    }


    if (output.array != NULL) {
        if (!critical_offset_is_in_range(&output, outoff, env)) {
            goto exit;
        }
    }

    if (!critical_offset_and_len_are_in_range(&input, inOff, len, env)) {
        goto exit;
    }


    if (!load_critical_ctx(&output)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid output array");
        goto exit;
    }

    if (!load_critical_ctx(&input)) {
        release_critical_ctx(&output);
        throw_java_invalid_state(env, "unable to obtain ptr to valid input array");
        goto exit;
    }


    // NULL is a valid destination if the caller is not expecting any output
    // GCM will return an error if there is a decryption result is generated.

    uint8_t *dest = output.critical == NULL ? NULL : output.critical + outoff;
    size_t outLen = output.array == NULL ? 0 : output.size - (size_t) outoff;

    uint8_t *src = input.critical + inOff;


    err = gcm_process_bytes(ctx,
                            src,
                            (size_t) len,
                            dest,
                            outLen,
                            &written);


    exit:
    release_critical_ctx(&input);
    release_critical_ctx(&output);


    handle_gcm_result(env, err);

    return (jint) written;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    doFinal
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_doFinal
        (JNIEnv *env, jclass, jlong ref, jbyteArray out, jint offset) {

    gcm_err *err = NULL;
    size_t written = 0;
    gcm_ctx *ctx = (gcm_ctx *) ref;
    critical_bytearray_ctx output;

    init_critical_ctx(&output, env, out);



    if (!critical_not_null(&output, "output was null", env)) {
        goto exit;
    }


    if (!critical_offset_is_in_range(&output, offset, env)) {
        goto exit;
    }

    if (!load_critical_ctx(&output)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid output array");
        goto exit;
    }

    uint8_t *dest = output.critical + offset;
    size_t len = output.size - (size_t) offset;

    err = gcm_doFinal(ctx, dest, len, &written);

    exit:
    release_critical_ctx(&output);

    handle_gcm_result(env, err);

    return (jint) written;

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    getUpdateOutputSize
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_getUpdateOutputSize
        (JNIEnv *env, jclass, jlong ref, jint len) {
    gcm_ctx *ctx = (gcm_ctx *) ref;

    if (len < 0) {
        throw_java_illegal_argument(env, "len is negative");
        return 0;
    }

    return (jint) gcm_get_update_output_size(ctx, (size_t) len);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    getOutputSize
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_getOutputSize
        (JNIEnv *env, jclass, jlong ref, jint len) {

    gcm_ctx *ctx = (gcm_ctx *) ref;

    if (len < 0) {
        throw_java_illegal_argument(env, "len is negative");
        return 0;
    }

    return (jint) gcm_get_output_size(ctx, (size_t) len);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    getMac
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_getMac
        (JNIEnv *env, jclass, jlong ref) {


    gcm_ctx *ctx = (gcm_ctx *) ref;
    size_t macBlockLen = gcm_getMac(ctx, NULL);

    jbyteArray out = (*env)->NewByteArray(env, (jint) macBlockLen);
    if (out == NULL) {
        throw_java_invalid_state(env, "unable to create output array");
        return NULL;
    }

    java_bytearray_ctx out_ctx;
    init_bytearray_ctx(&out_ctx);


    if (!load_bytearray_ctx(&out_ctx, env, out)) {
        throw_java_invalid_state(env, "unable to obtain ptr to output array");
        goto exit;
    }

    gcm_getMac(ctx, out_ctx.bytearray);

    exit:
    release_bytearray_ctx(&out_ctx);

    return out;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCM
 * Method:    setBlocksRemainingDown
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_setBlocksRemainingDown
        (JNIEnv *env, jobject, jlong ref, jlong downValue) {

    //
    // This method is not part of the public api, it is used in testing.
    //

    gcm_ctx *ctx = (gcm_ctx *) ref;

    if (downValue < 0) {
        throw_java_illegal_argument(env, "attempt to increment blocks remaining");
        return;
    }

    if (ctx->totalBytes > 0) {
        throw_java_illegal_argument(env, "data has been written");
        return;
    }

    if (ctx->blocksRemaining - downValue > ctx->blocksRemaining) {
        throw_java_illegal_argument(env, "attempt to increment blocks remaining");
        return;
    }

    ctx->blocksRemaining -= downValue;
}
