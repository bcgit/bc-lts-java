

#include <assert.h>
#include "org_bouncycastle_crypto_engines_AESNativeGCMSIV.h"
#include "../gcm_siv/gcm_siv.h"
#include "../../jniutil/exceptions.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/jni_asserts.h"


void handle_gcm_siv_result(JNIEnv *env, gcm_siv_err *err) {
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
            throw_java_invalid_state(env, "unknown error from GCMSIV");
            break;
    }

    gcm_siv_err_free(err);

}

// We need to be able to adjust this down for testing.


bool checkAEADStatus(JNIEnv *env, gcm_siv_ctx *ctx, size_t pLen) {

    /* Make sure that we haven't breached AEAD data limit */
    if (ctx->theAEADHasher.numHashed > (ctx->max_dl - pLen)) {
        throw_java_invalid_state(env, "AEAD byte count exceeded");
        return false;
    }
    return true;
}


bool checkStatus(JNIEnv *env, gcm_siv_ctx *ctx, size_t pLen, size_t size) {

    /* Make sure that we haven't breached data limit */
    size_t dataLimit = ctx->max_dl;

    if (!ctx->encryption) {
        dataLimit += BLOCK_SIZE;
    }
    if (size > dataLimit - pLen) {
        throw_java_invalid_state(env, "byte count exceeded");
        return false;
    }
    return true;
}


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_reset
        (JNIEnv *env, jobject o, jlong ref) {

    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;
    gcm_siv_reset(ctx, false);

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
 * Method:    initNative
 * Signature: (JZ[B[B[BI)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_initNative
        (JNIEnv *env, jclass cl, jlong ref, jboolean encryption, jbyteArray key_, jbyteArray iv_, jbyteArray ad_) {

    gcm_siv_err *err = NULL;
    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;
    java_bytearray_ctx key, iv, ad;

    init_bytearray_ctx(&key);
    init_bytearray_ctx(&iv);
    init_bytearray_ctx(&ad);


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

    if (!aes_keysize_is_valid_and_not_null_not_24(env, &key)) {
        goto exit;
    }


    if (!bytearray_not_null(&iv, "iv was null", env)) {
        goto exit;
    }

    if (iv.size != 12) {
        throw_java_illegal_argument(env, "iv must be 12 bytes");
        goto exit;
    }

    // gcm_siv_init checks for null ad array, asserts ad len is 0 if ad is null.

    err = gcm_siv_init(
            ctx,
            encryption == JNI_TRUE,
            key.bytearray,
            key.size,
            iv.bytearray,
            ad.bytearray,
            ad.size);

    exit:
    release_bytearray_ctx(&key);
    release_bytearray_ctx(&iv);
    release_bytearray_ctx(&ad);

    handle_gcm_siv_result(env, err);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
 * Method:    makeInstance
 * Signature: (IZ)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_makeInstance
        (JNIEnv *env, jclass cl) {
    gcm_siv_ctx *gcm_siv = gcm_siv_create_ctx();
    return (jlong) gcm_siv;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
 * Method:    dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_dispose
        (JNIEnv *env, jclass jc, jlong ref) {
    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;
    gcm_siv_free(ctx);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
 * Method:    processAADByte
 * Signature: (JB)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_processAADByte
        (JNIEnv *env, jclass cl, jlong ref, jbyte aadByte) {

    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;
    if (!checkAEADStatus(env, ctx, 1)) {
        return;
    }
    uint8_t theByte = (uint8_t) aadByte;
    gcm_siv_hasher_updateHash(&ctx->theAEADHasher, ctx->T, &theByte, 1, &ctx->theGHash);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
 * Method:    processAADBytes
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_processAADBytes
        (JNIEnv *env, jclass cl, jlong ref, jbyteArray aad_, jint offset, jint len) {

    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;
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
    if (!checkAEADStatus(env, ctx, (size_t) len)) {
        goto exit;
    }
    gcm_siv_hasher_updateHash(&ctx->theAEADHasher, ctx->T, aad.bytearray + offset, (size_t) len, &ctx->theGHash);

    exit:
    release_bytearray_ctx(&aad);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
 * Method:    doFinal
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_doFinal
        (JNIEnv *env, jclass cl, jlong ref, jbyteArray in, jint inLen, jbyteArray out, jint outOff) {

    gcm_siv_err *err = NULL;
    size_t written = 0;
    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;
    critical_bytearray_ctx input, output;

    init_critical_ctx(&output, env, out);
    init_critical_ctx(&input, env, in);

    if (!critical_offset_and_len_are_in_range_with_messages(
            &input,
            0, inLen,
            env,
            "input was null",
            "negative input offset",
            "input len is negative",
            "input too short for length")) {
        goto exit;
    }


    //
    // check input can be processed even
    //
    if (!checkStatus(env, ctx, 0, (size_t) input.size)) {
        goto exit;
    }

    //
    // Validate output
    //

    if (!critical_not_null(&output, "output was null", env)) {
        goto exit;
    }

    if (!critical_offset_is_in_range(&output, outOff, env)) {
        goto exit;
    }

    int64_t minOutputLen = gcm_siv_get_output_size(ctx->encryption, (size_t)inLen);

    //
    // < 0 if the input size is impossibly small,
    // for example, in decryption and input len < tag len
    //
    if (minOutputLen < 0) {
        throw_java_illegal_argument(env, "input less than tag len");
        goto exit;
    }

    // Assert space in buffer can contain the output len.
    if (output.size - (size_t) outOff < minOutputLen) {
        throw_java_illegal_argument(env, "output at offset too short");
        goto exit;
    }


    //
    // Load the contexts.
    //
    if (!load_critical_ctx(&output)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid output array");
        goto exit;
    }

    if (!load_critical_ctx(&input)) {
        release_critical_ctx(&output);
        throw_java_invalid_state(env, "unable to obtain ptr to valid input array");
        goto exit;
    }


    uint8_t *dest = output.critical + outOff;
    err = gcm_siv_doFinal(ctx, input.critical, (size_t)inLen, dest, &written);

    exit:
    release_critical_ctx(&input);
    release_critical_ctx(&output);

    handle_gcm_siv_result(env, err);

    return (jint) written;

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
 * Method:    getUpdateOutputSize
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_getUpdateOutputSize
        (JNIEnv *env, jclass cl, jlong ref, jint len, jint stream_len) {
    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;

    if (len < 0) {
        throw_java_illegal_argument(env, "len is negative");
        return 0;
    }

    int64_t l = gcm_siv_get_output_size(ctx->encryption, (size_t) len);
    if (l < 0) {
        return 0;
    }

    return (jint) l;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
 * Method:    getOutputSize
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_getOutputSize
        (JNIEnv *env, jclass jo, jlong ref, jint len) {

    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;

    if (len < 0) {
        throw_java_illegal_argument(env, "len is negative");
        return 0;
    }


    int64_t l = gcm_siv_get_output_size(ctx->encryption, (size_t) len);
    if (l < 0) {
        return 0;
    }

    return (jint) l;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
 * Method:    getMac
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_getMac
        (JNIEnv *env, jclass cl, jlong ref) {


    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;
    size_t macBlockLen = gcm_siv_getMac(ctx, NULL);

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

    gcm_siv_getMac(ctx, out_ctx.bytearray);

    exit:
    release_bytearray_ctx(&out_ctx);

    return out;
}


JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_test_1set_1max_1dl
        (JNIEnv *, jclass, jlong ref, jlong new_value) {

    //
    // Use to reduce upper processing limit so assertions around that limit can be verified in their natural
    // setting.
    //

    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;

    size_t lastValue = ctx->max_dl;
    ctx->max_dl = (size_t) new_value;

    //
    // Only be set lower than original
    //
    assert(lastValue > ctx->max_dl);
}

