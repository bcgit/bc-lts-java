

#include <assert.h>
#include "org_bouncycastle_crypto_engines_AESNativeGCMSIV.h"
#include "../gcm_siv/gcm_siv.h"
#include "../../jniutil/exceptions.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/jni_asserts.h"
#include "../../jniutil/bytearraycritical.h"


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

bool checkAEADStatus(JNIEnv *env, gcm_siv_ctx *ctx, int pLen) {
    /* Check we are initialised */
    if ((ctx->theFlags & INIT) == 0) {
        throw_java_invalid_state(env, "Cipher is not initialised");
        return true;
    }

    /* Check AAD is allowed */
    if ((ctx->theFlags & AEAD_COMPLETE) != 0) {
        throw_java_invalid_state(env, "AEAD data cannot be processed after ordinary data");
        return true;
    }

    /* Make sure that we haven't breached AEAD data limit */
    if (ctx->theAEADHasher.numHashed > (MAX_DATALEN - pLen)) {
        throw_java_invalid_state(env, "AEAD byte count exceeded");
        return true;
    }
    return false;
}

bool checkStatus(JNIEnv *env, gcm_siv_ctx *ctx, int pLen, int theEncDataSize) {
    /* Check we are initialised */
    if ((ctx->theFlags & INIT) == 0) {
        throw_java_invalid_state(env, "Cipher is not initialised");
        return true;
    }

    /* Complete the AEAD section if this is the first data */
    if ((ctx->theFlags & AEAD_COMPLETE) == 0) {
        gcm_siv_hasher_completeHash(&ctx->theAEADHasher, ctx->theReverse, &ctx->theMultiplier, ctx->theGHash);
        ctx->theFlags |= AEAD_COMPLETE;
    }

    /* Make sure that we haven't breached data limit */
    long dataLimit = MAX_DATALEN;
    long currBytes = theEncDataSize;
    if (!ctx->encryption) {
        dataLimit += BUFLEN;
    }
    if (currBytes > dataLimit - pLen) {
        throw_java_invalid_state(env, "byte count exceeded");
        return true;
    }
    return false;
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

    if (!aes_keysize_is_valid_and_not_null(env, &key)) {
        goto exit;
    }

    if (!bytearray_not_null(&iv, "iv was null", env)) {
        goto exit;
    }

    if (iv.size != 12) {
        throw_java_illegal_argument(env, "IV must be at least 12 bytes");
        goto exit;
    }

    err = gcm_siv_init(
            ctx,
            encryption == JNI_TRUE,
            key.bytearray,
            key.size,
            iv.bytearray,
            iv.size,
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
        (JNIEnv *env, jclass cl, jint i, jboolean ignored) {
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
    checkAEADStatus(env, ctx, 1);
    uint8_t theByte = (uint8_t) aadByte;
    gcm_siv_hasher_updateHash(&ctx->theAEADHasher, &ctx->theMultiplier, &theByte, 1, ctx->theReverse, ctx->theGHash);
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
    checkAEADStatus(env, ctx, len);
    gcm_siv_hasher_updateHash(&ctx->theAEADHasher, &ctx->theMultiplier, aad.bytearray + offset, len, ctx->theReverse,
                              ctx->theGHash);

    exit:
    release_bytearray_ctx(&aad);

}

///*
// * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
// * Method:    processByte
// * Signature: (JB[BI)I
// */
//JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_processByte
//        (JNIEnv *env, jclass cl, jlong ref, jbyte byte, jint theEndDataSize) {
//    size_t written = 0;
//    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;
//
////    if (offset < 0) {
////        throw_java_illegal_argument(env, "offset is negative");
////        goto exit;
////    }
//
//    if (checkStatus(env, ctx, 1, theEndDataSize)) {
//        goto exit;
//    }
//    // NULL is a valid destination if the caller is not expecting any output
//    // GCMSIV will return an error if there is a decryption result is generated.
//
//    uint8_t input = (uint8_t) byte;
//    gcm_siv_hasher_updateHash(&ctx->theAEADHasher, &ctx->theMultiplier, &input, 1, ctx->theReverse,
//                              ctx->theGHash);
//    exit:
//    return 0;
//}

///*
// * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
// * Method:    processBytes
// * Signature: (J[BII[BI)I
// */
//JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_processBytes
//        (JNIEnv *env, jclass cl, jlong ref, jbyteArray in, jint inOff, jint len,
//         jint theEndDataSize) {
//    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;
//    size_t written = 0;
//
//    critical_bytearray_ctx input;
//    init_critical_ctx(&input, env, in);
//
//
//    if (!critical_not_null(&input, "input was null", env)) {
//        goto exit;
//    }
//
////    if (outoff < 0) {
////        throw_java_illegal_argument(env, "output offset is negative");
////        goto exit;
////    }
//
//    if (!critical_offset_and_len_are_in_range(&input, inOff, len, env)) {
//        goto exit;
//    }
//
//    if (!load_critical_ctx(&input)) {
//        throw_java_invalid_state(env, "unable to obtain ptr to valid input array");
//        goto exit;
//    }
//
//    if (checkStatus(env, ctx, len, theEndDataSize)) {
//        goto exit;
//    }
//    // NULL is a valid destination if the caller is not expecting any output
//    // GCMSIV will return an error if there is a decryption result is generated.
//    uint8_t *src = input.critical + inOff;
//    gcm_siv_hasher_updateHash(&ctx->theAEADHasher, &ctx->theMultiplier, src, len, ctx->theReverse,
//                              ctx->theGHash);
//    exit:
//    release_critical_ctx(&input);
//
//    return (jint) written;
//}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMSIV
 * Method:    doFinal
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIV_doFinal
        (JNIEnv *env, jclass cl, jlong ref, jbyteArray out, jint offset, jbyteArray in, jint theEndDataSize) {

    gcm_siv_err *err = NULL;
    size_t written = 0;
    gcm_siv_ctx *ctx = (gcm_siv_ctx *) ref;
    critical_bytearray_ctx input, output;

    init_critical_ctx(&output, env, out);
    init_critical_ctx(&input, env, in);

    if (!critical_not_null(&output, "output was null", env)) {
        goto exit;
    }

    if (!critical_not_null(&input, "input was null", env)) {
        goto exit;
    }

    if (!critical_offset_is_in_range(&output, offset, env)) {
        goto exit;
    }

    if (!load_critical_ctx(&output)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid output array");
        goto exit;
    }

    if (!load_critical_ctx(&input)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid input array");
        goto exit;
    }

    if (checkStatus(env, ctx, 0, theEndDataSize)) {
        goto exit;
    }

    uint8_t *dest = output.critical + offset;
    size_t len = output.size - (size_t) offset;

    err = gcm_siv_doFinal(ctx, input.critical, (size_t) theEndDataSize, dest, &written);

    exit:
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

    return (jint) gcm_siv_get_output_size(ctx->encryption, (size_t) len);
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

    return (jint) gcm_siv_get_output_size(ctx->encryption, (size_t) len);
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

