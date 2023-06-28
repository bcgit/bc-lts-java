

#include "org_bouncycastle_crypto_engines_AESNativeCCM.h"
#include "../ccm/ccm.h"
#include "../../jniutil/exceptions.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/jni_asserts.h"
#include <stdlib.h>


void handle_ccm_result(JNIEnv *env, ccm_err *err) {
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
            throw_java_invalid_state(env, "unknown error from ccm");
            break;
    }

    ccm_err_free(err);

}


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCCM
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCCM_reset
        (JNIEnv *, jobject, jlong ref, jboolean keepMac) {
    ccm_ctx *ctx = (ccm_ctx *) ref;
    ccm_reset(ctx, keepMac);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCCM
 * Method:    initNative
 * Signature: (JZ[B[B[BI)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCCM_initNative
        (JNIEnv *env, jclass, jlong ref, jboolean encryption, jbyteArray key_, jbyteArray iv_, jbyteArray ad_,
         jint adlen, jint macSizeInBits) {

    ccm_err *err = NULL;
    ccm_ctx *ctx = (ccm_ctx *) ref;
    java_bytearray_ctx key, iv, ad;

    init_bytearray_ctx(&key);
    init_bytearray_ctx(&iv);
    init_bytearray_ctx(&ad);


    if (encryption && (macSizeInBits < 32 || macSizeInBits > 128 || 0 != (macSizeInBits & 15))) {
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

    if (iv.size < 7 || iv.size > 13) {
        throw_java_illegal_argument(env, "nonce must have length from 7 to 13 octets");
        goto exit;
    }


    err = ccm_init(
            ctx,
            encryption == JNI_TRUE,
            key.bytearray,
            key.size,
            iv.bytearray,
            iv.size,
            ad.bytearray,
            (size_t) adlen,
            (uint32_t) macSizeInBits / 8);

    exit:
    release_bytearray_ctx(&key);
    release_bytearray_ctx(&iv);
    release_bytearray_ctx(&ad);
    handle_ccm_result(env, err);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCCM
 * Method:    makeInstance
 * Signature: (IZ)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCCM_makeInstance
        (JNIEnv *, jclass, jint, jboolean ignored) {
    ccm_ctx *ccm = ccm_create_ctx();
    return (jlong) ccm;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCCM
 * Method:    dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCCM_dispose
        (JNIEnv *, jclass, jlong ref) {
    ccm_ctx *ctx = (ccm_ctx *) ((void *) ref);
    ccm_free(ctx);
}


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCCM
 * Method:    getUpdateOutputSize
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCCM_getUpdateOutputSize
        (JNIEnv *env, jclass, jlong ref, jint len) {
    ccm_ctx *ctx = (ccm_ctx *) ((void *) ref);

    if (len < 0) {
        throw_java_illegal_argument(env, "len is negative");
        return 0;
    }

    return 0;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCCM
 * Method:    getOutputSize
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCCM_getOutputSize
        (JNIEnv *env, jclass, jlong ref, jint len) {

    ccm_ctx *ctx = (ccm_ctx *) ((void *) ref);

    if (len < 0) {
        throw_java_illegal_argument(env, "len is negative");
        return 0;
    }

    return (jint) ccm_get_output_size(ctx, (size_t) len);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCCM
 * Method:    getMac
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCCM_getMac
        (JNIEnv *env, jclass, jlong ref) {
    ccm_ctx *ctx = (ccm_ctx *) ((void *) ref);
    jbyteArray out = (*env)->NewByteArray(env, (jint) ctx->macBlockLenInBytes);
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
    ccm_getMac(ctx, out_ctx.bytearray);

    exit:
    release_bytearray_ctx(&out_ctx);
    return out;
}


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCCM
 * Method:    processPacket
 * Signature: (J[B[B[BI)V
 */
JNIEXPORT int JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCCM_processPacket
        (JNIEnv *env, jclass, jlong ref, jbyteArray in, jint inOff, jint inLen, jbyteArray aad_,
         jint aad_len, jbyteArray out, jint outOff) {
    ccm_err *err = NULL;
    size_t written = 0;
    ccm_ctx *ctx = (ccm_ctx *) ((void *) ref);
    critical_bytearray_ctx input, output, aad;

    init_critical_ctx(&input, env, in);
    init_critical_ctx(&output, env, out);
    init_critical_ctx(&aad, env, aad_);

    if (in == NULL) {
        throw_java_illegal_argument(env, "input was null");
        goto exit;
    }

    if (inOff < 0) {
        throw_java_illegal_argument(env, "input offset was negative");
        goto exit;
    }


    if (!check_range(input.size, (size_t) inOff, (size_t) inLen)) {
        throw_bc_data_length_exception(env, "input buffer too short");
        goto exit;
    }

    if (out == NULL) {
        throw_java_illegal_argument(env, "output was null");
        goto exit;
    }

    if (outOff < 0) {
        throw_java_illegal_argument(env, "output offset was negative");
        goto exit;
    }

    if (outOff > output.size) {
        throw_java_illegal_argument(env, "output buffer too short");
        goto exit;
    }


    if (aad.array != NULL) {
        // Check associated data array.
        if (aad_len < 0) {
            throw_java_illegal_argument(env, "aad length was negative");
            goto exit;
        }

        if (aad_len > aad.size) {
            throw_java_illegal_argument(env, "aad length past end of array");
            goto exit;
        }

    }

    if (aad.array == NULL && aad_len != 0) {
        throw_java_illegal_argument(env, "aad null but length not zero");
        goto exit;
    }


    //
    // Check we have enough space for the output.
    //
    size_t calculated_output_size = ccm_get_output_size(ctx, (size_t) inLen);

    //
    // Check we have enough space in the output.
    //
    if (calculated_output_size > output.size - (size_t) outOff) {
        throw_bc_output_length_exception(env, "output buffer too short");
        goto exit;
    }


    //
    // Load the contexts
    //
    if (!load_critical_ctx(&input)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid input array");
        goto exit;
    }

    if (!load_critical_ctx(&output)) {
        release_critical_ctx(&input);
        throw_java_invalid_state(env, "unable to obtain ptr to valid output array");
        goto exit;
    }

    if (!load_critical_ctx(&aad)) {
        release_critical_ctx(&output);
        release_critical_ctx(&input);
        throw_java_invalid_state(env, "unable to obtain ptr to valid aad array");
        goto exit;
    }


    uint8_t *p_in = input.critical + inOff;
    uint8_t *p_out = output.critical + outOff;

    ccm_process_aad_bytes(ctx, aad.critical, (size_t) aad_len);

    err = processPacket(ctx, p_in, (size_t) inLen, p_out, &written);

    exit:
    release_critical_ctx(&output);
    release_critical_ctx(&input);
    release_critical_ctx(&aad);

    handle_ccm_result(env, err);
    return (jint) written;
}