#include "org_bouncycastle_crypto_engines_AESNativeCFBPacketCipher.h"


#include "../../jniutil/bytearraycritical.h"
#include "../../jniutil/jni_asserts.h"
#include "../packet/cfb_pc/cfb_pc.h"
#include "../common.h"

void handle_cfb_pc_result(JNIEnv *env, packet_err *err) {
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
            throw_java_invalid_state(env, "unknown error from cfb");
            break;
    }
    packet_err_free(err);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCFBPacketCipher
 * Method:    processPacket
 * Signature: (Z[BI[BI[BII[BII[BII)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFBPacketCipher_processPacket
        (JNIEnv *env, jclass,
         jboolean encryption,
         jbyteArray key_, jint keyLen,
         jbyteArray nonce_, jint nonceLen,
         jbyteArray in, jint inOff, jint inLen,
         jbyteArray out, jint outOff, jint outLen) {

    java_bytearray_ctx key, iv, ad;
    critical_bytearray_ctx input, output;
    packet_err *err = NULL;
    init_critical_ctx(&input, env, in);
    init_critical_ctx(&output, env, out);

    init_bytearray_ctx(&key);
    init_bytearray_ctx(&iv);
    init_bytearray_ctx(&ad);

    //
    // Load and assert key length
    //

    if (!load_bytearray_ctx(&key, env, key_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid key array");
        goto exit;
    }


    if (!aes_keysize_is_valid_and_not_null_with_len(env, &key, keyLen)) {
        goto exit;
    }


    //
    // Load and assert IV len as 128bits
    //
    if (!load_bytearray_ctx(&iv, env, nonce_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid iv array");
        goto exit;
    }

    if (!ivlen_is_16_and_not_null_with_len(env,&iv,nonceLen)) {
        goto exit;
    }

    //
    // Check input array with offset and minOutputSize
    //
    if (!critical_offset_and_len_are_in_range_with_messages(
            &input,
            inOff,
            inLen,
            env,
            EM_INPUT_NULL,
            EM_INPUT_OFFSET_NEGATIVE,
            EM_INPUT_LEN_NEGATIVE,
            EM_INPUT_TOO_SHORT)) {
        goto exit;
    }


    //
    // Check output array with offset and minOutputSize
    //
    if (!critical_offset_and_len_are_in_range_with_messages(
            &output,
            outOff,
            outLen,
            env,
            EM_OUTPUT_NULL,
            EM_OUTPUT_OFFSET_NEGATIVE,
            EM_OUTPUT_LENGTH_NEGATIVE,
            EM_OUTPUT_TOO_SHORT)) {
        goto exit;
    }


    if (outLen < inLen) {
        throw_java_illegal_argument(env, EM_OUTPUT_LENGTH);
        goto exit;
    }


    //
    // Load the contexts
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


    uint8_t *p_in = input.critical + inOff;
    uint8_t *p_out = output.critical + outOff;
    size_t outputLen = 0;
    err = cfb_pc_process_packet(
            encryption == JNI_TRUE,
            key.bytearray,
            (size_t) keyLen,
            iv.bytearray,
            (size_t) nonceLen,
            p_in,
            (size_t) inLen,
            p_out,
            &outputLen);
    exit:
    release_bytearray_ctx(&key);
    release_bytearray_ctx(&iv);
    release_bytearray_ctx(&ad);
    release_critical_ctx(&input);
    release_critical_ctx(&output);
    handle_cfb_pc_result(env, err);
    return (jint) outputLen;
}


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCFBPacketCipher
 * Method:    getOutputSize
 * Signature: (ZII)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFBPacketCipher_getOutputSize
        (JNIEnv *env, jclass, jint len) {
    if (len < 0) {
        throw_java_illegal_argument(env, EM_INPUT_LEN_NEGATIVE);
        return 0;
    }
    return len;
}