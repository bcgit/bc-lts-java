#include "org_bouncycastle_crypto_engines_AESNativeGCMPacketCipher.h"
#include "../packet/packet_utils.h"
#include "../packet/gcm_pc/gcm_pc.h"
#include "../../jniutil/exceptions.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/jni_asserts.h"
#include <stdlib.h>

void handle_gcm_pc_result(JNIEnv *env, packet_err *err) {
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
            throw_java_invalid_state(env, "unknown error from gcm");
            break;
    }
    packet_err_free(err);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMPacketCipher
 * Method:    processPacket
 * Signature: (Z[BI[BI[BII[BII[BII)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMPacketCipher_processPacket
        (JNIEnv *env, jclass, jboolean encryption, jbyteArray key_, jbyteArray nonce_,
         jbyteArray aad_, jint macSize, jbyteArray in, jint inOff, jint inLen, jbyteArray out, jint outOff,
         jint outLen) {
    java_bytearray_ctx key, iv, ad;
    critical_bytearray_ctx input, output;
    packet_err *err = NULL;
    size_t outputLen = 0;

    init_critical_ctx(&input, env, in);
    init_critical_ctx(&output, env, out);

    init_bytearray_ctx(&key);
    init_bytearray_ctx(&iv);
    init_bytearray_ctx(&ad);



    //
    // Load and check key
    //
    if (!load_bytearray_ctx(&key, env, key_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid key array");
        goto exit;
    }

    if (!aes_keysize_is_valid_and_not_null(env, &key)) {
        goto exit;
    }


    //
    // Load and check nonce.
    //
    if (!load_bytearray_ctx(&iv, env, nonce_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid iv array");
        goto exit;
    }

    if (!bytearray_not_null(&iv,"nonce is null",env)) {
        goto exit;
    }

    if (iv.size < 12) {
        throw_java_illegal_argument(env, "nonce must be at least 12 bytes");
        goto exit;
    }


    //
    // Load aad.
    //

    if (!load_bytearray_ctx(&ad, env, aad_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid ad array");
        goto exit;
    }


    //
    // Check input array with offset and outputSize
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
    // Check output array with offset and outputSize
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

    //
    // Assert mac len.
    //
    if (macSize < 4 || macSize > 16 ) {
        throw_java_invalid_state(env, EM_MACSIZE_INVALID);
        goto exit;
    }

    int outputSize = get_aead_output_size(encryption == JNI_TRUE, inLen, macSize);
    if (outputSize < 0) {
        // macLen < input len on decryption asserted here
        throw_java_illegal_argument(env, EM_INPUT_SHORT); // inlen < macSize
        goto exit;
    }
    if (outLen < outputSize) {
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

    err = gcm_pc_process_packet(
            encryption == JNI_TRUE,
            key.bytearray,
            (size_t) key.size,
            iv.bytearray,
            (size_t) iv.size,
            (size_t) macSize,
            ad.bytearray,
            (size_t) ad.size,
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
    handle_gcm_pc_result(env, err);
    return (jint) outputLen;
}


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeGCMPacketCipher
 * Method:    getOutputSize
 * Signature: (ZII)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMPacketCipher_getOutputSize
        (JNIEnv *env, jclass, jboolean encryption, jint len, jint macSize) {
    if (len < 0) {
        throw_java_illegal_argument(env, EM_INPUT_LEN_NEGATIVE);
        return -1;
    }

    if (macSize < 4 || macSize > 16) {
        throw_java_illegal_argument(env, EM_MACSIZE_INVALID);
        return -1;
    }

    int result = get_aead_output_size(encryption == JNI_TRUE, (int) len, (int) macSize);
    if (result < 0) {
        throw_bc_data_length_exception(env, EM_INVALID_LEN);
        return -1;
    }
    return result;
}