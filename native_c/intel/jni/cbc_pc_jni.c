#include "org_bouncycastle_crypto_engines_AESNativeCBCPacketCipher.h"
#include "../packet/packet_utils.h"
#include "../packet/cbc_pc/cbc_pc.h"
#include "../../jniutil/exceptions.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/jni_asserts.h"
#include <stdlib.h>


void handle_cbc_pc_result(JNIEnv *env, packet_err *err) {
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
            throw_java_invalid_state(env, "unknown error from cbc");
            break;
    }
    packet_err_free(err);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBCPacketCipher
 * Method:    processPacket
 * Signature: (Z[BI[BI[BII[BII[BII)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBCPacketCipher_processPacket
        (JNIEnv *env, jclass, jboolean encryption, jbyteArray key_, jint keyLen, jbyteArray nonce_, jint nonLen,
         jbyteArray in, jint inOff, jint inLen, jbyteArray out, jint outOff,
         jint outLen) {
    java_bytearray_ctx key, iv, ad;
    critical_bytearray_ctx input, output;
    packet_err *err = NULL;
    init_critical_ctx(&input, env, in);
    init_critical_ctx(&output, env, out);

    init_bytearray_ctx(&key);
    init_bytearray_ctx(&iv);
    init_bytearray_ctx(&ad);

    if (!load_bytearray_ctx(&key, env, key_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid key array");
        goto exit;
    }

    if (!load_bytearray_ctx(&iv, env, nonce_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid iv array");
        goto exit;
    }


    if (!aes_keysize_is_valid_and_not_null(env, &key)) {
        goto exit;
    }

    if (!ivlen_is_16_and_not_null(env, &iv)) {
        goto exit;
    }


    if (in == NULL) {
        throw_java_illegal_argument(env, EM_INPUT_NULL);
        goto exit;
    }

    if (inOff < 0) {
        throw_java_illegal_argument(env, EM_INPUT_OFFSET_NEGATIVE);
        goto exit;
    }

    if (inLen < 0) {
        throw_java_illegal_argument(env, EM_LEN_NEGATIVE);
        goto exit;
    }

    if (!check_range(input.size, (size_t) inOff, (size_t) inLen)) {
        throw_bc_data_length_exception(env, EM_INPUT_LENGTH);
        goto exit;
    }

    if (encryption != JNI_TRUE && (inLen & 15)) {
        throw_bc_data_length_exception(env, EM_AES_DECRYPTION_INPUT_LENGTH_INVALID);
        goto exit;
    }

    if (out == NULL) {
        throw_java_illegal_argument(env, EM_OUTPUT_NULL);
        goto exit;
    }

    if (outOff < 0) {
        throw_java_illegal_argument(env, EM_OUTPUT_OFFSET_NEGATIVE);
        goto exit;
    }

    if (!check_range(output.size, (size_t) outOff, (size_t) (((inLen >> 4) << 4) + (inLen & 15 ? 16 : 0)))) {
        throw_bc_data_length_exception(env, EM_OUTPUT_LENGTH);
        goto exit;
    }

    if (outOff > output.size) {
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
    err = cbc_pc_process_packet(
            encryption == JNI_TRUE,
            key.bytearray,
            (size_t) keyLen,
            iv.bytearray,
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
    handle_cbc_pc_result(env, err);
    return (jint) outputLen;
}


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBCPacketCipher
 * Method:    getOutputSize
 * Signature: (ZII)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBCPacketCipher_getOutputSize
        (JNIEnv *env, jclass, jboolean encryption, jint len) {
    if (len < 0) {
        throw_java_illegal_argument(env, EM_LEN_NEGATIVE);
        return 0;
    }
    int result = get_output_size(encryption == JNI_TRUE, (int) len);
    if (result < 0) {
        throw_bc_data_length_exception(env, EM_OUTPUT_LENGTH);
    }
    return result;
}