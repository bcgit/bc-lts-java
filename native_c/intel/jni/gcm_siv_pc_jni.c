#include "org_bouncycastle_crypto_engines_AESNativeGCMSIVPacketCipher.h"
#include "../packet/gcm_siv_pc/gcm_siv_pc.h"
#include "../../jniutil/exceptions.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/jni_asserts.h"


void handle_gcm_siv_pc_result(JNIEnv *env, packet_err *err) {
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

    packet_err_free(err);

}



/*
 * Class:     org_bouncycastle_crypto_engines_AESGCMSIVPacketCipher
 * Method:    doFinal
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIVPacketCipher_processPacket
        (JNIEnv *env, jclass,
         jboolean encryption,
         jbyteArray key_,
         jbyteArray nonce_,
         jbyteArray aad_,
         jbyteArray in, jint inOff, jint inLen,
         jbyteArray out, jint outOff, jint outLen) {

    packet_err *err = NULL;
    size_t outputLen = 0;
    java_bytearray_ctx key, iv, ad;
    critical_bytearray_ctx input, output;
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

    if (!aes_keysize_is_valid_and_not_null_not_24(env, &key)) {
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

    if (iv.size != 12) {
        throw_java_illegal_argument(env, "invalid nonce");
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


    int outputSize = get_aead_output_size(encryption == JNI_TRUE, inLen, BLOCK_SIZE);
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

    err = gcm_siv_pc_process_packet(
            encryption == JNI_TRUE,
            key.bytearray,
            (size_t) key.size,
            iv.bytearray,
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

    handle_gcm_siv_pc_result(env, err);
    return (jint) outputLen;
}



/*
 * Class:     org_bouncycastle_crypto_engines_AESGCMSIVPacketCipher
 * Method:    getOutputSize
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCMSIVPacketCipher_getOutputSize
        (JNIEnv *env, jclass, jboolean encryption, jint len) {
    if (len < 0) {
        throw_java_illegal_argument(env, EM_INPUT_LEN_NEGATIVE);
        return 0;
    }
    int result = get_aead_output_size(encryption == JNI_TRUE, (int) len, BLOCK_SIZE);
    if (result < 0) {
        throw_bc_data_length_exception(env, EM_INVALID_LEN);
        return -1;
    }
    return result;
}
