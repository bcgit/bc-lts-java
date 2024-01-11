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


JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBCPacketCipher_processPacket
        (JNIEnv *env, jclass, jboolean encryption, jbyteArray key_,  jbyteArray nonce_,
         jbyteArray in, jint inOff, jint inLen, jbyteArray out, jint outOff, jint outLen) {

    java_bytearray_ctx key, iv;
    critical_bytearray_ctx input, output;
    packet_err *err = NULL;
    init_critical_ctx(&input, env, in);
    init_critical_ctx(&output, env, out);

    init_bytearray_ctx(&key);
    init_bytearray_ctx(&iv);


    if (!load_bytearray_ctx(&key, env, key_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid array");
        goto exit;
    }

    if (!aes_keysize_is_valid_and_not_null(env, &key)) {
        goto exit;
    }

    if (!load_bytearray_ctx(&iv, env, nonce_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid array");
        goto exit;
    }

    if (!ivlen_is_16_and_not_null(env, &iv)) {
        goto exit;
    }


    //
    // Check input array with offset and len
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
    // Input len must be multiple of block size.
    //
    if (inLen % BLOCK_SIZE != 0) {
        throw_bc_data_length_exception(env, BLOCK_CIPHER_16_INPUT_LENGTH_INVALID);
        goto exit;
    }

    //
    // Check output array with offset and len
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

    // Assert that input can be processed into output
    // array size assertions for both arrays with respect to offset and length
    // have been applied by this point
    if (outLen < inLen) {
        throw_java_invalid_state(env, EM_OUTPUT_LENGTH);
        goto exit;
    }


    //
    // Load the critical arrays
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

    // keyLen, and inLen, inOff and outOff have been asserted not negative

    uint8_t *p_in = input.critical + inOff;
    uint8_t *p_out = output.critical + outOff;
    size_t outputLen = 0;
    err = cbc_pc_process_packet(
            encryption == JNI_TRUE,
            key.bytearray,
            (size_t) key.size,
            iv.bytearray,
            p_in,
            (size_t) inLen,
            p_out,
            &outputLen);
    exit:
    release_bytearray_ctx(&key);
    release_bytearray_ctx(&iv);
    release_critical_ctx(&input);
    release_critical_ctx(&output);
    handle_cbc_pc_result(env, err);
    return (jint) outputLen;
}



JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBCPacketCipher_getOutputSize
        (JNIEnv *env, jclass, jint len) {
    if (len < 0) {
        throw_java_illegal_argument(env, EM_INPUT_LEN_NEGATIVE);
        return -1;
    }
    int result = get_output_size((int) len);
    if (result < 0) {
        throw_java_illegal_argument(env, BLOCK_CIPHER_16_INPUT_LENGTH_INVALID);
        return -1;
    }
    return result;
}