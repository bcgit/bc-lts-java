#include "org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine.h"
#include "../../jniutil/bytearraycritical.h"
#include "../../jniutil/jni_asserts.h"
#include "jni.h"
#include "jni_md.h"
#include "../slhdsa/slhdsa_sha256.h"
#include "memory.h"

/*
 * Class:     org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine
 * Method:    initMemoStates
 * Signature: (J[B[BII)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine_initMemoStates
        (JNIEnv *env, jclass cl, jlong ref, jbyteArray _seed, jbyteArray _padding, jint pad1Len, jint pad2Len) {
    slhdsa_sha256 *ctx = (slhdsa_sha256 *) ((void *) ref);

    critical_bytearray_ctx seed, padding;
    init_critical_ctx(&seed, env, _seed);
    init_critical_ctx(&padding, env, _padding);

    if (!critical_not_null(&seed, "seed was null", env)) {
        goto exit;
    }

    if (!critical_offset_and_len_are_in_range_with_messages(
            &padding,
            0,
            pad1Len, env,
            "padding is null",
            "offset negative",
            "pad1Len is negative",
            "padding too short")) {
        goto exit;
    }

    if (!critical_offset_and_len_are_in_range_with_messages(
            &padding,
            0,
            pad2Len, env,
            "padding is null",
            "offset negative",
            "pad2Len is negative",
            "padding too short")) {
        goto exit;
    }


    // Attempt to obtain pointer to seed
    if (!load_critical_ctx(&seed)) {
        throw_java_invalid_state(env, "unable to obtain ptr seed array");
        goto exit;
    }

    // Attempt to obtain pointer to padding
    if (!load_critical_ctx(&padding)) {
        release_critical_ctx(&seed); // seed MUST be released before exception is allocated
        throw_java_invalid_state(env, "unable to obtain ptr padding array");
        goto exit;
    }

    // pad1Len and pad2Len asserted not negative by this point.
    slhdsa_sha256_init_memos(
            ctx,
            seed.critical,
            seed.size,
            padding.critical,
            (size_t) pad1Len,
            (size_t) pad2Len);

    exit:
    release_critical_ctx(&seed);
    release_critical_ctx(&padding);

}

/*
 * Class:     org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine
 * Method:    sha256DigestAndReturnRange
 * Signature: (JZ[B[B[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine_sha256DigestAndReturnRange
        (
                JNIEnv *env,
                jclass cl,
                jlong ref,
                jboolean use_memo,
                jbyteArray _output,
                jbyteArray _range,
                jbyteArray _in0,
                jbyteArray _in1,
                jbyteArray _in2,
                jbyteArray _in3) {

    slhdsa_sha256 *ctx = (slhdsa_sha256 *) ((void *) ref);


    if (use_memo == JNI_TRUE) {
        // Restore sha256Digest from memo
        memcpy(&ctx->sha256Digest, &ctx->sha256Memo, sizeof(sha256_ctx));
    }


    critical_bytearray_ctx output, range, in0, in1, in2, in3;

    init_critical_ctx(&output, env, _output);
    init_critical_ctx(&range, env, _range);
    init_critical_ctx(&in0, env, _in0);
    init_critical_ctx(&in1, env, _in1);
    init_critical_ctx(&in2, env, _in2);
    init_critical_ctx(&in3, env, _in3);


    if (output.array != NULL) {
        // Assert output array long enough
        if (output.size < SHA256_SIZE) {
            throw_java_illegal_argument(env, "output array too short");
            goto exit;
        }
        // Attempt to obtain pointer to output
        if (!load_critical_ctx(&output)) {
            throw_java_invalid_state(env, "unable to obtain ptr output array");
            goto exit;
        }
    }

    if (range.array != NULL) {
        if (!load_critical_ctx(&range)) {
            release_critical_ctx(&output);
            throw_java_invalid_state(env, "unable to obtain ptr range array");
            goto exit;
        }
    }


    if (in0.array != NULL) {

        // Attempt to obtain pointer to output
        if (!load_critical_ctx(&in0)) {

            release_critical_ctx(&output);
            release_critical_ctx(&range);

            throw_java_invalid_state(env, "unable to obtain ptr in0 array");
            goto exit;
        }
    }

    if (in1.array != NULL) {
        // Attempt to obtain pointer to output
        if (!load_critical_ctx(&in1)) {
            release_critical_ctx(&output);
            release_critical_ctx(&range);
            release_critical_ctx(&in0);
            throw_java_invalid_state(env, "unable to obtain ptr in1 array");
            goto exit;
        }
    }

    if (in2.array != NULL) {
        // Attempt to obtain pointer to output
        if (!load_critical_ctx(&in2)) {
            release_critical_ctx(&output);
            release_critical_ctx(&range);
            release_critical_ctx(&in0);
            release_critical_ctx(&in1);

            throw_java_invalid_state(env, "unable to obtain ptr in2 array");
            goto exit;
        }
    }

    if (in3.array != NULL) {
        // Attempt to obtain pointer to output
        if (!load_critical_ctx(&in3)) {
            release_critical_ctx(&output);
            release_critical_ctx(&range);
            release_critical_ctx(&in0);
            release_critical_ctx(&in1);
            release_critical_ctx(&in2);

            throw_java_invalid_state(env, "unable to obtain ptr in3 array");
            goto exit;
        }
    }

    uint8_t dig[SHA256_SIZE];

    // Working digest either points to a local or the output if output is defined.
    uint8_t *workingDigestOut = NULL;
    bool clear_local = false;

    if (output.array != NULL) {
        // output len asserted as long enough by this point.
        workingDigestOut = output.critical;
    } else {
        workingDigestOut = dig;
        clear_local = true;
    }

    slhdsa_sha256_sha256_digest(ctx,
                                workingDigestOut,
                                in0.critical, in0.size,
                                in1.critical, in1.size,
                                in2.critical, in2.size,
                                in3.critical, in3.size);


    //
    // Populate range array
    //
    if (range.array != NULL) {
        // Limit it to SHA256_SIZE
        memcpy(range.critical, workingDigestOut, range.size < SHA256_SIZE ? range.size : SHA256_SIZE);
    }

    if (clear_local) {
        memzero(dig, 32);
    }

    exit:
    release_critical_ctx(&output);
    release_critical_ctx(&range);
    release_critical_ctx(&in0);
    release_critical_ctx(&in1);
    release_critical_ctx(&in2);
    release_critical_ctx(&in3);

    return _range;
}

/*
 * Class:     org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine
 * Method:    msgDigestAndReturnRange
 * Signature: (JZ[B[B[B[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine_msgDigestAndReturnRange
        (
                JNIEnv *env,
                jclass cl,
                jlong ref,
                jboolean use_memo,
                jbyteArray _output,
                jbyteArray _range,
                jbyteArray _in0,
                jbyteArray _in1,
                jbyteArray _in2,
                jbyteArray _in3,
                jbyteArray _in4) {

    slhdsa_sha256 *ctx = (slhdsa_sha256 *) ((void *) ref);

    if (use_memo == JNI_TRUE) {
        memcpy(&ctx->msgDigest, &ctx->msgMemo, sizeof(sha256_ctx));
    }


    critical_bytearray_ctx output, range, in0, in1, in2, in3, in4;

    init_critical_ctx(&output, env, _output);
    init_critical_ctx(&range, env, _range);
    init_critical_ctx(&in0, env, _in0);
    init_critical_ctx(&in1, env, _in1);
    init_critical_ctx(&in2, env, _in2);
    init_critical_ctx(&in3, env, _in3);
    init_critical_ctx(&in4, env, _in4);


    if (output.array != NULL) {

        if (output.size < SHA256_SIZE) {
            throw_java_illegal_argument(env, "output array too short");
            goto exit;
        }

        if (!load_critical_ctx(&output)) {
            throw_java_invalid_state(env, "unable to obtain ptr output array");
            goto exit;
        }
    }

    if (range.array != NULL) {
        if (!load_critical_ctx(&range)) {
            release_critical_ctx(&output);
            throw_java_invalid_state(env, "unable to obtain ptr range array");
            goto exit;
        }
    }


    if (in0.array != NULL) {
        if (!load_critical_ctx(&in0)) {
            release_critical_ctx(&output);
            release_critical_ctx(&range);
            throw_java_invalid_state(env, "unable to obtain ptr in0 array");
            goto exit;
        }
    }

    if (in1.array != NULL) {
        if (!load_critical_ctx(&in1)) {
            release_critical_ctx(&output);
            release_critical_ctx(&range);
            release_critical_ctx(&in0);
            throw_java_invalid_state(env, "unable to obtain ptr in1 array");
            goto exit;
        }
    }

    if (in2.array != NULL) {
        if (!load_critical_ctx(&in2)) {
            release_critical_ctx(&output);
            release_critical_ctx(&range);
            release_critical_ctx(&in0);
            release_critical_ctx(&in1);

            throw_java_invalid_state(env, "unable to obtain ptr in2 array");
            goto exit;
        }
    }

    if (in3.array != NULL) {
        if (!load_critical_ctx(&in3)) {
            release_critical_ctx(&output);
            release_critical_ctx(&range);
            release_critical_ctx(&in0);
            release_critical_ctx(&in1);
            release_critical_ctx(&in2);
            throw_java_invalid_state(env, "unable to obtain ptr in3 array");
            goto exit;
        }
    }


    if (in4.array != NULL) {
        if (!load_critical_ctx(&in4)) {
            release_critical_ctx(&output);
            release_critical_ctx(&range);
            release_critical_ctx(&in0);
            release_critical_ctx(&in1);
            release_critical_ctx(&in2);
            release_critical_ctx(&in3);
            throw_java_invalid_state(env, "unable to obtain ptr in4 array");
            goto exit;
        }
    }


    uint8_t dig[SHA256_SIZE];

// Working digest either points to a local or the output if output is defined.
    uint8_t *workingDigestOut = NULL;
    bool clear_local = false;
    if (output.array != NULL) {
        // output len asserted as long enough by this point.
        workingDigestOut = output.critical;
    } else {
        workingDigestOut = dig;
        clear_local = true;
    }

    slhdsa_sha256_msgDigest_digest(ctx,
                                   workingDigestOut,
                                   in0.critical, in0.size,
                                   in1.critical, in1.size,
                                   in2.critical, in2.size,
                                   in3.critical, in3.size,
                                   in4.critical, in4.size
    );


    //
    // Populate range array
    //
    //
    // Populate range array
    //
    if (range.array != NULL) {
        // Limit it to SHA256_SIZE
        memcpy(range.critical, workingDigestOut, range.size < SHA256_SIZE ? range.size : SHA256_SIZE);
    }

    if (clear_local) {
        memzero(dig, 32);
    }

    exit:
    release_critical_ctx(&output);
    release_critical_ctx(&range);
    release_critical_ctx(&in0);
    release_critical_ctx(&in1);
    release_critical_ctx(&in2);
    release_critical_ctx(&in3);
    release_critical_ctx(&in4);
    return _range;
}


/*
 * Class:     org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine
 * Method:    bitmask
 * Signature: (J[B[B[B[B[B[B)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine_bitmask
        (
                JNIEnv *env,
                jclass cl,
                jlong ref,
                jbyteArray _key,
                jbyteArray _result,
                jbyteArray _in0,
                jbyteArray _in1,
                jbyteArray _in2,
                jbyteArray _in3) {

    slhdsa_sha256 *ctx = (slhdsa_sha256 *) ((void *) ref);

    critical_bytearray_ctx key, result, in0, in1, in2, in3;

    init_critical_ctx(&key, env, _key);
    init_critical_ctx(&result, env, _result);
    init_critical_ctx(&in0, env, _in0);
    init_critical_ctx(&in1, env, _in1);
    init_critical_ctx(&in2, env, _in2);
    init_critical_ctx(&in3, env, _in3);


    if (!critical_not_null(&key, "key is null", env)) {
        goto exit;
    }

    if (key.size < 48) {
        throw_java_illegal_argument(env, "key less than 48 bytes");
        goto exit;
    }


    if (!critical_not_null(&result, "result is null", env)) {
        goto exit;
    }

    size_t expected_len = in0.size + in1.size + in2.size + in3.size;
    if (result.size < expected_len) {
        throw_java_illegal_argument(env, "result array too small");
        goto exit;
    }


    // Attempt to obtain pointer to key
    if (!load_critical_ctx(&key)) {
        throw_java_invalid_state(env, "unable to obtain ptr key array");
        goto exit;
    }



    // Attempt to obtain pointer to output
    if (!load_critical_ctx(&result)) {
        release_critical_ctx(&key);
        throw_java_invalid_state(env, "unable to obtain ptr output array");
        goto exit;
    }


    if (in0.array != NULL) {

        // Attempt to obtain pointer to output
        if (!load_critical_ctx(&in0)) {
            release_critical_ctx(&key);
            release_critical_ctx(&result);
            throw_java_invalid_state(env, "unable to obtain ptr in0 array");
            goto exit;
        }
    }

    if (in1.array != NULL) {
        // Attempt to obtain pointer to output
        if (!load_critical_ctx(&in1)) {
            release_critical_ctx(&key);
            release_critical_ctx(&result);
            release_critical_ctx(&in0);
            throw_java_invalid_state(env, "unable to obtain ptr in1 array");
            goto exit;
        }
    }

    if (in2.array != NULL) {
        // Attempt to obtain pointer to output
        if (!load_critical_ctx(&in2)) {
            release_critical_ctx(&key);
            release_critical_ctx(&result);
            release_critical_ctx(&in0);
            release_critical_ctx(&in1);
            throw_java_invalid_state(env, "unable to obtain ptr in2 array");
            goto exit;
        }
    }

    if (in3.array != NULL) {
        // Attempt to obtain pointer to output
        if (!load_critical_ctx(&in3)) {
            release_critical_ctx(&key);
            release_critical_ctx(&result);
            release_critical_ctx(&in0);
            release_critical_ctx(&in1);
            release_critical_ctx(&in2);
            throw_java_invalid_state(env, "unable to obtain ptr in3 array");
            goto exit;
        }
    }

    slhdsa_sha256_mgf256_mask(ctx,
                              key.critical, key.size,
                              result.critical,
                              in0.critical, in0.size,
                              in1.critical, in1.size,
                              in2.critical, in2.size,
                              in3.critical, in3.size
    );


    exit:
    release_critical_ctx(&key);
    release_critical_ctx(&result);
    release_critical_ctx(&in0);
    release_critical_ctx(&in1);
    release_critical_ctx(&in2);
    release_critical_ctx(&in3);
}




/*
 * Class:     org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine
 * Method:    makeInstance
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine_makeInstance
        (JNIEnv *env, jclass cl) {
    return (jlong) slhdsa_sha256_create_ctx();
}

/*
 * Class:     org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine
 * Method:    dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_pqc_crypto_slhdsa_SLHDSASha2NativeEngine_dispose
        (JNIEnv *env, jclass cl, jlong ref) {
    slhdsa_sha256 *ctx = (slhdsa_sha256 *) ((void *) ref);
    slhdsa_sha256_free_ctx(ctx);
}