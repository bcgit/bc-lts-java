//
//


#include "org_bouncycastle_crypto_digests_SHAKENativeDigest.h"
#include "../sha/shake.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/bytearraycritical.h"
#include "../../jniutil/jni_asserts.h"
#include "../util/util.h"


/*
 * Class:     org_bouncycastle_crypto_digestsSHAKENativeDigest
 * Method:    makeNative
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_digests_SHAKENativeDigest_makeNative
        (JNIEnv *enc, jclass cl, jint bitLen) {

    switch (bitLen) {
        case 128:
        case 256:
            break;
        default:
            throw_java_illegal_argument(enc, "only 128, 256 bit lengths are supported for SHAKE");
            return 0;
    }

    shake_ctx *sha = shake_create_ctx(bitLen);
    bc_assert(sha != NULL);
    return (jlong) sha;
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA512NativeDigest
 * Method:    destroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHAKENativeDigest_destroy
        (JNIEnv *env, jclass cl, jlong ref) {
    shake_free_ctx((shake_ctx *) ((void *) ref));
}

/*
 * Class:     org_bouncycastle_crypto_digestsSHAKENativeDigest
 * Method:    getDigestSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHAKENativeDigest_getDigestSize
        (JNIEnv *env, jclass cl, jlong ref) {
    shake_ctx *sha = (shake_ctx *) ((void *) ref);
    bc_assert(sha != NULL);
    return (jint) shake_getSize(sha);

}

/*
 * Class:     org_bouncycastle_crypto_digestsSHAKENativeDigest
 * Method:    update
 * Signature: (JB)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHAKENativeDigest_update__JB
        (JNIEnv *env, jclass cl, jlong ref, jbyte b) {
    shake_ctx *sha = (shake_ctx *) ((void *) ref);
    bc_assert(sha != NULL);
    if (sha->squeezing) {
        throw_java_invalid_state(env, "attempt to absorb while squeezing");
        return;
    }
    shake_update_byte(sha, (uint8_t) b);
}

/*
 * Class:     org_bouncycastle_crypto_digestsSHAKENativeDigest
 * Method:    update
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHAKENativeDigest_update__J_3BII
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray array, jint inOff, jint len) {

    shake_ctx *sha = (shake_ctx *) ((void *) ref);
    bc_assert(sha != NULL);

    critical_bytearray_ctx input;
    init_critical_ctx(&input, env, array);

    uint8_t *start;

    if (sha->squeezing) {
        throw_java_invalid_state(env, "attempt to absorb while squeezing");
        goto exit;
    }


    if (!critical_not_null(&input, "input was null", env)) {
        goto exit;
    }

    // Does length and negative inputs assertions
    if (!critical_offset_and_len_are_in_range(&input, inOff, len, env)) {
        goto exit;
    }

    if (!load_critical_ctx(&input)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid input array");
        goto exit;
    }


    start = input.critical + inOff;
    shake_update(sha, start, (size_t) len);


    exit:
    release_critical_ctx(&input);

}

/*
 * Class:     org_bouncycastle_crypto_digests_SHAKENativeDigest
 * Method:    doFinal
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHAKENativeDigest_doFinal__J_3BI
        (JNIEnv *env, jclass cl, jlong ref, jbyteArray array, jint offset) {

    shake_ctx *sha = (shake_ctx *) ((void *) ref);
    bc_assert(sha != NULL);

    java_bytearray_ctx out;
    init_bytearray_ctx(&out);

    const int32_t len = (int32_t)shake_getSize(sha);

    if (!load_bytearray_ctx(&out, env, array)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid output array");
        goto exit;
    }

    if (!bytearray_offset_and_len_are_in_range_not_null_msgs(
            &out,
            offset,
            len,
            env,
            "output was null",
            "output offset negative",
            "output len is negative",
            "array + offset too short for digest output")) {
        goto exit;
    }

    shake_digest(sha, out.bytearray + offset, (size_t) len);

    exit:
    release_bytearray_ctx(&out);

    return (jint) len;
}



/*
 * Class:     org_bouncycastle_crypto_digests_SHAKENativeDigest
 * Method:    doFinal
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHAKENativeDigest_doFinal__J_3BII(
        JNIEnv *env, jclass jc, jlong ref, jbyteArray array, jint offset, jint len) {

    shake_ctx *sha = (shake_ctx *) ((void *) ref);
    bc_assert(sha != NULL);

    java_bytearray_ctx out;
    init_bytearray_ctx(&out);

    if (!load_bytearray_ctx(&out, env, array)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid output array");
        goto exit;
    }

    if (!bytearray_offset_and_len_are_in_range_not_null_msgs(
            &out,
            offset,
            len,
            env,
            "output was null",
            "output offset negative",
            "output len is negative",
            "array + offset too short for digest output")) {
        goto exit;
    }


    shake_digest(sha, out.bytearray + offset, (size_t) len);

    exit:
    release_bytearray_ctx(&out);

    return (jint) len;
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHAKENativeDigest
 * Method:    doOutput
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHAKENativeDigest_doOutput
        (JNIEnv *env, jclass cl, jlong ref, jbyteArray array, jint offset, jint len) {

    shake_ctx *sha = (shake_ctx *) ((void *) ref);
    bc_assert(sha != NULL);

    java_bytearray_ctx out;
    init_bytearray_ctx(&out);

    if (!load_bytearray_ctx(&out, env, array)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid output array");
        goto exit;
    }

    if (!bytearray_offset_and_len_are_in_range_not_null_msgs(
            &out,
            offset,
            len,
            env,
            "output was null",
            "output offset negative",
            "output len is negative",
            "array + offset too short for digest output")) {
        goto exit;
    }

    shake_squeeze(sha, out.bytearray + offset, (size_t) len);

    exit:
    release_bytearray_ctx(&out);

    return (jint) len;

}



/*
 * Class:     org_bouncycastle_crypto_digests_SHAKENativeDigest
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHAKENativeDigest_reset
        (JNIEnv *enc, jclass jc, jlong ref) {
    shake_ctx *sha = (shake_ctx *) ((void *) ref);
    bc_assert(sha != NULL);
    shake_reset(sha);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHAKENativeDigest
 * Method:    getByteLength
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHAKENativeDigest_getByteLength
        (JNIEnv *env, jclass jc, jlong ref) {
    shake_ctx *sha = (shake_ctx *) ((void *) ref);
    bc_assert(sha != NULL);
    return (jint) shake_getByteLen(sha);

}

/*
 * Class:     org_bouncycastle_crypto_digests_SHAKENativeDigest
 * Method:    sha512_encodeFullState
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHAKENativeDigest_encodeFullState
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray array, jint offset) {


    if (array == NULL) {
        return sizeof(shake_ctx);
    }

    shake_ctx *sha = (shake_ctx *) ((void *) ref);
    bc_assert(sha != NULL);

    size_t size = sizeof(shake_ctx);

    java_bytearray_ctx out;
    init_bytearray_ctx(&out);


    if (!load_bytearray_ctx(&out, env, array)) {
        throw_java_invalid_state(env, "unable to obtain ptr to output array");
        goto exit;
    }


    if (!bytearray_not_null(&out, "output was null", env)) {
        goto exit;
    }


    if (!bytearray_offset_is_in_range(&out, offset, env)) {
        goto exit;
    }

    size_t remaining = out.size - (size_t) offset;
    if (remaining < size) {
        throw_java_illegal_argument(env, "array at offset too short for encoded output");
        goto exit;
    }

    shake_encodeFullState(sha, out.bytearray + offset);

    exit:
    release_bytearray_ctx(&out);

    return sizeof(shake_ctx);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHAKENativeDigest
 * Method:    sha512_restoreFullState
 * Signature: (J[BI)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHAKENativeDigest_restoreFullState
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray in, jint offset) {

    shake_ctx *sha = (shake_ctx *) ((void *) ref);
    bc_assert(sha != NULL);
    java_bytearray_ctx input;
    init_bytearray_ctx(&input);


    if (!load_bytearray_ctx(&input, env, in)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid input array");
        goto exit;
    }

    size_t remaining;

    // size of struct
    size_t size = sizeof(shake_ctx);


    if (!bytearray_not_null(&input, "input was null", env)) {
        goto exit;
    }


    // Basic array and offset assertions
    if (!bytearray_offset_is_in_range(&input, offset, env)) {
        goto exit;
    }

    remaining = input.size - (size_t) offset;
    if (remaining < size) {
        throw_java_illegal_argument(env, "array at offset too short for encoded input");
        goto exit;
    }


    if (!shake_restoreFullState(sha, input.bytearray + offset)) {
        throw_java_illegal_argument(env, "invalid shake encoded state");
    }

    exit:
    release_bytearray_ctx(&input);


}
