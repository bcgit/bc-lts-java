//
//

#include <assert.h>
#include "org_bouncycastle_crypto_digests_SHA224NativeDigest.h"
#include "../sha/sha224.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/bytearraycritical.h"
#include "../../jniutil/jni_asserts.h"

/*
 * Class:     org_bouncycastle_crypto_digests_SHA224NativeDigest
 * Method:    makeNative
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_digests_SHA224NativeDigest_makeNative
        (JNIEnv *env, jclass cl) {
    return (jlong) sha224_create_ctx();
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA224NativeDigest
 * Method:    destroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA224NativeDigest_destroy
        (JNIEnv *env, jclass cl, jlong ref) {

    sha224_free_ctx((sha224_ctx *) ((void *) ref));

}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA224NativeDigest
 * Method:    getDigestSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHA224NativeDigest_getDigestSize
        (JNIEnv *env, jclass cl, jlong ref) {
    sha224_ctx *sha = (sha224_ctx *) ((void *) ref);
    return (jint) sha224_getSize(sha);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA224NativeDigest
 * Method:    update
 * Signature: (JB)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA224NativeDigest_update__JB
        (JNIEnv *env, jclass cl, jlong ref, jbyte b) {
    sha224_ctx *sha = (sha224_ctx *) ((void *) ref);
    sha224_update_byte(sha, (uint8_t) b);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA224NativeDigest
 * Method:    update
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA224NativeDigest_update__J_3BII
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray array, jint inOff, jint len) {

    critical_bytearray_ctx input;
    init_critical_ctx(&input, env, array);

    sha224_ctx *sha = (sha224_ctx *) ((void *) ref);
    uint8_t *start;


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
    sha224_update(sha, start, (size_t) len);


    exit:
    release_critical_ctx(&input);

}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA224NativeDigest
 * Method:    doFinal
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHA224NativeDigest_doFinal
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray array, jint offset) {

    java_bytearray_ctx out;
    init_bytearray_ctx(&out);
    jint outLen = 0;

    sha224_ctx *sha = (sha224_ctx *) ((void *) ref);
    int64_t remaining;

    if (!load_bytearray_ctx(&out, env, array)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid output array");
        goto exit;
    }


    if (!bytearray_not_null(&out, "output was null", env)) {
        goto exit;
    }


    if (!bytearray_offset_is_in_range(&out, offset, env)) {
        goto exit;
    }

    remaining = (int64_t) out.size - (int64_t) offset;

    if (remaining < sha224_getSize(sha)) {
        throw_java_illegal_argument(env, "array + offset too short for digest output");
        goto exit;
    }

    sha224_digest(sha, out.bytearray + offset);
    outLen = SHA224_SIZE;

    exit:
    release_bytearray_ctx(&out);

    return outLen;

}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA224NativeDigest
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA224NativeDigest_reset
        (JNIEnv *enc, jclass jc, jlong ref) {
    sha224_ctx *sha = (sha224_ctx *) ((void *) ref);
    sha224_reset(sha);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA224NativeDigest
 * Method:    getByteLength
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHA224NativeDigest_getByteLength
        (JNIEnv *env, jclass jc, jlong ref) {
    sha224_ctx *sha = (sha224_ctx *) ((void *) ref);
    return (jint) sha224_getByteLen(sha);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA224NativeDigest
 * Method:    sha224_encodeFullState
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHA224NativeDigest_encodeFullState
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray array, jint offset) {


    if (array == NULL) {
        return sizeof(sha224_ctx);
    }

    sha224_ctx *sha = (sha224_ctx *) ((void *) ref);

    size_t size = sizeof(sha224_ctx);

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

    sha224_encodeFullState(sha, out.bytearray + offset);

    exit:
    release_bytearray_ctx(&out);

    return sizeof(sha224_ctx);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA224NativeDigest
 * Method:    sha224_restoreFullState
 * Signature: (J[BI)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA224NativeDigest_restoreFullState
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray in, jint offset) {

    sha224_ctx *sha = (sha224_ctx *) ((void *) ref);
    java_bytearray_ctx input;
    init_bytearray_ctx(&input);


    if (!load_bytearray_ctx(&input, env, in)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid input array");
        goto exit;
    }

    size_t remaining;

    // size of struct
    size_t size = sizeof(sha224_ctx);


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


    if (!sha224_restoreFullState(sha, input.bytearray + offset)) {
        throw_java_illegal_argument(env, "invalid sha224 encoded state");
    }

    exit:
    release_bytearray_ctx(&input);
}
