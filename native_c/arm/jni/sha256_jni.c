//
//

#include <assert.h>
#include "org_bouncycastle_crypto_digests_SHA256NativeDigest.h"
#include "../sha/sha256.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/bytearraycritical.h"
#include "../../jniutil/jni_asserts.h"

/*
 * Class:     org_bouncycastle_crypto_digests_SHA256NativeDigest
 * Method:    makeNative
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_digests_SHA256NativeDigest_makeNative
        (JNIEnv *env, jclass cl) {
    return (jlong) sha256_create_ctx();
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA256NativeDigest
 * Method:    destroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA256NativeDigest_destroy
        (JNIEnv *env, jclass cl, jlong ref) {

    sha256_free_ctx((sha256_ctx *) ((void *) ref));

}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA256NativeDigest
 * Method:    getDigestSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHA256NativeDigest_getDigestSize
        (JNIEnv *env, jclass cl, jlong ref) {
    sha256_ctx *sha = (sha256_ctx *) ((void *) ref);
    return (jint) sha256_getSize(sha);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA256NativeDigest
 * Method:    update
 * Signature: (JB)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA256NativeDigest_update__JB
        (JNIEnv *env, jclass cl, jlong ref, jbyte b) {
    sha256_ctx *sha = (sha256_ctx *) ((void *) ref);
    sha256_update_byte(sha, (uint8_t) b);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA256NativeDigest
 * Method:    update
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA256NativeDigest_update__J_3BII
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray array, jint inOff, jint len) {

    critical_bytearray_ctx input;
    init_critical_ctx(&input, env, array);

    sha256_ctx *sha = (sha256_ctx *) ((void *) ref);
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
    sha256_update(sha, start, (size_t) len);


    exit:
    release_critical_ctx(&input);

}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA256NativeDigest
 * Method:    doFinal
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHA256NativeDigest_doFinal
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray array, jint offset) {

    java_bytearray_ctx out;
    init_bytearray_ctx(&out);


    sha256_ctx *sha = (sha256_ctx *) ((void *) ref);
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



    if (remaining < sha256_getSize(sha)) {
        throw_java_illegal_argument(env, "array + offset too short for digest output");
        goto exit;
    }

    sha256_digest(sha, out.bytearray + offset);


    exit:
    release_bytearray_ctx(&out);


    return (jint) sha256_getByteLen(sha);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA256NativeDigest
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA256NativeDigest_reset
        (JNIEnv *enc, jclass jc, jlong ref) {
    sha256_ctx *sha = (sha256_ctx *) ((void *) ref);
    sha256_reset(sha);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA256NativeDigest
 * Method:    getByteLength
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHA256NativeDigest_getByteLength
        (JNIEnv *env, jclass jc, jlong ref) {
    sha256_ctx *sha = (sha256_ctx *) ((void *) ref);
    return (jint) sha256_getByteLen(sha);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA256NativeDigest
 * Method:    sha256_encodeFullState
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHA256NativeDigest_encodeFullState
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray array, jint offset) {


    if (array == NULL) {
        return sizeof(sha256_ctx);
    }

    sha256_ctx *sha = (sha256_ctx *) ((void *) ref);

    size_t size = sizeof(sha256_ctx);

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

    size_t remaining =  out.size - (size_t)offset;
    if (remaining < size) {
        throw_java_illegal_argument(env, "array at offset too short for encoded output");
        goto exit;
    }

    sha256_encodeFullState(sha, out.bytearray + offset);

    exit:
    release_bytearray_ctx(&out);

    return sizeof(sha256_ctx);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA256NativeDigest
 * Method:    sha256_restoreFullState
 * Signature: (J[BI)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA256NativeDigest_restoreFullState
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray in, jint offset) {

    sha256_ctx *sha = (sha256_ctx *) ((void *) ref);
    java_bytearray_ctx input;
    init_bytearray_ctx(&input);


    if (!load_bytearray_ctx(&input, env, in)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid input array");
        goto exit;
    }

    size_t remaining;

    // size of struct
    size_t size = sizeof(sha256_ctx);


    if (!bytearray_not_null(&input, "input was null", env)) {
        goto exit;
    }


    // Basic array and offset assertions
    if (!bytearray_offset_is_in_range(&input, offset, env)) {
        goto exit;
    }

    remaining =  input.size - (size_t) offset;
    if (remaining < size) {
        throw_java_illegal_argument(env, "array at offset too short for encoded input");
        goto exit;
    }


    if (!sha256_restoreFullState(sha, input.bytearray + offset)) {
        throw_java_illegal_argument(env, "invalid sha256 encoded state");
    }

    exit:
    release_bytearray_ctx(&input);
}
