//
//


#include "org_bouncycastle_crypto_digests_SHA3NativeDigest.h"
#include "../sha/sha3.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/bytearraycritical.h"
#include "../../jniutil/jni_asserts.h"


/*
 * Class:     org_bouncycastle_crypto_digests_SHA3NativeDigest
 * Method:    makeNative
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_digests_SHA3NativeDigest_makeNative
        (JNIEnv *enc, jclass cl, jint bitLen) {

    switch (bitLen) {
        case 224:
        case 256:
        case 384:
        case 512:
            break;
        default:
            throw_java_illegal_argument(enc, "only 224, 256, 384 and 512 bit lengths are supported for SHA3");
            return 0;
    }

    return (jlong) sha3_create_ctx(bitLen);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA512NativeDigest
 * Method:    destroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA3NativeDigest_destroy
        (JNIEnv *env, jclass cl, jlong ref) {
    sha3_free_ctx((sha3_ctx *) ((void *) ref));
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA3NativeDigest
 * Method:    getDigestSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHA3NativeDigest_getDigestSize
        (JNIEnv *env, jclass cl, jlong ref) {
    sha3_ctx *sha = (sha3_ctx *) ((void *) ref);
    return (jint) sha3_getSize(sha);

}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA3NativeDigest
 * Method:    update
 * Signature: (JB)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA3NativeDigest_update__JB
        (JNIEnv *env, jclass cl, jlong ref, jbyte b) {
    sha3_ctx *sha = (sha3_ctx *) ((void *) ref);
    if (sha->squeezing) {
        throw_java_invalid_state(env, "attempt to absorb while squeezing");
        return;
    }
    sha3_update_byte(sha, (uint8_t) b);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA3NativeDigest
 * Method:    update
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA3NativeDigest_update__J_3BII
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray array, jint inOff, jint len) {

    critical_bytearray_ctx input;
    init_critical_ctx(&input, env, array);

    sha3_ctx *sha = (sha3_ctx *) ((void *) ref);
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
    sha3_update(sha, start, (size_t) len);


    exit:
    release_critical_ctx(&input);

}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA3NativeDigest
 * Method:    doFinal
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHA3NativeDigest_doFinal
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray array, jint offset) {

    java_bytearray_ctx out;
    init_bytearray_ctx(&out);
    jint outLen = 0;


    sha3_ctx *sha = (sha3_ctx *) ((void *) ref);
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


    if (remaining < sha3_getSize(sha)) {
        throw_java_illegal_argument(env, "array + offset too short for digest output");
        goto exit;
    }

    sha3_digest(sha, out.bytearray + offset);
    outLen = (jint) sha3_getSize(sha);

    exit:
    release_bytearray_ctx(&out);

    return (jint) outLen;
}





/*
 * Class:     org_bouncycastle_crypto_digests_SHA3NativeDigest
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA3NativeDigest_reset
        (JNIEnv *enc, jclass jc, jlong ref) {
    sha3_ctx *sha = (sha3_ctx *) ((void *) ref);
    sha3_reset(sha);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA3NativeDigest
 * Method:    getByteLength
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHA3NativeDigest_getByteLength
        (JNIEnv *env, jclass jc, jlong ref) {
    sha3_ctx *sha = (sha3_ctx *) ((void *) ref);
    return (jint) sha3_getByteLen(sha);

}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA3NativeDigest
 * Method:    sha512_encodeFullState
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_SHA3NativeDigest_encodeFullState
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray array, jint offset) {


    if (array == NULL) {
        return sizeof(sha3_ctx);
    }

    sha3_ctx *sha = (sha3_ctx *) ((void *) ref);

    size_t size = sizeof(sha3_ctx);

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

    sha3_encodeFullState(sha, out.bytearray + offset);

    exit:
    release_bytearray_ctx(&out);

    return sizeof(sha3_ctx);
}

/*
 * Class:     org_bouncycastle_crypto_digests_SHA3NativeDigest
 * Method:    sha512_restoreFullState
 * Signature: (J[BI)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_SHA3NativeDigest_restoreFullState
        (JNIEnv *env, jclass jc, jlong ref, jbyteArray in, jint offset) {

    sha3_ctx *sha = (sha3_ctx *) ((void *) ref);
    java_bytearray_ctx input;
    init_bytearray_ctx(&input);


    if (!load_bytearray_ctx(&input, env, in)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid input array");
        goto exit;
    }

    size_t remaining;

    // size of struct
    size_t size = sizeof(sha3_ctx);


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


    if (!sha3_restoreFullState(sha, input.bytearray + offset)) {
        throw_java_illegal_argument(env, "invalid sha3 encoded state");
    }

    exit:
    release_bytearray_ctx(&input);


}
