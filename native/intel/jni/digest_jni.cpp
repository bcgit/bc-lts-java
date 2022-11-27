
//
// Created  on 27/6/2022.
//

#include <exception>
#include <jni.h>
#include "../digest/Digest.h"
#include "../../jniutil/JavaByteArray.h"
#include "../../jniutil/JavaEnvUtils.h"
#include "../digest/SHA256.h"
#include "org_bouncycastle_crypto_digests_NativeDigest.h"

/*
 * Class:     org_bouncycastle_crypto_fips_NativeDigest
 * Method:    makeNative
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_digests_NativeDigest_makeNative
        (JNIEnv *env, jobject, jint type) {

    intel::digest::Digest *ptr;

    switch (type) {
        case 1:
            ptr = new intel::digest::Sha256();
            break;
        default:
            jniutil::JavaEnvUtils::throwIllegalArgumentException(env, "unknown digest type");
    }

    return (jlong) ptr;

}

/*
 * Class:     org_bouncycastle_crypto_fips_NativeDigest
 * Method:    destroyNative
 * Signature: (IJ)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_NativeDigest_destroy
        (JNIEnv *, jobject, jlong ref) {

    auto ptr = static_cast<intel::digest::Digest *>((void *) ref);
    delete ptr;
}

/*
 * Class:     org_bouncycastle_crypto_fips_NativeDigest
 * Method:    getDigestSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_NativeDigest_getDigestSize
        (JNIEnv *, jobject, jlong ref) {
    auto ptr = static_cast<intel::digest::Digest *>((void *) ref);
    return ptr->getDigestSize();
}

/*
 * Class:     org_bouncycastle_crypto_fips_NativeDigest
 * Method:    update
 * Signature: (JB)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_NativeDigest_update__JB
        (JNIEnv *, jobject, jlong ref, jbyte b) {

    auto ptr = static_cast<intel::digest::Digest *>((void *) ref);
    ptr->update(b);
}

/*
 * Class:     org_bouncycastle_crypto_fips_NativeDigest
 * Method:    update
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_NativeDigest_update__J_3BII
        (JNIEnv *env, jobject, jlong ref, jbyteArray in_, jint inOff, jint len) {
    auto ptr = static_cast<intel::digest::Digest *>((void *) ref);

    jniutil::JavaByteArray in(env, in_);
    if (in.isNull()) {
        jniutil::JavaEnvUtils::throwIllegalArgumentException(env, "input array is null");
        return;
    }

    if (in.length() < inOff + len) {
        jniutil::JavaEnvUtils::throwIllegalArgumentException(env, "input array less than offset + len");
        return;
    }

    ptr->update(in.uvalue(), inOff, len);
}

/*
 * Class:     org_bouncycastle_crypto_fips_NativeDigest
 * Method:    doFinal
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_NativeDigest_doFinal
        (JNIEnv *env, jobject, jlong ref, jbyteArray out_, jint start) {
    auto ptr = static_cast<intel::digest::Digest *>((void *) ref);

    jniutil::JavaByteArray out(env, out_);
    if (out.isNull()) {
        jniutil::JavaEnvUtils::throwIllegalArgumentException(env, "output array is null");
        return 0;
    }

    if (start + (ptr->getDigestSize()) > out.length()) {
        jniutil::JavaEnvUtils::throwIllegalArgumentException(env, "output buffer too small for digest at start");
        return 0;
    }

    ptr->digest(out.uvalue(), start);
    return ptr->getDigestSize();
}

/*
 * Class:     org_bouncycastle_crypto_fips_NativeDigest
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_NativeDigest_reset
        (JNIEnv *env, jobject, jlong ref) {
    auto ptr = static_cast<intel::digest::Digest *>((void *) ref);
    ptr->reset();
}

/*
 * Class:     org_bouncycastle_crypto_fips_NativeDigest
 * Method:    getByteLength
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_NativeDigest_getByteLength
        (JNIEnv *env, jobject, jlong ref) {
    auto ptr = static_cast<intel::digest::Digest *>((void *) ref);
    return ptr->getByteLength();
}



/*
 * Class:     org_bouncycastle_crypto_fips_NativeDigest
 * Method:    setState
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_NativeDigest_setState
        (JNIEnv *env, jobject, jlong ref, jbyteArray state_) {
    auto ptr = static_cast<intel::digest::Digest *>((void *) ref);

    jniutil::JavaByteArray state(env, state_);

    if (state.isNull()) {
        jniutil::JavaEnvUtils::throwIllegalArgumentException(env, "state data array was null");
    };

    try {
        ptr->setState(state.uvalue(), state.length());
    } catch (std::exception &e) {
        jniutil::JavaEnvUtils::throwIllegalArgumentException(env, e.what());
    }
}

/*
 * Class:     org_bouncycastle_crypto_fips_NativeDigest
 * Method:    getState
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bouncycastle_crypto_fips_NativeDigest_getState
        (JNIEnv *env, jobject, jlong ref) {

    auto ptr = static_cast<intel::digest::Digest *>((void *) ref);
    size_t len = 0;

//
// Null buffer causes length to be set and then exits.
//
    ptr->encodeState(nullptr, len);


//
// This array will be returned and is owned by the JVM.
//
    jbyteArray arr = env->NewByteArray((jint) len);

    jniutil::JavaByteArray destination(env, arr);
    ptr->encodeState(destination.uvalue(), len);

    return arr;

}
