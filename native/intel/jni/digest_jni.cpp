
//
// Created  on 27/6/2022.
//

#include <exception>
#include <jni.h>
#include <stdexcept>
#include "../digest/Digest.h"
#include "../../jniutil/JavaByteArray.h"
#include "../../jniutil/JavaEnvUtils.h"
#include "../digest/SHA256.h"
#include "org_bouncycastle_crypto_digests_NativeDigest.h"
#include "../../jniutil/JavaByteArrayCritical.h"

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
 * Class:     org_bouncycastle_crypto_digests_NativeDigest
 * Method:    destroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_NativeDigest_destroy
        (JNIEnv *, jclass, jlong ref) {

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

    jniutil::JavaByteArrayCritical out(env, out_);
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
 * Class:     org_bouncycastle_crypto_digests_NativeDigest
 * Method:    encodeFullState
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_digests_NativeDigest_encodeFullState
        (JNIEnv *env, jobject, jlong ref, jbyteArray dest, jint offset) {

    auto ptr = static_cast<intel::digest::Digest *>((void *) ref);
    size_t len = 0;
    jniutil::JavaByteArray destination(env, dest);
    if (destination.isNull()) {
        ptr->encodeFullState(nullptr, len);
    } else {
        ptr->encodeFullState(destination.uvalue() + offset, len);
    }
    return (jint) len;
}

/*
 * Class:     org_bouncycastle_crypto_digests_NativeDigest
 * Method:    restoreFullState
 * Signature: (J[BI)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_digests_NativeDigest_restoreFullState
        (JNIEnv *env, jobject, jlong ref, jbyteArray src, jint offset) {

    auto ptr = static_cast<intel::digest::Digest *>((void *) ref);
    jniutil::JavaByteArray source(env, src);

    try {
        ptr->restoreFullState(source.uvalue() + offset, source.length());
    } catch (const std::runtime_error &err) {
        jniutil::JavaEnvUtils::throwIllegalArgumentException(env, err.what());
    }
}

