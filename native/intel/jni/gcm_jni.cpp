#include "org_bouncycastle_crypto_engines_AESNativeGCM.h"

#include "../gcm/gcm.h"
#include "../gcm/AesGcm128wide.h"
#include "../../jniutil/JavaByteArray.h"
#include "../../exceptions/OutputLengthException.h"
#include "../../jniutil/JavaEnvUtils.h"
#include "../../exceptions/CipherTextException.h"
#include "../../jniutil/JavaByteArrayCritical.h"
#include "../../macro.h"

//
// NOTE:
// 99% of input validation is done on the java side and this code is not intended to
// stand apart from the java code that calls it. GCM implements some extra bounds checking
// in doFinal because it needs information held within the native implementation.
// GCM also has a limit to the number of blocks that can be processed, this is also
// enforced within the native implementation.
//


/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    reset
 * Signature: (J)V
 */
//[[maybe_unused]] JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_reset
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_reset
        (JNIEnv *, jobject, jlong ref) {
    auto instance = static_cast<intel::gcm::GCM *>((void *) ref);
    instance->reset(false);
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    initNative
 * Signature: (JZ[B[B[BI)V
 */
//[[maybe_unused]] JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_initNative
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_initNative
        (JNIEnv *env, jclass, jlong ref, jboolean direction, jbyteArray key_, jbyteArray nonce_, jbyteArray aad_,
         jint macSizeInBits) {


    jniutil::JavaByteArray key(env, key_);
    jniutil::JavaByteArray nonce(env, nonce_);
    jniutil::JavaByteArray aad(env, aad_);

    auto instance = static_cast<intel::gcm::GCM *>((void *) ref);
    instance->init(direction == JNI_TRUE,
                   key.uvalue(),
                   key.length(),
                   nonce.uvalue(),
                   nonce.length(),
                   aad.uvalue(),
                   aad.length(),
                   (size_t) macSizeInBits);
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    makeInstance
 * Signature: (I)J
 */
//[[maybe_unused]] JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_makeInstance
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_makeInstance
        (JNIEnv *, jclass, jint ,jboolean encryption) {

    // TODO add key size implementations.


    auto instance = encryption == JNI_TRUE?
            new intel::gcm::AesGcm128wideEncrypt():
            new intel::gcm::AesGcm128wideDecrypt();
    return (jlong) instance;
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    dispose
 * Signature: (J)V
 */
//[[maybe_unused]] JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_dispose
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_dispose
        (JNIEnv *, jclass, jlong ref) {
    auto instance = static_cast<intel::gcm::GCM *>((void *) ref);
    delete instance;
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    processAADByte
 * Signature: (JB)V
 */
//[[maybe_unused]] JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_processAADByte
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_processAADByte
        (JNIEnv *, jclass, jlong ref, jbyte b) {
    auto instance = static_cast<intel::gcm::GCM *>((void *) ref);
    instance->processAADByte((unsigned char) b);
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    processAADBytes
 * Signature: (J[BII)V
 */
//[[maybe_unused]] JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_processAADBytes
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_processAADBytes
        (JNIEnv *env, jclass, jlong ref, jbyteArray aad_, jint offset, jint len) {

    jniutil::JavaByteArrayCritical aad(env, aad_);
    auto instance = static_cast<intel::gcm::GCM *>((void *) ref);
    instance->processAADBytes(aad.uvalue(), (size_t) offset, (size_t) len);
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    processByte
 * Signature: (JB[BI)I
 */
//[[maybe_unused]] JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_processByte
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_processByte
        (JNIEnv *env, jclass, jlong ref, jbyte in, jbyteArray out_, jint outOff) {


    jniutil::JavaByteArray out(env, out_);
    auto instance = static_cast<intel::gcm::GCM *>((void *) ref);
    return (jint) instance->processByte((unsigned char) in, out.uvalue() + outOff, out.length());
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    processBytes
 * Signature: (J[BII[BI)I
 */
//[[maybe_unused]] JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_processBytes
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_processBytes
        (JNIEnv *env, jclass, jlong ref, jbyteArray in_, jint inOff, jint len, jbyteArray out_, jint outOff) {


    jniutil::JavaByteArrayCritical out(env, out_);
    jniutil::JavaByteArrayCritical in(env, in_);

    auto instance = static_cast<intel::gcm::GCM *>((void *) ref);

    //
    // out can be a null byte array ( out.isNull() ) if no output is expected.
    //
    try {
        return (jint) instance->processBytes(in.uvalue(), (size_t) inOff, (size_t) len, out.uvalue(), outOff,
                                             out.length() - (uint32_t)outOff);
    } catch (const exceptions::OutputLengthException &exp) {
        out.disposeNow();
        in.disposeNow();
        jniutil::JavaEnvUtils::throwException(env,
                                              "org/bouncycastle/crypto/internal/OutputLengthException",
                                              exp.what());
    } catch (const std::runtime_error &err) {
        out.disposeNow();
        in.disposeNow();
        jniutil::JavaEnvUtils::throwIllegalArgumentException(env, err.what());
    }

    return 0;
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    doFinal
 * Signature: (J[BI)I
 */
//[[maybe_unused]] JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_doFinal
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_doFinal
        (JNIEnv *env, jclass, jlong ref, jbyteArray out_, jint outOff) {


    jniutil::JavaByteArrayCritical out(env, out_);

    auto instance = static_cast<intel::gcm::GCM *>((void *) ref);
    try {
        return (jint) instance->doFinal(out.uvalue(), (size_t) outOff, out.length());
    } catch (const exceptions::OutputLengthException &exp) {
        out.disposeNow();
        jniutil::JavaEnvUtils::throwException(env,
                                              "org/bouncycastle/crypto/internal/OutputLengthException",
                                              exp.what());
    } catch (const exceptions::CipherTextException &exp) {
        out.disposeNow();
        jniutil::JavaEnvUtils::throwException(env,
                                              "org/bouncycastle/crypto/internal/InvalidCipherTextException",
                                              exp.what());
    } catch (const std::runtime_error &err) {
        out.disposeNow();
        jniutil::JavaEnvUtils::throwIllegalArgumentException(env, err.what());
    }

    return 0;
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    getUpdateOutputSize
 * Signature: (JI)I
 */
//[[maybe_unused]] JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_getUpdateOutputSize
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_getUpdateOutputSize
        (JNIEnv *, jclass, jlong ref, jint len) {


    auto instance = static_cast<intel::gcm::GCM *>((void *) ref);
    return (jint) instance->getUpdateOutputSize((size_t) len);
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    getOutputSize
 * Signature: (JI)I
 */
//[[maybe_unused]] JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_getOutputSize
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_getOutputSize
        (JNIEnv *, jclass, jlong ref, jint len) {
    auto instance = static_cast<intel::gcm::GCM *>((void *) ref);
    return (jint) instance->getOutputSize((size_t) len);
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    getMac
 * Signature: (J)[B
 */
//[[maybe_unused]] JNIEXPORT jbyteArray JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_getMac
JNIEXPORT jbyteArray JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_getMac
        (JNIEnv *env, jclass, jlong ref) {

    auto instance = static_cast<intel::gcm::GCM *>((void *) ref);

    jbyteArray out = env->NewByteArray((jint) instance->getMacLen());

    // Acquire elements.
    auto elements = env->GetByteArrayElements(out, nullptr);

    // Copy in value.
    instance->getMac((unsigned char *) elements);

    // Release elements
    env->ReleaseByteArrayElements(out, elements, 0);

    return out;

}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeGCM
 * Method:    setBlocksRemainingDown
 * Signature: (JJ)V
 */
//[[maybe_unused]] JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_fips_AESNativeGCM_setBlocksRemainingDown
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeGCM_setBlocksRemainingDown
        (JNIEnv *env, jobject, jlong ref, jlong step) {

    auto instance = static_cast<intel::gcm::GCM *>((void *) ref);
    try {
        instance->setBlocksRemainingDown(step);
    } catch (const std::runtime_error &err) {
        jniutil::JavaEnvUtils::throwIllegalArgumentException(env, err.what());
    }

}
