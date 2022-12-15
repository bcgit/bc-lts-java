#include "org_bouncycastle_crypto_engines_AESNativeCFB.h"

#include "../cfb/CFB128Wide.h"
#include "../cfb/AesCFB128Wide.h"
#include "../../jniutil/JavaByteArray.h"
#include "../../jniutil/JavaEnvUtils.h"
#include "../../jniutil/JavaByteArrayCritical.h"
#include "../../macro.h"
#include <exception>
#include <cassert>


//
// NOTE:
// All assertions of length and correctness are done on the java side.
// None of this code is intended to stand apart from the java code that calls it.
//


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCFB
 * Method:    processByte
 * Signature: (JB)B
 */
JNIEXPORT jbyte JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_processByte
        (JNIEnv *env, jclass, jlong ref, jbyte in) {
    auto instance = static_cast<intel::cfb::CFBLike *>((void *) ref);
    return instance->processByte((unsigned char) in);
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCFB
 * Method:    processBytes
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_processBytes
        (JNIEnv *env, jclass, jlong ref, jbyteArray in_, jint inOff, jint len, jbyteArray out_, jint outOff) {

    auto instance = static_cast<intel::cfb::CFBLike *>((void *) ref);

    //
    // Always wrap the output array first
    //
    jniutil::JavaByteArrayCritical out(env, out_);
    jniutil::JavaByteArrayCritical in(env, in_);

    return (jint) instance->processBytes(in.uvalue() + inOff, (size_t) len, out.uvalue() + outOff);

}


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    makeNative
 * Signature: (IZ)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_makeNative
        (JNIEnv *env, jclass, jboolean encrypt, jint keySize) {

    void *instance = nullptr;


    if (encrypt) {
        switch (keySize) {
            case 16:
                instance = new intel::cfb::AesCFB128Enc();
                break;
            case 24:
                instance = new intel::cfb::AesCFB192Enc();
                break;
            case 32:
                instance = new intel::cfb::AesCFB256Enc();
                break;
            default:
                jniutil::JavaEnvUtils::throwIllegalArgumentException(env, "key size must be 16,24 or 32 bytes");
                break;
        }
    } else {

        switch (keySize) {
            case 16:
                instance = new intel::cfb::AesCFB128Dec();
                break;
            case 24:
                instance = new intel::cfb::AesCFB192Dec();
                break;
            case 32:
                instance = new intel::cfb::AesCFB256Dec();
                break;
            default:
                jniutil::JavaEnvUtils::throwIllegalArgumentException(env, "key size must be 16,24 or 32 bytes");
                break;
        }

    }

    return (jlong)
            instance;
}




/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    init
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_init
        (JNIEnv *env, jobject, jlong ref, jbyteArray key_, jbyteArray iv_) {

    auto instance = static_cast<intel::cfb::CFBLike *>((void *) ref);
    jniutil::JavaByteArray key(env, key_);
    jniutil::JavaByteArray iv(env, iv_);
    try {
        instance->init(key.uvalue(), key.length(), iv.uvalue(), iv.length());
    } catch (const std::exception &exp) {
        jniutil::JavaEnvUtils::throwIllegalArgumentException(env, exp.what());
    }
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_dispose
        (JNIEnv *, jclass, jlong ref) {

    auto instance = static_cast<intel::cfb::CFBLike *>((void *) ref);
    delete instance;

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCFB_reset
        (JNIEnv *, jclass, jlong ref) {
    auto instance = static_cast<intel::cfb::CFBLike *>((void *) ref);
    instance->reset();
}