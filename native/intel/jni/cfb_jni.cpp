#include "org_bouncycastle_crypto_modes_AESNativeCFB.h"

#include "../cfb/cfb.h"
#include "../cfb/AesCFB.h"
#include "../../jniutil/JavaByteArray.h"
#include "../../jniutil/JavaEnvUtils.h"
#include <exception>


//
// NOTE:
// All assertions of length and correctness are done on the java side.
// None of this code is intended to stand apart from the java code that calls it.
//


/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    process
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_modes_AESNativeCFB_process
        (JNIEnv *env, jclass, jlong ref, jbyteArray in_, jint inOff, jint blocks, jbyteArray out_, jint outOff) {


    //
    // Always wrap output array first.
    //
    jniutil::JavaByteArray out(env, out_);
    jniutil::JavaByteArray in(env, in_);

    auto instance = static_cast<intel::cfb::CFB *>((void *) ref);
    return (jint) instance->processBlock(in.uvalue() + inOff, blocks, out.uvalue() + outOff);

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    makeNative
 * Signature: (IZ)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_modes_AESNativeCFB_makeNative
        (JNIEnv *, jclass, jint keySize, jboolean encryption) {

    void *instance = nullptr;

    if (encryption == JNI_TRUE) {


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
                break;
        }
    }

    return (jlong) instance;
}




/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    init
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_modes_AESNativeCFB_init
        (JNIEnv *env, jobject, jlong ref, jbyteArray key_, jbyteArray iv_) {

    auto instance = static_cast<intel::cfb::CFB *>((void *) ref);
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
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_modes_AESNativeCFB_dispose
        (JNIEnv *, jclass, jlong ref) {

    auto instance = static_cast<intel::cfb::CFB *>((void *) ref);
    delete instance;

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeCBC
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_modes_AESNativeCFB_reset
        (JNIEnv *, jclass, jlong ref) {
    auto instance = static_cast<intel::cfb::CFB *>((void *) ref);
    instance->reset();
}