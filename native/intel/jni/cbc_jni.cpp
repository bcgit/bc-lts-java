#include "org_bouncycastle_crypto_engines_AESNativeCBC.h"
#include <cassert>
#include "../cbc/CBCLike.h"
#include "../../jniutil/JavaByteArray.h"
#include "../../jniutil/JavaByteArrayCritical.h"
#include "../../macro.h"
#include "../cbc/CBC128wide.h"
#include "../cbc/AesCBCNarrow.h"


//
// NOTE:
// All assertions of length and correctness are done on the java side.
// None of this code is intended to stand apart from the java code that calls it.
//


/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeCBC
 * Method:    process
 * Signature: (J[BII[BI)I
 */
//[[maybe_unused]] JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_fips_AESNativeCBC_process
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_process
        (JNIEnv *env, jclass, jlong ref, jbyteArray in_, jint inOff, jint blocks, jbyteArray out_, jint outOff) {

    //
    // Always wrap output array first.
    //
    jniutil::JavaByteArrayCritical out(env, out_);
    jniutil::JavaByteArrayCritical in(env, in_);

    auto instance = static_cast<intel::cbc::CBCLike *>((void *) ref);
    return (jint) instance->processBlocks(in.uvalue() + inOff, (uint32_t) blocks, out.uvalue() + outOff);

}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeCBC
 * Method:    getMultiBlockSize
 * Signature: (I)I
 */
//[[maybe_unused]] JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_fips_AESNativeCBC_getMultiBlockSize
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_getMultiBlockSize
        (JNIEnv *, jclass, jlong) {
    return CBC_BLOCK_SIZE_4;
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeCBC
 * Method:    getBlockSize
 * Signature: (J)I
 */
//[[maybe_unused]] JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_fips_AESNativeCBC_getBlockSize
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_getBlockSize
        (JNIEnv *, jclass, jlong) {
    return CBC_BLOCK_SIZE;
}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeCBC
 * Method:    makeNative
 * Signature: (IZ)J
 */
//[[maybe_unused]] JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_fips_AESNativeCBC_makeNative
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_makeNative
        (JNIEnv *, jclass, jint keySize, jboolean encryption) {

    void *instance = nullptr;

    if (encryption == JNI_TRUE) {

        switch (keySize) {
            case 16:
                instance = new intel::cbc::AesCBC128Enc();
                break;
            case 24:
                instance = new intel::cbc::AesCBC192Enc();
                break;
            case 32:
                instance = new intel::cbc::AesCBC256Enc();
                break;
            default:
                break;
        }
    } else {
        switch (keySize) {

            case 16:
                instance = new intel::cbc::AesCBC128Dec();
                break;
            case 24:
                instance = new intel::cbc::AesCBC192Dec();
                break;
            case 32:
                instance = new intel::cbc::AesCBC256Dec();
                break;

            default:
                break;
        }
    }

    return (jlong) instance;
}




/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeCBC
 * Method:    init
 * Signature: (J[B[B)V
 */
//[[maybe_unused]] JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_fips_AESNativeCBC_init
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_init
        (JNIEnv *env, jobject, jlong ref, jbyteArray key_, jbyteArray iv_) {

    auto instance = static_cast<intel::cbc::CBCLike *>((void *) ref);
    jniutil::JavaByteArray key(env, key_);
    jniutil::JavaByteArray iv(env, iv_);

    instance->init(key.uvalue(), key.length(), iv.uvalue(), iv.length());

}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeCBC
 * Method:    dispose
 * Signature: (J)V
 */
//[[maybe_unused]] JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_fips_AESNativeCBC_dispose
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_dispose
        (JNIEnv *, jclass, jlong ref) {

    auto instance = static_cast<intel::cbc::CBCLike *>((void *) ref);
    delete instance;

}

/*
 * Class:     org_bouncycastle_crypto_fips_AESNativeCBC
 * Method:    reset
 * Signature: (J)V
 */
//[[maybe_unused]] JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_fips_AESNativeCBC_reset
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeCBC_reset
        (JNIEnv *, jclass, jlong ref) {
    auto instance = static_cast<intel::cbc::CBCLike *>((void *) ref);
    instance->reset();
}