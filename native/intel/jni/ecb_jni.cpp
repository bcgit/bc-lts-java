

#include <cassert>
#include "org_bouncycastle_crypto_engines_AESNativeEngine.h"
#include "../ecb/ecb.h"
#include "../../jniutil/JavaByteArray.h"
#include "../ecb/AesEcb.h"
#include "../../jniutil/JavaByteArrayCritical.h"
#include "../../macro.h"


//
// NOTE:
// All assertions of length and correctness are done on the java side.
// None of this code is intended to stand apart from the java code that calls it.
//



/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeEngine
 * Method:    reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_reset
        (JNIEnv *, jclass, jlong ref) {
    auto instance = static_cast<intel::ecb::ECB *>((void *) ref);
    instance->reset();
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeEngine
 * Method:    process
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_process
        (JNIEnv *env, jclass, jlong ref, jbyteArray _in, jint inOffset, jint blocks, jbyteArray _out, jint outOffset) {


    //
    // Always wrap output array first.
    //
    jniutil::JavaByteArrayCritical out(env, _out);
    jniutil::JavaByteArrayCritical in(env, _in);

    auto instance = static_cast<intel::ecb::ECB *>((void *) ref);
    return (jint) instance->processBlocks(in.uvalue(), (size_t)inOffset, in.length(),(uint32_t) blocks, out.uvalue(), (size_t)outOffset);

}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeEngine
 * Method:    getMultiBlockSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_getMultiBlockSize
        (JNIEnv *, jclass, jlong) {
    return 16;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeEngine
 * Method:    getBlockSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_getBlockSize
        (JNIEnv *, jclass, jlong) {
    return 16;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeEngine
 * Method:    makeInstance
 * Signature: (IZ)J
 */
JNIEXPORT jlong JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_makeInstance
        (JNIEnv *, jclass, jint keyLen, jboolean encryption) {

    void *instance;
    switch (keyLen) {
        case 16:
            if (encryption) {
                instance = new intel::ecb::AesEcb128E();
            } else {
                instance = new intel::ecb::AesEcb128D();
            }
            break;
        case 24:

            if (encryption) {
                instance = new intel::ecb::AesEcb192E();
            } else {
                instance = new intel::ecb::AesEcb192D();
            }
            break;
        case 32:
            if (encryption) {
                instance = new intel::ecb::AesEcb256E();
            } else {
                instance = new intel::ecb::AesEcb256D();
            }
            break;
        default:
            instance = nullptr;
            break;
    }

    //
    // Ownership is managed by the java class that has the reference to it.
    //
    return (jlong) instance;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeEngine
 * Method:    dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_dispose
        (JNIEnv *, jclass, jlong ref) {

    auto instance = static_cast<intel::ecb::ECB *>((void *) ref);
    delete instance;
}

/*
 * Class:     org_bouncycastle_crypto_engines_AESNativeEngine
 * Method:    init
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_engines_AESNativeEngine_init
        (JNIEnv *env, jclass, jlong ref, jbyteArray _key) {
    auto instance = static_cast<intel::ecb::ECB *>((void *) ref);
    jniutil::JavaByteArray key(env, _key);
    instance->init(key.uvalue());
}
